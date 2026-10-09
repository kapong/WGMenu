import SwiftUI
import AppKit
import ServiceManagement
import UniformTypeIdentifiers

// MARK: - Model

struct Tunnel: Identifiable {
    let name: String
    let isUp: Bool
    let iface: String
    let lastHandshake: Date?
    let rx: Int64
    let tx: Int64
    var id: String { name }
}

// MARK: - Helper bridge (sudo -n /usr/local/sbin/wgctl ...)

enum Helper {
    static let path = "/usr/local/sbin/wgctl"

    struct Result {
        let status: Int32
        let out: String
        let err: String
    }

    static func run(_ args: [String]) -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        p.arguments = ["-n", path] + args          // -n: never prompt; fail if sudoers rule missing
        let o = Pipe(), e = Pipe()
        p.standardOutput = o
        p.standardError = e
        do { try p.run() } catch {
            return Result(status: -1, out: "", err: error.localizedDescription)
        }
        let od = o.fileHandleForReading.readDataToEndOfFile()
        let ed = e.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Result(status: p.terminationStatus,
                      out: String(decoding: od, as: UTF8.self),
                      err: String(decoding: ed, as: UTF8.self))
    }

    static func runAsync(_ args: [String]) async -> Result {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                cont.resume(returning: run(args))
            }
        }
    }
}

// MARK: - Store

@MainActor
final class TunnelStore: ObservableObject {
    @Published var tunnels: [Tunnel] = []
    @Published var busy: Set<String> = []
    @Published var lastError: String?
    @Published var loaded = false
    @Published var launchAtLogin = SMAppService.mainApp.status == .enabled
    @Published var upInFlight: Set<String> = []          // names with a running `up` toggle
    @Published var rates: [String: Stats.Rate] = [:]     // per up tunnel, from the last two polls
    @Published private(set) var rxHealthy: Set<String> = []  // up tunnels passing Stats.rxHealth
    @Published private(set) var offices = UserDefaults.standard.dictionary(forKey: officeKey) as? [String: [String]] ?? [:]  // tunnel name -> office gateway MACs

    private var refreshTask: Task<Void, Never>?
    private var timer: Timer?
    private var lastCounters: [String: Stats.Counters] = [:]
    private var lastSampleAt: UInt64 = 0                // CLOCK_MONOTONIC ns: counts through sleep
    private var lastRxChange: [String: UInt64] = [:]    // CLOCK_MONOTONIC ns of the last rx increase (up tunnels only)
    private static let officeKey = "officeGatewayMACs"
    private var watcher: NetworkWatcher?
    private var gatewayTask: Task<Void, Never>?
    private var lastGatewayMAC: String?                 // last resolved gateway MAC; nil until the first one

    var activeCount: Int { tunnels.filter(\.isUp).count }

    var health: Stats.Health {
        Stats.health(healthy: tunnels.filter(\.isUp).map { rxHealthy.contains($0.name) },
                     upInFlight: !upInFlight.isEmpty)
    }

    init() {
        Task { await refresh() }
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.refreshTask == nil else { return }   // periodic poll: skip if one is running
                await self.refresh()
            }
        }
        watcher = NetworkWatcher { [weak self] in Task { @MainActor in self?.checkGateway() } }
        checkGateway()                                  // launching on an office network counts as arrival
    }

    // A poll already in flight may predate the caller's change, so wait for it, then poll anyway.
    func refresh() async {
        while let t = refreshTask { await t.value }
        let t = Task { await poll(); refreshTask = nil }
        refreshTask = t
        await t.value
    }

    private func poll() async {
        let r = await Helper.runAsync(["status"])
        loaded = true
        guard r.status == 0 else {
            lastError = Self.explain(r)
            rates = [:]
            return
        }
        tunnels = r.out.split(separator: "\n").compactMap { line in
            let f = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard f.count >= 6 else { return nil }
            let hs = TimeInterval(f[3]) ?? 0
            return Tunnel(name: f[0],
                          isUp: f[1] == "up",
                          iface: f[2],
                          lastHandshake: hs > 0 ? Date(timeIntervalSince1970: hs) : nil,
                          rx: Int64(f[4]) ?? 0,
                          tx: Int64(f[5]) ?? 0)
        }
        let now = clock_gettime_nsec_np(CLOCK_MONOTONIC)
        var cur: [String: Stats.Counters] = [:]
        for t in tunnels where t.isUp { cur[t.name] = Stats.Counters(rx: t.rx, tx: t.tx) }
        rates = Stats.rates(prev: lastCounters, cur: cur, elapsed: Double(now &- lastSampleAt) / 1e9)
        // Down or vanished tunnels drop out of lastRxChange because only up tunnels are carried over.
        let wall = Date()
        var changes: [String: UInt64] = [:]
        var healthy: Set<String> = []
        for t in tunnels where t.isUp {
            let s = Stats.rxHealth(rx: t.rx, prevRx: lastCounters[t.name]?.rx, lastRxChange: lastRxChange[t.name],
                                   handshakeAge: t.lastHandshake.map { wall.timeIntervalSince($0) }, now: now)
            changes[t.name] = s.lastRxChange
            if s.healthy { healthy.insert(t.name) }
        }
        lastRxChange = changes
        rxHealthy = healthy
        lastCounters = cur
        lastSampleAt = now
    }

    func toggle(_ t: Tunnel) {
        guard !busy.contains(t.name) else { return }
        let action = t.isUp ? "down" : "up"
        let name = t.name
        busy.insert(name)
        if action == "up" { upInFlight.insert(name) }
        Task {
            let r = await Helper.runAsync([action, name])
            lastError = r.status == 0 ? nil : "\(action) \(name) failed: " + Self.explain(r)
            await refresh()
            busy.remove(name)
            upInFlight.remove(name)
        }
    }

    // Office auto-off: when the gateway MAC changes to one a tunnel lists and that tunnel is up, take
    // it down once. Same MAC again (manual re-enable), no gateway or no ARP entry: do nothing.
    // A newer network change cancels a pending check.
    private func checkGateway() {
        gatewayTask?.cancel()
        gatewayTask = Task {
            var mac: String?
            for attempt in 0..<5 {                      // ARP may not know the router yet right after joining
                if attempt > 0 { try? await Task.sleep(nanoseconds: 1_000_000_000) }
                guard !Task.isCancelled, let router = watcher?.router else { return }
                mac = await Self.gatewayMAC(router)
                if mac != nil { break }
            }
            guard let mac, mac != lastGatewayMAC else { return }
            await refresh()                             // decide on fresh up/down state, not a 5 s old poll
            guard !Task.isCancelled else { return }
            let names = OfficeRules.toDisconnect(mac: mac, lastMAC: lastGatewayMAC, offices: offices,
                                                 up: tunnels.filter(\.isUp).map(\.name))
            lastGatewayMAC = mac
            for t in tunnels where names.contains(t.name) { toggle(t) }
        }
    }

    // `arp -n` needs no root. The IP is validated first so nothing else reaches arp's argv.
    private static func gatewayMAC(_ router: String) async -> String? {
        guard OfficeRules.isIPv4(router) else { return nil }
        return await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: "/usr/sbin/arp")
                p.arguments = ["-n", router]
                let o = Pipe()
                p.standardOutput = o
                p.standardError = FileHandle.nullDevice
                guard (try? p.run()) != nil else { return cont.resume(returning: nil) }
                let d = o.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                cont.resume(returning: OfficeRules.macFromArp(String(decoding: d, as: UTF8.self)))
            }
        }
    }

    func markOffice(_ t: Tunnel) {
        let name = t.name
        Task {
            guard let router = watcher?.router, let mac = await Self.gatewayMAC(router) else {
                NSApp.activate(ignoringOtherApps: true)
                Self.alert("No gateway found", "Couldn't read the default gateway's MAC address. Connect to the office network and try again.")
                return
            }
            setOffices(name, OfficeRules.adding(mac, to: offices[name] ?? []))
            lastGatewayMAC = mac                        // already here: don't treat this network as a new arrival
        }
    }

    func clearOffices(_ t: Tunnel) { setOffices(t.name, nil) }

    private func setOffices(_ name: String, _ macs: [String]?) {
        offices[name] = macs
        UserDefaults.standard.set(offices, forKey: Self.officeKey)
    }

    func disconnectAll() {
        let up = tunnels.filter(\.isUp).map(\.name)
        guard !up.isEmpty else { return }
        busy.formUnion(up)
        Task {
            var errors: [String] = []
            for name in up {
                let r = await Helper.runAsync(["down", name])
                if r.status != 0 { errors.append("\(name): " + Self.explain(r)) }
            }
            lastError = errors.isEmpty ? nil : errors.joined(separator: "\n")
            await refresh()
            busy.subtract(up)
        }
    }

    func setLaunchAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            lastError = "Launch at login: \(error.localizedDescription)"
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    // Copies .conf files into /etc/wireguard via an admin password prompt each time.
    // Deliberately NOT a wgctl command: wg-quick runs PostUp/PreUp as root, so a
    // passwordless import would hand any user-level process silent root.
    func importConfigs() {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [UTType(filenameExtension: "conf")].compactMap { $0 }
        panel.message = "Choose WireGuard .conf files to add to /etc/wireguard"
        guard panel.runModal() == .OK else { return }

        // Only trust the list if the last poll succeeded; otherwise the privileged command
        // refuses to overwrite any existing file (see ConfigImport.installCommand).
        let statusOK = loaded && lastError == nil
        let existing = statusOK ? Set(tunnels.map(\.name)) : []
        var accepted: [(name: String, data: Data, replace: Bool)] = []
        for url in panel.urls {
            let name = url.deletingPathExtension().lastPathComponent
            guard ConfigImport.isValidName(name) else {
                Self.alert("Skipped \(url.lastPathComponent)",
                           "The tunnel name (file name without .conf) must be 1–15 characters: letters, digits, _ = + . -")
                continue
            }
            guard !accepted.contains(where: { $0.name == name }) else {
                Self.alert("Skipped \(url.lastPathComponent)", "Another selected file is also named \(name).conf.")
                continue
            }
            let data = try? Data(contentsOf: url)
            guard let data, Self.vet(String(data: data, encoding: .utf8), rejected: "Skipped \(url.lastPathComponent)",
                                     name: name, ok: "Import Anyway") else { continue }
            let replace = existing.contains(name)
            if replace, !Self.confirm(
                "Replace \(name)?", "/etc/wireguard/\(name).conf already exists and will be overwritten.\n"
                    + "If the tunnel is up, it will later be stopped with the new config's PreDown/PostDown.",
                ok: "Replace") { continue }
            accepted.append((name, data, replace))
        }
        guard !accepted.isEmpty else { return }
        install(accepted, failure: "Import failed")
        Task { await refresh() }
    }

    // Shared by Import and Edit. Hooks: warn whenever the text has any, not only new ones; simpler,
    // and an edit can't silently smuggle a changed PostUp past the prompt.
    private static func vet(_ text: String?, rejected: String, name: String, ok: String) -> Bool {
        guard let text, ConfigImport.looksLikeConfig(text) else {
            alert(rejected, "Not a WireGuard config (UTF-8 text with an [Interface] section).")
            return false
        }
        return !ConfigImport.hasHooks(text) || confirm(
            "\(name) runs commands as root",
            "This config has PreUp/PostUp/PreDown/PostDown lines. wg-quick runs them as root every time the tunnel goes up or down. Continue only if you trust and have read this config.",
            ok: ok)
    }

    // Shared by Import and Edit: write exactly the validated bytes into a private temp dir (0700/0600,
    // removed on return), then one admin-prompt install that re-checks each file's SHA-256.
    @discardableResult
    private func install(_ accepted: [(name: String, data: Data, replace: Bool)], failure: String) -> Bool {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? fm.removeItem(at: tmp) }
        do {
            try fm.createDirectory(at: tmp, withIntermediateDirectories: false,
                                   attributes: [.posixPermissions: 0o700])
            for c in accepted {
                let dest = tmp.appendingPathComponent("\(c.name).conf")
                guard fm.createFile(atPath: dest.path, contents: c.data,
                                    attributes: [.posixPermissions: 0o600]) else {
                    throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: dest.path])
                }
            }
        } catch {
            Self.alert(failure, error.localizedDescription)
            return false
        }
        let items = accepted.map { ConfigImport.Item(name: $0.name, sha256: ConfigImport.sha256Hex($0.data), replace: $0.replace) }
        return Self.privileged(ConfigImport.appleScript(tmpDir: tmp.path, items: items), failure: failure) != nil
    }

    // NSAppleScript belongs on the main thread; it blocks only while the password prompt is up.
    // Returns stdout, or nil on cancel (-128, silent) or failure (alerted).
    private static func privileged(_ source: String, failure: String) -> String? {
        var err: NSDictionary?
        let out = NSAppleScript(source: source)?.executeAndReturnError(&err)
        if let err {
            if (err[NSAppleScript.errorNumber] as? Int) != -128 {
                alert(failure, err[NSAppleScript.errorMessage] as? String ?? "\(err)")
            }
            return nil
        }
        return out?.stringValue ?? ""
    }

    // Edit: read the root-only config with an admin prompt, then open the editor window.
    func edit(_ t: Tunnel) {
        guard !EditorWindow.focus(t.name), let cmd = ConfigImport.readCommand(name: t.name) else { return }
        NSApp.activate(ignoringOtherApps: true)
        guard let text = Self.privileged(ConfigImport.shellScript(cmd), failure: "Couldn't read \(t.name)") else { return }
        EditorWindow.open(name: t.name, text: text, store: self)
    }

    // Returns true when the editor may close (saved, or nothing changed).
    func save(name: String, original: String, edited: String) -> Bool {
        guard edited != original else { return true }
        guard ConfigImport.isValidName(name),
              Self.vet(edited, rejected: "Not saved", name: name, ok: "Save Anyway"),
              install([(name, Data(edited.utf8), true)], failure: "Save failed") else { return false }
        if tunnels.contains(where: { $0.name == name && $0.isUp }) || busy.contains(name) {
            Self.alert("Saved \(name)", "Reconnect to apply: the tunnel may be up and still uses the old config.")
        }
        Task { await refresh() }
        return true
    }

    func delete(_ t: Tunnel) {
        guard let cmd = ConfigImport.deleteCommand(name: t.name) else { return }
        let name = t.name
        guard !busy.contains(name) else { return }
        let wasUp = tunnels.contains(where: { $0.name == name && $0.isUp })
        NSApp.activate(ignoringOtherApps: true)
        guard Self.confirm("Delete tunnel \(name)?",
                           (wasUp ? "\(name) is up and will be disconnected first. " : "")
                               + "This removes /etc/wireguard/\(name).conf", ok: "Delete") else { return }
        busy.insert(name)
        Task {
            var downOK = true
            if wasUp {
                let r = await Helper.runAsync(["down", name])
                downOK = r.status == 0
                if !downOK { lastError = "down \(name) failed: " + Self.explain(r) }
            }
            if downOK {
                if Self.privileged(ConfigImport.shellScript(cmd), failure: "Delete failed") != nil {
                    lastError = nil
                    setOffices(name, nil)           // a re-import under this name starts without office rules
                } else if wasUp {
                    lastError = "Delete did not complete; \(name) was disconnected"
                }
            }
            busy.remove(name)
            await refresh()
        }
    }

    private static func alert(_ title: String, _ text: String) {
        let a = NSAlert()
        a.messageText = title
        a.informativeText = text
        a.runModal()
    }

    private static func confirm(_ title: String, _ text: String, ok: String) -> Bool {
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = title
        a.informativeText = text
        a.addButton(withTitle: "Cancel")      // first button = default (Return)
        a.addButton(withTitle: ok)
        return a.runModal() == .alertSecondButtonReturn
    }

    private static func explain(_ r: Helper.Result) -> String {
        let lines = r.err.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
        if lines.contains(where: { $0.contains("a password is required") }) {
            return "sudo rule missing. Run: sudo wgmenu-setup"
        }
        let tail = lines.suffix(3).joined(separator: "\n")
        return tail.isEmpty ? "exit code \(r.status)" : tail
    }
}

// MARK: - Views

struct TunnelRow: View {
    @EnvironmentObject var store: TunnelStore
    let tunnel: Tunnel

    private static let bytes: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .binary
        return f
    }()

    private var handshakeAge: TimeInterval? {
        tunnel.lastHandshake.map { Date().timeIntervalSince($0) }
    }

    // Green: up + rx increased within Stats.rxWindow. Orange: up toggle in flight, or up but nothing
    // received lately. Gray: down.
    private var color: Color {
        switch Stats.health(healthy: tunnel.isUp ? [store.rxHealthy.contains(tunnel.name)] : [], upInFlight: store.upInFlight.contains(tunnel.name)) {
        case .off: return .gray
        case .connecting: return .orange
        case .ok: return .green
        }
    }

    private var detail: String {
        guard tunnel.isUp else { return "Disconnected" }
        var parts = [tunnel.iface]
        if let a = handshakeAge {
            parts.append("handshake \(Self.age(a)) ago")
        } else {
            parts.append("waiting for handshake")
        }
        parts.append("↑\(Self.bytes.string(fromByteCount: tunnel.tx)) ↓\(Self.bytes.string(fromByteCount: tunnel.rx))")
        return parts.joined(separator: " · ")
    }

    private static func age(_ s: TimeInterval) -> String {
        let s = Int(max(0, s))
        if s < 60 { return "\(s)s" }
        if s < 3600 { return "\(s / 60)m" }
        return "\(s / 3600)h"
    }

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(color).frame(width: 9, height: 9)
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(tunnel.name).fontWeight(.medium)
                    if let r = store.rates[tunnel.name] {
                        Text(Stats.speed(r)).font(.caption).monospacedDigit().foregroundStyle(.secondary)
                    }
                }
                Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Menu {
                // Deferred so the menu closes before a password prompt or alert goes modal.
                Button("Edit…") { Task { @MainActor in store.edit(tunnel) } }
                Button("Delete…") { Task { @MainActor in store.delete(tunnel) } }
                Divider()
                Button("Mark this network as office") { Task { @MainActor in store.markOffice(tunnel) } }
                if let n = store.offices[tunnel.name]?.count {
                    Button("Clear office networks (\(n))") { store.clearOffices(tunnel) }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .padding(.trailing, 8)                    // keep clicks off the adjacent switch
            .disabled(store.busy.contains(tunnel.name))
            .help("Edit, delete or office networks for \(tunnel.name)")
            if store.busy.contains(tunnel.name) {
                ProgressView().controlSize(.small)
            } else {
                Toggle("", isOn: Binding(get: { tunnel.isUp },
                                         set: { _ in store.toggle(tunnel) }))
                    .toggleStyle(.switch)
                    .labelsHidden()
            }
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var store: TunnelStore

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("WireGuard Tunnels").font(.headline)
                Spacer()
                Button { Task { await store.refresh() } } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.borderless)
                    .help("Refresh")
            }
            Divider()

            if store.tunnels.isEmpty {
                Text(store.loaded ? "No configs found in /etc/wireguard" : "Loading…")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(store.tunnels) { TunnelRow(tunnel: $0) }
            }

            if let err = store.lastError {
                Text(err)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()
            Toggle("Launch at login", isOn: Binding(get: { store.launchAtLogin },
                                                    set: { store.setLaunchAtLogin($0) }))
            HStack {
                Button("Disconnect All") { store.disconnectAll() }
                    .disabled(store.activeCount == 0)
                Button("Import Config…") { store.importConfigs() }
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
        }
        .padding(12)
        .frame(width: 340)
    }
}

// MARK: - Editor window

// NSTextView rather than TextEditor: TextEditor follows the user's smart quote/dash/replacement
// settings, which would silently corrupt keys and PostUp commands.
struct ConfigTextView: NSViewRepresentable {
    @Binding var text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        let tv = scroll.documentView as! NSTextView
        tv.isRichText = false
        tv.allowsUndo = true
        tv.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        tv.isAutomaticQuoteSubstitutionEnabled = false
        tv.isAutomaticDashSubstitutionEnabled = false
        tv.isAutomaticTextReplacementEnabled = false
        tv.isAutomaticSpellingCorrectionEnabled = false
        tv.isContinuousSpellCheckingEnabled = false
        tv.isAutomaticLinkDetectionEnabled = false
        tv.isAutomaticDataDetectionEnabled = false
        tv.isAutomaticTextCompletionEnabled = false
        tv.smartInsertDeleteEnabled = false
        // Keep the config (private key) away from Writing Tools / Apple Intelligence and inline predictions.
        if #available(macOS 15, *) { tv.writingToolsBehavior = .none }
        if #available(macOS 14, *) { tv.inlinePredictionType = .no }
        tv.string = text
        tv.delegate = context.coordinator
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let tv = scroll.documentView as! NSTextView
        if tv.string != text { tv.string = text }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject, NSTextViewDelegate {
        let text: Binding<String>
        init(text: Binding<String>) { self.text = text }
        func textDidChange(_ n: Notification) {
            if let tv = n.object as? NSTextView { text.wrappedValue = tv.string }
        }
    }
}

final class EditorModel: ObservableObject {
    var original: String
    @Published var text: String
    @Published var formMode = true   // both modes edit `text`, so switching never loses data
    init(text: String) { original = text; self.text = text }
}

struct EditorView: View {
    @ObservedObject var model: EditorModel
    let save: () -> Void
    let cancel: () -> Void

    var body: some View {
        VStack(alignment: .trailing, spacing: 10) {
            Picker("Mode", selection: $model.formMode) {
                Text("Form").tag(true)
                Text("Text").tag(false)
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            .frame(maxWidth: .infinity)
            if model.formMode { ConfigForm(text: $model.text) } else { ConfigTextView(text: $model.text) }
            HStack {
                Text("Saving asks for your password. Reconnect an up tunnel to apply.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
                Button("Save", action: save).keyboardShortcut("s", modifiers: .command)
            }
        }
        .padding(12)
        .frame(minWidth: 560, minHeight: 420)
    }
}

// One window per tunnel. The config text (private key) lives only in memory and is cleared on close.
@MainActor
final class EditorWindow: NSObject, NSWindowDelegate {
    private static var windows: [String: EditorWindow] = [:]
    private let name: String
    private let window: NSWindow
    private let model: EditorModel
    private var fieldEditorObserver: NSObjectProtocol?

    // Brings an already-open editor forward (skips a second password prompt).
    static func focus(_ name: String) -> Bool {
        guard let w = windows[name] else { return false }
        NSApp.activate(ignoringOtherApps: true)
        w.window.makeKeyAndOrderFront(nil)
        return true
    }

    static func open(name: String, text: String, store: TunnelStore) {
        guard !focus(name) else { return }
        let w = EditorWindow(name: name, text: text, store: store)
        windows[name] = w
        NSApp.activate(ignoringOtherApps: true)
        w.window.center()
        w.window.makeKeyAndOrderFront(nil)
    }

    private init(name: String, text: String, store: TunnelStore) {
        self.name = name
        model = EditorModel(text: text)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 560),
                          styleMask: [.titled, .closable, .resizable, .miniaturizable],
                          backing: .buffered, defer: false)
        super.init()
        window.title = "Edit \(name) — /etc/wireguard/\(name).conf"
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        window.delegate = self
        // Form fields share the window's field editor: give it the same protections as ConfigTextView.
        fieldEditorObserver = NotificationCenter.default.addObserver(
            forName: NSTextView.didBeginEditingNotification, object: nil, queue: .main) { [weak window] n in
            guard let tv = n.object as? NSTextView, tv.window === window else { return }
            tv.isAutomaticTextReplacementEnabled = false
            if #available(macOS 15, *) { tv.writingToolsBehavior = .none }
            if #available(macOS 14, *) { tv.inlinePredictionType = .no }
        }
        let model = model
        window.contentView = NSHostingView(rootView: EditorView(
            model: model,
            save: { [weak self] in
                if store.save(name: name, original: model.original, edited: model.text) { self?.closeLater() }
            },
            cancel: { [weak self] in self?.closeLater() }))
    }

    // Not from inside the hosting view's own button action: closing tears the view down.
    private func closeLater() {
        DispatchQueue.main.async { [weak self] in self?.window.close() }
    }

    func windowWillClose(_ notification: Notification) {
        if let fieldEditorObserver { NotificationCenter.default.removeObserver(fieldEditorObserver) }
        model.text = ""
        model.original = ""
        window.contentView = nil
        Self.windows[name] = nil
    }
}

// MARK: - App

@main
struct WGMenuApp: App {
    @StateObject private var store = TunnelStore()

    var body: some Scene {
        MenuBarExtra {
            ContentView().environmentObject(store)
        } label: {
            Image(nsImage: MenuBarLabel.image(health: store.health, count: store.activeCount,
                                              speed: store.activeCount > 0 ? Stats.total(store.rates) : nil))
        }
        .menuBarExtraStyle(.window)
    }
}
