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
    let managed: Bool?      // up: brought up by WGMenu (`wgctl up`)? nil if down or the helper predates it
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

    static func run(_ args: [String], stdin: String? = nil) -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        p.arguments = ["-n", path] + args          // -n: never prompt; fail if sudoers rule missing
        let o = Pipe(), e = Pipe(), i = Pipe()
        p.standardOutput = o
        p.standardError = e
        if stdin != nil { p.standardInput = i }
        do { try p.run() } catch {
            return Result(status: -1, out: "", err: error.localizedDescription)
        }
        if let stdin {                              // small (a route plan): fits the pipe buffer
            let w = i.fileHandleForWriting
            _ = fcntl(w.fileDescriptor, F_SETNOSIGPIPE, 1)   // sudo/helper exiting unread must not kill us
            try? w.write(contentsOf: Data(stdin.utf8))
            try? w.close()
        }
        let od = o.fileHandleForReading.readDataToEndOfFile()
        let ed = e.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Result(status: p.terminationStatus,
                      out: String(decoding: od, as: UTF8.self),
                      err: String(decoding: ed, as: UTF8.self))
    }

    static func runAsync(_ args: [String], stdin: String? = nil) async -> Result {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                cont.resume(returning: run(args, stdin: stdin))
            }
        }
    }
}

// MARK: - Store

@MainActor
final class TunnelStore: ObservableObject {
    @Published var tunnels: [Tunnel] = []
    @Published var busy: Set<String> = [] { didSet { retryOfficeOff() } }
    @Published var lastError: String?
    @Published var loaded = false
    @Published var launchAtLogin = SMAppService.mainApp.status == .enabled
    @Published var upInFlight: Set<String> = []          // names with a running `up` toggle
    @Published var rates: [String: Stats.Rate] = [:]     // per up tunnel, from the last two polls
    @Published private(set) var rxHealthy: Set<String> = []  // up tunnels passing Stats.rxHealth
    @Published private(set) var offices = UserDefaults.standard.dictionary(forKey: officeKey) as? [String: [String]] ?? [:]  // tunnel name -> office gateway MACs
    @Published private(set) var priority = UserDefaults.standard.stringArray(forKey: priorityKey) ?? []  // tunnel names, highest first

    private var refreshTask: Task<Void, Never>?
    private var timer: Timer?
    private var lastCounters: [String: Stats.Counters] = [:]
    private var lastSampleAt: UInt64 = 0                // CLOCK_MONOTONIC ns: counts through sleep
    private var lastRxChange: [String: UInt64] = [:]    // CLOCK_MONOTONIC ns of the last rx increase (up tunnels only)
    private static let officeKey = "officeGatewayMACs"
    private static let priorityKey = "tunnelPriority"
    private var watcher: NetworkWatcher?
    private var gatewayTask: Task<Void, Never>?
    private var lastGatewayMAC: String?                 // last resolved gateway MAC; nil until the first one
    private var applying = false                        // an applyRoutes() pass is running
    private var applyAgain = false                      // ... and another was asked for meanwhile
    private var dnsApplied: [String: Bool] = [:]        // tunnels this run brought up -> DNS applied (no nodns)
    private var pendingOff: Set<String> = []            // office auto-off waiting for a busy tunnel
    private var warnedOldHelper = false                 // "helper out of date" shown once, not every poll
    private static let oldHelper = "The helper is out of date. Re-run: sudo wgmenu-setup"

    var activeCount: Int { tunnels.filter(\.isUp).count }

    // Up tunnels started outside WGMenu (plain `wg-quick up`): wg-quick's routes, not the priority plan.
    var outside: [Tunnel] { ordered.filter { $0.isUp && $0.managed == false && !busy.contains($0.name) } }

    // Tunnels in priority order (highest first); ones not in `priority` follow in status order.
    var ordered: [Tunnel] {
        let byName = Dictionary(tunnels.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        return RouteRules.ordered(tunnels.map(\.name), priority: priority).compactMap { byName[$0] }
    }

    var health: Stats.Health {
        Stats.health(healthy: tunnels.filter(\.isUp).map { rxHealthy.contains($0.name) },
                     upInFlight: !upInFlight.isEmpty)
    }

    init() {
        // Crash recovery: polls right away, then applies the current plan, which drops routes (and
        // copies) of tunnels no longer up and restores those of tunnels WGMenu brought up before.
        applyRoutes()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.refreshTask == nil else { return }   // periodic poll: skip if one is running
                await self.refresh()
            }
        }
        // New network: office check, and routes again (a full tunnel's endpoint route follows the gateway).
        watcher = NetworkWatcher { [weak self] in Task { @MainActor in self?.checkGateway(); self?.applyRoutes() } }
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
                          tx: Int64(f[5]) ?? 0,
                          managed: f.count >= 7 && f[1] == "up" ? f[6] == "managed" : nil)
        }
        if !warnedOldHelper, tunnels.contains(where: { $0.isUp && $0.managed == nil }) {
            warnedOldHelper = true
            lastError = Self.oldHelper
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
        run(t.name, up: !t.isUp)
    }

    // Take over a tunnel started outside WGMenu: reconnect it through `wgctl up` (after the usual
    // conflict check) so priority routing covers it. Only ever on the user's request.
    func takeOver(_ t: Tunnel) {
        guard !busy.contains(t.name) else { return }
        NSApp.activate(ignoringOtherApps: true)
        guard Self.confirm("Take over \(t.name)?",
                           "\(t.name) disconnects briefly and reconnects from WGMenu, which then installs its routes by priority and replaces the ones wg-quick added.",
                           ok: "Take Over") else { return }
        run(t.name, up: true, reconnect: true)
    }

    // `reconnect`: take the (outside) tunnel down right before the `up`, once the checks passed.
    private func run(_ name: String, up: Bool, reconnect: Bool = false) {
        let action = up ? "up" : "down"
        busy.insert(name)
        if up { upInFlight.insert(name) }
        Task {
            var args = [action, name]
            if up {
                guard let routes = await routesOK(name) else {
                    busy.remove(name)
                    upInFlight.remove(name)
                    return
                }
                // DNS follows priority: a higher tunnel that sets DNS keeps it. Taking it over, lower
                // holders drop theirs first (see moveDNS).
                let owner = routePlan(routes).dnsOwner
                if let owner, owner != name { args.append("nodns") }
                if owner == name { for n in dnsHolders(routes, except: name) { await bounce(n, dns: false) } }
            }
            var r = Helper.Result(status: 0, out: "", err: "")
            if reconnect { r = await Helper.runAsync(["down", name]) }
            if r.status == 0 { r = await Helper.runAsync(args) }
            lastError = r.status == 0 ? nil : "\(reconnect ? "Take over" : action) \(name) failed: " + Self.explain(r)
            await refresh()
            if r.status == 0 {
                dnsApplied[name] = action == "up" ? !args.contains("nodns") : nil
                applyRoutes()
            }
            busy.remove(name)
            upInFlight.remove(name)
        }
    }

    // Before every `up`: compare AllowedIPs/DNS with the tunnels already up (read through `wgctl routes`,
    // which prints no keys). Asks every time, Cancel by default; no "don't ask again".
    // Returns the routes read (`name` and the others; empty if they couldn't be read), nil on Cancel.
    private func routesOK(_ name: String) async -> [String: RouteRules.Routes]? {
        await refresh()
        // Other `up` toggles still running count too: `wgctl routes` reads down tunnels' configs as well.
        var up = tunnels.filter(\.isUp).map(\.name)
        up += upInFlight.subtracting(up).sorted()
        up.removeAll { $0 == name }
        guard !up.isEmpty else { return [:] }
        var routes: [String: RouteRules.Routes] = [:]
        for n in [name] + up {
            let r = await Helper.runAsync(["routes", n])
            guard r.status == 0 else {
                NSApp.activate(ignoringOtherApps: true)
                return Self.confirm("Connect \(name)?", "Can't check for conflicts — re-run wgmenu-setup to update the helper.", ok: "Continue") ? [:] : nil
            }
            routes[n] = RouteRules.parseRoutes(r.out)
        }
        let higher = Set(ordered.map(\.name).prefix(while: { $0 != name }))
        let issues = RouteRules.conflicts(routes[name]!, with: up.map { ($0, routes[$0]!) }, higher: higher,
                                          outside: Set(outside.map(\.name)))
        guard !issues.isEmpty else { return routes }
        NSApp.activate(ignoringOtherApps: true)
        return Self.confirm("\(name) conflicts with a connected tunnel",
                            issues.map { "• " + $0 }.joined(separator: "\n") + "\n\nConnecting may break traffic of either tunnel.",
                            ok: "Continue") ? routes : nil
    }

    // WGMenu owns the routes of the tunnels it brought up (`wgctl up` uses Table = off): after every
    // up, down, priority change and network change, read each up tunnel's AllowedIPs, compute the
    // priority plan and hand it to `wgctl apply-routes`, which skips tunnels started outside WGMenu.
    // One pass at a time; calls during a pass queue exactly one more, which reads fresh state.
    func applyRoutes() {
        guard !applying else { applyAgain = true; return }
        applying = true
        Task {
            repeat {
                applyAgain = false
                await applyRoutesOnce()
            } while applyAgain
            applying = false
        }
    }

    private func applyRoutesOnce() async {
        await refresh()
        let up = tunnels.filter(\.isUp).map(\.name)
        var routes: [String: RouteRules.Routes] = [:]
        for n in up {
            let r = await Helper.runAsync(["routes", n])
            // A missing tunnel would lose all its routes, so apply nothing rather than a partial plan.
            guard r.status == 0 else { lastError = "Routes not applied: " + Self.explain(r); return }
            routes[n] = RouteRules.parseRoutes(r.out)
        }
        let p = routePlan(routes)
        // A prefix without a textual form ("?") is dropped: the helper would reject the whole plan for it.
        let plan = p.routes.flatMap { t in t.routes.map(\.description).filter { $0 != "?" }.map { "\(t.name) \($0)\n" } }.joined()
        let r = await Helper.runAsync(["apply-routes"], stdin: plan)
        if r.status != 0 { lastError = "Routes not applied: " + Self.explain(r) }
        await moveDNS(owner: p.dnsOwner, routes)
    }

    // DNS follows priority among the tunnels this run brought up (others are left alone). wg-quick only
    // sets DNS at up and restores what it found then at down, so moving DNS means reconnecting: holders
    // that aren't the owner first come back with nodns, then an owner that came up with nodns comes back
    // with DNS. Bounced tunnels lost their routes, so another apply pass follows.
    private func moveDNS(owner: String?, _ routes: [String: RouteRules.Routes]) async {
        dnsApplied = dnsApplied.filter { routes[$0.key] != nil }   // forget tunnels no longer up
        var bounced = false
        for n in dnsHolders(routes, except: owner) { bounced = await bounce(n, dns: false) || bounced }
        if let owner, dnsApplied[owner] == false { bounced = await bounce(owner, dns: true) || bounced }
        if bounced { applyAgain = true }
    }

    // Tunnels this run brought up with DNS that set DNS, other than `except`.
    private func dnsHolders(_ routes: [String: RouteRules.Routes], except: String?) -> [String] {
        dnsApplied.filter { $0.value && $0.key != except && !(routes[$0.key]?.dns.isEmpty ?? true) }.keys.sorted()
    }

    // Internal reconnect to move DNS: no conflict prompt, no office check. Returns true if it went down.
    @discardableResult
    private func bounce(_ name: String, dns: Bool) async -> Bool {
        guard !busy.contains(name) else { return false }
        busy.insert(name)
        defer { busy.remove(name) }
        var r = await Helper.runAsync(["down", name])
        let wentDown = r.status == 0
        if wentDown {
            dnsApplied[name] = nil
            r = await Helper.runAsync(dns ? ["up", name] : ["up", name, "nodns"])
            if r.status == 0 { dnsApplied[name] = dns }
        }
        if r.status != 0 { lastError = "Reconnecting \(name) to move DNS failed: " + Self.explain(r) }
        return wentDown
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
            pendingOff = []                             // a new network replaces any wait from the last one
            for t in tunnels where names.contains(t.name) { officeOff(t) }
        }
    }

    // A busy tunnel (e.g. reconnecting to move DNS) is turned off as soon as it is free again.
    private func officeOff(_ t: Tunnel) {
        if busy.contains(t.name) { pendingOff.insert(t.name) } else { toggle(t) }   // up, so toggle = down
    }

    // Runs when `busy` changes: re-reads status and turns off only tunnels that are still up (never on).
    private func retryOfficeOff() {
        let ready = pendingOff.subtracting(busy)
        guard !ready.isEmpty else { return }
        pendingOff.subtract(ready)
        Task {
            await refresh()
            for t in tunnels where ready.contains(t.name) && t.isUp { officeOff(t) }
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

    // Swap with the neighbour above (-1) or below (+1).
    func move(_ t: Tunnel, by offset: Int) {
        guard let i = ordered.firstIndex(where: { $0.name == t.name }) else { return }
        move(t.name, to: i + offset)
    }

    // Put `name` at `index` of the displayed order and store the whole order.
    func move(_ name: String, to index: Int) {
        var names = ordered.map(\.name)
        guard let i = names.firstIndex(of: name), names.indices.contains(index), index != i else { return }
        names.insert(names.remove(at: i), at: index)
        setPriority(names)
        if activeCount > 1 { applyRoutes() }
    }

    private func setPriority(_ names: [String]) {
        priority = names
        UserDefaults.standard.set(names, forKey: Self.priorityKey)
    }

    // For applying routes: `routes` holds the `wgctl routes` output of each tunnel that is (or is
    // about to be) up. Returns each one's routes, highest priority first, and which one owns DNS.
    func routePlan(_ routes: [String: RouteRules.Routes]) -> (routes: [(name: String, routes: [RouteRules.CIDR])], dnsOwner: String?) {
        let up = RouteRules.ordered(routes.keys.sorted(), priority: ordered.map(\.name))
        return (RouteRules.plan(up.map { ($0, routes[$0]!.allowedIPs) }),
                RouteRules.dnsOwner(up.map { ($0, !routes[$0]!.dns.isEmpty) }))
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
            if errors.count < up.count { applyRoutes() }
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
            let text = data.flatMap { String(data: $0, encoding: .utf8) }
            guard let data, let text, Self.vet(text, rejected: "Skipped \(url.lastPathComponent)",
                                               name: name, ok: "Import Anyway") else { continue }
            let replace = existing.contains(name)
            if replace, !Self.confirm(
                "Replace \(name)?", "/etc/wireguard/\(name).conf already exists and will be overwritten.\n"
                    + "If the tunnel is up, it will later be stopped with the new config's PreDown/PostDown.",
                ok: "Replace") { continue }
            // Edit AllowedIPs: finish this file in the editor instead; its Save installs it.
            guard Self.keepFullTunnel(name, text) else {
                if EditorWindow.isOpen(name) {
                    Self.alert("Skipped \(url.lastPathComponent)", "An editor for \(name) is already open. Close it and import again.")
                } else {
                    EditorWindow.open(name: name, text: text, store: self, importing: replace)
                }
                continue
            }
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

    // Import and Save: a /0 (or both /1 halves) in any peer's AllowedIPs gets a warning. true = proceed (not a full tunnel,
    // or Keep full tunnel); false = the user chose Edit AllowedIPs.
    static func keepFullTunnel(_ name: String, _ text: String) -> Bool {
        let cfg = WGConfig(text)
        guard RouteRules.isFullTunnel(cfg.allowedIPs.flatMap { $0 }) else { return true }
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = RouteRules.fullTunnelWarning
        a.informativeText = "\(name) has AllowedIPs 0.0.0.0/0 or ::/0 (or both /1 halves), so it takes every connection and clashes with any other tunnel.\n\n"
            + RouteRules.fullTunnelHint(addresses: cfg.addresses)
        a.addButton(withTitle: "Keep full tunnel")
        a.addButton(withTitle: "Edit AllowedIPs")
        return a.runModal() == .alertFirstButtonReturn
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
    // `replace` is false for a new file finished from Import (never overwrite an existing config).
    // `importing`: nothing is installed yet, so even unchanged (e.g. emptied) text goes through vet.
    func save(name: String, original: String, edited: String, replace: Bool = true, importing: Bool = false) -> Bool {
        guard importing || edited != original else { return true }
        guard ConfigImport.isValidName(name),
              Self.vet(edited, rejected: "Not saved", name: name, ok: "Save Anyway"),
              install([(name, Data(edited.utf8), replace)], failure: "Save failed") else { return false }
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
                else { applyRoutes() }
            }
            if downOK {
                if Self.privileged(ConfigImport.shellScript(cmd), failure: "Delete failed") != nil {
                    lastError = nil
                    setOffices(name, nil)           // a re-import under this name starts without office rules
                    setPriority(priority.filter { $0 != name })   // ... and at the bottom of the list
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
        if lines.contains(where: { $0.contains("wgctl: usage:") }) {   // a helper older than this app
            return oldHelper
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
                Button("Move Up") { store.move(tunnel, by: -1) }.disabled(store.ordered.first?.name == tunnel.name)
                Button("Move Down") { store.move(tunnel, by: 1) }.disabled(store.ordered.last?.name == tunnel.name)
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
            .help("Edit, delete, priority or office networks for \(tunnel.name)")
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

// A row being dragged to a new priority. The list shows it at `index` while dragging; the order
// is stored once, on drop, so routes are re-applied once per drag.
@MainActor
final class RowDrag: ObservableObject {
    @Published var name: String?
    @Published var index = 0
    var mids: [String: CGFloat] = [:]   // each row's vertical centre in the list
}

struct RowMids: PreferenceKey {
    static var defaultValue: [String: CGFloat] = [:]
    static func reduce(value: inout [String: CGFloat], nextValue: () -> [String: CGFloat]) {
        value.merge(nextValue()) { $1 }
    }
}

@MainActor
struct RowDropDelegate: DropDelegate {
    let store: TunnelStore
    let drag: RowDrag

    func validateDrop(info: DropInfo) -> Bool { drag.name != nil }   // only our own rows

    // Land above the first other row whose centre is below the pointer.
    func dropUpdated(info: DropInfo) -> DropProposal? {
        guard let name = drag.name else { return nil }
        let i = drag.mids.filter { $0.key != name && $0.value < info.location.y }.count
        if i != drag.index { withAnimation(.easeInOut(duration: 0.15)) { drag.index = i } }
        return DropProposal(operation: .move)
    }

    func dropExited(info: DropInfo) { drag.name = nil }              // left the list, or cancelled

    func performDrop(info: DropInfo) -> Bool {
        guard let name = drag.name else { return false }
        store.move(name, to: drag.index)
        drag.name = nil
        return true
    }
}

struct ContentView: View {
    @EnvironmentObject var store: TunnelStore
    @StateObject private var drag = RowDrag()

    // Priority order, with a dragged row shown where it would land.
    private var rows: [Tunnel] {
        var r = store.ordered
        if let name = drag.name, let i = r.firstIndex(where: { $0.name == name }) {
            r.insert(r.remove(at: i), at: min(drag.index, r.count - 1))
        }
        return r
    }

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
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(rows) { t in                       // top = highest priority
                        TunnelRow(tunnel: t)
                            .background(GeometryReader { g in
                                Color.clear.preference(key: RowMids.self, value: [t.name: g.frame(in: .named("rows")).midY])
                            })
                            .contentShape(Rectangle())         // drag from the blank middle too
                            .onDrag {
                                drag.name = t.name
                                drag.index = store.ordered.firstIndex(where: { $0.name == t.name }) ?? 0
                                return NSItemProvider(object: t.name as NSString)
                            }
                    }
                }
                .coordinateSpace(name: "rows")
                .contentShape(Rectangle())                     // gaps between rows are still the list
                .onPreferenceChange(RowMids.self) { drag.mids = $0 }
                .onDrop(of: [.text], delegate: RowDropDelegate(store: store, drag: drag))
            }

            ForEach(store.outside) { t in
                HStack {
                    Text("\(t.name) was started outside WGMenu; priority routing not applied.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Take over") { Task { @MainActor in store.takeOver(t) } }   // deferred: alert goes modal
                        .controlSize(.small)
                }
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
    @Published var scrollTo: String?  // ConfigForm field id to bring into view
    init(text: String) { original = text; self.text = text }

    // Form mode, scrolled to the first peer whose AllowedIPs is a full tunnel.
    func showAllowedIPs() {
        let cfg = WGConfig(text)
        guard let s = cfg.peers.first(where: { RouteRules.isFullTunnel(cfg.values("AllowedIPs", in: $0)) }) else { return }
        formMode = true
        scrollTo = "\(s)-AllowedIPs"
    }
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
            if model.formMode { ConfigForm(text: $model.text, scrollTo: $model.scrollTo) } else { ConfigTextView(text: $model.text) }
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

    static func isOpen(_ name: String) -> Bool { windows[name] != nil }

    // `importing` (the replace flag) opens a not-yet-installed config from Import: Save installs it.
    static func open(name: String, text: String, store: TunnelStore, importing: Bool? = nil) {
        guard !focus(name) else { return }
        let w = EditorWindow(name: name, text: text, store: store, importing: importing)
        windows[name] = w
        NSApp.activate(ignoringOtherApps: true)
        w.window.center()
        w.window.makeKeyAndOrderFront(nil)
    }

    private init(name: String, text: String, store: TunnelStore, importing: Bool?) {
        self.name = name
        model = EditorModel(text: text)
        if importing != nil {
            model.original = ""        // nothing installed yet, so Save always installs
            model.showAllowedIPs()
        }
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 560),
                          styleMask: [.titled, .closable, .resizable, .miniaturizable],
                          backing: .buffered, defer: false)
        super.init()
        window.title = "\(importing == nil ? "Edit" : "Import") \(name) — /etc/wireguard/\(name).conf"
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        window.delegate = self
        // Form fields share the window's field editor: give it the same protections as ConfigTextView.
        // Selection changes fire on every focus (didBeginEditing only on the first keystroke), and
        // SwiftUI resets these settings on each focus, so a focused but unedited field stays covered.
        fieldEditorObserver = NotificationCenter.default.addObserver(
            forName: NSTextView.didChangeSelectionNotification, object: nil, queue: .main) { [weak window] n in
            guard let tv = n.object as? NSTextView, tv.window === window else { return }
            tv.isAutomaticTextReplacementEnabled = false
            if #available(macOS 15, *) { tv.writingToolsBehavior = .none }
            if #available(macOS 14, *) { tv.inlinePredictionType = .no }
        }
        let model = model
        window.contentView = NSHostingView(rootView: EditorView(
            model: model,
            save: { [weak self] in
                // Edit AllowedIPs: stay open, in Form mode at that field.
                // An import isn't installed yet, so unchanged text still needs the Keep confirmation.
                guard (importing == nil && model.text == model.original) || TunnelStore.keepFullTunnel(name, model.text) else {
                    return model.showAllowedIPs()
                }
                if store.save(name: name, original: model.original, edited: model.text,
                              replace: importing ?? true, importing: importing != nil) {
                    self?.closeLater()
                }
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
