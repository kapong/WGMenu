import SwiftUI

// Form mode of the tunnel editor. The config text stays the source of truth: every field reads a
// fresh WGConfig parse and writes back through it, so an edit rewrites only that field's line and
// comments, unknown keys and hook lines are left as they are.
// View state lives in small ObservableObjects (@StateObject), not @State: with the Command Line Tools
// toolchain @State expands to a macro whose plugin isn't shipped.
struct ConfigForm: View {
    @Binding var text: String

    static let interfaceKeys = ["Address", "DNS", "MTU", "ListenPort", "PrivateKey"]
    static let peerKeys = ["PublicKey", "Endpoint", "AllowedIPs", "PersistentKeepalive", "PresharedKey"]
    static let moreInterfaceKeys = ["Table", "FwMark", "SaveConfig", "PreUp", "PostUp", "PreDown", "PostDown"]
    static let secretKeys: Set = ["privatekey", "presharedkey"]

    var body: some View {
        let cfg = WGConfig(text)
        Form {
            if cfg.sections.isEmpty {
                Text("No [Interface] or [Peer] section found. Use Text mode.").foregroundStyle(.secondary)
            }
            ForEach(cfg.sections.indices, id: \.self) { s in
                let sec = cfg.sections[s]
                let keys = sec.name == "interface" ? Self.interfaceKeys : sec.name == "peer" ? Self.peerKeys : []
                Section(title(cfg, s)) {
                    ForEach(keys, id: \.self) { key in
                        KnownField(text: $text, section: s, key: key, secret: Self.secretKeys.contains(key.lowercased()))
                    }
                    // Repeated or unlisted keys (hooks, Table, typos…): one row per line.
                    ForEach(sec.entries.filter { !keys.map { $0.lowercased() }.contains($0.key.lowercased()) }, id: \.line) { e in
                        HStack {
                            LiveField(label: e.key, value: e.value, secret: Self.secretKeys.contains(e.key.lowercased())) { v in
                                update { $0.setLine(e.line, value: v) }
                            }
                            Button { update { $0.removeLine(e.line) } } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.borderless).help("Remove this line")
                        }
                    }
                    AddFieldRow(suggestions: sec.name == "interface" ? Self.moreInterfaceKeys : []) { k, v in
                        update { $0.add(k, v, in: s) }
                    }
                }
            }
            Button("Add Peer") { update { $0.addPeer() } }
        }
        .formStyle(.grouped)
    }

    private func title(_ cfg: WGConfig, _ s: Int) -> String {
        switch cfg.sections[s].name {
        case "interface": return "Interface"
        case "peer": return "Peer \((cfg.peers.firstIndex(of: s) ?? 0) + 1)"
        default: return "[\(cfg.sections[s].name)]"
        }
    }

    private func update(_ edit: (inout WGConfig) -> Void) {
        var cfg = WGConfig(text)
        edit(&cfg)
        text = cfg.text
    }
}

// One listed key of a section (combined across repeated lines). Clearing it removes its line(s);
// typing again re-inserts at the same place rather than at the end of the section.
private struct KnownField: View {
    @Binding var text: String
    let section: Int
    let key: String
    let secret: Bool
    @StateObject private var slot = Slot()

    final class Slot: ObservableObject { var line: Int? }   // last line of the key, for re-insertion

    var body: some View {
        let cfg = WGConfig(text)
        if let line = cfg.entries(key, in: section).first?.line { slot.line = line }
        return LiveField(label: key, value: cfg.value(key, in: section), secret: secret) { v in
            var cfg = WGConfig(text)
            cfg.set(key, to: v, in: section, at: slot.line)
            text = cfg.text
        }
    }
}

// Edits one value live. Keeps its own draft because stored values are trimmed: without it a typed
// trailing space (e.g. "a, ") would vanish on the next re-parse. Resyncs when the text changes underneath.
private struct LiveField: View {
    let label: String
    let value: String
    let secret: Bool
    let write: (String) -> Void
    @StateObject private var state = FieldState()

    final class FieldState: ObservableObject {
        @Published var draft = ""
        @Published var reveal = false
    }

    var body: some View {
        HStack {
            if secret && !state.reveal { SecureField(label, text: $state.draft, prompt: Text("not set")) } else { TextField(label, text: $state.draft, prompt: Text("not set")) }
            if secret {
                Button { state.reveal.toggle() } label: { Image(systemName: state.reveal ? "eye.slash" : "eye") }
                    .buttonStyle(.borderless).help(state.reveal ? "Hide" : "Show")
            }
        }
        .autocorrectionDisabled()
        .onAppear { state.draft = value }
        .onChange(of: state.draft) { d in if trimmed(d) != value { write(d) } }
        .onChange(of: value) { v in if v != trimmed(state.draft) { state.draft = v } }
    }

    private func trimmed(_ s: String) -> String { s.trimmingCharacters(in: .whitespacesAndNewlines) }
}

// "Add field": pick a known key or type any key, give it a value, Add appends a new line.
private struct AddFieldRow: View {
    let suggestions: [String]
    let add: (String, String) -> Void
    @StateObject private var new = NewField()

    final class NewField: ObservableObject {
        @Published var key = ""
        @Published var value = ""
    }

    var body: some View {
        let k = new.key.trimmingCharacters(in: .whitespaces)
        HStack {
            if !suggestions.isEmpty {
                Menu("Add field") { ForEach(suggestions, id: \.self) { s in Button(s) { new.key = s } } }.fixedSize()
            }
            TextField("Key", text: $new.key, prompt: Text("Key")).frame(width: 130)
            TextField("Value", text: $new.value, prompt: Text("Value"))
            Button("Add") { add(k, new.value); new.key = ""; new.value = "" }
                .disabled(!WGConfig.isValidKey(k) || new.value.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .labelsHidden()
    }
}
