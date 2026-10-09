import Foundation
import CryptoKit

// Pure logic for "Import Config…" and Edit/Delete (Foundation + CryptoKit only, so tests/ImportCheck.swift can compile it alone).
enum ConfigImport {
    // Same rule as wgctl: ^[a-zA-Z0-9_=+.-]{1,15}$
    static func isValidName(_ name: String) -> Bool {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_=+.-")
        return (1...15).contains(name.count) && name.allSatisfy(allowed.contains)
    }

    // NUL is rejected: bash `read` drops it, so wg-quick sees "Post\0Up" as PostUp but hasHooks would not.
    static func looksLikeConfig(_ text: String) -> Bool {
        text.contains("[Interface]") && !text.contains("\u{0}")
    }

    // wg-quick runs these keys as root; keys are case-insensitive. Mirror its parse_options:
    // the key is the text before the first "#", then before the first "=", whitespace-trimmed.
    static func hasHooks(_ text: String) -> Bool {
        let hooks: Set<String> = ["preup", "postup", "predown", "postdown"]
        return text.components(separatedBy: "\n").contains { line in
            let code = line.components(separatedBy: "#")[0]
            let key = code.components(separatedBy: "=")[0]
            return hooks.contains(key.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
        }
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func appleScriptLiteral(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    struct Item {
        let name: String
        let sha256: String
        let replace: Bool   // user confirmed overwriting an existing config
    }

    // Per file: refuse to clobber unless confirmed, install to DST.tmp, verify the hash of the
    // validated bytes (closes the temp-file swap/symlink race), then rename into place.
    static func installCommand(tmpDir: String, items: [Item], dir: String = "/etc/wireguard") -> String {
        (["/usr/bin/install -d -o root -g wheel -m 700 \(shellQuote(dir))"] + items.map { i in
            let dst = shellQuote("\(dir)/\(i.name).conf"), tmp = shellQuote("\(dir)/\(i.name).conf.tmp")
            let noClobber = i.replace ? "" :
                "{ test ! -e \(dst) || { echo \(shellQuote("\(i.name).conf already exists; not replaced")) >&2; exit 1; }; } && "
            return noClobber
                + "/usr/bin/install -o root -g wheel -m 600 \(shellQuote("\(tmpDir)/\(i.name).conf")) \(tmp)"
                + " && { printf '%s  %s\\n' \(shellQuote(i.sha256)) \(tmp) | /usr/bin/shasum -a 256 -c -s"
                + " || { /bin/rm -f \(tmp); echo \(shellQuote("\(i.name).conf changed after validation")) >&2; exit 1; }; }"
                + " && /bin/mv -f \(tmp) \(dst)"
        }).joined(separator: " && ")
    }

    static func appleScript(tmpDir: String, items: [Item]) -> String {
        shellScript(installCommand(tmpDir: tmpDir, items: items))
    }

    // Edit reads the root-only config through an admin prompt (never a passwordless wgctl command:
    // the file holds the private key). nil for a name wgctl would reject.
    static func readCommand(name: String, dir: String = "/etc/wireguard") -> String? {
        isValidName(name) ? "/bin/cat \(shellQuote("\(dir)/\(name).conf"))" : nil
    }

    static func deleteCommand(name: String, dir: String = "/etc/wireguard") -> String? {
        isValidName(name) ? "/bin/rm -f \(shellQuote("\(dir)/\(name).conf"))" : nil
    }

    // "without altering line endings": otherwise do shell script turns \n into \r and drops the
    // trailing newline, so an edited config would not round-trip byte for byte.
    static func shellScript(_ command: String, admin: Bool = true) -> String {
        "do shell script \(appleScriptLiteral(command))"
            + (admin ? " with administrator privileges" : "") + " without altering line endings"
    }
}

// Line-preserving model of a wg-quick config, for the form editor and AllowedIPs/route checks.
// Parsing mirrors wg-quick: a line's code is the text before the first "#"; "[Name]" starts a section
// (name compared case-insensitively); otherwise key = text before the first "=", value = the rest, both
// trimmed. `text` round-trips byte for byte, and edits touch only the lines they must.
//
// Repeated keys: wg-quick accumulates repeated Address/DNS/AllowedIPs lines, so `value`/`values` read
// all of them as one comma-separated list. `set` writes a changed combined value onto the first such
// line and drops the later duplicates (the form shows one field, so one line holds it). Other repeated
// keys (e.g. several PostUp lines) are separate commands: edit those per line with `setLine`.
struct WGConfig {
    struct Entry { let line: Int; let key: String; let value: String }
    struct Section { let name: String; let header: Int; var entries: [Entry] }  // name lowercased

    private(set) var lines: [String]
    private(set) var sections: [Section] = []

    init(_ text: String) {
        lines = text.components(separatedBy: "\n")
        for (i, line) in lines.enumerated() {
            let code = Self.trim(line.components(separatedBy: "#")[0])
            if code.hasPrefix("["), code.hasSuffix("]") {
                sections.append(Section(name: Self.trim(code.dropFirst().dropLast()).lowercased(), header: i, entries: []))
            } else if !sections.isEmpty, let eq = code.firstIndex(of: "=") {
                sections[sections.count - 1].entries.append(
                    Entry(line: i, key: Self.trim(code[..<eq]), value: Self.trim(code[code.index(after: eq)...])))
            }
        }
    }

    var text: String { lines.joined(separator: "\n") }

    // MARK: Reading

    var interface: Int? { sections.firstIndex { $0.name == "interface" } }
    var peers: [Int] { sections.indices.filter { sections[$0].name == "peer" } }
    var addresses: [String] { interface.map { values("Address", in: $0) } ?? [] }
    var dns: [String] { interface.map { values("DNS", in: $0) } ?? [] }
    var allowedIPs: [[String]] { peers.map { values("AllowedIPs", in: $0) } }   // one list per [Peer]

    func entries(_ key: String, in s: Int) -> [Entry] {
        sections[s].entries.filter { $0.key.lowercased() == key.lowercased() }
    }

    // All lines of `key` in section `s`, joined with ", " ("" when absent).
    func value(_ key: String, in s: Int) -> String {
        entries(key, in: s).map(\.value).joined(separator: ", ")
    }

    // All lines of `key` in section `s`, split on commas, trimmed, empties dropped.
    func values(_ key: String, in s: Int) -> [String] {
        entries(key, in: s).flatMap { $0.value.split(separator: ",").map(Self.trim) }.filter { !$0.isEmpty }
    }

    // MARK: Editing

    static func isValidKey(_ key: String) -> Bool {
        !key.isEmpty && trim(key) == key && !key.contains { "=#[]\r\n".contains($0) }
    }

    // Sets `key` in section `s`: rewrites the first line (dropping duplicates, see above), inserts a
    // line when absent (at `hint` if it lies inside the section, else after its last key), and removes
    // every line of the key when `value` is empty. An unchanged value leaves the text alone.
    mutating func set(_ key: String, to value: String, in s: Int, at hint: Int? = nil) {
        let v = Self.oneLine(value), found = entries(key, in: s)
        guard Self.isValidKey(key), v != self.value(key, in: s) else { return }
        if let first = found.first, !v.isEmpty {
            lines[first.line] = Self.replacingValue(lines[first.line], with: v)
            for e in found.dropFirst().reversed() { lines.remove(at: e.line) }
        } else if found.isEmpty {
            let end = s + 1 < sections.count ? sections[s + 1].header : lines.count
            let at = hint.flatMap { (sections[s].header + 1...end).contains($0) ? $0 : nil } ?? insertionPoint(s)
            lines.insert("\(key) = \(v)\(eol)", at: at)
        } else {
            for e in found.reversed() { lines.remove(at: e.line) }
        }
        self = WGConfig(text)
    }

    // Rewrites one key/value line's value, keeping its key spelling, spacing and inline comment.
    mutating func setLine(_ line: Int, value: String) {
        lines[line] = Self.replacingValue(lines[line], with: Self.oneLine(value))
        self = WGConfig(text)
    }

    mutating func removeLine(_ line: Int) {
        lines.remove(at: line)
        self = WGConfig(text)
    }

    // Appends a new line even when the key already exists (e.g. a second PostUp).
    mutating func add(_ key: String, _ value: String, in s: Int) {
        guard Self.isValidKey(key) else { return }
        lines.insert("\(key) = \(Self.oneLine(value))\(eol)", at: insertionPoint(s))
        self = WGConfig(text)
    }

    // Appends an empty [Peer] section after a blank line.
    mutating func addPeer() {
        if lines.last != "" { lines[lines.count - 1] += eol; lines.append("") }
        if lines.count > 1, !Self.trim(lines[lines.count - 2]).isEmpty { lines.insert(eol, at: lines.count - 1) }
        lines.insert("[Peer]\(eol)", at: lines.count - 1)
        self = WGConfig(text)
    }

    // MARK: Helpers

    private var eol: String { lines.contains { $0.hasSuffix("\r") } ? "\r" : "" }  // keep CRLF files CRLF

    private func insertionPoint(_ s: Int) -> Int { (sections[s].entries.last?.line ?? sections[s].header) + 1 }

    private static func trim<S: StringProtocol>(_ s: S) -> String { s.trimmingCharacters(in: .whitespacesAndNewlines) }

    private static func oneLine(_ s: String) -> String { trim(s.components(separatedBy: .newlines).joined(separator: " ")) }

    // Swaps only the value text between "=" and any "#", keeping surrounding whitespace (and a "\r").
    private static func replacingValue(_ raw: String, with value: String) -> String {
        let hash = raw.firstIndex(of: "#") ?? raw.endIndex
        guard let eq = raw[..<hash].firstIndex(of: "=") else { return raw }
        let rest = raw[raw.index(after: eq)..<hash]
        let lead = rest.prefix { $0.isWhitespace }, body = rest.dropFirst(lead.count)
        guard !body.isEmpty else { return raw[...eq] + (value.isEmpty ? "" : " ") + value + rest + raw[hash...] }
        return raw[...eq] + lead + value + String(body.reversed().prefix { $0.isWhitespace }.reversed()) + raw[hash...]
    }
}
