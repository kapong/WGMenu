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
