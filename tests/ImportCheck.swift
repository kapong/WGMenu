// Assert-based check for Sources/ConfigImport.swift (not shipped by build.sh). Run from repo root:
//   swiftc -parse-as-library Sources/ConfigImport.swift tests/ImportCheck.swift -o "${TMPDIR:-/tmp}/importcheck" && "${TMPDIR:-/tmp}/importcheck"
import Foundation

@main
enum ImportCheck {
    static func check(_ ok: Bool, _ what: String) {
        if !ok { print("FAIL: \(what)"); exit(1) }
    }

    static func main() {
        for n in ["wg0", "office-vpn", "a.b_c=d+e", "123456789012345"] { check(ConfigImport.isValidName(n), "valid \(n)") }
        for n in ["", "1234567890123456", "a b", "a/b", "../x", "x'y", "tést", "a;b"] { check(!ConfigImport.isValidName(n), "invalid \(n)") }

        check(ConfigImport.looksLikeConfig("[Interface]\nPrivateKey = x\n"), "config")
        check(!ConfigImport.looksLikeConfig("[Peer]\n"), "not config")
        check(!ConfigImport.looksLikeConfig("[Interface]\nPost\u{0}Up = x\n"), "NUL byte rejected")

        for t in ["PostUp = x", "  postup=x", "PREDOWN\t= x", "[Interface]\r\nPreUp = x\r\n", "PostDown = x", "PostUp #= x", "PostUp\u{0B}= x", "PostUp\u{0C}= x", "PostUp"] { check(ConfigImport.hasHooks(t), "hook \(t)") }
        for t in ["[Interface]\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1", "# PostUp = x", "PostUpX = x", "Table = PostUp"] { check(!ConfigImport.hasHooks(t), "no hook \(t)") }

        check(ConfigImport.shellQuote("a'b c") == "'a'\\''b c'", "shell quote")
        check(ConfigImport.appleScriptLiteral("a\"b\\c") == "\"a\\\"b\\\\c\"", "applescript literal")

        // End to end: compile the AppleScript, check the shell command it produces survives a hostile temp path.
        let tmp = "/tmp/we ird'\"\\$(touch pwned)"
        let items = [ConfigImport.Item(name: "wg0", sha256: "00", replace: false), ConfigImport.Item(name: "b", sha256: "11", replace: true)]
        let script = ConfigImport.appleScript(tmpDir: tmp, items: items)
        let suffix = " with administrator privileges without altering line endings"
        check(script.hasPrefix("do shell script \"") && script.hasSuffix(suffix), "script shape")
        let src = "return " + script.dropFirst("do shell script ".count).dropLast(suffix.count)
        var err: NSDictionary?
        let cmd = NSAppleScript(source: src)?.executeAndReturnError(&err).stringValue
        check(cmd == ConfigImport.installCommand(tmpDir: tmp, items: items), "applescript round trip \(String(describing: err))")
        check(sh("for a in \(ConfigImport.shellQuote("\(tmp)/wg0.conf")); do printf %s \"$a\"; done").out == "\(tmp)/wg0.conf", "shell round trip")
        check(cmd!.hasPrefix("/usr/bin/install -d -o root -g wheel -m 700 '/etc/wireguard' && { test ! -e '/etc/wireguard/wg0.conf' "), "command shape")

        // Run the generated command (minus root ownership) against a scratch dir standing in for /etc/wireguard.
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory.appendingPathComponent("importcheck-\(UUID().uuidString)/we ird'$x")
        let src_ = scratch.appendingPathComponent("src"), dst = scratch.appendingPathComponent("etc")
        try! fm.createDirectory(at: src_, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: scratch.deletingLastPathComponent()) }
        let good = Data("[Interface]\nPrivateKey = x\n".utf8)
        func put(_ name: String, _ d: Data) { try! d.write(to: src_.appendingPathComponent("\(name).conf")) }
        func got(_ name: String) -> Data? { fm.contents(atPath: dst.appendingPathComponent("\(name).conf").path) }
        func run(_ items: [ConfigImport.Item]) -> (status: Int32, out: String) {
            sh(ConfigImport.installCommand(tmpDir: src_.path, items: items, dir: dst.path)
                .replacingOccurrences(of: "-o root -g wheel ", with: ""))
        }
        let h = ConfigImport.sha256Hex(good)
        check(h == "\(sh("/usr/bin/printf '[Interface]\\nPrivateKey = x\\n' | /usr/bin/shasum -a 256").out.prefix(64))", "sha256Hex matches shasum")

        put("wg0", good)
        check(run([.init(name: "wg0", sha256: h, replace: false)]).status == 0 && got("wg0") == good, "fresh install")
        check(!fm.fileExists(atPath: dst.appendingPathComponent("wg0.conf.tmp").path), "no tmp left after install")

        let other = Data("[Interface]\nPrivateKey = y\n".utf8)
        put("wg0", other)
        let hOther = ConfigImport.sha256Hex(other)
        let r1 = run([.init(name: "wg0", sha256: hOther, replace: false)])
        check(r1.status != 0 && r1.out.contains("already exists") && got("wg0") == good, "no clobber without Replace")
        check(run([.init(name: "wg0", sha256: hOther, replace: true)]).status == 0 && got("wg0") == other, "replace when confirmed")

        // Temp file swapped after validation: hash mismatch fails, leaves the old file and no .tmp.
        put("wg0", good)
        let r2 = run([.init(name: "wg0", sha256: hOther, replace: true)])
        check(r2.status != 0 && r2.out.contains("changed after validation") && got("wg0") == other, "hash mismatch rejected")
        check(!fm.fileExists(atPath: dst.appendingPathComponent("wg0.conf.tmp").path), "tmp removed on mismatch")
        // Symlink swap: install follows it, hash check still catches it.
        try! fm.removeItem(at: src_.appendingPathComponent("wg0.conf"))
        try! fm.createSymbolicLink(atPath: src_.appendingPathComponent("wg0.conf").path, withDestinationPath: "/etc/hosts")
        check(run([.init(name: "wg0", sha256: hOther, replace: true)]).status != 0 && got("wg0") == other, "symlink swap rejected")

        // Read/Delete builders: invalid names refused; hostile dir stays one quoted word.
        for n in ["", "../x", "a b", "x'y", "1234567890123456"] {
            check(ConfigImport.readCommand(name: n) == nil && ConfigImport.deleteCommand(name: n) == nil, "read/delete reject \(n)")
        }
        check(ConfigImport.readCommand(name: "wg0") == "/bin/cat '/etc/wireguard/wg0.conf'", "read command shape")
        check(ConfigImport.deleteCommand(name: "wg0") == "/bin/rm -f '/etc/wireguard/wg0.conf'", "delete command shape")
        check(ConfigImport.shellScript("x") == "do shell script \"x\" with administrator privileges without altering line endings", "admin script shape")

        // Read through the real (non-admin) do shell script with a hostile dir: exact bytes back, nothing injected.
        let hostile = scratch.appendingPathComponent("r'\"\\$(touch pwned) `touch pwned2`;x")
        try! fm.createDirectory(at: hostile, withIntermediateDirectories: true)
        let body = "[Interface]\nPrivateKey = x\nPostUp = echo \"a\" 'b' \\ $HOME\n\n"
        try! Data(body.utf8).write(to: hostile.appendingPathComponent("wg0.conf"))
        let readCmd = ConfigImport.readCommand(name: "wg0", dir: hostile.path)!
        var rerr: NSDictionary?
        let read = NSAppleScript(source: ConfigImport.shellScript(readCmd, admin: false))?.executeAndReturnError(&rerr).stringValue
        check(read == body, "read round trip keeps bytes and newlines \(String(describing: rerr)) \(String(describing: read))")
        let cwd = fm.currentDirectoryPath
        check(!["pwned", "pwned2"].contains { fm.fileExists(atPath: "\(cwd)/\($0)") || fm.fileExists(atPath: "/\($0)") }, "no injection on read")

        // Delete against a scratch dir: removes only NAME.conf; a missing file is not an error.
        try! Data(body.utf8).write(to: hostile.appendingPathComponent("wg1.conf"))
        let delCmd = ConfigImport.deleteCommand(name: "wg0", dir: hostile.path)!
        check(sh(delCmd).status == 0, "delete runs")
        check(!fm.fileExists(atPath: hostile.appendingPathComponent("wg0.conf").path), "delete removed wg0.conf")
        check(fm.fileExists(atPath: hostile.appendingPathComponent("wg1.conf").path), "delete kept wg1.conf")
        check(sh(delCmd).status == 0, "delete of missing file ok")

        print("ImportCheck: all passed")
    }

    // Runs a /bin/sh command; returns exit status and stdout+stderr.
    static func sh(_ command: String) -> (status: Int32, out: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", command]
        let o = Pipe(); p.standardOutput = o; p.standardError = o
        try! p.run()
        let d = o.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: d, as: UTF8.self))
    }
}
