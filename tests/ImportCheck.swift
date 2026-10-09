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

        // WGConfig: line-preserving parse/edit for the form editor.
        let conf = """
        # office tunnel
        [Interface]
        PrivateKey = priv  # secret
        address=10.8.0.2/24
        PostUp = echo hi # hook
        Foo = bar

        [peer]
        PublicKey = pub
        AllowedIPs = 10.8.0.0/24, 10.1.0.0/16
        allowedips = fd00::/64
        Endpoint = vpn.example.com:51820

        """
        let lines0 = conf.components(separatedBy: "\n")
        func diff(_ a: String) -> [Int] {
            let l = a.components(separatedBy: "\n")
            return l.count == lines0.count ? l.indices.filter { l[$0] != lines0[$0] } : [-1]
        }
        var c = WGConfig(conf)
        check(c.text == conf, "round trip unchanged")
        check(WGConfig("[Interface]\r\nDNS = 1.1.1.1\r\n").text == "[Interface]\r\nDNS = 1.1.1.1\r\n", "CRLF round trip")
        check(WGConfig("").text == "" && WGConfig("x").text == "x", "degenerate round trip")
        check(c.interface == 0 && c.peers == [1], "sections case-insensitive")
        check(c.addresses == ["10.8.0.2/24"] && c.dns == [], "address/dns lists")
        check(c.allowedIPs == [["10.8.0.0/24", "10.1.0.0/16", "fd00::/64"]], "repeated AllowedIPs combined")
        check(c.value("PrivateKey", in: 0) == "priv", "inline comment stripped")
        check(c.value("AllowedIPs", in: 1) == "10.8.0.0/24, 10.1.0.0/16, fd00::/64", "combined value")

        c.set("PrivateKey", to: "new", in: 0)
        check(diff(c.text) == [2] && c.text.contains("PrivateKey = new  # secret\n"), "single-field edit changes one line, keeps comment")
        c = WGConfig(conf); c.set("ADDRESS", to: "10.9.0.2/24", in: 0)
        check(diff(c.text) == [3] && c.text.contains("\naddress=10.9.0.2/24\n"), "key case and spacing kept")
        c = WGConfig(conf); c.set("Address", to: "10.8.0.2/24", in: 0)
        check(c.text == conf, "unchanged value is a no-op")
        c = WGConfig(conf); c.set("AllowedIPs", to: c.value("AllowedIPs", in: 1), in: 1)
        check(c.text == conf, "unchanged combined value keeps duplicates")

        c = WGConfig(conf); c.set("DNS", to: "1.1.1.1", in: 0)
        var l = c.text.components(separatedBy: "\n")
        check(l.count == lines0.count + 1 && l[6] == "DNS = 1.1.1.1" && l[7] == "" && l[8] == "[peer]", "insert absent key at end of section")
        l.remove(at: 6)
        check(l.joined(separator: "\n") == conf, "insert leaves other lines alone")
        c = WGConfig(conf); c.set("MTU", to: "1380", in: 0, at: 3)
        check(c.text.components(separatedBy: "\n")[3] == "MTU = 1380", "insert at hint")
        c = WGConfig(conf); c.set("MTU", to: "1380", in: 0, at: 9)
        check(c.text.components(separatedBy: "\n")[6] == "MTU = 1380", "hint outside section ignored")

        c = WGConfig(conf); c.set("Foo", to: "", in: 0)
        l = lines0; l.remove(at: 5)
        check(c.text == l.joined(separator: "\n"), "remove key")
        c = WGConfig(conf); c.set("AllowedIPs", to: "0.0.0.0/0", in: 1)
        l = lines0; l[9] = "AllowedIPs = 0.0.0.0/0"; l.remove(at: 10)
        check(c.text == l.joined(separator: "\n") && c.allowedIPs == [["0.0.0.0/0"]], "edit repeated key: first line rewritten, duplicates dropped")

        c = WGConfig("[Interface]\nPrivateKey = k # main key\nDNS = 1.1.1.1\nDNS = 9.9.9.9 # backup\n")
        c.set("PrivateKey", to: "", in: 0); c.set("DNS", to: "8.8.8.8", in: 0)
        check(c.text == "[Interface]\n# main key\nDNS = 8.8.8.8\n# backup\n", "removed lines keep inline comments")
        c = WGConfig("[Interface]\n"); c.set("MTU", to: "14\u{0}20", in: 0); c.add("Post\u{0}Up", "x", in: 0)
        check(c.text == "[Interface]\nMTU = 1420\n" && !WGConfig.isValidKey("Post\u{0}Up"), "NUL stripped from values, rejected in keys")
        c = WGConfig(conf); c.setLine(4, value: "echo bye")
        check(diff(c.text) == [4] && c.text.contains("PostUp = echo bye # hook"), "setLine keeps comment")
        c = WGConfig(conf); c.add("PostUp", "echo two", in: 0)
        check(c.entries("PostUp", in: 0).map(\.value) == ["echo hi", "echo two"] && ConfigImport.hasHooks(c.text), "add repeats key")
        c = WGConfig(conf); c.add("Bad=Key", "x", in: 0); c.set("PrivateKey", to: "a\nPostUp = x", in: 0)
        check(!c.text.contains("Bad") && c.entries("PostUp", in: 0).count == 1, "invalid key and newline in value rejected")
        c = WGConfig("[Interface]\nPrivateKey =\n"); c.setLine(1, value: "k")
        check(c.text == "[Interface]\nPrivateKey = k\n", "fill empty value")

        c = WGConfig(conf); c.addPeer()
        check(c.text == conf + "\n[Peer]\n" && c.peers == [1, 2], "add peer appends blank line + header")
        c = WGConfig("[Interface]\n\n"); c.addPeer()
        check(c.text == "[Interface]\n\n[Peer]\n", "add peer reuses trailing blank line")
        c = WGConfig("[Interface]\nPrivateKey = x"); c.addPeer(); c.set("PublicKey", to: "p", in: 1)
        check(c.text == "[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = p\n", "add peer without trailing newline")
        c = WGConfig("[Interface]\r\nPrivateKey = x\r\n"); c.addPeer(); c.set("Endpoint", to: "h:1", in: 1)
        check(c.text == "[Interface]\r\nPrivateKey = x\r\n\r\n[Peer]\r\nEndpoint = h:1\r\n", "CRLF kept on insert")

        // Comments, unknown keys and hook lines survive a series of edits.
        c = WGConfig(conf)
        c.set("PrivateKey", to: "k2", in: 0); c.set("MTU", to: "1420", in: 0); c.set("Endpoint", to: "1.2.3.4:51820", in: 1)
        for keep in ["# office tunnel", "PrivateKey = k2  # secret", "Foo = bar", "PostUp = echo hi # hook", "[peer]", "address=10.8.0.2/24"] {
            check(c.text.contains(keep), "preserved \(keep)")
        }

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
