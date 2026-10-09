// Assert-based check for Sources/RouteRules.swift (not shipped by build.sh). Run from repo root:
//   swiftc -parse-as-library Sources/RouteRules.swift tests/RouteCheck.swift -o "${TMPDIR:-/tmp}/routecheck" && "${TMPDIR:-/tmp}/routecheck"
import Foundation

@main
enum RouteCheck {
    static func check(_ ok: Bool, _ what: String) {
        if !ok { print("FAIL: \(what)"); exit(1) }
    }

    static func cidr(_ s: String) -> RouteRules.CIDR { RouteRules.parse(s)! }

    static func main() {
        // Parsing and normalization.
        check(RouteRules.parse("10.1.2.3/16")?.description == "10.1.0.0/16", "v4 network")
        check(RouteRules.parse(" 10.1.2.3 ")?.description == "10.1.2.3/32", "bare v4 = /32")
        check(RouteRules.parse("0.0.0.0/0")?.description == "0.0.0.0/0", "v4 default")
        check(RouteRules.parse("10.1.2.3/23")?.description == "10.1.2.0/23", "v4 odd prefix")
        check(RouteRules.parse("fd00:1:2::5/48")?.description == "fd00:1:2::/48", "v6 network")
        check(RouteRules.parse("fd00::1")?.description == "fd00::1/128", "bare v6 = /128")
        check(RouteRules.parse("::/0")?.description == "::/0", "v6 default")
        check(RouteRules.parse("fd00::ff/121")?.description == "fd00::80/121", "v6 odd prefix")
        for bad in ["", "10.1.2/24", "10.1.2.3/33", "fd00::/129", "10.0.0.0/", "10.0.0.0/-1", "10.0.0.0/+8",
                    "10.0.0.0/8/8", "example.com", "10.0.0.0/0x8", "10.0.0.0/٨"] {
            check(RouteRules.parse(bad) == nil, "rejects \(bad)")
        }

        // Containment and overlap.
        check(cidr("10.0.0.0/8").contains(cidr("10.1.0.0/16")), "v4 contains")
        check(!cidr("10.1.0.0/16").contains(cidr("10.0.0.0/8")), "v4 not contained")
        check(cidr("10.1.0.0/16").overlaps(cidr("10.0.0.0/8")), "v4 overlap symmetric")
        check(!cidr("10.1.0.0/16").overlaps(cidr("10.2.0.0/16")), "v4 disjoint")
        check(cidr("0.0.0.0/0").overlaps(cidr("192.168.1.1")), "default overlaps host")
        check(!cidr("0.0.0.0/0").overlaps(cidr("::/0")), "families never overlap")
        check(cidr("fd00::/16").overlaps(cidr("fd00:1::/32")), "v6 overlap")
        check(!cidr("fd00::/16").overlaps(cidr("fd01::/16")), "v6 disjoint")
        check(cidr("10.1.2.3/24").contains(cidr("10.1.2.200")), "host bits ignored")

        // Full tunnel.
        check(RouteRules.isFullTunnel(["10.8.0.0/24", "0.0.0.0/0"]), "v4 full")
        check(RouteRules.isFullTunnel(["::/0"]), "v6 full")
        check(RouteRules.isFullTunnel(["10.8.0.0/24", "0.0.0.0/1", "128.0.0.0/1"]), "v4 /1 halves")
        check(RouteRules.isFullTunnel(["8000::/1", "10.8.0.0/24", "::/1"]), "v6 /1 halves")
        check(!RouteRules.isFullTunnel(["0.0.0.0/1", "0.0.0.0/1"]), "one v4 half twice")
        check(!RouteRules.isFullTunnel(["0.0.0.0/1", "8000::/1"]), "halves of different families")
        check(!RouteRules.isFullTunnel(["128.0.0.0/1", "10.0.0.0/8"]), "one v4 half")
        check(!RouteRules.isFullTunnel(["garbage"]), "garbage")

        // Suggestion from Address.
        check(RouteRules.suggestion(addresses: ["10.8.0.2/24"]) == "10.8.0.0/24", "v4 suggestion")
        check(RouteRules.suggestion(addresses: ["10.8.0.2/24", "fd00::2/64"]) == "10.8.0.0/24, fd00::/64", "dual stack")
        check(RouteRules.suggestion(addresses: ["10.8.0.2/32", "10.8.0.2"]) == "", "host-only skipped")
        check(RouteRules.fullTunnelHint(addresses: ["10.8.0.2/24"]).contains("10.8.0.0/24"), "hint names subnet")
        check(RouteRules.fullTunnelHint(addresses: []).contains("10.1.0.0/16"), "hint names office LAN example")

        // Overlap pairs.
        check(RouteRules.overlaps(["10.0.0.0/8", "192.168.1.0/24"], ["10.1.0.0/16", "172.16.0.0/12"]) == ["10.0.0.0/8 ↔ 10.1.0.0/16"], "pairs")
        check(RouteRules.overlaps(["10.0.0.0/8"], ["fd00::/8"]).isEmpty, "mixed families")

        // wgctl routes output.
        let r = RouteRules.parseRoutes("allowedips 10.8.0.0/24, 10.1.0.0/16\nallowedips fd00::/64\ndns 1.1.1.1,  corp.example\n\nbogus line\n")
        check(r.allowedIPs == ["10.8.0.0/24", "10.1.0.0/16", "fd00::/64"], "routes allowedips")
        check(r.dns == ["1.1.1.1", "corp.example"], "routes dns")
        check(RouteRules.parseRoutes("") == RouteRules.Routes(), "empty output")

        // Conflicts.
        let full = RouteRules.Routes(allowedIPs: ["0.0.0.0/0", "::/0"], dns: ["1.1.1.1"])
        let office = RouteRules.Routes(allowedIPs: ["10.1.0.0/16"], dns: [])
        let home = RouteRules.Routes(allowedIPs: ["192.168.50.0/24"], dns: ["192.168.50.1"])
        check(RouteRules.conflicts(office, with: [("home", home)], higher: []).isEmpty, "disjoint, one DNS: no conflict")
        let c1 = RouteRules.conflicts(full, with: [("office", office)], higher: ["office"])
        check(c1 == ["AllowedIPs overlap with office: 0.0.0.0/0 ↔ 10.1.0.0/16. office has higher priority and keeps it."], "full vs split: \(c1)")
        let c2 = RouteRules.conflicts(full, with: [("vpn2", full)], higher: [])
        check(c2 == ["vpn2 is also a full tunnel for 0.0.0.0/0 and ::/0 (or the /1 halves). This tunnel has higher priority and takes it.",
                     "DNS is also set by vpn2 (1.1.1.1). This tunnel has higher priority and takes it."], "two full: \(c2)")
        let c3 = RouteRules.conflicts(home, with: [("vpn2", full), ("office", office)], higher: ["vpn2"])
        check(c3 == ["AllowedIPs overlap with vpn2: 192.168.50.0/24 ↔ 0.0.0.0/0. vpn2 has higher priority and keeps it.",
                     "DNS is also set by vpn2 (1.1.1.1). vpn2 has higher priority and keeps it."], "names other: \(c3)")
        let halves = RouteRules.Routes(allowedIPs: ["0.0.0.0/1", "128.0.0.0/1"])
        let c4 = RouteRules.conflicts(halves, with: [("vpn2", full)], higher: ["vpn2"])
        check(c4 == ["vpn2 is also a full tunnel for 0.0.0.0/0 (or the /1 halves). vpn2 has higher priority and keeps it."], "halves vs full: \(c4)")
        // Full in different families: no shared traffic, so no conflict.
        let v4full = RouteRules.Routes(allowedIPs: ["0.0.0.0/0"]), v6full = RouteRules.Routes(allowedIPs: ["::/0"])
        check(RouteRules.conflicts(v4full, with: [("v6", v6full)], higher: []).isEmpty, "v4 full vs v6 full: no conflict")
        check(RouteRules.conflicts(halves, with: [("v6", .init(allowedIPs: ["::/1", "8000::/1"]))], higher: []).isEmpty, "v4 halves vs v6 halves")
        // Both full for IPv4 only; v6 subnets still compared.
        let c5 = RouteRules.conflicts(.init(allowedIPs: ["0.0.0.0/0", "fd00::/16"]), with: [("x", .init(allowedIPs: ["0.0.0.0/1", "128.0.0.0/1", "fd00:1::/32"]))], higher: [])
        check(c5 == ["x is also a full tunnel for 0.0.0.0/0 (or the /1 halves). This tunnel has higher priority and takes it.",
                     "AllowedIPs overlap with x: fd00::/16 ↔ fd00:1::/32. This tunnel has higher priority and takes it."], "v4-only both full: \(c5)")
        // A v6 full tunnel against a v4 full one still reports its v4 subnet overlap.
        let c6 = RouteRules.conflicts(.init(allowedIPs: ["::/0", "10.1.0.0/16"]), with: [("x", v4full)], higher: ["x"])
        check(c6 == ["AllowedIPs overlap with x: 10.1.0.0/16 ↔ 0.0.0.0/0. x has higher priority and keeps it."], "mixed full: \(c6)")
        check(RouteRules.fullFamilies(["0.0.0.0/0", "::/1"]) == [4] && RouteRules.fullFamilies(["::/1", "8000::/1"]) == [16], "full families")
        let v6 = RouteRules.conflicts(.init(allowedIPs: ["fd00:1::/32"]), with: [("x", .init(allowedIPs: ["fd00::/16"]))], higher: [])
        check(v6 == ["AllowedIPs overlap with x: fd00:1::/32 ↔ fd00::/16. This tunnel has higher priority and takes it."], "v6 conflict: \(v6)")

        // Subtraction.
        func sub(_ a: String, _ b: String) -> [String] { RouteRules.subtract(cidr(a), cidr(b)).map(\.description) }
        check(sub("10.1.0.0/16", "10.2.0.0/16") == ["10.1.0.0/16"], "disjoint")
        check(sub("10.1.0.0/16", "10.0.0.0/8").isEmpty, "contained")
        check(sub("10.1.0.0/16", "10.1.0.0/16").isEmpty, "equal")
        check(sub("10.0.0.0/8", "10.128.0.0/9") == ["10.0.0.0/9"], "half")
        check(sub("10.0.0.0/8", "10.1.0.0/16") == ["10.128.0.0/9", "10.64.0.0/10", "10.32.0.0/11", "10.16.0.0/12",
                                                    "10.8.0.0/13", "10.4.0.0/14", "10.2.0.0/15", "10.0.0.0/16"], "containing")
        let deep = RouteRules.subtract(cidr("10.0.0.0/8"), cidr("10.1.2.3"))
        check(deep.count == 24 && deep.last?.description == "10.1.2.2/32" && deep.allSatisfy { !$0.overlaps(cidr("10.1.2.3")) },
              "nested deep: \(deep)")
        check(sub("10.1.2.3/32", "10.1.2.3/32").isEmpty && sub("10.1.2.3", "10.1.2.4") == ["10.1.2.3/32"], "/32")
        check(sub("0.0.0.0/0", "0.0.0.0/0").isEmpty && sub("0.0.0.0/0", "128.0.0.0/1") == ["0.0.0.0/1"], "/0")
        check(sub("10.0.0.0/8", "fd00::/8") == ["10.0.0.0/8"], "families never subtract")
        check(sub("fd00::/16", "fd00:8000::/17") == ["fd00::/17"] && sub("::/0", "fd00::/8").count == 8, "v6")
        let list = RouteRules.subtract([cidr("10.0.0.0/8"), cidr("192.168.0.0/16")],
                                       minus: [cidr("10.0.0.0/9"), cidr("10.192.0.0/10"), cidr("192.168.0.0/16")])
        check(list.map(\.description) == ["10.128.0.0/10"], "list: \(list)")
        // Sizes add up: a /8 minus one host leaves 2^24 - 1 addresses.
        let total = deep.reduce(0) { $0 + (1 << (32 - $1.prefix)) }
        check(total == (1 << 24) - 1, "deep sizes: \(total)")

        // Route plan.
        func plan(_ t: [(String, [String])]) -> [String] {
            RouteRules.plan(t.map { (name: $0.0, allowedIPs: $0.1) }).map { "\($0.name): " + $0.routes.map(\.description).joined(separator: " ") }
        }
        check(plan([("high", ["10.1.0.0/16"]), ("low", ["10.0.0.0/8"])]) == [
            "high: 10.1.0.0/16",
            "low: 10.0.0.0/16 10.2.0.0/15 10.4.0.0/14 10.8.0.0/13 10.16.0.0/12 10.32.0.0/11 10.64.0.0/10 10.128.0.0/9"],
              "issue example")
        check(plan([("a", ["10.1.0.0/16"]), ("b", ["10.1.0.0/16", "192.168.1.0/24"])]) == ["a: 10.1.0.0/16", "b: 192.168.1.0/24"],
              "equal prefixes: lower loses")
        check(plan([("a", ["10.1.0.0/16"]), ("b", ["10.1.0.0/16"])]) == ["a: 10.1.0.0/16", "b: "], "lower gets nothing")
        let fullLow = plan([("office", ["10.1.0.0/16", "fd00::/16"]), ("vpn", ["0.0.0.0/0", "::/0"])])
        check(fullLow[0] == "office: 10.1.0.0/16 fd00::/16", "split high: \(fullLow)")
        let vpn = RouteRules.plan([(name: "office", allowedIPs: ["10.1.0.0/16"]), (name: "vpn", allowedIPs: ["0.0.0.0/0", "::/0"])])[1].routes
        check(vpn.count == 16 + 2 && !vpn.contains { $0.prefix == 0 } && vpn.allSatisfy { !$0.overlaps(cidr("10.1.0.0/16")) }
              && vpn.filter { $0.bytes.count == 16 }.map(\.description) == ["::/1", "8000::/1"], "full-tunnel low: \(vpn)")
        check(plan([("vpn", ["0.0.0.0/0"]), ("office", ["10.1.0.0/16"])]) == ["vpn: 0.0.0.0/1 128.0.0.0/1", "office: "],
              "full-tunnel high takes all")
        check(plan([("a", ["garbage", "10.1.2.3/24", "10.1.2.0/24", "10.1.2.128/25"])]) == ["a: 10.1.2.0/24"], "canonical, skips garbage")
        check(plan([]).isEmpty, "no tunnels")

        // DNS owner.
        check(RouteRules.dnsOwner([("a", false), ("b", true), ("c", true)]) == "b", "dns owner")
        check(RouteRules.dnsOwner([("a", false)]) == nil && RouteRules.dnsOwner([]) == nil, "no dns owner")

        // Priority order.
        check(RouteRules.ordered(["a", "b", "c", "d"], priority: ["c", "x", "a"]) == ["c", "a", "b", "d"], "ordered")
        check(RouteRules.ordered(["b", "a"], priority: []) == ["b", "a"], "unlisted keep order")
        check(RouteRules.ordered(["a", "b"], priority: ["b", "a", "b"]) == ["b", "a"], "duplicate in list")

        print("RouteCheck: all passed")
    }
}
