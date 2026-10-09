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
        check(!RouteRules.isFullTunnel(["10.8.0.0/24", "0.0.0.0/1", "128.0.0.0/1"]), "split default is not /0")
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
        check(RouteRules.conflicts(office, with: [("home", home)]).isEmpty, "disjoint, one DNS: no conflict")
        let c1 = RouteRules.conflicts(full, with: [("office", office)])
        check(c1 == ["AllowedIPs overlap with office: 0.0.0.0/0 ↔ 10.1.0.0/16"], "full vs split: \(c1)")
        let c2 = RouteRules.conflicts(full, with: [("vpn2", full)])
        check(c2 == ["vpn2 is also a full tunnel (0.0.0.0/0 or ::/0).", "DNS is also set by vpn2 (1.1.1.1)."], "two full: \(c2)")
        let c3 = RouteRules.conflicts(home, with: [("vpn2", full), ("office", office)])
        check(c3 == ["AllowedIPs overlap with vpn2: 192.168.50.0/24 ↔ 0.0.0.0/0", "DNS is also set by vpn2 (1.1.1.1)."], "names other: \(c3)")
        let v6 = RouteRules.conflicts(.init(allowedIPs: ["fd00:1::/32"]), with: [("x", .init(allowedIPs: ["fd00::/16"]))])
        check(v6 == ["AllowedIPs overlap with x: fd00:1::/32 ↔ fd00::/16"], "v6 conflict: \(v6)")

        print("RouteCheck: all passed")
    }
}
