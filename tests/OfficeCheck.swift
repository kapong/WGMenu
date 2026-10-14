// Assert-based check for Sources/OfficeRules.swift (not shipped by build.sh). Run from repo root:
//   swiftc -parse-as-library Sources/OfficeRules.swift tests/OfficeCheck.swift -o "${TMPDIR:-/tmp}/officecheck" && "${TMPDIR:-/tmp}/officecheck"
import Foundation

@main
enum OfficeCheck {
    static func check(_ ok: Bool, _ what: String) {
        if !ok { print("FAIL: \(what)"); exit(1) }
    }

    static func main() {
        // MAC normalization.
        check(OfficeRules.normalizeMAC("0:1b:2C:3d:4e:F") == "00:1b:2c:3d:4e:0f", "pads and lowercases")
        check(OfficeRules.normalizeMAC("58:d6:1f:8e:8d:75") == "58:d6:1f:8e:8d:75", "already normal")
        check(OfficeRules.normalizeMAC("0:1b:2c:3d:4e") == nil, "5 octets")
        check(OfficeRules.normalizeMAC("0:1b:2c:3d:4e:5f:6") == nil, "7 octets")
        check(OfficeRules.normalizeMAC("0:1b::3d:4e:5f") == nil, "empty octet")
        check(OfficeRules.normalizeMAC("0:1b:2c:3d:4e:123") == nil, "3-char octet")
        check(OfficeRules.normalizeMAC("0:1b:2c:3d:4e:zz") == nil, "non-hex")
        check(OfficeRules.normalizeMAC("(incomplete)") == nil, "incomplete")
        check(OfficeRules.normalizeMAC("0:0:0:0:0:0") == nil, "all zero")
        check(OfficeRules.normalizeMAC("ff:ff:ff:ff:ff:ff") == nil, "broadcast")

        // arp -n output.
        check(OfficeRules.macFromArp("? (10.1.31.1) at 58:d6:1f:8e:8d:75 on en0 ifscope [ethernet]\n") == "58:d6:1f:8e:8d:75", "arp entry")
        check(OfficeRules.macFromArp("? (192.168.1.1) at 0:1b:2c:3d:4e:5f on en0 ifscope [ethernet]") == "00:1b:2c:3d:4e:5f", "arp unpadded")
        check(OfficeRules.macFromArp("? (192.168.1.1) at (incomplete) on en0 ifscope [ethernet]") == nil, "arp incomplete")
        check(OfficeRules.macFromArp("10.255.255.254 (10.255.255.254) -- no entry\n") == nil, "arp no entry")
        check(OfficeRules.macFromArp("") == nil, "arp empty")

        // IPv4 validation before arp argv.
        check(OfficeRules.isIPv4("10.1.31.1"), "plain ipv4")
        check(OfficeRules.isIPv4("255.255.255.255"), "max octets")
        check(!OfficeRules.isIPv4("256.1.1.1"), "octet > 255")
        check(!OfficeRules.isIPv4("10.1.31"), "3 parts")
        check(!OfficeRules.isIPv4("10..31.1"), "empty part")
        check(!OfficeRules.isIPv4("-a.1.1.1"), "option-like")
        check(!OfficeRules.isIPv4("fe80::1"), "ipv6")
        check(!OfficeRules.isIPv4("1.1.1.1 "), "trailing space")
        check(!OfficeRules.isIPv4("1.1.1.١"), "non-ASCII digit")
        check(!OfficeRules.isIPv4("1.1.1.0001"), "4-digit octet")

        // Dedup on mark.
        check(OfficeRules.adding(["aa:bb:cc:dd:ee:ff"], to: []) == ["aa:bb:cc:dd:ee:ff"], "add to empty")
        check(OfficeRules.adding(["aa:bb:cc:dd:ee:ff"], to: ["aa:bb:cc:dd:ee:ff"]) == ["aa:bb:cc:dd:ee:ff"], "dedup")
        check(OfficeRules.adding(["11:22:33:44:55:66"], to: ["aa:bb:cc:dd:ee:ff"]).count == 2, "second network")

        // Public lookup: HTTP body, ifconfig.co JSON, ipify plain text.
        check(OfficeRules.httpBody("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{}") == "{}", "http 200")
        check(OfficeRules.httpBody("HTTP/1.1 429 Too Many\r\n\r\n{}") == nil, "non-200")
        check(OfficeRules.httpBody("{}") == nil, "no headers")
        let json = #"{"ip":"203.0.113.5","ip_decimal":1,"country":"TH","asn":"AS64500","asn_org":"Example ISP","hostname":"office-1.example.net"}"#
        let pub = OfficeRules.publicFromJSON(json)
        check(pub?.ipv4 == "203.0.113.5", "json ip")
        check(pub?.label == "203.0.113.5 (AS64500 Example ISP) / office-1.example.net", "label with asn_org and hostname")
        check(OfficeRules.publicFromJSON(#"{"ip":"203.0.113.5"}"#)?.label == "203.0.113.5", "json missing fields")
        check(OfficeRules.publicFromJSON(#"{"ip":"203.0.113.5","hostname":"203.0.113.5"}"#)?.label == "203.0.113.5",
              "hostname echoing the ip not repeated")
        check(OfficeRules.publicFromJSON(#"{"ip":"2001:db8::1"}"#) != nil, "ipv6 decodes")
        check(OfficeRules.publicFromJSON(#"{"ip":"2001:db8::1"}"#)?.ipv4 == nil, "ipv6 is not a key")
        check(OfficeRules.publicFromJSON("<html>203.0.113.5</html>") == nil, "html rejected")
        check(OfficeRules.publicFromPlain("203.0.113.7\n")?.ipv4 == "203.0.113.7", "ipify plain")
        check(OfficeRules.publicFromPlain("2001:db8::1") == nil, "ipify ipv6 rejected")
        check(OfficeRules.usesPublic(["a": ["aa:bb:cc:dd:ee:ff", "203.0.113.7"]]), "list has ip")
        check(!OfficeRules.usesPublic(["a": ["aa:bb:cc:dd:ee:ff"]]), "macs only")
        check(OfficeRules.adding(["203.0.113.5"], to: ["203.0.113.5"]) == ["203.0.113.5"], "dedup ip")

        // Which tunnels to take down (arrival is gated by the caller).
        let office = "aa:bb:cc:dd:ee:ff", home = "11:22:33:44:55:66", ip = "203.0.113.7"
        let offices = ["work": [home + "x", office], "lab": [office], "other": [home], "byip": [ip]]
        check(OfficeRules.toDisconnect(ids: [office], offices: offices, up: ["work", "other"]) == ["work"], "up tunnels listing the MAC")
        check(OfficeRules.toDisconnect(ids: [office], offices: offices, up: ["work", "lab"]) == ["work", "lab"], "several tunnels")
        check(OfficeRules.toDisconnect(ids: [], offices: offices, up: ["work"]).isEmpty, "no identifiers -> none")
        check(OfficeRules.toDisconnect(ids: [home], offices: offices, up: ["work"]).isEmpty, "other network -> none")
        check(OfficeRules.toDisconnect(ids: [office], offices: offices, up: []).isEmpty, "nothing up -> none")
        check(OfficeRules.toDisconnect(ids: [office], offices: [:], up: ["work"]).isEmpty, "no rules -> none")
        check(OfficeRules.toDisconnect(ids: [ip], offices: offices, up: ["byip", "work"]) == ["byip"], "no MAC: public IP matches")
        check(OfficeRules.toDisconnect(ids: [office, ip], offices: offices, up: ["byip", "lab"]) == ["byip", "lab"],
              "MAC and IP both matched")
        check(OfficeRules.toDisconnect(ids: ["198.51.100.9"], offices: offices, up: ["byip"]).isEmpty, "other IP -> none")

        print("OfficeCheck: all passed")
    }
}
