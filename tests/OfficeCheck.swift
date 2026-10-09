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
        check(OfficeRules.adding("aa:bb:cc:dd:ee:ff", to: []) == ["aa:bb:cc:dd:ee:ff"], "add to empty")
        check(OfficeRules.adding("aa:bb:cc:dd:ee:ff", to: ["aa:bb:cc:dd:ee:ff"]) == ["aa:bb:cc:dd:ee:ff"], "dedup")
        check(OfficeRules.adding("11:22:33:44:55:66", to: ["aa:bb:cc:dd:ee:ff"]).count == 2, "second network")

        // Which tunnels to take down.
        let office = "aa:bb:cc:dd:ee:ff", home = "11:22:33:44:55:66"
        let offices = ["work": [home + "x", office], "lab": [office], "other": [home]]
        check(OfficeRules.toDisconnect(mac: office, lastMAC: home, offices: offices, up: ["work", "other"]) == ["work"],
              "arrival takes down up tunnels listing the MAC")
        check(OfficeRules.toDisconnect(mac: office, lastMAC: nil, offices: offices, up: ["work", "lab"]) == ["work", "lab"],
              "launch in office counts as arrival")
        check(OfficeRules.toDisconnect(mac: office, lastMAC: office, offices: offices, up: ["work"]).isEmpty,
              "same MAC (manual re-enable) -> none")
        check(OfficeRules.toDisconnect(mac: nil, lastMAC: home, offices: offices, up: ["work"]).isEmpty, "no gateway -> none")
        check(OfficeRules.toDisconnect(mac: home, lastMAC: office, offices: offices, up: ["work"]).isEmpty, "leaving -> none")
        check(OfficeRules.toDisconnect(mac: office, lastMAC: home, offices: offices, up: []).isEmpty, "nothing up -> none")
        check(OfficeRules.toDisconnect(mac: office, lastMAC: home, offices: [:], up: ["work"]).isEmpty, "no rules -> none")

        print("OfficeCheck: all passed")
    }
}
