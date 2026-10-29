import Foundation

// Pure rules for "office network" auto-off: a tunnel lists the MACs of default gateways
// (first-hop routers) where it should go down on arrival; the office rule's down tunnels are "suspended"
// and come back up on leaving. No UI; only I/O is the suspended set in UserDefaults. See tests/OfficeCheck.swift.
enum OfficeRules {
    // Lowercase, zero-padded "aa:bb:cc:dd:ee:ff", or nil. arp prints octets unpadded ("0:1b:...").
    static func normalizeMAC(_ s: String) -> String? {
        let parts = s.lowercased().split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 6 else { return nil }
        var out: [String] = []
        for p in parts {
            guard (1...2).contains(p.count), p.allSatisfy(\.isHexDigit) else { return nil }
            out.append(p.count == 1 ? "0" + p : String(p))
        }
        let mac = out.joined(separator: ":")
        return mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" ? nil : mac
    }

    // From `arp -n <ip>`: "? (10.0.0.1) at 0:1b:2c:3d:4e:5f on en0 ifscope [ethernet]".
    // "(incomplete)" and "-- no entry" give nil.
    static func macFromArp(_ out: String) -> String? {
        for line in out.split(separator: "\n") {
            guard let at = line.range(of: " at "),
                  let on = line.range(of: " on ", range: at.upperBound..<line.endIndex) else { continue }
            if let mac = normalizeMAC(String(line[at.upperBound..<on.lowerBound])) { return mac }
        }
        return nil
    }

    // Dotted-quad IPv4 only, so nothing else (options, hostnames, IPv6) reaches arp's argv.
    static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { p in
            (1...3).contains(p.count) && p.allSatisfy { $0.isASCII && $0.isNumber } && Int(p)! <= 255
        }
    }

    // Adds mac to a tunnel's list, deduplicated; the list keeps insertion order.
    static func adding(_ mac: String, to list: [String]) -> [String] {
        list.contains(mac) ? list : list + [mac]
    }

    // Tunnels to take down: only on arrival (gateway MAC differs from the last one seen), and only
    // up tunnels that list it. Same MAC again (a manual re-enable in the office) or no MAC -> none.
    static func toDisconnect(mac: String?, lastMAC: String?, offices: [String: [String]], up: [String]) -> [String] {
        guard let mac, mac != lastMAC else { return [] }
        return up.filter { offices[$0]?.contains(mac) == true }
    }

    // Suspended tunnels to bring back up: those whose office list no longer contains the gateway MAC
    // (left the office, or relaunched elsewhere). No MAC (no gateway / no ARP entry) -> none: keep waiting.
    // Unlike toDisconnect there is no lastMAC guard, so a relaunch away from the office restores them.
    static func toReconnect(mac: String?, suspended: Set<String>, offices: [String: [String]]) -> [String] {
        guard let mac else { return [] }
        return suspended.filter { offices[$0]?.contains(mac) != true }.sorted()
    }

    // Drops suspended names whose tunnel no longer exists, no longer lists any office MAC, or is up by
    // other means (`up`: names up and not busy). Busy ones may be going down for the office rule, down ones wait.
    static func pruned(_ suspended: Set<String>, existing: [String], offices: [String: [String]], up: [String]) -> Set<String> {
        suspended.filter { existing.contains($0) && offices[$0]?.isEmpty == false && !up.contains($0) }
    }

    // Conflict candidates for an office reconnect: tunnels up or coming up, minus those suspended or
    // reconnected with it, which ran together with it before the office took them down.
    static func othersForRestore(_ others: [String], coRestored: Set<String>) -> [String] {
        others.filter { !coRestored.contains($0) }
    }

    // Persisted as a string array so the suspended set survives a quit or relaunch.
    static let suspendedKey = "suspendedByOffice"

    static func loadSuspended(_ d: UserDefaults = .standard) -> Set<String> {
        Set(d.stringArray(forKey: suspendedKey) ?? [])
    }

    static func saveSuspended(_ s: Set<String>, _ d: UserDefaults = .standard) {
        d.set(s.sorted(), forKey: suspendedKey)
    }
}
