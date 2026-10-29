import Foundation

// Pure rules for "office network" auto-off: a tunnel lists the networks where it should go down on
// arrival. Entries are strings, classified by shape: the MAC of the default gateway (first-hop
// router) or, when that couldn't be read, the network's public IPv4. Hostname and ASN are shown, never
// matched (ASN covers a whole ISP). The office rule's down tunnels are "suspended" and come back up on
// leaving. No UI; only I/O is the suspended set in UserDefaults. See tests/OfficeCheck.swift.
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

    // The network as a what's-my-IP service sees it. Only the IPv4 is a match key; hostname and
    // ASN are for display.
    struct Public: Decodable, Equatable {
        var ip: String?
        var hostname: String?
        var asn: String?
        var asnOrg: String?
        enum CodingKeys: String, CodingKey { case ip, hostname, asn, asnOrg = "asn_org" }

        // The stored entry: IPv4 only (IPv6 privacy addresses change per device).
        var ipv4: String? { ip.flatMap { isIPv4($0) ? $0 : nil } }

        // "203.0.113.5 (AS64500 Example ISP) / office-1.example.net".
        var label: String {
            let who = [asn, asnOrg].compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: " ")
            var out = ip ?? "unknown"
            if !who.isEmpty { out += " (\(who))" }
            if let h = hostname, !h.isEmpty, h != ip { out += " / " + h }
            return out
        }
    }

    // Body of a raw HTTP/1.x response with status 200, else nil.
    static func httpBody(_ response: String) -> String? {
        guard let split = response.range(of: "\r\n\r\n"),
              response[..<split.lowerBound].split(separator: " ", maxSplits: 2).dropFirst().first == "200" else { return nil }
        return String(response[split.upperBound...])
    }

    // ifconfig.co/json body. Missing fields are fine; nil if it is not JSON.
    static func publicFromJSON(_ body: String) -> Public? {
        try? JSONDecoder().decode(Public.self, from: Data(body.utf8))
    }

    // api.ipify.org body: the IPv4 alone.
    static func publicFromPlain(_ body: String) -> Public? {
        let ip = body.trimmingCharacters(in: .whitespacesAndNewlines)
        return isIPv4(ip) ? Public(ip: ip) : nil
    }

    // Adds entries (a MAC or a public IP) to a tunnel's list, deduplicated, in insertion order.
    static func adding(_ entries: [String], to list: [String]) -> [String] {
        entries.reduce(list) { $0.contains($1) ? $0 : $0 + [$1] }
    }

    // True if any tunnel lists a network by public IP (so a lookup is worth a request).
    static func usesPublic(_ offices: [String: [String]]) -> Bool {
        offices.values.contains { $0.contains(where: isIPv4) }
    }

    // Up tunnels listing any of the network's identifiers `ids` (gateway MAC, public IP). The caller
    // decides whether this is an arrival.
    static func toDisconnect(ids: [String], offices: [String: [String]], up: [String]) -> [String] {
        up.filter { offices[$0]?.contains(where: ids.contains) == true }
    }

    // Suspended tunnels to bring back up: those whose office list shares nothing with the current
    // network's identifiers `ids` (left the office, or relaunched elsewhere), and only when ids has an
    // identifier of every kind (MAC, public IPv4) the list uses: a MAC alone can't rule out an IP-marked
    // office, nor the reverse. No identifiers (no gateway, no ARP entry, no lookup) -> none: keep
    // waiting. No list -> released. There is no arrival guard, so a relaunch away from the office restores them.
    static func toReconnect(ids: Set<String>, suspended: Set<String>, offices: [String: [String]]) -> [String] {
        guard !ids.isEmpty else { return [] }
        let kinds = Set(ids.map(isIPv4))
        return suspended.filter { n in
            let l = offices[n] ?? []
            return !l.contains(where: ids.contains) && Set(l.map(isIPv4)).isSubset(of: kinds)
        }.sorted()
    }

    // True if a suspended tunnel is held only because ids lacks a kind its list uses (e.g. the public-IP
    // lookup failed): the network is worth identifying again.
    static func undecided(ids: Set<String>, suspended: Set<String>, offices: [String: [String]]) -> Bool {
        let kinds = Set(ids.map(isIPv4))
        return suspended.contains { n in
            let l = offices[n] ?? []
            return !l.contains(where: ids.contains) && !Set(l.map(isIPv4)).isSubset(of: kinds)
        }
    }

    // Drops suspended names whose tunnel no longer exists, no longer lists any office network, or is up by
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
