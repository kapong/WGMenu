import Foundation

// Pure AllowedIPs/DNS checks (Foundation only, so tests/RouteCheck.swift can compile it alone).
enum RouteRules {
    // An IPv4 (4 bytes) or IPv6 (16 bytes) prefix. `bytes` is the address as written.
    struct CIDR: Hashable, CustomStringConvertible {
        let bytes: [UInt8]
        let prefix: Int

        // The address with host bits cleared.
        var network: [UInt8] {
            bytes.enumerated().map { i, b in
                let bits = min(max(prefix - i * 8, 0), 8)
                return bits == 8 ? b : b & ~(0xFF >> bits)
            }
        }

        // True when `other` lies inside this prefix (same family).
        func contains(_ other: CIDR) -> Bool {
            other.bytes.count == bytes.count && other.prefix >= prefix
                && CIDR(bytes: other.bytes, prefix: prefix).network == network
        }

        func overlaps(_ other: CIDR) -> Bool { contains(other) || other.contains(self) }

        var description: String {
            var net = network
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let family = bytes.count == 4 ? AF_INET : AF_INET6
            guard inet_ntop(family, &net, &buf, socklen_t(buf.count)) != nil else { return "?" }
            return "\(String(cString: buf))/\(prefix)"
        }
    }

    // a minus b as the fewest prefixes: disjoint -> [a]; b covers a -> []; otherwise, walking from a
    // down to b, the sibling of b's path at each level (largest first). Results are normalized.
    static func subtract(_ a: CIDR, _ b: CIDR) -> [CIDR] {
        guard a.overlaps(b) else { return [a] }
        guard !b.contains(a) else { return [] }
        return (a.prefix + 1...b.prefix).map { p in
            var bytes = CIDR(bytes: b.bytes, prefix: p).network
            bytes[(p - 1) / 8] ^= 0x80 >> ((p - 1) % 8)
            return CIDR(bytes: bytes, prefix: p)
        }
    }

    static func subtract(_ a: [CIDR], minus b: [CIDR]) -> [CIDR] {
        b.reduce(a) { rest, x in rest.flatMap { subtract($0, x) } }
    }

    // Normalized, without duplicates or prefixes covered by another; IPv4 first, then by address.
    static func canonical(_ cidrs: [CIDR]) -> [CIDR] {
        let u = Set(cidrs.map { CIDR(bytes: $0.network, prefix: $0.prefix) })
        return u.filter { c in !u.contains { $0 != c && $0.contains(c) } }.sorted {
            $0.bytes.count != $1.bytes.count ? $0.bytes.count < $1.bytes.count
                : $0.bytes != $1.bytes ? $0.bytes.lexicographicallyPrecedes($1.bytes) : $0.prefix < $1.prefix
        }
    }

    // macOS already has a /0 default route, so a /0 is routed as its two /1 halves.
    static func splitDefault(_ c: CIDR) -> [CIDR] {
        guard c.prefix == 0 else { return [c] }
        let zero = [UInt8](repeating: 0, count: c.bytes.count)
        var high = zero
        high[0] = 0x80
        return [CIDR(bytes: zero, prefix: 1), CIDR(bytes: high, prefix: 1)]
    }

    // Up tunnels in priority order (highest first) -> the routes each one gets: its AllowedIPs minus
    // everything a higher tunnel claims. Unparsable entries are skipped; each list is canonical.
    static func plan(_ tunnels: [(name: String, allowedIPs: [String])]) -> [(name: String, routes: [CIDR])] {
        var higher: [CIDR] = []
        return tunnels.map { t in
            let mine = t.allowedIPs.compactMap(parse).flatMap(splitDefault)
            defer { higher += mine }
            return (t.name, canonical(subtract(mine, minus: higher)))
        }
    }

    // The highest-priority up tunnel that sets DNS.
    static func dnsOwner(_ tunnels: [(name: String, hasDNS: Bool)]) -> String? {
        tunnels.first(where: \.hasDNS)?.name
    }

    // Names in priority order: listed ones first in list order, the rest after in their given order.
    static func ordered(_ names: [String], priority: [String]) -> [String] {
        let rank = Dictionary(priority.enumerated().map { ($1, $0) }, uniquingKeysWith: min)
        return names.enumerated().sorted {
            (rank[$0.element] ?? priority.count, $0.offset) < (rank[$1.element] ?? priority.count, $1.offset)
        }.map(\.element)
    }

    // "10.1.0.0/16", "fd00::/64"; a bare address is a single host (/32 or /128). nil if invalid.
    static func parse(_ s: String) -> CIDR? {
        let parts = s.trimmingCharacters(in: .whitespaces).split(separator: "/", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count) else { return nil }
        var v4 = in_addr(), v6 = in6_addr()
        let bytes: [UInt8]
        if inet_pton(AF_INET, String(parts[0]), &v4) == 1 {
            bytes = withUnsafeBytes(of: &v4) { Array($0) }
        } else if inet_pton(AF_INET6, String(parts[0]), &v6) == 1 {
            bytes = withUnsafeBytes(of: &v6) { Array($0) }
        } else { return nil }
        let maxBits = bytes.count * 8
        guard parts.count == 2 else { return CIDR(bytes: bytes, prefix: maxBits) }
        let p = parts[1]
        guard !p.isEmpty, p.count <= 3, p.allSatisfy(\.isASCII), p.allSatisfy(\.isNumber),
              let prefix = Int(p), prefix <= maxBits else { return nil }
        return CIDR(bytes: bytes, prefix: prefix)
    }

    // Any /0 (0.0.0.0/0, ::/0), or both /1 halves (0.0.0.0/1 + 128.0.0.0/1, ::/1 + 8000::/1), routes
    // everything of that family through the tunnel.
    static func isFullTunnel(_ allowedIPs: [String]) -> Bool { !fullFamilies(allowedIPs).isEmpty }

    // The families (address size: 4 = IPv4, 16 = IPv6) that `allowedIPs` covers entirely.
    static func fullFamilies(_ allowedIPs: [String]) -> Set<Int> {
        let cidrs = allowedIPs.compactMap(parse)
        return Set([4, 16].filter { n in
            let mine = cidrs.filter { $0.bytes.count == n }
            return mine.contains { $0.prefix == 0 }
                || Set(mine.filter { $0.prefix == 1 }.map { $0.network[0] }).count == 2
        })
    }

    // The VPN subnet(s) from Interface Address: "10.8.0.2/24" -> "10.8.0.0/24". Host-only (/32, /128)
    // or /0 addresses say nothing about the subnet and are skipped.
    static func suggestion(addresses: [String]) -> String {
        addresses.compactMap(parse).filter { $0.prefix > 0 && $0.prefix < $0.bytes.count * 8 }
            .map(\.description).joined(separator: ", ")
    }

    static let fullTunnelWarning = "This tunnel sends ALL traffic through the VPN."

    static func fullTunnelHint(addresses: [String]) -> String {
        let s = suggestion(addresses: addresses)
        return (s.isEmpty ? "List only the networks you need in AllowedIPs." : "Suggested AllowedIPs: \(s) (the VPN subnet from Address).")
            + " Add your office LAN too, e.g. 10.1.0.0/16."
    }

    // Every overlapping pair, as "x ↔ y" (normalized prefixes). Unparsable entries are ignored.
    static func overlaps(_ a: [String], _ b: [String]) -> [String] {
        overlapPairs(a, b).map { "\($0) ↔ \($1)" }
    }

    private static func overlapPairs(_ a: [String], _ b: [String]) -> [(CIDR, CIDR)] {
        let bs = b.compactMap(parse)
        return a.compactMap(parse).flatMap { x in bs.filter { x.overlaps($0) }.map { (x, $0) } }
    }

    struct Routes: Equatable {
        var allowedIPs: [String] = []
        var dns: [String] = []
    }

    // Output of `wgctl routes NAME`: "allowedips <list>" and "dns <list>" lines, comma-separated.
    static func parseRoutes(_ out: String) -> Routes {
        var r = Routes()
        for line in out.split(whereSeparator: \.isNewline) {
            let f = line.split(separator: " ", maxSplits: 1)
            guard f.count == 2 else { continue }
            let items = f[1].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            switch f[0] {
            case "allowedips": r.allowedIPs += items
            case "dns": r.dns += items
            default: break
            }
        }
        return r
    }

    // Reasons connecting `target` clashes with tunnels already up, naming each other tunnel and which
    // side wins by priority. `higher`: the names among `others` ranked above `target`. `outside`: the
    // ones started outside WGMenu, whose routes priority doesn't decide.
    static func conflicts(_ target: Routes, with others: [(name: String, routes: Routes)], higher: Set<String>,
                          outside: Set<String> = []) -> [String] {
        let full = fullFamilies(target.allowedIPs)
        return others.flatMap { o -> [String] in
            var out: [String] = []
            let wins = outside.contains(o.name) ? " \(o.name) was started outside WGMenu; its routes are not managed."
                : higher.contains(o.name) ? " \(o.name) has higher priority and keeps it." : " This tunnel has higher priority and takes it."
            let bothFull = full.intersection(fullFamilies(o.routes.allowedIPs))
            if !bothFull.isEmpty {
                let defaults = [(4, "0.0.0.0/0"), (16, "::/0")].filter { bothFull.contains($0.0) }.map(\.1)
                out.append("\(o.name) is also a full tunnel for \(defaults.joined(separator: " and ")) (or the /1 halves)." + wins)
            }
            // Default against default (/0 or /1 halves) of a family both cover fully is already said above.
            let pairs = overlapPairs(target.allowedIPs, o.routes.allowedIPs)
                .filter { !bothFull.contains($0.0.bytes.count) || $0.0.prefix > 1 || $0.1.prefix > 1 }.map { "\($0) ↔ \($1)" }
            if !pairs.isEmpty { out.append("AllowedIPs overlap with \(o.name): " + pairs.joined(separator: ", ") + "." + wins) }
            if !target.dns.isEmpty, !o.routes.dns.isEmpty {
                out.append("DNS is also set by \(o.name) (\(o.routes.dns.joined(separator: ", ")))." + wins)
            }
            return out
        }
    }
}
