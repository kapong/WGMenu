import Foundation

// Pure AllowedIPs/DNS checks (Foundation only, so tests/RouteCheck.swift can compile it alone).
enum RouteRules {
    // An IPv4 (4 bytes) or IPv6 (16 bytes) prefix. `bytes` is the address as written.
    struct CIDR: Equatable, CustomStringConvertible {
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
    static func isFullTunnel(_ allowedIPs: [String]) -> Bool {
        let cidrs = allowedIPs.compactMap(parse)
        return cidrs.contains { $0.prefix == 0 } || [4, 16].contains { n in
            Set(cidrs.filter { $0.bytes.count == n && $0.prefix == 1 }.map { $0.network[0] }).count == 2
        }
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

    // Reasons connecting `target` clashes with tunnels already up, naming each other tunnel.
    static func conflicts(_ target: Routes, with others: [(name: String, routes: Routes)]) -> [String] {
        let full = isFullTunnel(target.allowedIPs)
        return others.flatMap { o -> [String] in
            var out: [String] = []
            let bothFull = full && isFullTunnel(o.routes.allowedIPs)
            if bothFull { out.append("\(o.name) is also a full tunnel (0.0.0.0/0 or ::/0).") }
            // When both are full, default against default (/0 or /1 halves) is already said above.
            let pairs = overlapPairs(target.allowedIPs, o.routes.allowedIPs)
                .filter { !bothFull || $0.0.prefix > 1 || $0.1.prefix > 1 }.map { "\($0) ↔ \($1)" }
            if !pairs.isEmpty { out.append("AllowedIPs overlap with \(o.name): " + pairs.joined(separator: ", ")) }
            if !target.dns.isEmpty, !o.routes.dns.isEmpty {
                out.append("DNS is also set by \(o.name) (\(o.routes.dns.joined(separator: ", "))).")
            }
            return out
        }
    }
}
