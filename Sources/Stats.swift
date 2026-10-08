import Foundation

// Pure logic for the menu-bar label (Foundation only, so tests/StatsCheck.swift can compile it alone).
enum Stats {
    // Health rule: WireGuard is UDP, so there is no "connection"; the only proof the peer is alive is
    // RECEIVED data. A tunnel is healthy iff rx > 0 AND rx increased within the last rxWindow seconds.
    // Up but receiving nothing = connecting (orange). rxWindow matches WireGuard REJECT_AFTER_TIME: a live
    // session handshakes (and so receives) at least every ~2-3 min while used; PersistentKeepalive adds more.
    // The handshake is used only to seed the first sample after launch (and for display).
    static let rxWindow: TimeInterval = 180

    enum Health { case off, connecting, ok }

    struct Counters { let rx: Int64; let tx: Int64 }
    struct Rate { let rx: Double; let tx: Double }   // bytes per second

    // lastRxChange: CLOCK_MONOTONIC ns when rx last increased (nil = never seen).
    struct RxState: Equatable { let lastRxChange: UInt64?; let healthy: Bool }

    // One poll of one UP tunnel. prevRx nil = first sample (app start or tunnel just came up): then a
    // handshake within rxWindow (age in s) seeds lastRxChange at the handshake time, so a tunnel that is
    // already up does not flash orange at launch. Any rx change counts, including a counter reset
    // (rx dropped after a restart), but only while the new rx > 0; rx == 0 is always connecting.
    static func rxHealth(rx: Int64, prevRx: Int64?, lastRxChange: UInt64?, handshakeAge: TimeInterval?,
                         now: UInt64) -> RxState {
        guard rx > 0 else { return RxState(lastRxChange: nil, healthy: false) }
        var last = lastRxChange
        if let p = prevRx {
            if rx != p { last = now }
        } else if last == nil, let a = handshakeAge, a >= 0, a <= rxWindow {
            let ago = UInt64(a * 1e9)
            last = ago <= now ? now - ago : 0
        }
        let healthy = last.map { now >= $0 && Double(now - $0) / 1e9 <= rxWindow } ?? false
        return RxState(lastRxChange: last, healthy: healthy)
    }

    // healthy: rxHealth(...).healthy of each UP tunnel. upInFlight: an `up` toggle is running.
    // Any connecting tunnel makes the total connecting.
    static func health(healthy: [Bool], upInFlight: Bool) -> Health {
        if upInFlight { return .connecting }
        if healthy.isEmpty { return .off }
        return healthy.allSatisfy { $0 } ? .ok : .connecting
    }

    // Per-tunnel rates from two polls. Tunnels without a previous sample are skipped;
    // a negative delta (counters reset by a tunnel restart) counts as 0.
    static func rates(prev: [String: Counters], cur: [String: Counters], elapsed: TimeInterval) -> [String: Rate] {
        guard elapsed > 0 else { return [:] }
        var out: [String: Rate] = [:]
        for (name, c) in cur {
            guard let p = prev[name] else { continue }
            out[name] = Rate(rx: Double(max(0, c.rx - p.rx)) / elapsed,
                             tx: Double(max(0, c.tx - p.tx)) / elapsed)
        }
        return out
    }

    static func total(_ rates: [String: Rate]) -> Rate {
        Rate(rx: rates.values.reduce(0) { $0 + $1.rx }, tx: rates.values.reduce(0) { $0 + $1.tx })
    }

    // Compact decimal units: "512 B", "1.2 KB", "34 KB", "999 MB", "1.5 GB".
    static func bytes(_ value: Double) -> String {
        let units = ["B", "KB", "MB", "GB"]
        var v = max(0, value), i = 0
        while v >= 999.5 && i < units.count - 1 { v /= 1000; i += 1 }
        if i == 0 { return "\(Int(v.rounded())) B" }
        return String(format: v < 9.95 ? "%.1f %@" : "%.0f %@", v, units[i])
    }

    static func speed(_ r: Rate) -> String { "↑\(bytes(r.tx))/s ↓\(bytes(r.rx))/s" }
}
