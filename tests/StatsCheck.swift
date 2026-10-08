// Assert-based check for Sources/Stats.swift (not shipped by build.sh). Run from repo root:
//   swiftc -parse-as-library Sources/Stats.swift tests/StatsCheck.swift -o "${TMPDIR:-/tmp}/statscheck" && "${TMPDIR:-/tmp}/statscheck"
import Foundation

@main
enum StatsCheck {
    static func check(_ ok: Bool, _ what: String) {
        if !ok { print("FAIL: \(what)"); exit(1) }
    }

    static func main() {
        // Total health: in flight > off > any connecting.
        check(Stats.health(healthy: [], upInFlight: false) == .off, "none up -> off")
        check(Stats.health(healthy: [], upInFlight: true) == .connecting, "up in flight -> connecting")
        check(Stats.health(healthy: [true], upInFlight: true) == .connecting, "in flight beats ok")
        check(Stats.health(healthy: [true, true], upInFlight: false) == .ok, "all healthy -> ok")
        check(Stats.health(healthy: [true, false], upInFlight: false) == .connecting, "any connecting -> connecting")

        // Per-tunnel rx rule (monotonic ns clock).
        let s: UInt64 = 1_000_000_000, t0: UInt64 = 10_000 * s, w = UInt64(Stats.rxWindow) * s
        let zero = Stats.rxHealth(rx: 0, prevRx: 0, lastRxChange: t0, handshakeAge: 5, now: t0 + 5 * s)
        check(!zero.healthy && zero.lastRxChange == nil, "rx 0 -> connecting")
        check(!Stats.rxHealth(rx: 0, prevRx: nil, lastRxChange: nil, handshakeAge: 1, now: t0).healthy, "rx 0 + fresh handshake -> connecting")
        let inc = Stats.rxHealth(rx: 200, prevRx: 100, lastRxChange: nil, handshakeAge: nil, now: t0)
        check(inc.healthy && inc.lastRxChange == t0, "rx increasing -> healthy")
        check(!Stats.rxHealth(rx: 200, prevRx: 200, lastRxChange: t0, handshakeAge: 10, now: t0 + w + s).healthy, "rx flat > 180 s -> connecting")
        let flat = Stats.rxHealth(rx: 200, prevRx: 200, lastRxChange: t0, handshakeAge: nil, now: t0 + w - s)
        check(flat.healthy && flat.lastRxChange == t0, "rx flat < 180 s -> healthy")
        check(Stats.rxHealth(rx: 200, prevRx: 200, lastRxChange: t0, handshakeAge: nil, now: t0 + w).healthy, "exactly 180 s -> healthy")
        check(!Stats.rxHealth(rx: 200, prevRx: 200, lastRxChange: nil, handshakeAge: 1, now: t0).healthy, "flat, never changed -> connecting")

        let seeded = Stats.rxHealth(rx: 500, prevRx: nil, lastRxChange: nil, handshakeAge: 30, now: t0)
        check(seeded.healthy && seeded.lastRxChange == t0 - 30 * s, "launch + fresh handshake -> healthy")
        check(!Stats.rxHealth(rx: 500, prevRx: 500, lastRxChange: seeded.lastRxChange, handshakeAge: 30, now: t0 + w - 29 * s).healthy,
              "seed ages from the handshake time")
        check(!Stats.rxHealth(rx: 500, prevRx: nil, lastRxChange: nil, handshakeAge: 181, now: t0).healthy, "launch + stale handshake -> connecting")
        check(!Stats.rxHealth(rx: 500, prevRx: nil, lastRxChange: nil, handshakeAge: nil, now: t0).healthy, "launch + no handshake -> connecting")

        let reset = Stats.rxHealth(rx: 50, prevRx: 9000, lastRxChange: t0, handshakeAge: nil, now: t0 + w + s)
        check(reset.healthy && reset.lastRxChange == t0 + w + s, "counter reset to rx > 0 counts as a change")
        let reset0 = Stats.rxHealth(rx: 0, prevRx: 9000, lastRxChange: t0, handshakeAge: nil, now: t0 + s)
        check(!reset0.healthy && reset0.lastRxChange == nil, "counter reset to 0 -> connecting")

        let prev = ["a": Stats.Counters(rx: 1000, tx: 500), "b": Stats.Counters(rx: 9000, tx: 9000)]
        let cur = ["a": Stats.Counters(rx: 3000, tx: 1500), "b": Stats.Counters(rx: 100, tx: 9400), "c": Stats.Counters(rx: 5, tx: 5)]
        let r = Stats.rates(prev: prev, cur: cur, elapsed: 2)
        check(r["a"]?.rx == 1000 && r["a"]?.tx == 500, "rate a")
        check(r["b"]?.rx == 0 && r["b"]?.tx == 200, "negative delta ignored")
        check(r["c"] == nil, "first sample skipped")
        let t = Stats.total(r)
        check(t.rx == 1000 && t.tx == 700, "total")
        check(Stats.rates(prev: prev, cur: cur, elapsed: 0).isEmpty, "zero elapsed")

        for (v, s) in [(0.0, "0 B"), (512, "512 B"), (999.4, "999 B"), (999.6, "1.0 KB"), (1234, "1.2 KB"),
                       (34_000, "34 KB"), (999_400, "999 KB"), (1_260_000, "1.3 MB"), (2.5e9, "2.5 GB"), (5e12, "5000 GB"), (-3, "0 B")] {
            check(Stats.bytes(v) == s, "bytes \(v) -> \(Stats.bytes(v))")
        }
        check(Stats.speed(.init(rx: 1_200_000, tx: 34_000)) == "↑34 KB/s ↓1.2 MB/s", "speed")
        print("StatsCheck: all passed")
    }
}
