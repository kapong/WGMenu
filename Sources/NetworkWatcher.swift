import Foundation
import SystemConfiguration
import Network

// Calls onChange on the main run loop whenever State:/Network/Global/IPv4 changes (new router,
// primary interface switch, link up/down). Event-driven via SCDynamicStore; no polling.
// It only reports changes, so callers do their own check at launch.
final class NetworkWatcher {
    private static let key = "State:/Network/Global/IPv4" as CFString
    private let onChange: () -> Void
    private var store: SCDynamicStore?
    private var source: CFRunLoopSource?

    init(onChange: @escaping () -> Void) {
        self.onChange = onChange
        var ctx = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                        retain: nil, release: nil, copyDescription: nil)
        store = SCDynamicStoreCreate(nil, "WGMenu" as CFString, { _, _, info in
            guard let info else { return }
            Unmanaged<NetworkWatcher>.fromOpaque(info).takeUnretainedValue().onChange()
        }, &ctx)
        guard let store, SCDynamicStoreSetNotificationKeys(store, [Self.key] as CFArray, nil),
              let src = SCDynamicStoreCreateRunLoopSource(nil, store, 0) else { return }
        CFRunLoopAddSource(CFRunLoopGetMain(), src, .commonModes)
        source = src
    }

    deinit {
        if let source { CFRunLoopSourceInvalidate(source) }
    }

    // Default gateways, primary service first, then other services with a router (the primary can be
    // another VPN whose Router has no MAC). Tunnel interfaces are skipped. `mac` is the router MAC
    // configd resolved for the service (ARPResolvedHardwareAddress), if any. Empty when offline.
    var gateways: [(router: String, mac: String?)] {
        guard let store else { return [] }
        let primary = (SCDynamicStoreCopyValue(store, Self.key) as? [String: Any])?["PrimaryService"] as? String
        let all = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/[^/]+/IPv4" as CFString) as? [String] ?? []
        let isPrimary = { (k: String) in primary.map { k.contains("/\($0)/") } ?? false }
        let keys = all.filter(isPrimary) + all.filter { !isPrimary($0) }.sorted()
        var out: [(router: String, mac: String?)] = []
        for k in keys {
            guard let d = SCDynamicStoreCopyValue(store, k as CFString) as? [String: Any],
                  let router = d["Router"] as? String, !out.contains(where: { $0.router == router }) else { continue }
            let ifname = d["InterfaceName"] as? String ?? ""
            if ["utun", "ipsec", "ppp"].contains(where: ifname.hasPrefix) { continue }
            out.append((router, d["ARPResolvedIPAddress"] as? String == router ? d["ARPResolvedHardwareAddress"] as? String : nil))
        }
        return out
    }
}

extension NetworkWatcher {
    // The physical network as the internet sees it: ifconfig.co/json (IP, plus hostname and ASN for
    // display), with api.ipify.org for the IPv4 when that fails or gives none. Callers use `ipv4`.
    // Tunnel interfaces (utun is .other) are prohibited, so the connection is bound to the real
    // interface and goes out via its scoped default route: a full tunnel's egress is never returned.
    static func publicInfo() async -> OfficeRules.Public? {
        var info = await fetch("ifconfig.co", "/json").flatMap(OfficeRules.publicFromJSON)
        if info?.ipv4 == nil, let ip = await fetch("api.ipify.org", "/").flatMap(OfficeRules.publicFromPlain)?.ip {
            if info == nil { info = OfficeRules.Public() }
            info?.ip = ip
        }
        return info
    }

    // HTTP/1.0 (no chunked body) GET over TLS on IPv4; the 200 response body, or nil.
    private static func fetch(_ host: String, _ path: String) async -> String? {
        let params = NWParameters(tls: .init())
        params.prohibitedInterfaceTypes = [.other]
        (params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options)?.version = .v4   // IPv4 answer
        let conn = NWConnection(host: .init(host), port: 443, using: params)
        let queue = DispatchQueue(label: "WGMenu.publicIP")
        return await withCheckedContinuation { cont in
            var done = false, data = Data()             // touched on `queue` only
            func finish(_ body: String?) {
                guard !done else { return }
                done = true
                conn.stateUpdateHandler = nil           // breaks the conn <-> handler cycle
                conn.cancel()
                cont.resume(returning: body)
            }
            func receive() {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { d, _, complete, error in
                    if let d { data.append(d) }
                    if complete || error != nil || data.count > 16384 {
                        finish(OfficeRules.httpBody(String(decoding: data, as: UTF8.self)))
                    } else { receive() }
                }
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    let req = "GET \(path) HTTP/1.0\r\nHost: \(host)\r\nAccept: application/json, text/plain\r\nUser-Agent: WGMenu\r\n\r\n"
                    conn.send(content: Data(req.utf8), completion: .contentProcessed { _ in })
                    receive()
                case .failed: finish(nil)               // .waiting may recover: the timer decides
                default: break
                }
            }
            conn.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 5) {   // timeout: use what arrived (HTTP/1.0 may not close)
                finish(OfficeRules.httpBody(String(decoding: data, as: UTF8.self)))
            }
        }
    }
}
