import Foundation
import SystemConfiguration

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

    // Current default gateway IP (the primary service's Router), or nil when offline.
    var router: String? {
        guard let store else { return nil }
        return (SCDynamicStoreCopyValue(store, Self.key) as? [String: Any])?["Router"] as? String
    }
}
