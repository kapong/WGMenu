import SwiftUI
import AppKit
import Combine

// Opt-in "island": a black notch-style overlay at the top centre of the menu-bar screen that replaces the
// status item while on. Collapsed it wraps the notch (or sits as a pill under the menu bar on screens
// without one) with status wings; hovering expands it into the tunnel list and the menu's footer.
// Everything comes from TunnelStore, TunnelRow and MenuFooter, so tunnel logic lives in one place.

@MainActor
enum Island {
    private static var panel: IslandPanel?

    // Shows or closes the panel to match store.showIsland; live, no restart.
    static func sync(_ store: TunnelStore) {
        if store.showIsland {
            if panel == nil { panel = IslandPanel(store: store) }
            panel?.orderFrontRegardless()
        } else {
            panel?.close()
            panel = nil
        }
    }
}

@MainActor
final class IslandModel: ObservableObject {
    @Published var expanded = false                      // the shape's state; animated
    @Published var open = false                          // the window's state: expanded size while true
    @Published var listHeight: CGFloat = 0               // the list's laid-out height, measured while hidden
    @Published var expandedSize = CGSize(width: 400, height: 30)
    @Published var notch: CGSize?                        // nil: screen has no notch
    @Published var collapsed = CGSize(width: 260, height: 30)
    @Published var visible = true                        // panel on screen and not occluded: pulse runs
    @Published var leftWing = IslandPanel.leftWing(dots: 0)
    @Published var rightWing = IslandPanel.rightWing(meter: false)
}

// Borderless, non-activating, on every Space but not in full-screen ones (no .fullScreenAuxiliary).
// The frame is resized with the state (collapsed pill / expanded list), so it never covers more of the
// menu bar than it shows.
@MainActor
final class IslandPanel: NSPanel {
    static let maxDots = 5                               // more tunnels than this: "+N" after the dots
    static let expandedWidth: CGFloat = 400
    static let spring = Animation.spring(response: 0.35, dampingFraction: 0.82)
    static let slack: CGFloat = 8                        // below the expanded shape: spring overshoot isn't clipped
    static let springTime: UInt64 = 600_000_000          // ns: the spring has settled by then

    let model = IslandModel()
    private weak var store: TunnelStore?
    private var host: NSView?
    private var observers: [NSObjectProtocol] = []
    private var storeChange: AnyCancellable?
    private var listChange: AnyCancellable?
    private var wantOpen = false                         // last hover: inside the shape or not
    private var hoverGen = 0                             // bumps on every hover change: stale tasks give up
    private var springEnd = Date.distantPast             // a spring runs until then: no setFrame before
    private var menuOpen = false                         // a row's "…" menu is tracking: don't collapse under it

    init(store: TunnelStore) {
        self.store = store
        super.init(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        isFloatingPanel = true
        level = .statusBar                               // above the menu bar (.mainMenu)
        collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle]
        backgroundColor = .clear
        isOpaque = false
        hasShadow = false
        hidesOnDeactivate = false
        isMovable = false
        isReleasedWhenClosed = false
        appearance = NSAppearance(named: .darkAqua)      // always black: rows render light-on-dark in both modes
        let host = NSHostingView(rootView: IslandView(model: model).environmentObject(store))
        host.sizingOptions = []                          // the frame is ours, not the view's
        // Not the contentView itself: as a window's contentView, NSHostingView (under the SwiftUI App
        // lifecycle) animates the window frame on its own when a resize lands in an animated transaction,
        // fighting place(); every animated step re-invalidates constraints until AppKit throws "more Update
        // Constraints in Window passes than there are views" and the app crashes on hover.
        let box = HoverView(shape: { [weak self] in self?.shapeRect ?? .zero }) { [weak self] in self?.hover($0) }
        host.frame = box.bounds
        host.autoresizingMask = [.width, .height]
        box.addSubview(host)
        contentView = box
        self.host = host
        place()
        storeChange = store.objectWillChange.sink { [weak self] _ in   // willSet: read the store after it
            Task { @MainActor in
                guard let self, let store = self.store else { return }
                if Self.leftWing(dots: Self.dots(store).count) != self.model.leftWing
                    || Self.rightWing(meter: store.activeCount > 0) != self.model.rightWing { self.refit() }
            }
        }
        // The list's height changed (first layout, tunnel added or removed, error shown, Loading… done):
        // refit window and target size so the footer (the way back) is never clipped.
        listChange = model.$listHeight.removeDuplicates { abs($0 - $1) <= 1 }.sink { [weak self] _ in
            Task { @MainActor in self?.refit() }
        }
        let nc = NotificationCenter.default
        observers = [
            nc.addObserver(forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.place() }
            },
            nc.addObserver(forName: NSWindow.didChangeOcclusionStateNotification, object: self, queue: .main) { [weak self] _ in
                Task { @MainActor in
                    guard let self else { return }
                    self.model.visible = self.occlusionState.contains(.visible)
                }
            },
            // Synchronous (queue .main): menuOpen must be set before the menu-caused mouseExited arrives.
            nc.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.menuOpen = true }
            },
            nc.addObserver(forName: NSMenu.didEndTrackingNotification, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.menuOpen = false
                    if !self.shapeRect.contains(NSEvent.mouseLocation) { self.hover(false) }   // left while the menu was up
                }
            },
        ]
    }

    // Key (without activating the app) so the switches and the row menu work on first click.
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    override func close() {
        observers.forEach(NotificationCenter.default.removeObserver)
        observers = []
        storeChange = nil
        listChange = nil
        super.close()
    }

    // Connected / connecting tunnels, one dot each, in priority order.
    static func dots(_ store: TunnelStore) -> [Stats.Health] {
        store.ordered.map(store.health(of:)).filter { $0 != .off }
    }

    // Left of the notch: 14 lead, the WireGuard logo, 4 gap, 6pt dots 4pt apart (one gray dot when none),
    // room for "+N", 10 trail.
    static let logoSize: CGFloat = 12
    static func leftWing(dots n: Int) -> CGFloat {
        let shown = CGFloat(min(max(n, 1), maxDots))
        return 14 + logoSize + 4 + shown * 6 + (shown - 1) * 4 + (n > maxDots ? 16 : 0) + 10
    }

    // Right of the notch: the two-line speed meter while a tunnel is up, else just a rounded end.
    static func rightWing(meter: Bool) -> CGFloat { meter ? 70 : 16 }

    // Top centre of the menu-bar screen. Notch width = screen minus the menu-bar areas left and right of it.
    private func place() {
        guard let screen = NSScreen.screens.first else { return }
        let f = screen.frame
        let top: CGFloat
        var left = f.midX                                    // x of the collapsed bar's left edge, set below
        model.leftWing = Self.leftWing(dots: store.map { Self.dots($0).count } ?? 0)
        model.rightWing = Self.rightWing(meter: (store?.activeCount ?? 0) > 0)
        if screen.safeAreaInsets.top > 0, let l = screen.auxiliaryTopLeftArea, let r = screen.auxiliaryTopRightArea {
            let notch = CGSize(width: f.width - l.width - r.width, height: screen.safeAreaInsets.top)
            model.notch = notch
            model.collapsed = CGSize(width: notch.width + model.leftWing + model.rightWing, height: notch.height)
            left = f.minX + l.width - model.leftWing         // wings are uneven: keep the gap over the notch
            top = f.maxY
        } else {
            model.notch = nil
            model.collapsed = CGSize(width: model.leftWing + model.rightWing + 24, height: 30)
            left = f.midX - model.collapsed.width / 2
            top = screen.visibleFrame.maxY - 4               // just under the menu bar
        }
        // The list is always laid out (hidden while collapsed), so the expanded size is known up front.
        model.expandedSize = CGSize(width: max(model.collapsed.width, Self.expandedWidth),
                                    height: min(screen.visibleFrame.height, model.collapsed.height + model.listHeight))
        var size = model.collapsed
        var x = left
        if model.open {
            size = model.expandedSize
            size.height = min(screen.visibleFrame.height, size.height + Self.slack)   // room for the overshoot
            x = left + model.collapsed.width / 2 - size.width / 2   // centred on the collapsed bar
        }
        setFrame(NSRect(x: x, y: top - size.height, width: size.width, height: size.height),
                 display: true)
    }

    // The black shape in screen coordinates, at its target state (not mid-spring): the expanded window is
    // larger than the collapsed shape while the spring starts or before it shrinks, and that clear space
    // must neither count as hover nor take clicks.
    var shapeRect: NSRect {
        if model.open && model.expanded {
            return NSRect(x: frame.minX, y: frame.maxY - model.expandedSize.height,
                          width: frame.width, height: model.expandedSize.height)
        }
        return NSRect(x: frame.midX - model.collapsed.width / 2, y: frame.maxY - model.collapsed.height,
                      width: model.collapsed.width, height: model.collapsed.height)
    }

    // place(), but never while a spring runs: then once it has settled.
    private func refit() {
        let wait = springEnd.timeIntervalSinceNow
        guard wait <= 0 else {
            DispatchQueue.main.asyncAfter(deadline: .now() + wait) { [weak self] in self?.refit() }
            return
        }
        place()
    }

    // Expand: window to full size first (the shape, top-pinned in it, is still collapsed; the rest is
    // clear), then on the next turn one spring grows the shape down. Collapse: the same spring back up,
    // and the window shrinks only once it has settled. The frame never changes while the spring runs.
    private func hover(_ inside: Bool) {
        guard inside != wantOpen, inside || !menuOpen else { return }   // repeats (mouseMoved) change nothing
        wantOpen = inside
        hoverGen += 1
        let gen = hoverGen
        if inside {
            if !model.open {
                model.open = true
                place()
            }
            DispatchQueue.main.async { [weak self] in
                guard let self, self.hoverGen == gen else { return }
                self.springEnd = Date() + Double(Self.springTime) / 1e9
                withAnimation(Self.spring) { self.model.expanded = true }
            }
        } else {
            springEnd = Date() + Double(Self.springTime) / 1e9
            withAnimation(Self.spring) { model.expanded = false }
            Task {
                try? await Task.sleep(nanoseconds: Self.springTime)
                guard hoverGen == gen else { return }   // re-entered meanwhile
                model.open = false
                place()
            }
        }
    }
}

// The panel's content view. Hover comes from an .activeAlways tracking area on the whole panel rather than
// SwiftUI's onHover: WGMenu is an agent app that is almost never active and the panel is rarely key, so
// enter/exit must not depend on either; it also keeps hover() (and its setFrame) out of SwiftUI's update.
// Only the shape counts: hover is "pointer inside shape()", and clicks outside it fall through.
@MainActor
final class HoverView: NSView {
    private let shape: () -> NSRect                      // screen coordinates
    private let onHover: (Bool) -> Void

    init(shape: @escaping () -> NSRect, onHover: @escaping (Bool) -> Void) {
        self.shape = shape
        self.onHover = onHover
        super.init(frame: .zero)
        addTrackingArea(NSTrackingArea(rect: .zero, options: [.mouseEnteredAndExited, .mouseMoved, .activeAlways, .inVisibleRect],
                                       owner: self, userInfo: nil))   // .inVisibleRect: follows the frame
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    override func mouseEntered(with event: NSEvent) { onHover(shape().contains(NSEvent.mouseLocation)) }
    override func mouseMoved(with event: NSEvent) { onHover(shape().contains(NSEvent.mouseLocation)) }
    override func mouseExited(with event: NSEvent) { onHover(false) }

    override func hitTest(_ point: NSPoint) -> NSView? {   // point: superview coordinates
        guard let window else { return nil }
        let r = convert(window.convertFromScreen(shape()), from: nil)
        return r.contains(convert(point, from: superview)) ? super.hitTest(point) : nil
    }
}

// Rounded rectangle with separate top/bottom radii: top 0 sits flush with the screen edge like the notch.
struct IslandShape: Shape {
    var top: CGFloat
    var bottom: CGFloat

    var animatableData: AnimatablePair<CGFloat, CGFloat> {
        get { AnimatablePair(top, bottom) }
        set { top = newValue.first; bottom = newValue.second }
    }

    func path(in r: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: r.minX, y: r.minY + top))
        p.addArc(tangent1End: CGPoint(x: r.minX, y: r.minY), tangent2End: CGPoint(x: r.minX + top, y: r.minY), radius: top)
        p.addArc(tangent1End: CGPoint(x: r.maxX, y: r.minY), tangent2End: CGPoint(x: r.maxX, y: r.minY + top), radius: top)
        p.addArc(tangent1End: CGPoint(x: r.maxX, y: r.maxY), tangent2End: CGPoint(x: r.maxX - bottom, y: r.maxY), radius: bottom)
        p.addArc(tangent1End: CGPoint(x: r.minX, y: r.maxY), tangent2End: CGPoint(x: r.minX, y: r.maxY - bottom), radius: bottom)
        p.closeSubpath()
        return p
    }
}

struct ListHeight: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }   // views without it report 0
}

struct IslandView: View {
    @EnvironmentObject var store: TunnelStore
    @ObservedObject var model: IslandModel

    // Same rule as the status item: green connected, orange connecting, gray off.
    private var title: String {
        let up = store.ordered.filter(\.isUp)
        if up.isEmpty { return "VPN off" }
        return up.count == 1 ? up[0].name : "\(up[0].name) +\(up.count - 1)"
    }

    private var accessibilityTitle: String {
        if store.health == .off { return "VPN off" }
        if store.activeCount == 0 { return "VPN connecting" }    // only a toggle in flight: no name yet
        return "VPN \(title), \(state)"
    }

    private var size: CGSize { model.expanded ? model.expandedSize : model.collapsed }

    private var state: String {
        switch store.health {
        case .ok: return "connected"
        case .connecting: return "connecting"
        case .off: return "off"
        }
    }

    private var shape: IslandShape {
        IslandShape(top: model.notch == nil ? 12 : 0, bottom: model.expanded ? 22 : (model.notch == nil ? 12 : 14))
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                HStack(spacing: 4) {                     // no names: the menu bar's logo, then the dots
                    Image(nsImage: MenuBarLabel.logo)
                        .renderingMode(.template)
                        .resizable()
                        .frame(width: IslandPanel.logoSize, height: IslandPanel.logoSize)
                        .foregroundStyle(.white.opacity(0.85))
                        .accessibilityHidden(true)
                    StatusDots(states: IslandPanel.dots(store), visible: model.visible)
                }
                .padding(.leading, 14)
                    .frame(width: model.leftWing, alignment: .leading)
                Spacer(minLength: model.notch?.width ?? 24)
                rates
                    .padding(.trailing, 12)
                    .frame(width: model.rightWing, alignment: .trailing)
            }
            .frame(width: size.width, height: model.collapsed.height)   // expanded: wings move to the edges
            .accessibilityElement(children: .combine)
            .accessibilityLabel(accessibilityTitle)

            // Always laid out at full width (so its height is known before expanding), revealed by the shape
            // growing down over it; hidden and inert while collapsed.
            VStack(alignment: .leading, spacing: 10) {
                if store.tunnels.isEmpty {
                    Text(store.loaded ? "No configs found in /etc/wireguard" : "Loading…")
                        .foregroundStyle(.secondary)
                }
                ForEach(store.ordered) { TunnelRow(tunnel: $0) }   // same rows, same actions as the menu
                MenuFooter()                                         // settings, import, quit, way back
            }
            .padding(.horizontal, 18)
            .padding(.top, 10)
            .padding(.bottom, 16)
            .frame(width: model.expandedSize.width, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
            .background(GeometryReader { Color.clear.preference(key: ListHeight.self, value: $0.size.height) })
            .opacity(model.expanded ? 1 : 0)
            .allowsHitTesting(model.expanded)
            .accessibilityHidden(!model.expanded)
        }
        .frame(width: size.width, height: size.height, alignment: .top)   // one spring: width and height
        .background(shape.fill(Color.black))
        .clipShape(shape)
        .contentShape(shape)
        .onPreferenceChange(ListHeight.self) { model.listHeight = $0 }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)   // pinned to the window's top
    }

    // Speed meter while a tunnel is up: total up/down rate, two short lines; a direction dims while idle.
    @ViewBuilder private var rates: some View {
        if store.activeCount > 0 {
            let r = Stats.total(store.rates)
            VStack(alignment: .trailing, spacing: -1) {
                Text("↑\(Stats.bytes(r.tx))/s").foregroundStyle(r.tx >= 0.5 ? .white : .white.opacity(0.4))
                Text("↓\(Stats.bytes(r.rx))/s").foregroundStyle(r.rx >= 0.5 ? .white : .white.opacity(0.4))
            }
            .font(.system(size: 9, weight: .medium).monospacedDigit())
            .lineLimit(1)
            .fixedSize()
        }                                                // nothing up: no meter, the wing shrinks to an end
    }
}

// One dot per connected (green) / connecting (orange) tunnel, each with a slow pulse ring unless Reduce
// Motion is on; one dim gray dot when none. One shared TimelineView drives every pulse, paused while
// the panel is occluded. TimelineView instead of @State: the SDK's @State is a macro that bare swiftc
// (build.sh) can't expand.
struct StatusDots: View {
    let states: [Stats.Health]                           // .ok / .connecting only; empty: nothing up
    let visible: Bool                                    // false: panel occluded, so the pulse stops ticking
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        if states.isEmpty || reduceMotion {
            row(nil)
        } else {
            TimelineView(.animation(minimumInterval: 1.0 / 12, paused: !visible)) { ctx in
                row(ctx.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 1.6) / 1.6)
            }
        }
    }

    // t: pulse phase 0..<1, nil for no pulse.
    private func row(_ t: Double?) -> some View {
        HStack(spacing: 4) {
            if states.isEmpty {
                Circle().fill(Color.gray.opacity(0.6)).frame(width: 6, height: 6)
            }
            ForEach(Array(states.prefix(IslandPanel.maxDots).enumerated()), id: \.offset) { _, state in
                let c: Color = state == .ok ? .green : .orange
                ZStack {
                    if let t {
                        Circle().stroke(c, lineWidth: 1)
                            .scaleEffect(1 + 1.2 * t)
                            .opacity(0.7 * (1 - t))
                    }
                    Circle().fill(c)
                }
                .frame(width: 6, height: 6)
            }
            if states.count > IslandPanel.maxDots {
                Text("+\(states.count - IslandPanel.maxDots)")
                    .font(.system(size: 8, weight: .semibold).monospacedDigit())
                    .foregroundStyle(.white.opacity(0.7))
            }
        }
        .accessibilityHidden(true)
    }
}
