import AppKit

// Menu-bar label: state-tinted WireGuard logo with the up count in a disc over the lower loop of the
// "8", then a two-row speed block (↑ tx on top, ↓ rx below). AppKit + Stats only, so an offline render
// harness can compile this file as-is.
//
// One non-template image: MenuBarExtra (checked on macOS 27 with a probe) uses only the FIRST Image of
// an HStack label, so logo and speeds cannot be split into a colored image + a template image. The image
// is handed to NSStatusBarButton as-is and its drawing handler runs at draw time under the button's own
// appearance (VibrantDark/VibrantLight, even when the app appearance differs), so labelColor and
// tertiaryLabelColor resolve for the menu bar, not for the app.
enum MenuBarLabel {
    static let height: CGFloat = 18
    static let logoSize: CGFloat = 16, logoY: CGFloat = 1     // logo 16x16 pt at y 1...17

    // Count disc (pt, label coordinates): 9 pt across, spanning x 6...15, y 0...9 (pixel-aligned at 2x),
    // over the lower loop of the 8. A 0.9 pt clear ring separates it from the logo. 8 pt heavy digit cut
    // out of the disc (clear blend) so the menu bar shows through, like the logo's snake; a fixed white
    // digit was hard to read on the green/orange disc. 10+ uses the condensed width and grows the disc
    // into a capsule.
    static let discD: CGFloat = 9, discCX: CGFloat = 10.5, discCY: CGFloat = 4.5, discRing: CGFloat = 0.9
    static let digitFont = NSFont.monospacedDigitSystemFont(ofSize: 8, weight: .heavy)
    static let digitsFont = NSFont.systemFont(ofSize: 8, weight: .heavy, width: .condensed)

    static let arrowFont = NSFont.systemFont(ofSize: 9, weight: .semibold)
    static let speedFont = NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .regular)
    static let arrowW: CGFloat = 7
    static let speedW: CGFloat = 43                          // fits "999 MB/s" (42.1 pt), widest Stats.bytes output
    static let rowY: [CGFloat] = [9, 0]                      // ↑ row, ↓ row draw origins: no clipping in 18 pt

    // Settable so a render harness (no app bundle) can inject the PDF.
    static var logo: NSImage = Bundle.main.url(forResource: "wireguard", withExtension: "pdf")
        .flatMap { NSImage(contentsOf: $0) } ?? NSImage(size: NSSize(width: 24, height: 24), flipped: false) { r in
            NSBezierPath(ovalIn: r).fill(); return true      // fallback: plain disc, still tintable
        }

    static func tint(_ health: Stats.Health) -> NSColor {
        health == .ok ? .systemGreen : health == .connecting ? .systemOrange : .systemGray
    }

    // speed nil = no tunnel up: logo only. count 0 = no disc.
    static func image(health: Stats.Health, count: Int, speed: Stats.Rate?) -> NSImage {
        let color = tint(health)
        let digits = count > 0 ? "\(count)" : ""
        let font = digits.count > 1 ? digitsFont : digitFont
        let digitAttrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: NSColor.black]
        let digitW = (digits as NSString).size(withAttributes: digitAttrs).width
        let disc: NSRect? = digits.isEmpty ? nil : {
            let w = max(discD, digitW + 2.2)
            return NSRect(x: discCX - w / 2, y: discCY - discD / 2, width: w, height: discD)
        }()
        let logoW = max(logoSize, ceil(disc?.maxX ?? 0))
        let width = logoW + (speed == nil ? 0 : 1 + arrowW + speedW)

        let tinted = NSImage(size: NSSize(width: logoSize, height: logoSize), flipped: false) { r in
            logo.draw(in: r)
            color.set()
            r.fill(using: .sourceAtop)
            return true
        }
        let img = NSImage(size: NSSize(width: width, height: height), flipped: false) { _ in
            tinted.draw(in: NSRect(x: 0, y: logoY, width: logoSize, height: logoSize))
            if let disc, let ctx = NSGraphicsContext.current?.cgContext {
                let r = disc.height / 2
                ctx.setBlendMode(.clear)
                NSBezierPath(roundedRect: disc.insetBy(dx: -discRing, dy: -discRing),
                             xRadius: r + discRing, yRadius: r + discRing).fill()
                ctx.setBlendMode(.normal)
                color.setFill()
                NSBezierPath(roundedRect: disc, xRadius: r, yRadius: r).fill()
                ctx.setBlendMode(.clear)
                (digits as NSString).draw(at: NSPoint(x: disc.midX - digitW / 2,
                                                      y: disc.midY - font.capHeight / 2 + font.descender),
                                          withAttributes: digitAttrs)
                ctx.setBlendMode(.normal)
            }
            if let speed {
                // Active direction: labelColor arrow + rate. Idle (exactly 0): tertiary arrow and "-".
                // Rate left-aligned after the arrow; the fixed column keeps the label width stable.
                let x0 = logoW + 1
                let textAttrs: [NSAttributedString.Key: Any] = [.font: speedFont, .foregroundColor: NSColor.labelColor]
                for (arrow, rate, y) in [("↑", speed.tx, rowY[0]), ("↓", speed.rx, rowY[1])] {
                    let arrowColor: NSColor = rate > 0 ? .labelColor : .tertiaryLabelColor
                    (arrow as NSString).draw(at: NSPoint(x: x0, y: y),
                                             withAttributes: [.font: arrowFont, .foregroundColor: arrowColor])
                    let text = rate > 0 ? "\(Stats.bytes(rate))/s" : "-"
                    (text as NSString).draw(at: NSPoint(x: x0 + arrowW, y: y), withAttributes: textAttrs)
                }
            }
            return true
        }
        img.accessibilityDescription = "WGMenu"
        return img
    }
}
