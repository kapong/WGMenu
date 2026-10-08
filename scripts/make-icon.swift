// Generates Resources/AppIcon.icns (and docs/icon.png, 128 px). Run from anywhere:
//   swift scripts/make-icon.swift
// Design "menu-bar hub": a white menu-bar strip with a status pill, branching into three
// tunnel dots (green, orange, green) on an indigo squircle. Sizes <= 32 px get a simplified,
// pixel-fitted variant (bigger body, thicker shapes, no shadows/gradients), as Apple does.
import AppKit

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()

func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat(hex >> 16 & 0xff) / 255, green: CGFloat(hex >> 8 & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: a)
}
let green: (UInt32, UInt32) = (0x5BE38A, 0x22B35E), orange: (UInt32, UInt32) = (0xFFB547, 0xF07C1E)

/// Rounded square with continuous-looking corners.
func squircle(_ r: CGRect, _ radius: CGFloat) -> CGPath {
    let p = CGMutablePath(), k = radius * 1.528, c = k * 0.36
    let (x0, y0, x1, y1) = (r.minX, r.minY, r.maxX, r.maxY)
    p.move(to: CGPoint(x: x0 + k, y: y0)); p.addLine(to: CGPoint(x: x1 - k, y: y0))
    p.addCurve(to: CGPoint(x: x1, y: y0 + k), control1: CGPoint(x: x1 - c, y: y0), control2: CGPoint(x: x1, y: y0 + c))
    p.addLine(to: CGPoint(x: x1, y: y1 - k))
    p.addCurve(to: CGPoint(x: x1 - k, y: y1), control1: CGPoint(x: x1, y: y1 - c), control2: CGPoint(x: x1 - c, y: y1))
    p.addLine(to: CGPoint(x: x0 + k, y: y1))
    p.addCurve(to: CGPoint(x: x0, y: y1 - k), control1: CGPoint(x: x0 + c, y: y1), control2: CGPoint(x: x0, y: y1 - c))
    p.addLine(to: CGPoint(x: x0, y: y0 + k))
    p.addCurve(to: CGPoint(x: x0 + k, y: y0), control1: CGPoint(x: x0, y: y0 + c), control2: CGPoint(x: x0 + c, y: y0))
    p.closeSubpath(); return p
}

func gradient(_ ctx: CGContext, _ colors: [CGColor], _ top: CGFloat, _ bottom: CGFloat) {
    let g = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB)!, colors: colors as CFArray, locations: nil)!
    ctx.drawLinearGradient(g, start: CGPoint(x: 0, y: top), end: CGPoint(x: 0, y: bottom),
                           options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
}

func fill(_ ctx: CGContext, _ path: CGPath, _ c: (UInt32, UInt32), shadow: Bool) {
    let b = path.boundingBoxOfPath, k = ctx.ctm.a
    if shadow {
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -10 * k), blur: 22 * k, color: rgb(0, 0.35))
        ctx.addPath(path); ctx.setFillColor(rgb(c.1)); ctx.fillPath(); ctx.restoreGState()
    }
    ctx.saveGState(); ctx.addPath(path); ctx.clip()
    gradient(ctx, [rgb(c.0), rgb(c.1)], b.maxY, b.minY); ctx.restoreGState()
}

/// Draws the icon in 1024-unit space (origin bottom-left). Simplified variant at <= 32 px.
func draw(_ ctx: CGContext, px: Int) {
    let small = px <= 32, tiny = px <= 16
    let body = small ? CGRect(x: 32, y: 32, width: 960, height: 960) : CGRect(x: 100, y: 100, width: 824, height: 824)
    let shape = squircle(body, small ? 200 : 185), k = ctx.ctm.a
    if !small { // drop shadow
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -12 * k), blur: 28 * k, color: rgb(0, 0.35))
        ctx.addPath(shape); ctx.setFillColor(rgb(0x161A4A)); ctx.fillPath(); ctx.restoreGState()
    }
    ctx.saveGState(); ctx.addPath(shape); ctx.clip()
    gradient(ctx, small ? [rgb(0x3438A0), rgb(0x1E2260)] : [rgb(0x3C3FA8), rgb(0x161A4A)], body.maxY, body.minY)

    // Menu-bar strip with a status pill. Small geometry sits on a 64-unit (1 px @16) grid.
    let barY: CGFloat = small ? 736 : body.maxY - 216
    ctx.setFillColor(rgb(0xFFFFFF, small ? 1 : 0.94)); ctx.fill(CGRect(x: 0, y: barY, width: 1024, height: 1024 - barY))
    if !small { // soft shadow under the strip
        ctx.saveGState(); ctx.clip(to: CGRect(x: 0, y: barY - 30, width: 1024, height: 30))
        gradient(ctx, [rgb(0, 0.28), rgb(0, 0)], barY, barY - 30); ctx.restoreGState()
    }
    let pill = small ? CGRect(x: 320, y: 800, width: 384, height: 128) : CGRect(x: 412, y: barY + 58, width: 200, height: 104)
    ctx.addPath(CGPath(roundedRect: pill, cornerWidth: pill.height / 2, cornerHeight: pill.height / 2, transform: nil))
    ctx.setFillColor(rgb(0x2B2F8F)); ctx.fillPath()

    // Branches from the strip to three tunnel dots (16 px: centre stem only).
    let dotY: CGFloat = small ? 352 : 300, r: CGFloat = small ? 128 : 116
    let xs: [CGFloat] = small ? [192, 512, 832] : [248, 512, 776]
    let lines = CGMutablePath()
    for x in xs where !tiny || x == 512 {
        lines.move(to: CGPoint(x: 512, y: barY))
        if small { lines.addLine(to: CGPoint(x: x, y: dotY)) } else {
            lines.addCurve(to: CGPoint(x: x, y: dotY + 40), control1: CGPoint(x: 512, y: 520), control2: CGPoint(x: x, y: 600))
        }
    }
    ctx.saveGState(); ctx.addPath(lines); ctx.setLineWidth(small ? 64 : 72); ctx.setLineCap(small ? .butt : .round)
    ctx.setStrokeColor(rgb(0xDDE4FF)); ctx.strokePath(); ctx.restoreGState()
    for (x, c) in zip(xs, [green, orange, green]) {
        fill(ctx, CGPath(ellipseIn: CGRect(x: x - r, y: dotY - r, width: 2 * r, height: 2 * r), transform: nil), c, shadow: !small)
    }
    ctx.restoreGState()

    if !small { // thin light rim at the top
        ctx.saveGState(); ctx.addPath(squircle(body.insetBy(dx: 2, dy: 2), 183)); ctx.setLineWidth(4)
        ctx.replacePathWithStrokedPath(); ctx.clip()
        gradient(ctx, [rgb(0xFFFFFF, 0.30), rgb(0xFFFFFF, 0), rgb(0, 0.18)], body.maxY, body.minY); ctx.restoreGState()
    }
}

func png(_ px: Int, to url: URL) throws {
    let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.scaleBy(x: CGFloat(px) / 1024, y: CGFloat(px) / 1024)
    draw(ctx, px: px)
    guard let data = NSBitmapImageRep(cgImage: ctx.makeImage()!).representation(using: .png, properties: [:])
    else { throw CocoaError(.fileWriteUnknown) }
    try data.write(to: url)
}

let set = FileManager.default.temporaryDirectory.appendingPathComponent("wgmenu-\(getpid()).iconset")
try FileManager.default.createDirectory(at: set, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: set) }
for pt in [16, 32, 128, 256, 512] {
    try png(pt, to: set.appendingPathComponent("icon_\(pt)x\(pt).png"))
    try png(pt * 2, to: set.appendingPathComponent("icon_\(pt)x\(pt)@2x.png"))
}
let out = root.appendingPathComponent("Resources/AppIcon.icns")
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", set.path, "-o", out.path]
try p.run(); p.waitUntilExit()
guard p.terminationStatus == 0 else { fatalError("iconutil failed") }
try png(128, to: root.appendingPathComponent("docs/icon.png"))
print("Wrote \(out.path)")
