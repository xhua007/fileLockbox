import AppKit
import Foundation

// 用法: swift make_icon.swift <输出 PNG 路径>
// 生成一个 1024x1024 的渐变背景 + 白色锁形图标。

guard CommandLine.arguments.count > 1 else {
    FileHandle.standardError.write(Data("缺少输出路径\n".utf8))
    exit(1)
}
let outputPath = CommandLine.arguments[1]

let side: CGFloat = 1024
let size = NSSize(width: side, height: side)
let image = NSImage(size: size)
image.lockFocus()

let rect = NSRect(x: 0, y: 0, width: side, height: side)

// 圆角背景（配合 macOS 图标风格）
let bgPath = NSBezierPath(roundedRect: rect.insetBy(dx: 40, dy: 40), xRadius: 180, yRadius: 180)
let gradient = NSGradient(colors: [
    NSColor(calibratedRed: 0.29, green: 0.56, blue: 0.96, alpha: 1),
    NSColor(calibratedRed: 0.10, green: 0.30, blue: 0.72, alpha: 1)
])!
gradient.draw(in: bgPath, angle: -90)

// 锁环（顶部半圆）
let ringCenter = NSPoint(x: 512, y: 560)
let ringRadius: CGFloat = 190
let ring = NSBezierPath()
ring.appendArc(withCenter: ringCenter, radius: ringRadius, startAngle: 0, endAngle: 360)
ring.lineWidth = 66
ring.lineCapStyle = .round
NSColor.white.setStroke()
ring.stroke()

// 锁体
let bodyRect = NSRect(x: 250, y: 200, width: 524, height: 400)
let body = NSBezierPath(roundedRect: bodyRect, xRadius: 72, yRadius: 72)
NSColor.white.setFill()
body.fill()

// 钥匙孔（用背景色“挖空”）
let darkBlue = NSColor(calibratedRed: 0.10, green: 0.30, blue: 0.72, alpha: 1)
darkBlue.setFill()
let holeCircle = NSBezierPath(ovalIn: NSRect(x: 462, y: 396, width: 100, height: 100))
holeCircle.fill()
let holeStem = NSBezierPath(roundedRect: NSRect(x: 480, y: 262, width: 64, height: 176), xRadius: 20, yRadius: 20)
holeStem.fill()

image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let rep = NSBitmapImageRep(data: tiff),
      let png = rep.representation(using: .png, properties: [:]) else {
    FileHandle.standardError.write(Data("生成 PNG 失败\n".utf8))
    exit(1)
}

do {
    try png.write(to: URL(fileURLWithPath: outputPath))
} catch {
    FileHandle.standardError.write(Data("写入失败: \(error.localizedDescription)\n".utf8))
    exit(1)
}
