// A disposable native window for verifier controls, never the product App.
import AppKit
import QuartzCore
import Foundation

guard CommandLine.arguments.count == 2 else { exit(64) }
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let window = NSWindow(contentRect: NSRect(x: 100, y: 100, width: 640, height: 420),
    styleMask: [.titled, .closable], backing: .buffered, defer: false)
window.title = "FA0027 owned query control"
window.contentView?.wantsLayer = true
window.contentView?.layer?.backgroundColor = NSColor.systemRed.cgColor
window.makeKeyAndOrderFront(nil)
app.activate(ignoringOtherApps: true)
let ready: [String: Any] = ["pid": ProcessInfo.processInfo.processIdentifier,
                          "window_id": window.windowNumber]
let data = try JSONSerialization.data(withJSONObject: ready, options: [.sortedKeys])
try data.write(to: URL(fileURLWithPath: CommandLine.arguments[1]), options: [.atomic])
app.run()
