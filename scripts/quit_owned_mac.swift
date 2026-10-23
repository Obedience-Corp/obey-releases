// A normal AppKit termination request, never force termination or policy changes.
import AppKit
import Foundation

guard CommandLine.arguments.count == 3,
      let pid = Int32(CommandLine.arguments[1]),
      let app = NSRunningApplication(processIdentifier: pid),
      app.bundleURL?.standardizedFileURL.path == URL(fileURLWithPath: CommandLine.arguments[2]).standardizedFileURL.path
else {
    fputs("Owned App process/bundle identity mismatch\n", stderr)
    exit(1)
}
guard app.terminate() else {
    fputs("Owned App refused normal termination request\n", stderr)
    exit(1)
}
print("Normal AppKit termination requested")
