// Read only visible windows owned by the explicit App process.
import CoreGraphics
import Foundation

guard CommandLine.arguments.count == 2,
      let pid = Int(CommandLine.arguments[1]), pid > 0, pid <= Int(Int32.max),
      let windows = CGWindowListCopyWindowInfo(
        [.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]]
else {
    fputs("Invalid owned PID or unavailable CoreGraphics window list\n", stderr)
    exit(1)
}
let owned = windows.filter { ($0["kCGWindowOwnerPID"] as? Int) == pid }
do {
    let data = try JSONSerialization.data(withJSONObject: owned, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
} catch {
    fputs("Owned window metadata could not be encoded\n", stderr)
    exit(1)
}
