# Capture the actual displayed pixels of the identified disposable App window.
$ErrorActionPreference = 'Stop'
if ($env:CANDIDATE_NATIVE_DISPOSABLE -ne '1' -or $env:CANDIDATE_RUNNER_KIND -ne 'github-hosted') {
    throw 'Window capture requires a disposable hosted native runner'
}
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class AppWindowCapture {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct Point { public int X, Y; }
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll", EntryPoint="GetWindowLongW")] public static extern int GetWindowLong(IntPtr window, int index);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool SetWindowPos(IntPtr window, IntPtr after, int x, int y, int width, int height, uint flags);
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(Point point);
    [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr window, uint flags);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr window, int attribute, out Rect value, int size);
    [DllImport("dwmapi.dll")] public static extern int DwmFlush();
}
'@
[void][AppWindowCapture]::SetProcessDPIAware()
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$appId = [int]$env:APP_PROOF_PID
$handle = [IntPtr][long]$env:APP_PROOF_HANDLE
function RequireOwnedWindow {
    $process = Get-Process -Id $appId -ErrorAction Stop
    [uint32]$ownerId = 0
    [void][AppWindowCapture]::GetWindowThreadProcessId($handle, [ref]$ownerId)
    if ($ownerId -ne $appId -or $process.MainWindowHandle -ne $handle -or
        $process.Path -ne $env:APP_PROOF_EXE -or
        $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $env:APP_PROOF_STARTED) {
        throw 'Owned App process/window identity changed'
    }
    if (-not [AppWindowCapture]::IsWindowVisible($handle) -or [AppWindowCapture]::IsIconic($handle)) {
        throw 'Owned App window is not displayed'
    }
    return $process
}
$process = RequireOwnedWindow
$wasTopmost = ([AppWindowCapture]::GetWindowLong($handle, -20) -band 8) -ne 0
# Change only the owned window's ordering; do not close/minimize other windows.
$flags = [uint32](0x0001 -bor 0x0002 -bor 0x0010) # NOSIZE, NOMOVE, NOACTIVATE
try {
    if (-not [AppWindowCapture]::SetWindowPos($handle, [IntPtr](-1), 0, 0, 0, 0, $flags)) {
        throw 'Could not expose the owned App window'
    }
    if ([AppWindowCapture]::DwmFlush() -ne 0) { throw 'Desktop composition did not flush' }
    Start-Sleep -Milliseconds 200
    $process = RequireOwnedWindow
    $frame = [AppWindowCapture+Rect]::new()
    if ([AppWindowCapture]::DwmGetWindowAttribute($handle, 9, [ref]$frame, 16) -ne 0) {
        throw 'Cannot read the owned App frame'
    }
    $rect = [Drawing.Rectangle]::FromLTRB($frame.Left, $frame.Top, $frame.Right, $frame.Bottom)
    $screen = [Windows.Forms.SystemInformation]::VirtualScreen
    if ($rect.Width -lt 100 -or $rect.Height -lt 100 -or -not $screen.Contains($rect)) {
        throw 'Owned App frame is empty or outside the displayed desktop'
    }
    $point = [AppWindowCapture+Point]::new()
    $point.X = $rect.Left + [int]($rect.Width / 2)
    $point.Y = $rect.Top + [int]($rect.Height / 2)
    $visible = [AppWindowCapture]::GetAncestor([AppWindowCapture]::WindowFromPoint($point), 2)
    if ($visible -ne $handle) { throw 'Another window obscures the owned App' }
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($handle)
    if ($root.Current.ProcessId -ne $appId) { throw 'UI root belongs to another process' }
    $elements = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    $names = @($elements | Where-Object { -not $_.Current.IsOffscreen } | ForEach-Object { $_.Current.Name } | Where-Object { $_ } | Select-Object -Unique -First 80)
    $bitmap = [Drawing.Bitmap]::new($rect.Width, $rect.Height)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
        [void](RequireOwnedWindow)
        $bitmap.Save($env:APP_PROOF_SCREENSHOT)
    } finally { $graphics.Dispose(); $bitmap.Dispose() }
    $record = @{handle=$handle.ToInt64(); title=$process.MainWindowTitle; pid=$appId;
        started=$env:APP_PROOF_STARTED; path=$process.Path; method='owned-window-screen';
        width=$rect.Width; height=$rect.Height; visible_names=$names}
} finally {
    [void](RequireOwnedWindow)
    $restore = if ($wasTopmost) { [IntPtr](-1) } else { [IntPtr](-2) }
    if (-not [AppWindowCapture]::SetWindowPos($handle, $restore, 0, 0, 0, 0, $flags)) {
        throw 'Could not restore owned App window topmost state'
    }
    if (([AppWindowCapture]::GetWindowLong($handle, -20) -band 8) -ne $(if ($wasTopmost) { 8 } else { 0 })) {
        throw 'Owned App window topmost state was not restored'
    }
}
$record.topmost_restored = $true
$record | ConvertTo-Json -Depth 4 -Compress
