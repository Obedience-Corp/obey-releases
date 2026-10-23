# Capture the actual displayed pixels of the identified disposable App window.
$ErrorActionPreference = 'Stop'
if ($env:CANDIDATE_NATIVE_DISPOSABLE -ne '1' -or $env:CANDIDATE_RUNNER_KIND -ne 'github-hosted') {
    throw 'Window capture requires a disposable hosted native runner'
}
function CaptureStage([string]$stage) {
    $entry = @{stage=$stage; utc=[DateTime]::UtcNow.ToString('o'); helper_pid=$PID} | ConvertTo-Json -Compress
    $path = if ($env:APP_PROOF_DIAGNOSTICS) { $env:APP_PROOF_DIAGNOSTICS } else { "$($env:APP_PROOF_SCREENSHOT).capture.jsonl" }
    try { [IO.File]::AppendAllText($path, "$entry`n") } catch { [Console]::Error.WriteLine($entry) }
}
CaptureStage 'compile-win32'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class AppWindowCapture {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct Point { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] public struct Placement {
        public uint Length, Flags, ShowCommand;
        public Point Minimum, Maximum;
        public Rect Normal;
    }
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll", EntryPoint="GetWindowLongW")] public static extern int GetWindowLong(IntPtr window, int index);
    [DllImport("user32.dll")] public static extern bool GetWindowPlacement(IntPtr window, ref Placement placement);
    [DllImport("user32.dll")] public static extern bool SetWindowPlacement(IntPtr window, ref Placement placement);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr window, int command);
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
CaptureStage 'win32-ready'
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
CaptureStage 'validate-owned-window'
$process = RequireOwnedWindow
$wasTopmost = ([AppWindowCapture]::GetWindowLong($handle, -20) -band 8) -ne 0
$placement = [AppWindowCapture+Placement]::new()
$placement.Length = [Runtime.InteropServices.Marshal]::SizeOf($placement)
if (-not [AppWindowCapture]::GetWindowPlacement($handle, [ref]$placement)) { throw 'Cannot read owned window placement' }
$maximized = $false
function ReadFrame {
    $frame = [AppWindowCapture+Rect]::new()
    if ([AppWindowCapture]::DwmGetWindowAttribute($handle, 9, [ref]$frame, 16) -ne 0) {
        throw 'Cannot read the owned App frame'
    }
    return [Drawing.Rectangle]::FromLTRB($frame.Left, $frame.Top, $frame.Right, $frame.Bottom)
}
# Change only the owned window's ordering; do not close/minimize other windows.
$flags = [uint32](0x0001 -bor 0x0002 -bor 0x0010) # NOSIZE, NOMOVE, NOACTIVATE
try {
    CaptureStage 'expose-owned-window'
    if (-not [AppWindowCapture]::SetWindowPos($handle, [IntPtr](-1), 0, 0, 0, 0, $flags)) {
        throw 'Could not expose the owned App window'
    }
    if ([AppWindowCapture]::DwmFlush() -ne 0) { throw 'Desktop composition did not flush' }
    Start-Sleep -Milliseconds 200
    $process = RequireOwnedWindow
    $rect = ReadFrame
    $originalFrame = $rect.ToString()
    $screen = [Windows.Forms.SystemInformation]::VirtualScreen
    if ($rect.Width -lt 100 -or $rect.Height -lt 100) { throw "Owned App frame is empty: $rect; screen: $screen" }
    if (-not $screen.Contains($rect)) {
        # Use the normal window-manager operation for a window larger than this
        # disposable desktop. Restore its original placement after the capture.
        $maximized = $true
        [void][AppWindowCapture]::ShowWindow($handle, 3)
        if ([AppWindowCapture]::DwmFlush() -ne 0) { throw 'Maximized frame did not flush' }
        Start-Sleep -Milliseconds 200
        [void](RequireOwnedWindow)
        $rect = ReadFrame
        if ($rect.Width -lt 100 -or $rect.Height -lt 100 -or -not $screen.Contains($rect)) {
            throw "Owned App frame cannot fit desktop: $rect; original: $originalFrame; screen: $screen"
        }
    }
    $point = [AppWindowCapture+Point]::new()
    $point.X = $rect.Left + [int]($rect.Width / 2)
    $point.Y = $rect.Top + [int]($rect.Height / 2)
    $visible = [AppWindowCapture]::GetAncestor([AppWindowCapture]::WindowFromPoint($point), 2)
    if ($visible -ne $handle) { throw 'Another window obscures the owned App' }
    CaptureStage 'capture-displayed-pixels'
    $bitmap = [Drawing.Bitmap]::new($rect.Width, $rect.Height)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
        [void](RequireOwnedWindow)
        $bitmap.Save($env:APP_PROOF_SCREENSHOT)
    } finally { $graphics.Dispose(); $bitmap.Dispose() }
    $record = @{handle=$handle.ToInt64(); title=$process.MainWindowTitle; pid=$appId;
        started=$env:APP_PROOF_STARTED; path=$process.Path; method='owned-window-screen';
        width=$rect.Width; height=$rect.Height; visible_names=@(); uia_verified=$false;
        original_frame=$originalFrame; captured_frame=$rect.ToString(); screen=$screen.ToString();
        maximized_for_capture=$maximized}
} finally {
    CaptureStage 'restore-owned-window'
    [void](RequireOwnedWindow)
    try {
        if ($maximized) {
            if (-not [AppWindowCapture]::SetWindowPlacement($handle, [ref]$placement)) { throw 'Cannot restore owned window placement' }
            $restored = [AppWindowCapture+Placement]::new()
            $restored.Length = [Runtime.InteropServices.Marshal]::SizeOf($restored)
            if (-not [AppWindowCapture]::GetWindowPlacement($handle, [ref]$restored) -or
                $restored.ShowCommand -ne $placement.ShowCommand -or
                $restored.Normal.Left -ne $placement.Normal.Left -or $restored.Normal.Top -ne $placement.Normal.Top -or
                $restored.Normal.Right -ne $placement.Normal.Right -or $restored.Normal.Bottom -ne $placement.Normal.Bottom) {
                throw 'Owned window placement was not restored'
            }
        }
    } finally {
        $restore = if ($wasTopmost) { [IntPtr](-1) } else { [IntPtr](-2) }
        if (-not [AppWindowCapture]::SetWindowPos($handle, $restore, 0, 0, 0, 0, $flags)) {
            throw 'Could not restore owned App window topmost state'
        }
        if (([AppWindowCapture]::GetWindowLong($handle, -20) -band 8) -ne $(if ($wasTopmost) { 8 } else { 0 })) {
            throw 'Owned App window topmost state was not restored'
        }
    }
}
$record.topmost_restored = $true
$record.placement_restored = $true
CaptureStage 'pixels-saved-placement-restored'
# UIAutomation can block inside an application's accessibility provider. It
# runs only AFTER pixels and restoration, in an owned bounded child process.
$stdout = "$($env:APP_PROOF_SCREENSHOT).uia.stdout.log"
$stderr = "$($env:APP_PROOF_SCREENSHOT).uia.stderr.log"
$worker = Join-Path $PSScriptRoot 'query_windows_app.ps1'
CaptureStage 'query-uia'
$child = $null
try {
    $child = Start-Process (Get-Command pwsh).Source -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ArgumentList @('-NoProfile', '-NonInteractive', '-File', "`"$worker`"")
    if (-not $child.WaitForExit(15000)) {
        $child.Kill($true)
        if (-not $child.WaitForExit(5000)) { throw 'Owned UIAutomation worker did not exit after termination' }
        throw 'Owned UIAutomation query timed out after 15 seconds'
    }
    if ($child.ExitCode -ne 0) { throw "Owned UIAutomation query failed: $(Get-Content -Raw $stderr)" }
    $text = Get-Content -Raw $stdout | ConvertFrom-Json
    if ($text.pid -ne $appId -or $text.handle -ne $handle.ToInt64() -or $text.started -ne $env:APP_PROOF_STARTED) { throw 'UIAutomation worker identity differs from captured window' }
    [void](RequireOwnedWindow)
    $record.visible_names = @($text.visible_names)
    $record.uia_verified = $true
    CaptureStage 'uia-complete'
} catch {
    $record.uia_failure = $_.Exception.Message
    CaptureStage 'uia-failed'
} finally {
    if ($child) {
        if (-not $child.HasExited) {
            $child.Kill($true)
            if (-not $child.WaitForExit(5000)) { throw 'Owned UIAutomation worker cleanup failed' }
        }
        $child.Dispose()
    }
}
$record | ConvertTo-Json -Depth 4 -Compress
