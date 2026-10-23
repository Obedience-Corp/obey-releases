param([string]$WindowColor, [string]$ReadyPath, [switch]$SlowUIA)
$ErrorActionPreference = 'Stop'
if ($env:CANDIDATE_NATIVE_DISPOSABLE -ne '1' -or $env:CANDIDATE_RUNNER_KIND -ne 'github-hosted') {
    throw 'Window integration requires a disposable hosted Windows runner'
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
if ($WindowColor) {
    if ($SlowUIA) {
        # Supplying explicit references replaces Add-Type's normal framework
        # set. Preserve the installed PowerShell reference assemblies as well
        # as WinForms' runtime-only forwarded Message assembly.
        $references = @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object FullName)
        if ($references.Count -eq 0) { throw 'Installed PowerShell compiler reference set is missing' }
        $references += @([Windows.Forms.Form].Assembly.Location, [Windows.Forms.Message].Assembly.Location)
        Add-Type -ReferencedAssemblies $references @'
using System;
using System.Windows.Forms;
public class SlowAccessibleFixture : Form {
    public string DiagnosticPath;
    protected override void WndProc(ref Message message) {
        if (message.Msg == 0x003D && !String.IsNullOrEmpty(DiagnosticPath)) {
            System.IO.File.AppendAllText(DiagnosticPath, "WM_GETOBJECT entered\n");
            System.Threading.Thread.Sleep(30000);
        }
        base.WndProc(ref message);
    }
}
'@
        $form = [SlowAccessibleFixture]::new()
        $form.DiagnosticPath = "$ReadyPath.uia-blocked.log"
    } else { $form = [Windows.Forms.Form]::new() }
    $form.Text = "FA0027 capture $WindowColor"
    $form.StartPosition = 'Manual'
    $form.Location = [Drawing.Point]::new(100, 100)
    $form.Size = [Drawing.Size]::new(500, 400)
    $form.BackColor = [Drawing.Color]::FromName($WindowColor)
    $form.TopMost = $WindowColor -eq 'Blue'
    if ($WindowColor -eq 'Red') {
        $menu = [Windows.Forms.MenuStrip]::new()
        $appMenu = [Windows.Forms.ToolStripMenuItem]::new('App')
        $check = [Windows.Forms.ToolStripMenuItem]::new('Check for app updates')
        $script:menuInvocations = 0
        $check.Add_Click({
            $script:menuInvocations++
            [IO.File]::WriteAllText("$ReadyPath.menu.json", (@{pid=$PID; count=$script:menuInvocations} | ConvertTo-Json -Compress))
        })
        [void]$appMenu.DropDownItems.Add($check)
        [void]$menu.Items.Add($appMenu)
        $form.MainMenuStrip = $menu
        $form.Controls.Add($menu)
    }
    $form.Add_Shown({
        $state = @{pid=$PID; handle=$form.Handle.ToInt64(); visible=$form.Visible;
            apartment=[Threading.Thread]::CurrentThread.ApartmentState.ToString()} | ConvertTo-Json -Compress
        [IO.File]::WriteAllText("$ReadyPath.tmp", $state)
        [IO.File]::Move("$ReadyPath.tmp", $ReadyPath)
    })
    [Windows.Forms.Application]::Run($form)
    exit 0
}
$children = @()
function StartFixture($color, [switch]$blockUIA) {
    $label = if ($blockUIA) { "$color-slow" } else { $color }
    $ready = Join-Path $env:RUNNER_TEMP "capture-fixture-$label.ready.json"
    $stdout = Join-Path $env:RUNNER_TEMP "capture-fixture-$label.stdout.log"
    $stderr = Join-Path $env:RUNNER_TEMP "capture-fixture-$label.stderr.log"
    # This is a GUI fixture: a hidden startup window can suppress its first show.
    $arguments = @('-NoProfile', '-STA', '-File', "`"$PSCommandPath`"", '-WindowColor', $color, '-ReadyPath', "`"$ready`"")
    if ($blockUIA) { $arguments += '-SlowUIA' }
    $child = Start-Process (Get-Command pwsh).Source -WindowStyle Normal -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ArgumentList $arguments
    $script:children += $child
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $child.Refresh()
        if ($child.HasExited) { throw "Fixture $color exited before displaying its window; stderr: $(Get-Content -Raw $stderr)" }
        if ((Test-Path $ready) -and $child.MainWindowHandle -ne 0) {
            $state = Get-Content -Raw $ready | ConvertFrom-Json
            if (-not $state.visible -or $state.pid -ne $child.Id -or $state.handle -ne $child.MainWindowHandle.ToInt64()) {
                throw "Fixture $color visible window differs from its owned main window: $(Get-Content -Raw $ready)"
            }
            Write-Host "Fixture $color displayed: $(Get-Content -Raw $ready)"
            return $child
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Fixture $color window timed out: pid=$($child.Id), handle=$($child.MainWindowHandle), title=$($child.MainWindowTitle); stderr: $(Get-Content -Raw $stderr)"
}
try {
    $target = StartFixture 'Red'
    $env:APP_UPGRADE_MODE = 'check-updates'
    $env:APP_UPGRADE_PID = $target.Id.ToString()
    $env:APP_UPGRADE_EXE = $target.Path
    $env:APP_UPGRADE_STARTED = '0'
    $menuAction = Join-Path $PSScriptRoot '../scripts/windows_app_upgrade.ps1'
    $menuResult = Join-Path $env:RUNNER_TEMP 'capture-fixture-Red.ready.json.menu.json'
    function InvokeMenuFixture($tag) {
        $stdout = Join-Path $env:RUNNER_TEMP "capture-fixture-menu-$tag.stdout.log"
        $stderr = Join-Path $env:RUNNER_TEMP "capture-fixture-menu-$tag.stderr.log"
        $helper = Start-Process (Get-Command pwsh).Source -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ArgumentList @('-NoProfile', '-NonInteractive', '-File', "`"$menuAction`"")
        try { return @{code=$helper.ExitCode; output=(Get-Content -Raw $stdout); error=(Get-Content -Raw $stderr)} }
        finally { $helper.Dispose() }
    }
    $stale = InvokeMenuFixture 'stale'
    if ($stale.code -eq 0 -or $stale.error -notmatch 'PID was reused') { throw "Stale menu identity was not refused: $($stale.error)" }
    if (Test-Path $menuResult) { throw 'Rejected identity invoked the menu fixture' }
    $env:APP_UPGRADE_STARTED = $target.StartTime.ToUniversalTime().Ticks.ToString()
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $invocation = InvokeMenuFixture 'owned'
        if ($invocation.code -ne 0) { throw "Owned menu helper failed: $($invocation.error)" }
        $menu = $invocation.output | ConvertFrom-Json
        if ($menu.invoked) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $menu.invoked -or $menu.root_pid -ne $target.Id) { throw 'Owned native App menu invocation did not verify' }
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while (-not (Test-Path $menuResult) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
    $observed = Get-Content -Raw $menuResult | ConvertFrom-Json
    if ($observed.pid -ne $target.Id -or $observed.count -ne 1) { throw 'Menu action did not run exactly once in the owned fixture' }
    'PASS: stale menu identity refused; actual owned App menu action invoked once'
    $obscurer = StartFixture 'Blue'
    Start-Sleep -Milliseconds 500
    $baseline = [Drawing.Bitmap]::new(1, 1)
    $graphics = [Drawing.Graphics]::FromImage($baseline)
    try {
        $graphics.CopyFromScreen(350, 300, 0, 0, $baseline.Size)
        $pixel = $baseline.GetPixel(0, 0)
        if ($pixel.R -ne 0 -or $pixel.G -ne 0 -or $pixel.B -ne 255) { throw 'Fixture did not obscure the target window' }
    } finally { $graphics.Dispose(); $baseline.Dispose() }
    $env:APP_PROOF_PID = $target.Id.ToString()
    $env:APP_PROOF_HANDLE = $target.MainWindowHandle.ToInt64().ToString()
    $env:APP_PROOF_EXE = $target.Path
    $env:APP_PROOF_STARTED = '0'
    $env:APP_PROOF_SCREENSHOT = Join-Path $env:RUNNER_TEMP 'owned-window-capture.png'
    if (Test-Path $env:APP_PROOF_SCREENSHOT) { throw 'Refusing existing capture output' }
    $capture = Join-Path $PSScriptRoot '../scripts/capture_windows_app.ps1'
    try {
        & $capture
        throw 'Stale process identity unexpectedly captured a window'
    } catch {
        if ($_.Exception.Message -notmatch 'identity changed') { throw }
    }
    if (Test-Path $env:APP_PROOF_SCREENSHOT) { throw 'Rejected identity wrote an image' }
    $env:APP_PROOF_STARTED = $target.StartTime.ToUniversalTime().Ticks.ToString()
    $result = (& $capture) | ConvertFrom-Json
    if (-not $result.topmost_restored -or $result.pid -ne $target.Id) { throw 'Capture ownership/topmost restoration did not verify' }
    if (-not $result.uia_verified -or $result.visible_names -notcontains 'App') { throw 'Normal accessibility did not return the actual visible App menu' }
    $bitmap = [Drawing.Bitmap]::new($env:APP_PROOF_SCREENSHOT)
    try {
        $pixel = $bitmap.GetPixel([int]($bitmap.Width / 2), [int]($bitmap.Height / 2))
        if ($pixel.R -ne 255 -or $pixel.G -ne 0 -or $pixel.B -ne 0) { throw 'Captured the covering window instead of the target' }
    } finally { $bitmap.Dispose() }
    'PASS: rejected stale identity; captured owned red window behind blue window; restored topmost state'
    $desktop = [Windows.Forms.SystemInformation]::VirtualScreen
    if (-not [AppWindowCapture]::SetWindowPos($target.MainWindowHandle, [IntPtr](-2), 100, 100, $desktop.Width + 200, $desktop.Height + 100, 0x0010)) {
        throw 'Could not create oversized owned fixture'
    }
    $original = [AppWindowCapture+Placement]::new()
    $original.Length = [Runtime.InteropServices.Marshal]::SizeOf($original)
    if (-not [AppWindowCapture]::GetWindowPlacement($target.MainWindowHandle, [ref]$original)) { throw 'Cannot inspect oversized fixture placement' }
    function AssertRestoredPlacement {
        $actual = [AppWindowCapture+Placement]::new()
        $actual.Length = [Runtime.InteropServices.Marshal]::SizeOf($actual)
        if (-not [AppWindowCapture]::GetWindowPlacement($target.MainWindowHandle, [ref]$actual) -or
            $actual.ShowCommand -ne $original.ShowCommand -or
            $actual.Normal.Left -ne $original.Normal.Left -or $actual.Normal.Top -ne $original.Normal.Top -or
            $actual.Normal.Right -ne $original.Normal.Right -or $actual.Normal.Bottom -ne $original.Normal.Bottom -or
            ([AppWindowCapture]::GetWindowLong($target.MainWindowHandle, -20) -band 8) -ne 0) {
            throw 'Capture did not restore oversized fixture geometry and topmost state'
        }
    }
    $env:APP_PROOF_SCREENSHOT = Join-Path $env:RUNNER_TEMP 'owned-window-capture-maximized.png'
    $result = (& $capture) | ConvertFrom-Json
    if (-not $result.maximized_for_capture -or -not $result.placement_restored) { throw 'Oversized capture did not maximize and restore' }
    AssertRestoredPlacement
    $bitmap = [Drawing.Bitmap]::new($env:APP_PROOF_SCREENSHOT)
    try {
        $pixel = $bitmap.GetPixel([int]($bitmap.Width / 2), [int]($bitmap.Height / 2))
        if ($pixel.R -ne 255 -or $pixel.G -ne 0 -or $pixel.B -ne 0) { throw 'Oversized target did not render in the captured frame' }
    } finally { $bitmap.Dispose() }
    $env:APP_PROOF_SCREENSHOT = Join-Path $env:RUNNER_TEMP 'missing-capture-directory/image.png'
    try {
        & $capture
        throw 'Invalid output directory unexpectedly accepted'
    } catch {
        if ($_.Exception.Message -notmatch 'Save') { throw }
    }
    AssertRestoredPlacement
    'PASS: oversized target maximized and rendered; original placement/topmost restored on success and failed image write'
    $slow = StartFixture 'Red' -blockUIA
    $env:APP_PROOF_PID = $slow.Id.ToString()
    $env:APP_PROOF_HANDLE = $slow.MainWindowHandle.ToInt64().ToString()
    $env:APP_PROOF_EXE = $slow.Path
    $env:APP_PROOF_STARTED = $slow.StartTime.ToUniversalTime().Ticks.ToString()
    $env:APP_PROOF_SCREENSHOT = Join-Path $env:RUNNER_TEMP 'owned-window-capture-slow-uia.png'
    $env:APP_PROOF_DIAGNOSTICS = "$($env:APP_PROOF_SCREENSHOT).capture.jsonl"
    $result = (& $capture) | ConvertFrom-Json
    if ($result.uia_verified -or $result.uia_failure -notmatch 'timed out' -or
        -not $result.topmost_restored -or -not $result.placement_restored) { throw 'Slow accessibility did not preserve bounded failure and restoration' }
    $marker = Join-Path $env:RUNNER_TEMP 'capture-fixture-Red-slow.ready.json.uia-blocked.log'
    if (-not (Test-Path $marker)) { throw 'Owned accessibility fixture did not actually block' }
    if (([AppWindowCapture]::GetWindowLong($slow.MainWindowHandle, -20) -band 8) -ne 0) { throw 'Slow UIAutomation left target topmost' }
    $bitmap = [Drawing.Bitmap]::new($env:APP_PROOF_SCREENSHOT)
    try {
        $pixel = $bitmap.GetPixel([int]($bitmap.Width / 2), [int]($bitmap.Height / 2))
        if ($pixel.R -ne 255 -or $pixel.G -ne 0 -or $pixel.B -ne 0) { throw 'Slow accessibility erased actual target pixels' }
    } finally { $bitmap.Dispose() }
    'PASS: pixels saved and placement restored before real blocked accessibility query; bounded worker terminated; text readiness remains false'

} finally {
    foreach ($child in $children) {
        $child.Refresh()
        if (-not $child.HasExited) {
            [void]$child.CloseMainWindow()
            if (-not $child.WaitForExit(10000)) { $child.Kill(); $child.WaitForExit() }
        }
        $child.Dispose()
    }
}
