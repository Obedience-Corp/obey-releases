param([string]$WindowColor)
$ErrorActionPreference = 'Stop'
if ($env:CANDIDATE_NATIVE_DISPOSABLE -ne '1' -or $env:CANDIDATE_RUNNER_KIND -ne 'github-hosted') {
    throw 'Window integration requires a disposable hosted Windows runner'
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
if ($WindowColor) {
    $form = [Windows.Forms.Form]::new()
    $form.Text = "FA0027 capture $WindowColor"
    $form.StartPosition = 'Manual'
    $form.Location = [Drawing.Point]::new(100, 100)
    $form.Size = [Drawing.Size]::new(500, 400)
    $form.BackColor = [Drawing.Color]::FromName($WindowColor)
    $form.TopMost = $WindowColor -eq 'Blue'
    [Windows.Forms.Application]::Run($form)
    exit 0
}
$children = @()
function StartFixture($color) {
    $child = Start-Process (Get-Command pwsh).Source -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile', '-File', "`"$PSCommandPath`"", '-WindowColor', $color)
    $script:children += $child
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $child.Refresh()
        if ($child.HasExited) { throw 'Fixture exited before displaying its window' }
        if ($child.MainWindowHandle -ne 0) { return $child }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Fixture window timed out'
}
try {
    $target = StartFixture 'Red'
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
    $bitmap = [Drawing.Bitmap]::new($env:APP_PROOF_SCREENSHOT)
    try {
        $pixel = $bitmap.GetPixel([int]($bitmap.Width / 2), [int]($bitmap.Height / 2))
        if ($pixel.R -ne 255 -or $pixel.G -ne 0 -or $pixel.B -ne 0) { throw 'Captured the covering window instead of the target' }
    } finally { $bitmap.Dispose() }
    'PASS: rejected stale identity; captured owned red window behind blue window; restored topmost state'
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
