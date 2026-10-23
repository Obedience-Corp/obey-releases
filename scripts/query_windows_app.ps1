# Read-only text query for an already captured owned window; no window mutation.
$ErrorActionPreference = 'Stop'
if ($env:CANDIDATE_NATIVE_DISPOSABLE -ne '1' -or $env:CANDIDATE_RUNNER_KIND -ne 'github-hosted') {
    throw 'UIAutomation query requires a disposable hosted native runner'
}
function TextStage([string]$stage) {
    if ($env:APP_PROOF_DIAGNOSTICS) {
        $entry = @{stage=$stage; utc=[DateTime]::UtcNow.ToString('o'); helper_pid=$PID} | ConvertTo-Json -Compress
        [IO.File]::AppendAllText($env:APP_PROOF_DIAGNOSTICS, "$entry`n")
    }
}
TextStage 'uia-compile'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class AppTextOwnership {
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
}
'@
TextStage 'uia-load-assemblies'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$appId = [int]$env:APP_PROOF_PID
$handle = [IntPtr][long]$env:APP_PROOF_HANDLE
function CheckOwnership {
    $process = Get-Process -Id $appId -ErrorAction Stop
    [uint32]$owner = 0
    [void][AppTextOwnership]::GetWindowThreadProcessId($handle, [ref]$owner)
    if ($owner -ne $appId -or $process.MainWindowHandle -ne $handle -or
        $process.Path -ne $env:APP_PROOF_EXE -or
        $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $env:APP_PROOF_STARTED) {
        throw 'UIAutomation owned process/window identity changed'
    }
}
TextStage 'uia-owned-check'
CheckOwnership
TextStage 'uia-from-handle'
$root = [System.Windows.Automation.AutomationElement]::FromHandle($handle)
if ($root.Current.ProcessId -ne $appId) { throw 'UI root belongs to another process' }
TextStage 'uia-find-descendants'
$elements = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
TextStage 'uia-read-visible-names'
$names = @($elements | Where-Object { -not $_.Current.IsOffscreen } | ForEach-Object { $_.Current.Name } | Where-Object { $_ } | Select-Object -Unique -First 80)
CheckOwnership
@{pid=$appId; handle=$handle.ToInt64(); started=$env:APP_PROOF_STARTED; visible_names=$names} | ConvertTo-Json -Depth 4 -Compress
