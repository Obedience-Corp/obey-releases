# Real owned-window interaction and identity-aware process observation only.
$ErrorActionPreference = 'Stop'
function ProcessRecord($process) {
    return @{pid=$process.Id; started=$process.StartTime.ToUniversalTime().Ticks.ToString(); path=$process.Path}
}
$mode = $env:APP_UPGRADE_MODE
if ($mode -eq 'find') {
    $matches = @(Get-Process -Name 'festival-app' -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -eq $env:APP_UPGRADE_EXE -and $_.Id -ne [int]$env:APP_UPGRADE_OLD_PID -and
        $_.StartTime.ToUniversalTime().Ticks -gt [long]$env:APP_UPGRADE_AFTER
    })
    if ($matches.Count -gt 1) { throw 'Ambiguous post-update App processes' }
    if ($matches.Count -eq 1) { ProcessRecord $matches[0] | ConvertTo-Json -Compress } else { 'null' }
    exit 0
}
$appId = [int]$env:APP_UPGRADE_PID
$process = Get-Process -Id $appId -ErrorAction SilentlyContinue
if ($mode -eq 'identity') {
    if ($null -eq $process) { 'null' } else { ProcessRecord $process | ConvertTo-Json -Compress }
    exit 0
}
if ($null -eq $process -or $process.Path -ne $env:APP_UPGRADE_EXE) { throw 'Owned App identity/path unavailable' }
if ($env:APP_UPGRADE_STARTED -and $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $env:APP_UPGRADE_STARTED) {
    throw 'App PID was reused'
}
if ($mode -eq 'quit') {
    if (-not $process.CloseMainWindow()) { throw 'Owned App refused normal close request' }
    '{"normal_close_requested":true}'
    exit 0
}
if ($mode -ne 'restart') { throw 'Unknown App UI operation' }
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
if ($process.MainWindowHandle -eq 0) { '{"invoked":false}'; exit 0 }
$root = [System.Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
if ($root.Current.ProcessId -ne $appId) { throw 'UI root is not the owned App window' }
$all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
$names = @($all | ForEach-Object { $_.Current.Name } | Where-Object { $_ })
$description = "Festival App $($env:APP_UPGRADE_VERSION) is downloaded."
if (-not ($names -contains 'Update ready') -or -not (@($names | Where-Object { $_.StartsWith($description) }).Count)) {
    @{invoked=$false; visible_names=@($names | Select-Object -First 80)} | ConvertTo-Json -Depth 3 -Compress
    exit 0
}
$condition = [System.Windows.Automation.AndCondition]::new(
    [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty, 'Restart now'),
    [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button))
$buttons = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
if ($buttons.Count -gt 1) { throw 'Ambiguous Restart now controls' }
if ($buttons.Count -eq 0 -or -not $buttons[0].Current.IsEnabled) { '{"invoked":false}'; exit 0 }
$pattern = $buttons[0].GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
$pattern.Invoke()
@{invoked=$true; method='UIAutomation.InvokePattern'; root_pid=$appId; button='Restart now'; version=$env:APP_UPGRADE_VERSION} | ConvertTo-Json -Compress
