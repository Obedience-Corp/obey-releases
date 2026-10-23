param([switch]$SelfTest)
# Read-only ownership evidence for this disposable fixture's task and executable.
$ErrorActionPreference = 'Stop'
if ($env:CANDIDATE_NATIVE_DISPOSABLE -ne '1' -or $env:CANDIDATE_RUNNER_KIND -ne 'github-hosted') { throw 'Requires disposable hosted Windows' }
function ReadLiteralIdentity($ast) {
    $invocations = @(); $configs = @()
    foreach ($cmd in $ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]}, $true)) {
        $values = @($cmd.CommandElements | ForEach-Object {
            if ($_ -is [Management.Automation.Language.StringConstantExpressionAst]) { $_.Value }
            elseif ($_ -is [Management.Automation.Language.CommandParameterAst] -and $null -eq $_.Argument) { $_.Extent.Text }
            else { @{nonliteral=$true} }
        })
        if ($cmd.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand) { $invocations += ,$values }
        if ($cmd.GetCommandName() -eq 'Set-Item') {
            # Read only the config literal; never evaluate a script or export its environment.
            $elements = $cmd.CommandElements
            if ($elements.Count -eq 5 -and $elements[1].Extent.Text -eq '-LiteralPath' -and
                $elements[2] -is [Management.Automation.Language.StringConstantExpressionAst] -and $elements[2].Value -eq 'Env:OBEY_CONFIG') {
                if ($elements[3].Extent.Text -ne '-Value' -or $elements[4] -isnot [Management.Automation.Language.StringConstantExpressionAst]) { throw 'Nonliteral supervisor configuration' }
                $configs += $elements[4].Value
            }
        }
    }
    return @{invocations=@($invocations); config_values=@($configs)}
}
if ($SelfTest) {
    $tokens=$null; $parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput(@'
Set-Item -LiteralPath 'Env:OBEY_CONFIG' -Value 'C:\owned\obey.yaml'
& 'C:\owned\managed\bin\obey.exe' serve --daemon-mode
'@, [ref]$tokens, [ref]$parseErrors)
    $identity=ReadLiteralIdentity $ast
    if ($parseErrors.Count -or $identity.invocations.Count -ne 1 -or $identity.invocations[0].Count -ne 3 -or
        $identity.invocations[0][0] -ne 'C:\owned\managed\bin\obey.exe' -or $identity.invocations[0][2] -ne '--daemon-mode' -or
        $identity.config_values.Count -ne 1 -or $identity.config_values[0] -ne 'C:\owned\obey.yaml') { throw 'Native literal supervisor AST contract differs' }
    $dynamic=[Management.Automation.Language.Parser]::ParseInput('& $dynamic serve --daemon-mode', [ref]$tokens, [ref]$parseErrors)
    $unsafe=ReadLiteralIdentity $dynamic
    if ($unsafe.invocations[0][0] -is [string]) { throw 'Dynamic invocation was treated as a literal executable' }
    Write-Output 'PASS: actual PowerShell literal config/executable/native-flag AST; dynamic executable remains nonliteral'
    return
}
$unit = $env:APP_PROOF_UNIT
$script = Join-Path (Split-Path $unit) 'service-start.ps1'
$tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -like '*Obey*' } | ForEach-Object {
    @{name=$_.TaskName; path=$_.TaskPath; actions=@($_.Actions | ForEach-Object { @{execute=$_.Execute; arguments=$_.Arguments; working_directory=$_.WorkingDirectory} })}
})
$invocations = @()
$configs = @()
$scriptHash = $null
if (Test-Path -LiteralPath $script) {
    if ((Get-Item -LiteralPath $script).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing linked supervisor script' }
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw 'Supervisor script cannot be parsed safely' }
    $identity = ReadLiteralIdentity $ast
    $invocations = $identity.invocations
    $configs = $identity.config_values
    $scriptHash = (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant()
}
$processes = @()
foreach ($item in @(Get-CimInstance Win32_Process -Filter "Name='obey.exe'")) {
    if (-not $item.ExecutablePath) { throw 'Cannot inspect an Obey process executable' }
    if ([StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($item.ExecutablePath), [IO.Path]::GetFullPath($env:APP_PROOF_MANAGED_EXE))) {
        $p = Get-Process -Id $item.ProcessId -ErrorAction Stop
        $processes += @{pid=$p.Id; started=$p.StartTime.ToUniversalTime().Ticks.ToString(); path=$p.Path; parent_pid=$item.ParentProcessId}
    }
}
$unitExists = Test-Path -LiteralPath $unit
if ($unitExists -and ((Get-Item -LiteralPath $unit).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Refusing linked task definition' }
@{expected_task=('ObedienceCorp.Obey.' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value);
  unit=$unit; unit_exists=$unitExists; script=$script; script_exists=(Test-Path -LiteralPath $script);
  script_sha256=$scriptHash; invocations=@($invocations); config_values=@($configs); tasks=@($tasks); processes=@($processes)} | ConvertTo-Json -Depth 8 -Compress
