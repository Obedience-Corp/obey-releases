# Only stop identities captured from this newly created disposable console tree.
$ErrorActionPreference='Stop'
if ($env:CANDIDATE_NATIVE_DISPOSABLE -ne '1' -or $env:CANDIDATE_RUNNER_KIND -ne 'github-hosted') {
    throw 'Console cleanup requires a disposable hosted account'
}
$records=@($env:APP_CONSOLE_IDENTITIES | ConvertFrom-Json)
foreach ($record in $records) {
    if ((-not ($record.pid -is [int] -or $record.pid -is [long])) -or $record.pid -le 0 -or $record.pid -gt [int]::MaxValue -or [string]$record.started -notmatch '^\d+$') {
        throw 'Invalid owned console identity; refusing all cleanup'
    }
}
[array]::Reverse($records)
foreach ($record in $records) {
    $owned=Get-Process -Id $record.pid -ErrorAction SilentlyContinue
    if ($null -eq $owned) { continue }
    try {
        # Acquire and retain the actual process handle before comparing birth;
        # never kill a newly reused PID or select processes by a broad name.
        [void]$owned.Handle
        if ($owned.StartTime.ToUniversalTime().Ticks.ToString() -eq [string]$record.started) {
            $owned.Kill()
            if (-not $owned.WaitForExit(5000)) { throw 'Owned console process did not exit' }
        }
    } catch {
        $failure=$_
        $again=Get-Process -Id $record.pid -ErrorAction SilentlyContinue
        if ($null -ne $again) {
            try {
                if ($again.StartTime.ToUniversalTime().Ticks.ToString() -eq [string]$record.started) { throw $failure }
            } finally { $again.Dispose() }
        }
    } finally { $owned.Dispose() }
}
'{"owned_console_stop_attempted":true}'
