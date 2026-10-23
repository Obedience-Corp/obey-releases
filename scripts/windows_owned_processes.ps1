# Read only process identity capture/readback; never terminates a process.
$ErrorActionPreference = 'Stop'
if ($env:APP_PROOF_PROCESS_MODE -eq 'snapshot') {
    $rootId = [int]$env:APP_PROOF_PROCESS_PID
    $all = @(Get-CimInstance Win32_Process)
    $ownedIds = [System.Collections.Generic.HashSet[int]]::new()
    [void]$ownedIds.Add($rootId)
    do {
        $added = $false
        foreach ($item in $all) {
            if ($ownedIds.Contains([int]$item.ParentProcessId) -and $ownedIds.Add([int]$item.ProcessId)) {
                $added = $true
            }
        }
    } while ($added)
    $records = @()
    foreach ($ownedId in $ownedIds) {
        $process = Get-Process -Id $ownedId -ErrorAction SilentlyContinue
        if ($null -ne $process) {
            $records += @{pid=$ownedId; started=$process.StartTime.ToUniversalTime().Ticks.ToString()}
        }
    }
    ConvertTo-Json -InputObject @($records) -Compress
} elseif ($env:APP_PROOF_PROCESS_MODE -eq 'verify') {
    $records = @($env:APP_PROOF_PROCESS_IDENTITIES | ConvertFrom-Json)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $survivors = @()
        foreach ($record in $records) {
            $process = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
            if ($null -ne $process -and $process.StartTime.ToUniversalTime().Ticks.ToString() -eq $record.started) {
                $survivors += $record
            }
        }
        if ($survivors.Count -eq 0) {
            Write-Output '{"owned_processes_exited":true}'
            exit 0
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw ('Owned process cleanup incomplete: ' + (ConvertTo-Json -InputObject $survivors -Compress))
} else {
    throw 'Unknown owned process query mode'
}
