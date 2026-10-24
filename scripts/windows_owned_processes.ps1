# Read-only process identity capture/readback; never terminates a process.
$ErrorActionPreference = 'Stop'

function Get-CreationTicks($Item) {
    if ($null -eq $Item.CreationDate -or $Item.CreationDate -isnot [datetime]) {
        throw 'Process creation identity unavailable'
    }
    return $Item.CreationDate.ToUniversalTime().Ticks
}

function Select-BirthValidProcessTree([object[]]$Rows, [int]$RootId) {
    if ($RootId -le 0) { throw 'Invalid owned root PID' }
    $byId = @{}
    foreach ($item in $Rows) {
        $processId = [int]$item.ProcessId
        if ($byId.ContainsKey($processId)) { throw 'Ambiguous process snapshot PID' }
        $byId[$processId] = $item
    }
    if (-not $byId.ContainsKey($RootId)) { throw 'Owned root absent from process snapshot' }
    [void](Get-CreationTicks $byId[$RootId])
    $owned = @{$RootId = $byId[$RootId]}
    $ordered = [System.Collections.Generic.List[object]]::new()
    $ordered.Add($byId[$RootId])
    do {
        $added = $false
        foreach ($item in $Rows) {
            $processId = [int]$item.ProcessId
            $parentId = [int]$item.ParentProcessId
            if ($owned.ContainsKey($processId) -or -not $owned.ContainsKey($parentId)) { continue }
            if ($processId -le 0) { throw 'Invalid descendant PID' }
            # ParentProcessId can name a reused PID. Validate EVERY edge, not
            # merely that a descendant was born after the root.
            if ((Get-CreationTicks $item) -lt (Get-CreationTicks $owned[$parentId])) { continue }
            $owned[$processId] = $item
            $ordered.Add($item)
            $added = $true
        }
    } while ($added)
    return $ordered.ToArray()
}

function Get-OwnedProcessSnapshot([int]$RootId, [string]$ExpectedStarted) {
    if ($RootId -le 0 -or $ExpectedStarted -notmatch '^[0-9]+$' -or [long]$ExpectedStarted -le 0) {
        throw 'Owned snapshot requires the known root PID and birth'
    }
    $handles = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
    try {
        $root = Get-Process -Id $RootId -ErrorAction Stop
        $handles.Add($root)
        [void]$root.Handle
        if ($root.HasExited -or $root.StartTime.ToUniversalTime().Ticks.ToString() -ne $ExpectedStarted) {
            throw 'Owned root process identity changed'
        }
        $selected = @(Select-BirthValidProcessTree @(Get-CimInstance Win32_Process) $RootId)
        $records = @()
        $live = @{}
        foreach ($item in $selected) {
            $processId = [int]$item.ProcessId
            $parentId = [int]$item.ParentProcessId
            if ($processId -eq $RootId) { $current = $root }
            else {
                $current = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($null -eq $current) {
                    # A vanished leaf needs no cleanup; a live subtree cannot
                    # inherit ownership from an unvalidated parent generation.
                    if (@($selected | Where-Object { [int]$_.ParentProcessId -eq $processId }).Count -gt 0) {
                        throw 'Owned parent exited during process snapshot'
                    }
                    continue
                }
                $handles.Add($current)
                [void]$current.Handle
            }
            # Held handles prevent PID reuse while checking the fresh CIM
            # identity. Compare CIM with CIM (microsecond precision), while
            # retaining the exact GetProcessTimes-compatible birth for callers.
            $again = @(Get-CimInstance Win32_Process -Filter "ProcessId = $processId")
            if ($again.Count -ne 1 -or [int]$again[0].ParentProcessId -ne $parentId -or
                (Get-CreationTicks $again[0]) -ne (Get-CreationTicks $item)) {
                throw 'Process generation changed during owned snapshot'
            }
            $started = $current.StartTime.ToUniversalTime().Ticks
            if ($processId -ne $RootId) {
                if (-not $live.ContainsKey($parentId)) { throw 'Owned parent identity unavailable' }
                if ($started -lt [long]$live[$parentId].started) { throw 'Owned process birth edge changed' }
            }
            $record = @{pid=$processId; started=$started.ToString()}
            $live[$processId] = $record
            $records += $record
        }
        if ($root.HasExited) { throw 'Owned root exited during process snapshot' }
        return $records
    } finally {
        foreach ($handle in $handles) { $handle.Dispose() }
    }
}

# Native controls dot-source only the read-only selector; normal -File callers
# must supply one of the fixed modes below.
if ($MyInvocation.InvocationName -eq '.') { return }
if ($env:APP_PROOF_PROCESS_MODE -eq 'snapshot') {
    $records = @(Get-OwnedProcessSnapshot ([int]$env:APP_PROOF_PROCESS_PID) $env:APP_PROOF_PROCESS_STARTED)
    ConvertTo-Json -InputObject $records -Compress
} elseif ($env:APP_PROOF_PROCESS_MODE -eq 'verify') {
    [object[]]$records = ConvertFrom-Json -InputObject $env:APP_PROOF_PROCESS_IDENTITIES
    foreach ($record in $records) {
        if ((-not ($record.pid -is [int] -or $record.pid -is [long])) -or $record.pid -le 0 -or
            $record.pid -gt [int]::MaxValue -or [string]$record.started -notmatch '^[0-9]+$' -or [long]$record.started -le 0) {
            throw 'Invalid owned process identity readback'
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $survivors = @()
        foreach ($record in $records) {
            $current = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
            if ($null -eq $current) { continue }
            try {
                [void]$current.Handle
                if ($current.StartTime.ToUniversalTime().Ticks.ToString() -eq $record.started) { $survivors += $record }
            } finally { $current.Dispose() }
        }
        if ($survivors.Count -eq 0) { Write-Output '{"owned_processes_exited":true}'; exit 0 }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw ('Owned process cleanup incomplete: ' + (ConvertTo-Json -InputObject $survivors -Compress))
} else { throw 'Unknown owned process query mode' }
