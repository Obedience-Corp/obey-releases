"""Real owned process tree and deterministic historical-PPID collision controls."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

if os.name != 'nt' or os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted':
    raise RuntimeError('owned process controls require disposable hosted Windows')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import verify_app_candidate as app
from windows_console import process_birth
from verify_candidate import command

output = Path(os.environ['RUNNER_TEMP']) / 'owned-process-proof'
output.mkdir()
shell = shutil.which('pwsh')
legacy = Path(os.environ['SYSTEMROOT']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
observer = Path(__file__).resolve().parents[1] / 'scripts/windows_owned_processes.ps1'
stop = output / 'stop'
trigger = output / 'start-child'
root_ready, child_ready = output / 'root.json', output / 'children.json'
q = lambda p: "'" + str(p).replace("'", "''") + "'"
loop = f"while (-not (Test-Path -LiteralPath {q(stop)})) {{ Start-Sleep -Milliseconds 100 }}"
(output / 'leaf.ps1').write_text(loop)
(output / 'child.ps1').write_text(
    "$ErrorActionPreference='Stop'; $self=Get-Process -Id $PID; "
    f"$leaf=Start-Process -FilePath {q(shell)} -ArgumentList @('-NoProfile','-NonInteractive','-File','\"{output / 'leaf.ps1'}\"') -PassThru; "
    f"[IO.File]::WriteAllText({q(child_ready)},(@{{child=@{{pid=$PID;started=$self.StartTime.ToUniversalTime().Ticks.ToString()}};leaf=@{{pid=$leaf.Id;started=$leaf.StartTime.ToUniversalTime().Ticks.ToString()}}}} | ConvertTo-Json -Depth 5 -Compress)); " + loop)
(output / 'root.ps1').write_text(
    "$ErrorActionPreference='Stop'; "
    f"[IO.File]::WriteAllText({q(root_ready)},'ready'); "
    f"while (-not (Test-Path -LiteralPath {q(trigger)})) {{ Start-Sleep -Milliseconds 100 }}; "
    f"$child=Start-Process -FilePath {q(shell)} -ArgumentList @('-NoProfile','-NonInteractive','-File','\"{output / 'child.ps1'}\"') -PassThru; " + loop)
model = output / 'model.ps1'
model.write_text(r'''
$ErrorActionPreference='Stop'
. $env:OWNED_OBSERVER_SCRIPT
$known=ConvertFrom-Json -InputObject $env:OWNED_FIXTURE_IDENTITIES
$rows=@()
foreach($name in @('leaf','older','root','between','child')) {
  $item=Get-CimInstance Win32_Process -Filter ('ProcessId = '+$known.$name.pid)
  if($null -eq $item) {throw 'Native fixture process absent'}
  $parent=[int]$item.ParentProcessId
  if($name -eq 'older') {$parent=[int]$known.root.pid}
  if($name -eq 'between') {$parent=[int]$known.child.pid}
  $rows += [pscustomobject]@{ProcessId=[int]$item.ProcessId;ParentProcessId=$parent;CreationDate=$item.CreationDate}
}
$byId=@{};foreach($row in $rows){$byId[[int]$row.ProcessId]=$row}
if((Get-CreationTicks $byId[[int]$known.between.pid]) -le (Get-CreationTicks $byId[[int]$known.root.pid]) -or
   (Get-CreationTicks $byId[[int]$known.between.pid]) -ge (Get-CreationTicks $byId[[int]$known.child.pid])) {throw 'Missing actual root < foreign < child ordering'}
$selected=@(Select-BirthValidProcessTree $rows ([int]$known.root.pid))
$ids=@($selected | ForEach-Object {$_.ProcessId} | Sort-Object)
$expected=@($known.root.pid,$known.child.pid,$known.leaf.pid | Sort-Object)
if(($ids -join ',') -ne ($expected -join ',')){throw 'Historical parent PID collision was admitted'}
$bad=@($rows | ForEach-Object {if($_.ProcessId -eq $known.child.pid){[pscustomobject]@{ProcessId=$_.ProcessId;ParentProcessId=$_.ParentProcessId;CreationDate=$null}}else{$_}})
$refused=$false
try {[void](Select-BirthValidProcessTree $bad ([int]$known.root.pid))}catch{if($_.Exception.Message -notmatch 'creation identity unavailable'){throw};$refused=$true}
if(-not $refused){throw 'Unknown child birth was admitted'}
$duplicateRefused=$false
try {[void](Select-BirthValidProcessTree @($rows+$byId[[int]$known.root.pid]) ([int]$known.root.pid))}catch{if($_.Exception.Message -notmatch 'Ambiguous process snapshot PID'){throw};$duplicateRefused=$true}
if(-not $duplicateRefused){throw 'Duplicate PID admitted'}
@{selected=$ids;historical_root_collision_refused=$true;historical_child_collision_refused=$true;unknown_birth_refused=$refused;duplicate_pid_refused=$duplicateRefused} | ConvertTo-Json -Depth 5 -Compress
''')


def wait_file(path):
    deadline = time.monotonic() + 15
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise RuntimeError('owned process fixture readiness timed out: ' + path.name)
        time.sleep(.1)


def churn_controls(runtime, foreign, scenario):
    """Replay actual prior CIM rows after normal child exits, never App state."""
    directory = output / ('churn-' + scenario + '-' + Path(runtime).stem)
    directory.mkdir()
    root_stop, parent_stop, leaf_stop = [directory / name for name in ('root-stop', 'parent-stop', 'leaf-stop')]
    churn_stops.append(root_stop)
    ready = directory / 'children.json'
    (directory/'leaf.ps1').write_text(
        f"while (-not (Test-Path -LiteralPath {q(leaf_stop)}) -and -not (Test-Path -LiteralPath {q(root_stop)})) {{ Start-Sleep -Milliseconds 50 }}")
    (directory/'parent.ps1').write_text(
        "$ErrorActionPreference='Stop'; $self=Get-Process -Id $PID; "
        f"$leaf=Start-Process -FilePath {q(shell)} -ArgumentList @('-NoProfile','-NonInteractive','-File','\"{directory / 'leaf.ps1'}\"') -PassThru; "
        f"[IO.File]::WriteAllText({q(ready)},(@{{parent=@{{pid=$PID;started=$self.StartTime.ToUniversalTime().Ticks.ToString()}};leaf=@{{pid=$leaf.Id;started=$leaf.StartTime.ToUniversalTime().Ticks.ToString()}}}} | ConvertTo-Json -Depth 5 -Compress)); "
        f"while (-not (Test-Path -LiteralPath {q(parent_stop)}) -and -not (Test-Path -LiteralPath {q(root_stop)})) {{ Start-Sleep -Milliseconds 50 }}")
    (directory/'root.ps1').write_text(
        "$ErrorActionPreference='Stop'; "
        f"$child=Start-Process -FilePath {q(shell)} -ArgumentList @('-NoProfile','-NonInteractive','-File','\"{directory / 'parent.ps1'}\"') -PassThru; "
        f"while (-not (Test-Path -LiteralPath {q(root_stop)})) {{ Start-Sleep -Milliseconds 50 }}")
    owned = subprocess.Popen([shell, '-NoProfile', '-NonInteractive', '-File', str(directory/'root.ps1')])
    processes.append(owned)
    try:
        wait_file(ready)
        identities = json.loads(ready.read_text(encoding='utf-8-sig'))
        identities['root'] = {'pid': owned.pid, 'started': process_birth(owned)}
        identities['foreign'] = {'pid': foreign.pid, 'started': process_birth(foreign)}
        capture = directory/'capture.ps1'
        capture.write_text(r'''
$ErrorActionPreference='Stop'
. $env:OWNED_OBSERVER_SCRIPT
$known=ConvertFrom-Json -InputObject $env:OWNED_FIXTURE_IDENTITIES
$selected=@(Select-BirthValidProcessTree @(Get-CimInstance Win32_Process) ([int]$known.root.pid))
$ids=@($selected | ForEach-Object {[int]$_.ProcessId})
foreach($name in @('root','parent','leaf')) {if([int]$known.$name.pid -notin $ids){throw 'Actual churn tree incomplete'}}
@{rows=@($selected | ForEach-Object {@{pid=[int]$_.ProcessId;parent_pid=[int]$_.ParentProcessId;cim_created_ticks=(Get-CreationTicks $_).ToString()}}); tracked=@(Get-OwnedProcessSnapshot ([int]$known.root.pid) $known.root.started)} | ConvertTo-Json -Depth 5 -Compress
''')
        env = dict(os.environ, OWNED_OBSERVER_SCRIPT=str(observer), OWNED_FIXTURE_IDENTITIES=json.dumps(identities))
        # Every row comes from the actual live tree, before any child exit.
        captured = command([runtime, '-NoProfile', '-NonInteractive', '-File', capture], env, json_output=True)
        rows = captured['rows']
        tracked = captured['tracked']
        snapshot = directory/'prior-cim.json'
        snapshot.write_text(json.dumps(rows))
        parent_stop.write_text('normal exit')
        if scenario == 'gone': leaf_stop.write_text('normal exit')
        control = directory/'control.ps1'
        control.write_text(r'''
$ErrorActionPreference='Stop'
. $env:OWNED_OBSERVER_SCRIPT
$known=ConvertFrom-Json -InputObject $env:OWNED_FIXTURE_IDENTITIES
$decoded=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($env:OWNED_PRIOR_CIM))
$rows=@(foreach($row in $decoded) {
    [pscustomobject]@{ProcessId=[int]$row.pid;ParentProcessId=[int]$row.parent_pid;
        CreationDate=[datetime]::new([long]$row.cim_created_ticks,[DateTimeKind]::Utc)}})
$deadline=[DateTime]::UtcNow.AddSeconds(15)
do {
    $parent=Get-ProcessOrObservedAbsent ([int]$known.parent.pid)
    if($null -ne $parent){$parent.Dispose();Start-Sleep -Milliseconds 50;continue}
    try {$gone=@(Confirm-ObservedAbsentSubtree $rows ([int]$known.parent.pid) ([int]$known.root.pid));break}
    catch {
        if($_.Exception.Message -notmatch '^Owned subtree has a live or unverified descendant:'){throw}
        if($env:OWNED_CHURN_SCENARIO -eq 'orphan'){break}
        Start-Sleep -Milliseconds 50
    }
} while([DateTime]::UtcNow -lt $deadline)
if($null -ne (Get-ProcessOrObservedAbsent ([int]$known.parent.pid))){throw 'Churn parent failed to exit normally'}
# Model enumeration timing only: prior rows are genuine captured CIM data.
# Per-process revalidation still queries the actual current OS identities.
function Get-CimInstance {
    param([string]$ClassName,[string]$Filter)
    if($ClassName -eq 'Win32_Process' -and -not $Filter){return $script:rows}
    return CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $Filter
}
$result=@{scenario=$env:OWNED_CHURN_SCENARIO;known=$known;prior_rows=$rows.Count}
if($env:OWNED_CHURN_SCENARIO -eq 'gone'){
    $gone=@(Confirm-ObservedAbsentSubtree $rows ([int]$known.parent.pid) ([int]$known.root.pid))
    $retired=@($gone | ForEach-Object {[int]$_.pid})
    if([int]$known.parent.pid -notin $retired -or [int]$known.leaf.pid -notin $retired -or [int]$known.root.pid -in $retired){throw 'Wrong absent subtree'}
    $actual=@(Get-OwnedProcessSnapshot ([int]$known.root.pid) $known.root.started)
    if([int]$known.root.pid -notin @($actual | ForEach-Object {[int]$_.pid})){throw 'Live root omitted'}
    if(@($actual | Where-Object {[int]$_.pid -in $retired}).Count -ne 0){throw 'Absent identity remained owned'}
    $result.absent_subtree=$gone;$result.actual_snapshot=$actual
    # A historical root ParentProcessId must never retire the held root.
    $historical=@($rows | ForEach-Object {
        if([int]$_.ProcessId -eq [int]$known.root.pid){[pscustomobject]@{ProcessId=$_.ProcessId;ParentProcessId=[int]$known.parent.pid;CreationDate=$_.CreationDate}}
        else {$_}})
    if(@(Confirm-ObservedAbsentSubtree $historical ([int]$known.parent.pid) ([int]$known.root.pid) | Where-Object {[int]$_.pid -eq [int]$known.root.pid}).Count -ne 0){throw 'Historical root edge admitted'}
    $result.root_historical_edge_refused=$true
    # Model a departed leaf's numeric PID reused by an actual unrelated live
    # generation. Never claim an actual OS PID allocation was forced.
    $oldLeaf=@($rows | Where-Object {[int]$_.ProcessId -eq [int]$known.leaf.pid})[0]
    $reused=@($rows | Where-Object {[int]$_.ProcessId -in @([int]$known.root.pid,[int]$known.parent.pid)})
    $reused += [pscustomobject]@{ProcessId=[int]$known.foreign.pid;ParentProcessId=[int]$known.parent.pid;CreationDate=$oldLeaf.CreationDate}
    $refused=$false
    try {[void](Confirm-ObservedAbsentSubtree $reused ([int]$known.parent.pid) ([int]$known.root.pid))}
    catch {if($_.Exception.Message -notmatch '^Owned subtree has a live or unverified descendant:'){throw};$refused=$true}
    if(-not $refused){throw 'Reused PID allowed branch retirement'}
    $result.modeled_reused_pid_refused=$true
    function Get-Process {param([int]$Id,[string]$ErrorAction);throw [UnauthorizedAccessException]::new('Injected process query denied')}
    $denied=$false
    try {[void](Confirm-ObservedAbsentSubtree $rows ([int]$known.parent.pid) ([int]$known.root.pid))}
    catch {if($_.Exception.Message -notmatch 'Injected process query denied'){throw};$denied=$true}
    finally {Remove-Item Function:Get-Process}
    if(-not $denied){throw 'Unverified query allowed branch retirement'}
    $result.query_failure_refused=$true
} else {
    $refused=$false
    try {[void](Get-OwnedProcessSnapshot ([int]$known.root.pid) $known.root.started)}
    catch {if($_.Exception.Message -notmatch '^Owned subtree has a live or unverified descendant:'){throw};$refused=$true}
    if(-not $refused){throw 'Live orphan allowed branch retirement'}
    $leaf=Get-Process -Id ([int]$known.leaf.pid) -ErrorAction Stop
    try {if($leaf.StartTime.ToUniversalTime().Ticks.ToString() -ne $known.leaf.started){throw 'Orphan identity changed'}}finally{$leaf.Dispose()}
    $result.actual_live_orphan_refused=$true
}
foreach($name in @('root','foreign')){
    $current=Get-Process -Id ([int]$known.$name.pid) -ErrorAction Stop
    try {if($current.StartTime.ToUniversalTime().Ticks.ToString() -ne $known.$name.started){throw 'Unrelated or root identity changed'}}finally{$current.Dispose()}
}
$result | ConvertTo-Json -Depth 8 -Compress
''')
        checked = subprocess.run([runtime, '-NoProfile', '-NonInteractive', '-File', str(control)],
            env=dict(env, OWNED_PRIOR_CIM=str(snapshot), OWNED_CHURN_SCENARIO=scenario),
            capture_output=True, text=True, timeout=40)
        (directory/'stdout.log').write_text(checked.stdout)
        (directory/'stderr.log').write_text(checked.stderr)
        assert checked.returncode == 0, checked.stderr
        result = json.loads(checked.stdout)
        if scenario == 'gone':
            diagnostics = [json.loads(line) for line in checked.stderr.splitlines() if line.strip()]
            assert any(x.get('event') == 'observed_absent_owned_subtree' and
                       {identities['parent']['pid'], identities['leaf']['pid']} <= {r['pid'] for r in x['identities']}
                       for x in diagnostics), diagnostics
        assert owned.poll() is None and process_birth(owned) == identities['root']['started']
        assert foreign.poll() is None and process_birth(foreign) == identities['foreign']['started']
        (directory/'proof.json').write_text(json.dumps(result, indent=2)+'\n')
        return result
    finally:
        root_stop.write_text('normal fixture shutdown')
        owned.wait(timeout=10)
        if 'tracked' in locals():
            exited = command([runtime, '-NoProfile', '-NonInteractive', '-File', observer],
                dict(os.environ, APP_PROOF_PROCESS_MODE='verify', APP_PROOF_PROCESS_IDENTITIES=json.dumps(tracked)), json_output=True)
            assert exited['owned_processes_exited'] is True
            if 'result' in locals():
                result['fixture_cleanup_verified'] = True
                (directory/'proof.json').write_text(json.dumps(result, indent=2)+'\n')


processes = []
churn_stops = []
proof = {'modeled_parent_pid_collisions': True, 'original_natural_failure_run': '40082723078',
         'snapshot_churn_failure_run': '40097043291'}
try:
    older = subprocess.Popen([shell, '-NoProfile', '-NonInteractive', '-Command', loop])
    processes.append(older)
    root = subprocess.Popen([shell, '-NoProfile', '-NonInteractive', '-File', str(output / 'root.ps1')])
    processes.append(root)
    wait_file(root_ready)
    between = subprocess.Popen([shell, '-NoProfile', '-NonInteractive', '-Command', loop])
    processes.append(between)
    trigger.write_text('start')
    wait_file(child_ready)
    known = json.loads(child_ready.read_text(encoding='utf-8-sig'))
    known.update({name: {'pid': proc.pid, 'started': process_birth(proc)} for name, proc in [('older', older), ('root', root), ('between', between)]})
    proof['fixture_identities'] = known
    records = None
    for runtime in [shell, str(legacy)]:
        env = dict(os.environ, APP_PROOF_PROCESS_MODE='snapshot', APP_PROOF_PROCESS_PID=str(root.pid), APP_PROOF_PROCESS_STARTED=known['root']['started'])
        rows = command([runtime, '-NoProfile', '-NonInteractive', '-File', observer], env, json_output=True)
        assert {known[n]['pid'] for n in ['root','child','leaf']} <= {row['pid'] for row in rows}, rows
        assert not {older.pid, between.pid} & {row['pid'] for row in rows}, rows
        records = rows
        proof[Path(runtime).name + '-snapshot'] = rows
        proof[Path(runtime).name + '-model'] = command([runtime, '-NoProfile', '-NonInteractive', '-File', model], dict(os.environ, OWNED_OBSERVER_SCRIPT=str(observer), OWNED_FIXTURE_IDENTITIES=json.dumps(known)), json_output=True)
        stale = subprocess.run([runtime, '-NoProfile', '-NonInteractive', '-File', str(observer)], env=dict(env, APP_PROOF_PROCESS_STARTED=str(int(known['root']['started'])+1)), capture_output=True, text=True, timeout=20)
        assert stale.returncode != 0 and 'Owned root process identity changed' in stale.stderr, stale.stderr
        assert root.poll() is None and process_birth(root) == known['root']['started']
    # Strictly require the intended live-survivor refusal, not any command error.
    live = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-File', str(observer)], env=dict(os.environ, APP_PROOF_PROCESS_MODE='verify', APP_PROOF_PROCESS_IDENTITIES=json.dumps(records)), capture_output=True, text=True, timeout=30)
    assert live.returncode != 0 and 'Owned process cleanup incomplete' in live.stderr, live.stderr
    proof['live_survivor_refused'] = True
    app.stop_owned(root, dict(os.environ))
    for runtime in [shell, str(legacy)]:
        result = command([runtime, '-NoProfile', '-NonInteractive', '-File', observer], dict(os.environ, APP_PROOF_PROCESS_MODE='verify', APP_PROOF_PROCESS_IDENTITIES=json.dumps(records)), json_output=True)
        assert result['owned_processes_exited'] is True
    assert older.poll() is None and between.poll() is None
    assert process_birth(older) == known['older']['started'] and process_birth(between) == known['between']['started']
    proof['churn_controls'] = {}
    for runtime in [shell, str(legacy)]:
        for scenario in ['gone', 'orphan']:
            proof['churn_controls'][Path(runtime).stem + '-' + scenario] = churn_controls(runtime, between, scenario)
    proof.update(owned_tree_exit_verified=True, unrelated_generations_survive=True)
    print('PASS: birth-valid actual tree cleanup; both historical PPID collisions, unknown birth, duplicate PID and stale root refused; unrelated processes survive')
except BaseException as error:
    proof['failure'] = str(error)
    raise
finally:
    for marker in churn_stops: marker.write_text('stop')
    stop.write_text('stop')
    for proc in processes:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.terminate(); proc.wait(timeout=5)
    (output/'proof.json').write_text(json.dumps(proof,indent=2)+'\n')
