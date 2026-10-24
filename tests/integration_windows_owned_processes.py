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


processes = []
proof = {'modeled_parent_pid_collisions': True, 'original_natural_failure_run': '40082723078'}
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
    proof.update(owned_tree_exit_verified=True, unrelated_generations_survive=True)
    print('PASS: birth-valid actual tree cleanup; both historical PPID collisions, unknown birth, duplicate PID and stale root refused; unrelated processes survive')
except BaseException as error:
    proof['failure'] = str(error)
    raise
finally:
    stop.write_text('stop')
    for proc in processes:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.terminate(); proc.wait(timeout=5)
    (output/'proof.json').write_text(json.dumps(proof,indent=2)+'\n')
