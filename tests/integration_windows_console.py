"""Actual ordinary console startup/owned timeout proof on disposable Windows."""
import json
import os
from pathlib import Path
import shutil
import sys

if os.name != 'nt' or os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted':
    raise RuntimeError('console integration requires disposable hosted Windows')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from windows_console import run_prompt

output=Path(os.environ['RUNNER_TEMP'])/'ordinary-console-proof'
output.mkdir()
shell=shutil.which('pwsh')
if not shell:raise RuntimeError('installed PowerShell7 missing')
document=run_prompt(shell,'@{answer=(6*7)}',dict(os.environ),output,'positive')
assert document['data']['answer']==42
assert document['guard']['input_redirected'] is False
assert not document['guard']['probe_marker']
transport=json.loads((output/'positive.transport.json').read_text())
assert transport['backend_name']=='pywinpty-3.1.0-ConPTY' and transport['dimensions']==[120,40]
assert transport['adapter_returncode']==0 and transport['shell_exit']['shell_returncode']==0
assert transport['shell_exit']['shell_pid']==document['console_process']['pid']
assert transport['owned_console_exit_verified'] is True
assert (output/'positive.terminal.log').stat().st_size>0
eof_records=[json.loads(line) for line in (output/transport['eof_diagnostics_file']).read_text().splitlines()]
assert eof_records and eof_records[-1]['alive'] is False and eof_records[-1]['iseof'] is True
assert eof_records[-1]['status']==0,eof_records
print('PASS: actual owned console starts ordinary PowerShell with unredirected input and no startup/readiness override')
try:
    body="[IO.File]::WriteAllText('"+str(output/'timeout.body-started').replace("'","''")+"','sleep begun'); Start-Sleep -Seconds 30; @{unexpected=$true}"
    run_prompt(shell,body,dict(os.environ),output,'timeout',timeout=5)
except RuntimeError:
    transport=json.loads((output/'timeout.transport.json').read_text())
    assert transport.get('ordinary_startup_verified') is True,transport
    assert transport.get('failure')=='owned interactive console exceeded execution/output bounds',transport
    assert (output/'timeout.body-started').read_text()=='sleep begun'
    assert (output/'timeout.started.json').is_file() and not (output/'timeout.console.json').exists()
    assert transport.get('tracked_console_cleanup_verified') is True,transport
    assert 'cleanup_failure' not in transport,transport
    print('PASS: timed-out real console retains diagnostics and all recorded owned process identities exit')
else:raise AssertionError('owned console timeout did not fail')

# Deliberately end only this console's authenticated adapter while its owned
# PowerShell body is still alive; cleanup must not depend on adapter.poll().
identity_path=output/'early-exit.adapter.json'
body=("$identity=Get-Content -Raw -LiteralPath '"+str(identity_path).replace("'","''")+"' | ConvertFrom-Json; "
      "$adapter=Get-Process -Id $identity.pid -ErrorAction Stop; [void]$adapter.Handle; "
      "if ($adapter.StartTime.ToUniversalTime().Ticks.ToString() -ne $identity.started) { throw 'adapter identity changed' }; "
      "[IO.File]::WriteAllText('"+str(output/'early-exit.body-started').replace("'","''")+"','adapter kill begins'); "
      "$adapter.Kill(); Start-Sleep -Seconds 30; @{unexpected=$true}")
try:
    run_prompt(shell,body,dict(os.environ),output,'early-exit',timeout=5)
except RuntimeError:
    transport=json.loads((output/'early-exit.transport.json').read_text())
    assert transport.get('ordinary_startup_verified') is True,transport
    assert transport.get('failure') in ('ordinary console exited before its structured readback','console adapter exited before an authenticated tree snapshot'),transport
    assert (output/'early-exit.body-started').read_text()=='adapter kill begins'
    assert (output/'early-exit.started.json').is_file() and not (output/'early-exit.console.json').exists()
    assert transport.get('ownership_snapshot_complete') is True,transport
    assert transport.get('tracked_console_cleanup_verified') is True,transport
    assert 'cleanup_failure' not in transport,transport
    print('PASS: early adapter exit still stops/verifies tracked owned console descendants')
else:raise AssertionError('deliberate adapter exit did not fail')
