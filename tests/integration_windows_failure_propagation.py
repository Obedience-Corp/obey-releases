"""Actual nonzero-before-success proof for the workflow's checked Python wrapper."""
import json
import os
from pathlib import Path
import shutil
import subprocess

if (os.name != 'nt' or os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
        os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted'):
    raise RuntimeError('native failure controls require disposable hosted Windows')

output = Path(os.environ['RUNNER_TEMP']) / 'windows-native-failure-proof'
output.mkdir()
wrapper = Path(__file__).resolve().parents[1] / 'scripts/windows_checked_python.ps1'
legacy = Path(os.environ['SYSTEMROOT']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
first = output/'first.py'
second = output/'second.py'
first.write_text("import sys\nfrom pathlib import Path\nPath(sys.argv[1]).write_text('native-started')\nraise SystemExit(int(sys.argv[2]))\n")
second.write_text("import sys\nfrom pathlib import Path\nPath(sys.argv[1]).write_text('later-success')\n")
proof = {}
try:
    for runtime in [shutil.which('pwsh'), str(legacy)]:
        for fail in [False, True]:
            label = Path(runtime).stem + ('-failure' if fail else '-success')
            before, after = output/(label+'-before'), output/(label+'-after')
            assert not before.exists() and not after.exists()
            script = output/(label+'.ps1')
            exit_code = 23 if fail else 0
            script.write_text(
                "$ErrorActionPreference='Stop'\n. $env:CHECKED_PYTHON_WRAPPER\n"
                "Invoke-CheckedPython $env:CHECKED_FIRST $env:CHECKED_BEFORE " + str(exit_code) + "\n"
                "Invoke-CheckedPython $env:CHECKED_SECOND $env:CHECKED_AFTER\n")
            result = subprocess.run([runtime, '-NoProfile', '-NonInteractive', '-File', str(script)],
                env=dict(os.environ, CHECKED_PYTHON_WRAPPER=str(wrapper), CHECKED_BEFORE=str(before), CHECKED_AFTER=str(after),
                         CHECKED_FIRST=str(first), CHECKED_SECOND=str(second)),
                text=True, capture_output=True, timeout=30)
            (output/(label+'.stdout.log')).write_text(result.stdout)
            (output/(label+'.stderr.log')).write_text(result.stderr)
            assert before.read_text() == 'native-started', 'Control never reached the first native Python command'
            if fail:
                assert result.returncode != 0 and not after.exists(), 'Native failure was masked by the later success command'
            else:
                assert result.returncode == 0 and after.read_text() == 'later-success', 'Successful native commands did not complete'
            proof[label] = {'native_exit_requested': exit_code, 'shell_exit': result.returncode,
                            'native_started': True, 'later_success_executed': after.exists()}
    print('PASS: exact checked-native wrapper propagates actual nonzero before later success in PS7 and Windows PowerShell5.1')
except BaseException as error:
    proof['failure'] = str(error)
    raise
finally:
    (output/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
