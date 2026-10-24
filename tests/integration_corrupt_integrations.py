"""Actual Windows preference rollback control; never product auto-repair."""
import json
import os
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from corrupt_integrations import Fixture
if (os.name != 'nt' or os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
        os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted'):
    raise RuntimeError('requires disposable native Windows control')
output = Path(os.environ['RUNNER_TEMP'])/'corrupt-integration-control'; output.mkdir()
report = {'restoration_verified': False, 'product_recovery_verified': False}
try:
    with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as directory:
        root = Path(directory); managed = root/'managed'; managed.mkdir()
        (managed/'integrations.json').write_text('{"disabled":false,"files":["native fixture only"],"helpers":[]}\n')
        fixture = Fixture(managed, root/'private', report)
        try:
            fixture.corrupt()
            try: json.loads(fixture.path.read_bytes())
            except json.JSONDecodeError as error: report['actual_json_error'] = str(error)
            else: raise RuntimeError('actual corrupted preferences unexpectedly succeeded')
            fixture.unchanged_corruption()
        finally: fixture.restore()
        assert json.loads(fixture.path.read_bytes())['files'] == ['native fixture only']
        report['restoration_verified'] = True
finally: (output/'proof.json').write_text(json.dumps(report, indent=2)+'\n')
print('Actual Windows corrupt integration preferences and descriptor-bound exact restoration PASS')
