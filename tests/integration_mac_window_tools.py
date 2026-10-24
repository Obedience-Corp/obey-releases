"""Real compiled CoreGraphics/query/normal-quit controls on fresh native Macs."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

if sys.platform != 'darwin' or os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted':
    raise RuntimeError('native Mac controls require a disposable hosted account')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import mac_window_tools
from verify_candidate import command, wait_until

output = Path(os.environ['RUNNER_TEMP']) / 'mac-window-tools-proof'
output.mkdir()
report = {'native_mac_window_controls_verified': False}
process = None
try:
    with tempfile.TemporaryDirectory(prefix='mac-window-controls-', dir=os.environ['RUNNER_TEMP']) as directory:
        work = Path(directory)
        tools = mac_window_tools.prepare(work, output, dict(os.environ))
        bundle = work / 'Owned Query Fixture.app'
        binaries = bundle / 'Contents/MacOS'
        binaries.mkdir(parents=True)
        import plistlib
        (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': 'dev.fa0027.window-query-fixture', 'CFBundleExecutable': 'mac-fixture',
            'CFBundleName': 'FA0027 owned query control', 'CFBundlePackageType': 'APPL'}))
        fixture = binaries / 'mac-fixture'
        source = Path(__file__).parent / 'fixtures/mac_window_fixture.swift'
        command([tools.identity['compiler'], '-module-cache-path', tools.query_binary.parent / 'module-cache', source, '-o', fixture], os.environ, timeout=180)
        report['fixture_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        report['fixture_binary_sha256'] = hashlib.sha256(fixture.read_bytes()).hexdigest()
        ready = work / 'ready.json'
        with (output / 'fixture.log').open('w') as log:
            process = subprocess.Popen([str(fixture), str(ready)], stdout=log, stderr=subprocess.STDOUT)
            def owned_ready():
                if process.poll() is not None: raise RuntimeError('owned Mac fixture exited before its window')
                return json.loads(ready.read_text()) if ready.is_file() else None
            identity = wait_until('owned Mac control window', owned_ready)
            if identity['pid'] != process.pid: raise ValueError('native fixture PID mismatch')
            def own_window():
                return next((row for row in tools.query(process.pid, os.environ)
                             if row.get('kCGWindowNumber') == identity['window_id']
                             and row.get('kCGWindowBounds', {}).get('Width', 0) >= 640), None)
            report['owned_window'] = wait_until('compiled owned window query', own_window)
            if tools.query(os.getpid(), os.environ): raise ValueError('foreign verifier PID unexpectedly had a window')
            report['foreign_pid_window_list_empty'] = True
            try:
                tools.quit(process.pid, work / 'Foreign.app', os.environ)
            except RuntimeError:
                if process.poll() is not None: raise RuntimeError('wrong-bundle refusal terminated the fixture')
            else: raise RuntimeError('wrong bundle was not refused')
            report['wrong_bundle_refused_without_termination'] = True
            screenshot = output / 'owned-window.png'
            command(['screencapture', '-x', '-l', str(identity['window_id']), screenshot], os.environ)
            if not screenshot.is_file() or screenshot.stat().st_size == 0:
                raise RuntimeError('owned native window screenshot is missing')
            report['screenshot_sha256'] = hashlib.sha256(screenshot.read_bytes()).hexdigest()
            tools.quit(process.pid, bundle, os.environ)
            report['fixture_exit_status'] = process.wait(timeout=30)
            if report['fixture_exit_status'] != 0 or tools.query(process.pid, os.environ):
                raise RuntimeError('owned fixture normal quit/window disappearance failed')
            process = None
            report['native_mac_window_controls_verified'] = True
except BaseException as error:
    report['failure'] = str(error)
    report['native_mac_window_controls_verified'] = False
    raise
finally:
    if process is not None and process.poll() is None:
        try: process.terminate(); process.wait(timeout=15)
        except Exception as error:
            report['cleanup_failure'] = str(error)
            report['native_mac_window_controls_verified'] = False
    (output / 'proof.json').write_text(json.dumps(report, indent=2) + '\n')
