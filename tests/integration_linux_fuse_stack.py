"""A real user-owned FUSE executable, matching AppImage's access boundary."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('FUSE fixture requires an isolated Docker PID/mount namespace')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_startup_stack as stack

drop = ['/usr/bin/setpriv', '--reuid=10001', '--regid=10001', '--clear-groups']
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); root.chmod(0o755)
    source = root/'source'; source.mkdir()
    shutil.copyfile('/usr/bin/sleep', source/'owned-sleeper'); (source/'owned-sleeper').chmod(0o755)
    image = root/'fixture.squashfs'
    subprocess.run(['mksquashfs', str(source), str(image), '-noappend', '-no-progress', '-quiet'], check=True)
    mount = root/'mount'; mount.mkdir(); os.chown(mount, 10001, 10001)
    process = None
    with (root/'mount.log').open('w') as log:
        daemon = subprocess.Popen([*drop, 'squashfuse', '-f', str(image), str(mount)], stdout=log, stderr=subprocess.STDOUT)
        try:
            executable = mount/'owned-sleeper'
            deadline = time.monotonic()+10
            while subprocess.run([*drop, 'test', '-r', str(executable)]).returncode != 0:
                if daemon.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('owned FUSE mount failed: '+(root/'mount.log').read_text())
                time.sleep(.05)
            try:
                executable.read_bytes()
            except PermissionError:
                print('Actual FUSE: mounting UID can read executable; root cannot PASS', flush=True)
            else:
                raise AssertionError('fixture did not reproduce the root FUSE access boundary')
            process = subprocess.Popen([*drop, str(executable), '60'])
            time.sleep(.1)
            birth = stack.identity(process.pid)['start_ticks']
            result = stack.capture(process, birth, root/'stack.log', os.environ, elevated=False)
            trace = (root/'stack.log').read_text()
            assert result.get('exit') == 0 and result['debugger_identity_verified'], (result, trace)
            assert result['requested_debugger_identity'] == {'Uid':10001, 'Gid':10001}, result
            assert result['after_identity_verified'] and result['after_tracer_pid'] == 0, result
            assert result['after_state'] not in ('T','t'), result
            assert 'clock_nanosleep' in trace and 'no executable was specified' not in trace, trace
            print('Actual same-UID FUSE executable stack has symbols; only SYS_PTRACE; detached PASS', flush=True)
        finally:
            if process is not None and process.poll() is None:
                process.terminate(); process.wait(timeout=5)
            if daemon.poll() is None:
                subprocess.run([*drop, 'fusermount3', '-u', str(mount)], check=True, timeout=5)
                daemon.wait(timeout=5)
