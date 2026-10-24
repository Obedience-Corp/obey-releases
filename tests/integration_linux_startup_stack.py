"""Real debugger attach/detach and timeout in an isolated PID namespace."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('native debugger fixture requires Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_startup_stack as stack


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    heartbeat = root/'heartbeat'
    source = "from pathlib import Path; import sys,time\np=Path(sys.argv[1]); n=0\nwhile True:\n n+=1; p.write_text(str(n)); time.sleep(.05)\n"
    process = subprocess.Popen([sys.executable, '-c', source, str(heartbeat)])
    try:
        deadline = time.monotonic()+5
        while not heartbeat.exists() and time.monotonic()<deadline:
            time.sleep(.05)
        assert heartbeat.exists(), 'fixture did not start'
        birth = stack.identity(process.pid)['start_ticks']
        result = stack.capture(process, birth, root/'normal.log', os.environ, elevated=False)
        assert result.get('exit') == 0, (result, (root/'normal.log').read_text())
        assert result['after_identity_verified'] and result['after_tracer_pid'] == 0, result
        assert result['after_state'] not in ('T', 't'), result
        assert 'Thread 1' in (root/'normal.log').read_text()
        print('Actual GDB stack and detach PASS', flush=True)

        run = subprocess.run
        def force_timeout(arguments, **kwargs):
            # Exercise the same timeout wrapper after an actual stack has been
            # collected. Only this fixture injects a blocking debugger command.
            arguments = list(arguments)
            arguments[arguments.index('12s')] = '1s'
            arguments[-2:-2] = ['-ex', 'python import time; time.sleep(30)']
            return run(arguments, **kwargs)
        with patch.object(stack.subprocess, 'run', side_effect=force_timeout):
            result = stack.capture(process, birth, root/'timeout.log', os.environ, elevated=False)
        assert result.get('exit') in (124, 137), result
        assert 'Thread 1' in (root/'timeout.log').read_text(), 'debugger did not attach before timeout'
        assert result['after_identity_verified'] and result['after_tracer_pid'] == 0, result
        assert result['after_state'] not in ('T', 't'), result
        before = heartbeat.read_text()
        time.sleep(.25)
        assert heartbeat.read_text() != before, 'fixture did not resume after debugger timeout'
        print('Actual debugger timeout, detach, and resumed heartbeat PASS', flush=True)
    finally:
        process.terminate()
        process.wait(timeout=5)
