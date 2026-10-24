"""Wait for the verifier's Openbox desktop before launching a candidate."""
import re
import subprocess
import time

from linux_git_retry import birth


def wait_for_openbox(manager, environment, seconds=15):
    if manager.poll() is not None:
        raise RuntimeError('owned Openbox exited before readiness')
    expected_birth = birth(manager.pid)
    environment = dict(environment, LC_ALL='C')
    deadline = time.monotonic() + seconds
    probes = {}

    def require_alive():
        if manager.poll() is not None or birth(manager.pid) != expected_birth:
            raise RuntimeError('owned Openbox exited or changed identity before readiness')

    def query(name, arguments):
        require_alive()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ''
        result = subprocess.run(arguments, env=environment, capture_output=True,
                                text=True, timeout=min(3, remaining))
        probes[name] = {'exit': result.returncode, 'stdout': result.stdout[:8192],
                        'stderr': result.stderr[:8192]}
        return result.stdout if result.returncode == 0 else ''

    while time.monotonic() < deadline:
        require_alive()
        try:
            root = query('root_check', ['xprop', '-root', '_NET_SUPPORTING_WM_CHECK'])
            match = re.fullmatch(r'_NET_SUPPORTING_WM_CHECK\(WINDOW\): window id # (0x[0-9a-fA-F]+)\s*', root)
            if match and int(match[1], 16):
                window = match[1]
                own = query('self_check', ['xprop', '-id', window, '_NET_SUPPORTING_WM_CHECK', '_NET_WM_NAME'])
                lines = own.splitlines()
                same = f'_NET_SUPPORTING_WM_CHECK(WINDOW): window id # {window}' in lines
                named = '_NET_WM_NAME(UTF8_STRING) = "Openbox"' in lines
                events = query('root_events', ['xwininfo', '-root', '-events'])
                redirect = 'SubstructureRedirect' in [line.strip() for line in events.splitlines()]
                if same and named and redirect:
                    require_alive()
                    # The owned X server starts empty; this live child was the
                    # only manager launched. Openbox does not publish WM_PID.
                    return {'launched_pid': manager.pid, 'start_ticks': expected_birth,
                            'check_window': window, 'ewmh_self_reference': True,
                            'root_redirect_selected': True, 'probes': probes,
                            'ready_monotonic_ns': time.monotonic_ns()}
        except subprocess.TimeoutExpired:
            pass
        time.sleep(min(.05, max(0, deadline - time.monotonic())))
    raise RuntimeError('timed out waiting for owned Openbox desktop: ' + repr(probes))
