"""Real X11 lifecycle, nonexclusive subscription, and observer failure controls."""
import ctypes as C
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('window lifecycle fixture requires Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_window_events as events

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    environment = dict(os.environ, DISPLAY=':98')
    server = subprocess.Popen(['Xvfb', ':98', '-screen', '0', '640x480x24'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    recorder = display = None
    library = events.xlib()
    try:
        deadline = time.monotonic() + 5
        while not display and time.monotonic() < deadline:
            display = library.XOpenDisplay(b':98')
            if not display:
                time.sleep(.05)
        assert display, 'fixture display did not start'
        report = {}
        recorder = events.Recorder(root, environment, report)
        assert report['linux_window_events']['ready'], report
        window_root = library.XDefaultRootWindow(display)
        # Another client may own SubstructureRedirect (the WM contract) while
        # the observer is subscribed. XSync would terminate on BadAccess.
        library.XSelectInput(display, window_root, 1 << 20)
        library.XSync(display, False)
        library.XCreateSimpleWindow.argtypes = [C.c_void_p, C.c_ulong, C.c_int, C.c_int,
                                               C.c_uint, C.c_uint, C.c_uint, C.c_ulong, C.c_ulong]
        library.XCreateSimpleWindow.restype = C.c_ulong
        window = library.XCreateSimpleWindow(display, window_root, 0, 0, 320, 200, 0, 0, 0)
        for name in ('XMapWindow', 'XUnmapWindow', 'XDestroyWindow'):
            function = getattr(library, name)
            function.argtypes = [C.c_void_p, C.c_ulong]
            function.restype = C.c_int
            function(display, window)
            library.XSync(display, False)
        # Server processing is acknowledged above; wait for the observer's
        # corresponding flushed record before asking it to exit.
        deadline = time.monotonic() + 5
        records = []
        while time.monotonic() < deadline:
            records = [json.loads(line) for line in recorder.path.read_text().splitlines() if line.endswith('}')]
            if any(row.get('window') == window and row['kind'] == 'destroy' for row in records):
                break
            time.sleep(.025)
        actual = [row for row in records if row.get('window') == window]
        assert [row['kind'] for row in actual] == ['create', 'map', 'unmap', 'destroy'], actual
        assert all(row['event'] == window_root and not row['synthetic'] for row in actual), actual
        recorder.stop()
        assert report['linux_window_events']['complete'], report
        assert json.loads(recorder.path.read_text().splitlines()[-1])['kind'] == 'stopped'
        print('Actual create/map/unmap/destroy order and nonexclusive WM subscription PASS', flush=True)
        invalid = root/'invalid'; invalid.mkdir()
        failure = {}
        failed = events.Recorder(invalid, dict(environment, DISPLAY=':97'), failure)
        assert not failure['linux_window_events']['ready'] and not failure['linux_window_events']['complete'], failure
        assert failure['linux_window_events']['exit'] != 0, failure
        assert failed.process.poll() is not None and failed.log.closed and failed.errors.closed
        print('Unavailable display refuses readiness and retains failure; owned observer cleanup PASS', flush=True)
        hung = root/'hung'; hung.mkdir()
        hung_report = {}
        stuck = events.Recorder(hung, environment, hung_report)
        try:
            assert hung_report['linux_window_events']['ready'], hung_report
            os.kill(stuck.process.pid, signal.SIGSTOP)
            stuck.stop()
            assert hung_report['linux_window_events']['forced_kill'], hung_report
            assert not hung_report['linux_window_events']['complete'], hung_report
            assert stuck.process.poll() is not None and stuck.log.closed and stuck.errors.closed
            print('Unresponsive owned observer is killed and reaped; incomplete trace retained PASS', flush=True)
        finally:
            stuck.stop()
    finally:
        if recorder is not None:
            recorder.stop()
        if display:
            library.XCloseDisplay(display)
        server.terminate()
        server.wait(timeout=5)
