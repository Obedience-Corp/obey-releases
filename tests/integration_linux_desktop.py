"""Real Openbox readiness before a managed window and original capture path."""
import ctypes as C
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('desktop mutation fixture requires Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from linux_desktop import wait_for_openbox
from linux_window_events import xlib
from verify_app_candidate import window_capture


def fixture_window():
    library = xlib()
    display = library.XOpenDisplay(None)
    assert display
    library.XCreateSimpleWindow.argtypes = [C.c_void_p, C.c_ulong, C.c_int, C.c_int,
                                           C.c_uint, C.c_uint, C.c_uint, C.c_ulong, C.c_ulong]
    library.XCreateSimpleWindow.restype = C.c_ulong
    window = library.XCreateSimpleWindow(display, library.XDefaultRootWindow(display),
                                         0, 0, 320, 200, 0, 0, 0x3366cc)
    library.XStoreName.argtypes = [C.c_void_p, C.c_ulong, C.c_char_p]
    library.XStoreName(display, window, b'Owned readiness fixture')
    library.XSync(display, False)
    subprocess.run(['xprop', '-id', str(window), '-f', '_NET_WM_PID', '32c',
                    '-set', '_NET_WM_PID', str(os.getpid())], check=True)
    library.XMapWindow.argtypes = [C.c_void_p, C.c_ulong]
    library.XMapWindow(display, window)
    library.XSync(display, False)
    while True:
        time.sleep(1)


if sys.argv[1:] == ['--window']:
    fixture_window()
    raise SystemExit

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    environment = dict(os.environ, DISPLAY=':98', HOME=str(root))
    server = subprocess.Popen(['Xvfb', ':98', '-screen', '0', '640x480x24'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    manager = child = sleeper = None
    try:
        deadline = time.monotonic() + 5
        while subprocess.run(['xdpyinfo'], env=environment, capture_output=True).returncode:
            assert time.monotonic() < deadline, 'fixture display did not start'
            time.sleep(.05)
        # A live process alone is insufficient: the actual empty display must
        # refuse readiness without EWMH self-reference and root redirection.
        sleeper = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            wait_for_openbox(sleeper, environment, seconds=.2)
        except RuntimeError as error:
            assert 'timed out waiting' in str(error), error
        else:
            raise AssertionError('empty desktop accepted')
        print('Actual empty desktop refuses readiness despite live child PASS', flush=True)
        manager = subprocess.Popen(['openbox'], env=environment, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        ready = wait_for_openbox(manager, environment)
        assert ready['launched_pid'] == manager.pid and ready['ewmh_self_reference'] and ready['root_redirect_selected']
        print('Actual owned Openbox live birth, EWMH self-reference/name and redirect readiness PASS', flush=True)
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--window'], env=environment)
        destination = root/'owned-window.png'
        captured = window_capture(child, 'x86_64-unknown-linux-gnu', destination, environment)
        assert captured['title'] == 'Owned readiness fixture', captured
        png = destination.read_bytes()
        assert png[:8] == b'\x89PNG\r\n\x1a\n' and struct.unpack('>II', png[16:24]) == (320, 200)
        if os.environ.get('DESKTOP_FIXTURE_EVIDENCE'):
            evidence = Path(os.environ['DESKTOP_FIXTURE_EVIDENCE']); evidence.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(destination, evidence/'owned-window.png')
        print('Actual managed window captured through unchanged App capture path PASS', flush=True)
        manager.terminate(); manager.wait(timeout=5)
        try:
            wait_for_openbox(manager, environment)
        except (RuntimeError, FileNotFoundError):
            pass
        else:
            raise AssertionError('exited manager accepted')
        print('Actual exited manager refused PASS', flush=True)
    finally:
        for process in (child, manager, sleeper, server):
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)
