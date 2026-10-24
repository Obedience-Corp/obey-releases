"""Observe root-child lifecycle on the verifier's owned X display.

SubstructureNotify is nonexclusive and never redirects a window-manager request.
Events after a child is reparented away from the root are outside this trace's
scope. No window contents, titles, input, or process environment are collected.
"""
import ctypes as C
import json
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

SUBSTRUCTURE_NOTIFY = 1 << 19
KINDS = {16: 'create', 17: 'destroy', 18: 'unmap', 19: 'map',
         21: 'reparent', 22: 'configure', 24: 'circulate'}


# These event structures share this prefix; XEvent reserves 24 native longs.
# https://www.x.org/releases/current/doc/libX11/libX11/libX11.html
class StructureEvent(C.Structure):
    _fields_ = [('type', C.c_int), ('serial', C.c_ulong),
                ('send_event', C.c_int), ('display', C.c_void_p),
                ('event', C.c_ulong), ('window', C.c_ulong)]


class Event(C.Union):
    _fields_ = [('structure', StructureEvent), ('pad', C.c_long * 24)]


def xlib():
    library = C.CDLL('libX11.so.6')
    signatures = {
        'XOpenDisplay': (C.c_void_p, [C.c_char_p]),
        'XDefaultRootWindow': (C.c_ulong, [C.c_void_p]),
        'XSelectInput': (C.c_int, [C.c_void_p, C.c_ulong, C.c_long]),
        'XSync': (C.c_int, [C.c_void_p, C.c_int]),
        'XPending': (C.c_int, [C.c_void_p]),
        'XNextEvent': (C.c_int, [C.c_void_p, C.POINTER(Event)]),
        'XConnectionNumber': (C.c_int, [C.c_void_p]),
        'XCloseDisplay': (C.c_int, [C.c_void_p]),
    }
    for name, (result, arguments) in signatures.items():
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
    return library


def observe():
    library = xlib()
    display = library.XOpenDisplay(None)
    if not display:
        raise RuntimeError('cannot open owned X display')
    stopped = False

    def stop(signum, frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def emit(record):
        print(json.dumps(dict(record, monotonic_ns=time.monotonic_ns())), flush=True)

    count = 0
    try:
        root = library.XDefaultRootWindow(display)
        library.XSelectInput(display, root, SUBSTRUCTURE_NOTIFY)
        library.XSync(display, False)
        emit({'kind': 'ready', 'root': root, 'mask': SUBSTRUCTURE_NOTIFY,
              'scope': 'root-children', 'diagnostic_only': True})
        event = Event()
        while True:
            while library.XPending(display):
                library.XNextEvent(display, C.byref(event))
                value = event.structure
                if value.type not in KINDS:
                    continue
                if count >= 100000:
                    raise RuntimeError('window event recording limit exceeded; trace incomplete')
                emit({'kind': KINDS[value.type], 'type': value.type,
                      'window': value.window, 'event': value.event,
                      'serial': value.serial, 'synthetic': bool(value.send_event)})
                count += 1
            if stopped:
                break
            select.select([library.XConnectionNumber(display)], [], [], .1)
        emit({'kind': 'stopped', 'events': count})
    finally:
        library.XCloseDisplay(display)


class Recorder:
    def __init__(self, output, environment, report):
        self.record = report['linux_window_events'] = {
            'diagnostic_only': True, 'scope': 'root-children', 'ready': False}
        self.path = output / 'linux-window-events.jsonl'
        self.log = self.path.open('w')
        self.errors = (output / 'linux-window-events.stderr').open('w')
        self.process = None
        try:
            self.process = subprocess.Popen(
                [str(Path(sys.executable).absolute()), '-I', str(Path(__file__).resolve())],
                env=environment, stdout=self.log, stderr=self.errors)
            deadline = time.monotonic() + 5
            while self.process.poll() is None and time.monotonic() < deadline:
                with self.path.open() as stream:
                    line = stream.readline(4096)
                if line.endswith('\n'):
                    ready = json.loads(line)
                    if ready.get('kind') != 'ready' or ready.get('mask') != SUBSTRUCTURE_NOTIFY:
                        raise RuntimeError('invalid window observer readiness')
                    self.record.update(ready=True, subscription=ready)
                    return
                time.sleep(.025)
            raise RuntimeError('window observer failed before readiness')
        except Exception as error:
            self.record['error'] = str(error)
            self.stop()

    def stop(self):
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.record['forced_kill'] = True
                    self.process.kill()
                    self.process.wait(timeout=5)
                self.record['exit'] = self.process.returncode
        finally:
            self.log.close()
            self.errors.close()
        # A diagnostic failure is reported without replacing the App result.
        self.record['complete'] = (self.record['ready'] and self.record.get('exit') == 0
                                   and not self.record.get('forced_kill'))


if __name__ == '__main__':
    observe()
