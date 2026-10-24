"""Real GTK/AT-SPI action fixture; never removes Git or launches Festival."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('GTK fixture requires isolated Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_git_retry as retry
import gi

if len(sys.argv) == 3 and sys.argv[1] == '--fixture':
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    window = Gtk.Window(title='Owned missing-Git Retry fixture')
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    button = Gtk.Button(label=retry.BUTTON)
    def clicked(_):
        Path(sys.argv[2]).write_text('normal GTK action invoked\n')
        box.pack_start(Gtk.Button(label=retry.BUTTON), True, True, 0)
        box.show_all()
    button.connect('clicked', clicked)
    box.pack_start(button, True, True, 0)
    window.add(box)
    window.connect('destroy', Gtk.main_quit)
    window.show_all()
    Gtk.main()
    raise SystemExit(0)

gi.require_version('Atspi', '2.0')
from gi.repository import Atspi
Atspi.set_timeout(1000, 5000)
with tempfile.TemporaryDirectory() as temporary:
    marker = Path(temporary)/'clicked'
    process = subprocess.Popen([sys.executable, __file__, '--fixture', str(marker)])
    try:
        birth = retry.birth(process.pid)
        deadline = time.monotonic()+30
        last_error = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('GTK fixture exited before action')
            desktop = Atspi.get_desktop(0)
            apps = [desktop.get_child_at_index(i) for i in range(desktop.get_child_count())]
            try:
                action, count = retry.select_button(apps, process.pid, Atspi)
                break
            except RuntimeError as error:
                last_error = error
                time.sleep(.1)
        else:
            raise RuntimeError('actual GTK button never became accessible') from last_error
        try:
            retry.select_button(apps, os.getpid(), Atspi)
        except RuntimeError:
            pass
        else:
            raise AssertionError('foreign process accepted')
        retry.require_owner(process.pid, birth, Path(sys.executable))
        try:
            retry.require_owner(process.pid, birth+1, Path(sys.executable))
        except RuntimeError:
            pass
        else:
            raise AssertionError('stale process identity accepted')
        assert not marker.exists()
        assert action.do_action(0) is True
        deadline = time.monotonic()+5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert marker.read_text() == 'normal GTK action invoked\n'
        # The real callback adds a second same-labelled button. A fresh tree
        # read must refuse this ambiguity instead of repeating either action.
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            Atspi.Accessible.clear_cache(desktop)
            try:
                retry.select_button(apps, process.pid, Atspi)
            except RuntimeError as error:
                assert 'ambiguous' in str(error), error
                break
            time.sleep(.05)
        else:
            raise AssertionError('duplicate real Retry controls were accepted')
        print('Actual owned GTK Retry action PASS; foreign PID, stale birth and ambiguous controls refused', flush=True)
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
