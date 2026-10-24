"""Real GTK/AT-SPI action fixture; never removes Git or launches Festival."""
import json
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
import linux_receipt_ui as receipt_ui
import corrupt_receipts as receipts
from linux_accessibility import ToolkitSetting
import gi

if len(sys.argv) == 3 and sys.argv[1] == '--fixture':
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    window = Gtk.Window(title='Owned missing-Git Retry fixture')
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    diagnostic = Gtk.Label(label=receipts.MESSAGE)
    diagnostic.set_line_wrap(True)
    diagnostic.set_max_width_chars(80)
    box.pack_start(diagnostic, True, True, 0)
    hidden = Gtk.Label(label='hidden receipt diagnostic')
    hidden.set_no_show_all(True)
    box.pack_start(hidden, True, True, 0)
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
    accessibility = ToolkitSetting(dict(os.environ))
    marker = Path(temporary)/'clicked'
    process = None
    try:
        accessibility.enable()
        process = subprocess.Popen([sys.executable, __file__, '--fixture', str(marker)])
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
        visible, _ = receipt_ui.visible_text(apps, process.pid, Atspi)
        assert receipts.MESSAGE in visible, visible
        assert 'hidden receipt diagnostic' not in visible, visible
        helper = Path(receipt_ui.__file__).resolve()
        observer_environment = dict(os.environ, CANDIDATE_NATIVE_DISPOSABLE='1',
                                    CANDIDATE_RUNNER_KIND='github-hosted')
        def observe(expected_birth, environment):
            return subprocess.run([sys.executable, '-I', str(helper), '--pid', str(process.pid),
                                   '--birth', str(expected_birth), '--executable', sys.executable],
                                  env=environment, capture_output=True, text=True, timeout=10)
        observed = observe(birth, observer_environment)
        assert observed.returncode == 0, observed.stderr
        observation = json.loads(observed.stdout)
        assert observation['pid'] == process.pid and observation['birth'] == birth
        assert observation['owned_accessibility_verified'] is True
        assert receipts.MESSAGE in observation['visible_text']
        assert 'hidden receipt diagnostic' not in observation['visible_text']
        stale = observe(birth+1, observer_environment)
        assert stale.returncode != 0 and 'identity changed' in stale.stderr
        unqualified = observe(birth, dict(observer_environment, CANDIDATE_NATIVE_DISPOSABLE='0'))
        assert unqualified.returncode != 0 and 'requires an owned disposable' in unqualified.stderr
        try:
            receipt_ui.visible_text(apps, os.getpid(), Atspi)
        except RuntimeError:
            pass
        else:
            raise AssertionError('foreign receipt text accepted')
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
        print('Actual owned visible receipt text PASS; hidden and foreign text excluded; observation invoked no action', flush=True)
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)
        finally:
            accessibility.restore()
        assert accessibility.read() == accessibility.original
