"""Public App journey inside the real local desktop of an owned disposable VM.

The private fixture password is read once, removed from disk, and never placed
in the App environment, command arguments or public evidence. OS authorization
remains normal sudo/polkit; the outer VM owns final machine disposal.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from verify_candidate import command, require_disposable, wait_until
import linux_guest_session

TARGET = 'x86_64-unknown-linux-gnu'
AGENT = Path('/usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1')


def local_context(environment):
    require_disposable()
    if Path('/etc/hostname').read_text().strip() != 'festival-clean-linux':
        raise RuntimeError('App desktop proof requires the dedicated clean guest')
    state = linux_guest_session.read_session()
    if state is None or not state['desktop_ready']:
        raise RuntimeError('local desktop is not ready')
    checked_driver_session(state, environment, Path('/proc/self/cgroup').read_text())
    return state


def checked_driver_session(state, environment, groups):
    scope = state['session']['Scope']
    if not any(scope in row.split(':', 2)[2].split('/') for row in groups.splitlines()):
        raise RuntimeError('App driver must be a child of the actual local login, not SSH')
    for name, value in state['environment'].items():
        if environment.get(name) != value:
            raise RuntimeError('driver did not inherit the actual desktop environment: ' + name)


def private_password(path):
    status = path.lstat()
    if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) != 0o600:
        raise RuntimeError('fixture credential is not an owned private regular file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns):
            raise RuntimeError('fixture credential changed during open')
        value = os.read(descriptor, 100).decode()
    finally:
        os.close(descriptor)
    if len(value) != 32 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789' for c in value):
        raise ValueError('invalid fixture credential alphabet/length')
    path.unlink()
    return value


def process_birth(pid):
    return int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])


def pkexec_child(app_pid):
    """Bind the OS prompt to the real App's exact Git installation request."""
    from linux_window_diagnostics import process_inventory
    rows = process_inventory(app_pid)
    found = []
    for row in rows:
        try:
            args = Path(f'/proc/{row["pid"]}/cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError, ProcessLookupError):
            continue
        if args == [b'/usr/bin/pkexec', b'/usr/bin/apt-get', b'install', b'--yes', b'git', b'']:
            found.append({'pid': row['pid'], 'start_ticks': row['start_ticks'], 'parent_pid': row['parent_pid'],
                          'arguments': [value.decode() for value in args[:-1]]})
    if len(found) != 1:
        raise RuntimeError('expected one App-descended pkexec apt-get install --yes git')
    return found[0]


def polkit_controls(agent_pid, api):
    desktop = api.get_desktop(0)
    if not 0 <= desktop.get_child_count() <= 64:
        raise RuntimeError('unbounded accessibility desktop')
    roots = [desktop.get_child_at_index(i) for i in range(desktop.get_child_count())]
    roots = [node for node in roots if node.get_process_id() == agent_pid]
    if len(roots) != 1:
        return None
    queue, entries, buttons, names = roots[:], [], [], []
    count = 0
    while queue:
        node = queue.pop(); count += 1
        if count > 2000:
            raise RuntimeError('unbounded OS authentication accessibility tree')
        states = node.get_state_set()
        visible = all(states.contains(flag) for flag in (api.StateType.SHOWING, api.StateType.VISIBLE, api.StateType.ENABLED, api.StateType.SENSITIVE))
        if visible:
            if node.get_role() == api.Role.PASSWORD_TEXT:
                entries.append(node)
            elif node.get_role() == api.Role.PUSH_BUTTON and node.get_name().replace('_', '') == 'Authenticate':
                buttons.append(node)
            else:
                names.append(node.get_name() or '')
        children = node.get_child_count()
        if children < 0 or children + count + len(queue) > 2000:
            raise RuntimeError('invalid OS authentication child count')
        queue.extend(node.get_child_at_index(i) for i in range(children))
    if len(entries) != 1 or len(buttons) != 1 or not any('/usr/bin/apt-get' in name for name in names):
        return None
    return entries[0], buttons[0], names


class Context:
    def __init__(self, root):
        self.environment = dict(os.environ)
        self.session = local_context(self.environment)
        self.password = private_password(root / 'credential')
        self.agent = None
        self.accessibility = None

    def validate(self):
        current = local_context(self.environment)
        if current['session'] != self.session['session'] or current['process_identity'] != self.session['process_identity']:
            raise RuntimeError('local login changed during the App journey')
        return current

    def sudo(self, arguments, environment, timeout, check=True):
        self.validate()
        args = ['sudo', '-k', '-S', '-p', '', '--', *map(str, arguments)]
        result = subprocess.run(args, input=self.password + '\n', text=True, capture_output=True,
                                env=environment, timeout=timeout)
        # Do not serialize stdin or exception repr; scrub even unexpected echoes.
        stdout = result.stdout.replace(self.password, '[private fixture credential]')
        stderr = result.stderr.replace(self.password, '[private fixture credential]')
        print(json.dumps({'command': args, 'exit': result.returncode, 'stdout': stdout, 'stderr': stderr}), flush=True)
        if check and result.returncode:
            raise RuntimeError('normal guest password sudo command failed')
        return stdout

    def before_launch(self, installer, environment, output, report):
        import missing_git
        report['git_missing_prerequisite'] = missing_git.git_status(installer, environment, False, output / 'git-absent-status.json')
        self.accessibility = command(['gsettings', 'get', 'org.gnome.desktop.interface', 'toolkit-accessibility'], environment).strip()
        if self.accessibility not in ('true', 'false'):
            raise RuntimeError('invalid desktop accessibility setting')
        command(['gsettings', 'set', 'org.gnome.desktop.interface', 'toolkit-accessibility', 'true'], environment)
        # Xfce's minimal desktop may not enable the packaged GNOME policy agent
        # automatically. Start that ordinary user-session agent, never pkttyagent
        # or an authorization rule that grants permission without the OS dialog.
        candidates = []
        for proc in Path('/proc').iterdir():
            if not proc.name.isdecimal():
                continue
            try:
                if proc.stat().st_uid == os.getuid() and (proc / 'exe').resolve() == AGENT:
                    candidates.append(int(proc.name))
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
        if len(candidates) > 1:
            raise RuntimeError('ambiguous polkit desktop agent')
        if candidates:
            self.agent_pid = candidates[0]
        else:
            self.agent = subprocess.Popen([str(AGENT)], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.agent_pid = self.agent.pid
        self.agent_birth = process_birth(self.agent_pid)
        report['polkit_agent'] = {'pid': self.agent_pid, 'start_ticks': self.agent_birth,
                                  'executable': str(AGENT), 'started_by_fixture': self.agent is not None}

    def install_git(self, process, binary, installer, environment, output, report):
        import missing_git
        import gi
        gi.require_version('Atspi', '2.0')
        from gi.repository import Atspi
        Atspi.set_timeout(1000, 5000)
        report['git_missing_ui'] = missing_git.interact(process, binary, environment, 'inspect')
        command(['import', '-window', 'root', output / 'git-missing-desktop.png'], environment)
        report['git_install_action'] = missing_git.interact(process, binary, environment, 'retry')
        def prompt():
            if process.poll() is not None:
                raise RuntimeError('App exited before OS Git authorization')
            self.validate()
            if process_birth(self.agent_pid) != self.agent_birth or Path(f'/proc/{self.agent_pid}/exe').resolve() != AGENT:
                raise RuntimeError('OS authentication agent identity changed')
            controls = polkit_controls(self.agent_pid, Atspi)
            return controls if controls else None
        entry, button, names = wait_until('normal OS Git password dialog', prompt, seconds=60)
        report['git_pkexec_request'] = pkexec_child(process.pid)
        report['git_authorization_prompt'] = names
        command(['import', '-window', 'root', output / 'git-os-authorization.png'], environment)
        current = prompt()
        if current is None or current[0] != entry or current[1] != button or pkexec_child(process.pid) != report['git_pkexec_request']:
            raise RuntimeError('OS authorization controls/request changed before password entry')
        editable = entry.get_editable_text_iface()
        action = button.get_action_iface()
        if editable is None or action is None or action.get_n_actions() != 1:
            raise RuntimeError('normal OS dialog lacks unique password/action controls')
        if editable.set_text_contents(self.password) is not True or action.do_action(0) is not True:
            raise RuntimeError('normal OS password authentication action failed')
        def installed():
            if process.poll() is not None:
                raise RuntimeError('App exited during Git installation')
            try:
                return missing_git.git_status(installer, environment, True, output / 'git-installed-status.json')
            except RuntimeError:
                return None
        report['git_installed_prerequisite'] = wait_until('App-authorized Git installation', installed, seconds=600)
        report['automatic_git_authorization_verified'] = True

    def close(self):
        if self.agent is not None and self.agent.poll() is None:
            self.agent.terminate(); self.agent.wait(timeout=15)
        if self.accessibility is not None:
            command(['gsettings', 'set', 'org.gnome.desktop.interface', 'toolkit-accessibility', self.accessibility], self.environment)
            self.accessibility = None
        self.password = None


def persisted_state():
    result = {}
    for name in ('.obey/festival-app/settings.json', '.obey/installer/integrations.json'):
        path = Path.home() / name
        if path.is_symlink():
            raise RuntimeError('unexpected persisted settings symlink')
        result[name] = {'present': path.exists()}
        if path.exists():
            result[name].update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                mtime_ns=path.stat().st_mtime_ns)
    return result


def responsive_readback(installer, managed, environment):
    import verify_app_candidate as app
    import sqlite3
    try:
        return app.fresh_setup_readback(installer, managed, environment)
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        return None


def reboot_readback(root, output):
    import verify_app_candidate as app
    import verify_app_upgrade as upgrade
    environment = dict(os.environ)
    report = {'reboot_verified': False, 'useful_first_use_verified': False, 'consumer_trust_verified': False}
    output.mkdir()
    process = None
    before = json.loads((root / 'evidence/install/proof.json').read_text())
    try:
        report['local_session'] = local_context(environment)
        old = json.loads((root / 'install-boot.json').read_text())
        current = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if old['boot_id'] == current:
            raise RuntimeError('App reboot proof did not cross an actual OS boot')
        report.update(previous_boot_id=old['boot_id'], boot_id=current)
        managed = Path.home() / '.obey/installer'
        installer, binary = Path('/usr/bin/festival'), Path('/usr/bin/festival-app')
        report['before_app_launch'] = wait_until('installed user service returns after real reboot',
            lambda: responsive_readback(installer, managed, environment), seconds=90)
        report['persisted_before_launch'] = persisted_state()
        expected_state = json.loads((root / 'persisted-after-install.json').read_text())
        if report['persisted_before_launch'] != expected_state:
            raise RuntimeError('OS reboot changed persisted App/integration settings')
        for key in ('receipts', 'selected_mtime_ns'):
            if report['before_app_launch'][key] != before['default_after_reopen'][key]:
                raise RuntimeError('OS reboot changed installed selected receipts/files')
        with (output / 'app.log').open('w') as log:
            process = subprocess.Popen([str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT)
            report['after_app_launch'] = app.wait_fresh_setup(process, installer, managed, TARGET, output, environment, report, 'reboot')
            for key in ('receipts', 'selected_mtime_ns'):
                if report['after_app_launch'][key] != report['before_app_launch'][key]:
                    raise RuntimeError('post-reboot App launch changed selected receipts/files')
            report['persisted_after_launch'] = persisted_state()
            if report['persisted_after_launch'] != expected_state:
                raise RuntimeError('post-reboot App launch changed persisted settings')
            upgrade.normal_quit(process, binary, None, TARGET, environment, output)
            process = None
        report['reboot_verified'] = True
    except Exception as error:
        report['failure'] = str(error)
        raise
    finally:
        if process is not None:
            app.stop_owned(process, environment)
        (output / 'proof.json').write_text(json.dumps(report, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root
    stage = (root / 'stage').read_text().strip()
    if stage not in ('install', 'reboot'):
        raise ValueError('invalid guest App stage')
    environment = dict(os.environ)
    environment.update(CANDIDATE_NATIVE_DISPOSABLE='1', CANDIDATE_RUNNER_KIND='github-hosted',
                       GITHUB_REPOSITORY='Obedience-Corp/obey-releases', RUNNER_TEMP=str(root / 'temporary'))
    os.environ.update(environment)
    evidence = root / 'evidence'
    # The host releases this barrier only after real local login and capture.
    wait_until('host releases authenticated desktop journey', lambda: (root / 'start').is_file(), seconds=180)
    output = evidence / stage
    context = None
    try:
        local_context(environment)
        if stage == 'install':
            from app_upgrade_contract import checked_public
            import verify_app_candidate as app
            config = json.loads((root / 'config.json').read_text())
            document = checked_public(root / 'public', config['source'], config['version'])
            context = Context(root)
            (root / 'install-boot.json').write_text(json.dumps({'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))
            app.native(root / 'public/assets', document, TARGET, output,
                       fresh_setup=True, public_root=root / 'public', guest_context=context)
            (root / 'persisted-after-install.json').write_text(json.dumps(persisted_state(), indent=2))
        else:
            reboot_readback(root, output)
        (evidence / (stage + '-result.json')).write_text(json.dumps({'success': True}))
    except Exception as error:
        (evidence / (stage + '-result.json')).write_text(json.dumps({'success': False, 'error': str(error)}))
        raise
    finally:
        if context is not None:
            context.close()


if __name__ == '__main__':
    main()
