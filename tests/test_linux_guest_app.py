"""Reject SSH/display substitution and unsafe private credential handling."""
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('guest App controls require Docker filesystem isolation')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_guest_app as guest
import verify_app_candidate as app


class GuestAppControls(unittest.TestCase):
    def test_ssh_process_with_correct_display_is_not_a_local_session(self):
        state = {'session': {'Scope': 'session-c2.scope'}, 'environment': {'DISPLAY': ':0', 'XDG_SESSION_ID': 'c2'}}
        env = dict(state['environment'])
        with self.assertRaisesRegex(RuntimeError, 'actual local login'):
            guest.checked_driver_session(state, env, '0::/user.slice/user-1000.slice/session-c3.scope\n')
        with self.assertRaisesRegex(RuntimeError, 'actual desktop environment'):
            guest.checked_driver_session(state, dict(env, DISPLAY=':99'), '0::/user.slice/session-c2.scope\n')
        guest.checked_driver_session(state, env, '0::/user.slice/session-c2.scope\n')

    def test_credential_is_consumed_privately_and_symlink_public_file_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'credential'; link = root / 'link'
            value = 'a1' * 16
            path.write_text(value); path.chmod(0o600)
            link.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, 'private regular file'):
                guest.private_password(link)
            self.assertTrue(path.exists())
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'private regular file'):
                guest.private_password(path)
            path.chmod(0o600)
            self.assertEqual(guest.private_password(path), value)
            self.assertFalse(path.exists())

    def test_invalid_credential_never_reaches_an_authentication_command(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'credential'
            path.write_text('invalid\n'); path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'alphabet/length'):
                guest.private_password(path)
            self.assertTrue(path.exists())

    def test_guest_sudo_does_not_put_secret_in_argv_environment_or_output(self):
        ctx = guest.Context.__new__(guest.Context)
        ctx.password = 'b2' * 16; ctx.validate = Mock()
        response = SimpleNamespace(returncode=0, stdout='echo:' + ctx.password, stderr=ctx.password)
        output = io.StringIO(); environment = {'PATH': '/usr/bin:/bin'}
        with patch.object(guest.subprocess, 'run', return_value=response) as run, patch('sys.stdout', output):
            ctx.sudo(['true'], environment, 30)
        args, kwargs = run.call_args
        self.assertNotIn(ctx.password, args[0])
        self.assertNotIn(ctx.password, kwargs['env'].values())
        self.assertEqual(kwargs['input'], ctx.password + '\n')
        self.assertNotIn(ctx.password, output.getvalue())
        self.assertIn('-k', args[0]); self.assertIn('-S', args[0])

    def test_no_guest_context_silently_removes_normal_apt_timeout(self):
        authorization = Mock()
        app.apt_command(['install', '-y', 'example'], {}, 60, authorization=authorization)
        args = authorization.sudo.call_args.args[0]
        self.assertEqual(args[:4], ['timeout', '--signal=TERM', '--kill-after=15s', '60s'])
        self.assertEqual(args[4:], ['apt-get', 'install', '-y', 'example'])

    def test_persisted_settings_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); settings = home / '.obey/festival-app/settings.json'
            settings.parent.mkdir(parents=True)
            foreign = home / 'foreign'; foreign.write_text('{}')
            settings.symlink_to(foreign)
            with patch.object(Path, 'home', return_value=home), self.assertRaisesRegex(RuntimeError, 'settings symlink'):
                guest.persisted_state()


class Node:
    def __init__(self, name='', role='label', pid=4, children=(), visible=True):
        self.name, self.role, self.pid, self.children, self.visible = name, role, pid, list(children), visible
    def get_name(self): return self.name
    def get_role(self): return self.role
    def get_process_id(self): return self.pid
    def get_child_count(self): return len(self.children)
    def get_child_at_index(self, index): return self.children[index]
    def get_state_set(self): return SimpleNamespace(contains=lambda flag: self.visible)


class PolkitControls(unittest.TestCase):
    def api(self, roots):
        return SimpleNamespace(get_desktop=lambda index: Node(children=roots),
            Role=SimpleNamespace(PASSWORD_TEXT='password', PUSH_BUTTON='button'),
            StateType=SimpleNamespace(SHOWING=1, VISIBLE=2, ENABLED=3, SENSITIVE=4))

    def test_exact_owned_os_prompt_required(self):
        entry = Node(role='password'); button = Node('Authenticate', 'button')
        prompt = Node('Authentication is required to run /usr/bin/apt-get')
        root = Node(children=[entry, button, prompt])
        self.assertIsNotNone(guest.polkit_controls(4, self.api([root])))
        self.assertIsNone(guest.polkit_controls(5, self.api([root])))
        self.assertIsNone(guest.polkit_controls(4, self.api([root, root])))
        root.children.append(Node(role='password'))
        self.assertIsNone(guest.polkit_controls(4, self.api([root])))
        root.children.pop(); prompt.name = 'Authentication is required to run /bin/sh'
        self.assertIsNone(guest.polkit_controls(4, self.api([root])))
        prompt.name = '/usr/bin/apt-get'; button.visible = False
        self.assertIsNone(guest.polkit_controls(4, self.api([root])))
