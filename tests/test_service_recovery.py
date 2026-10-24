import copy
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import active_provider
import active_session
import service_recovery as recovery
import verify_app_candidate as app


class ServiceRecoveryContracts(unittest.TestCase):
    def setUp(self):
        if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
            raise RuntimeError('service recovery mutation controls require Docker')
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def properties(self):
        return 'MainPID=12\nNRestarts=0\nActiveState=active\nSubState=running\nRestart=always\nFragmentPath=/owned/obey.service\n'

    def test_exact_supervisor_identity_and_restart_policy_required(self):
        value = self.properties()
        self.assertEqual(recovery.checked_unit(value, '/owned/obey.service')['MainPID'], 12)
        for changed in [value+'MainPID=12\n', value.replace('MainPID=12', 'MainPID=0'),
                        value.replace('NRestarts=0', 'NRestarts=-1'), value.replace('Restart=always', 'Restart=no'),
                        value.replace('SubState=running', 'SubState=dead'), value.replace('/owned/', '/foreign/'),
                        value.replace('ActiveState=active\n', '')]:
            with self.assertRaises(ValueError): recovery.checked_unit(changed, '/owned/obey.service')

    def test_owned_unit_rejects_symbolic_and_hard_links(self):
        path = self.root/'unit'; path.write_text('known')
        before = recovery.owned_regular(path)
        self.assertEqual(before, recovery.owned_regular(path))
        link = self.root/'link'; link.symlink_to(path)
        with self.assertRaises(ValueError): recovery.owned_regular(link)
        link.unlink(); os.link(path, link)
        with self.assertRaises(ValueError): recovery.owned_regular(path)

    def child(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(90)'])
        def close():
            if child.poll() is None: child.kill()
            child.wait(timeout=10)
        self.addCleanup(close)
        return child

    def test_actual_held_pidfd_kills_only_revalidated_owned_child(self):
        child, survivor = self.child(), self.child()
        expected = active_session.process_identity(child.pid)
        called = []
        recovery.kill_bound(expected, sys.executable, expected['executable_sha256'], lambda: called.append(True))
        self.assertEqual(child.wait(timeout=10), -9)
        self.assertEqual(called, [True]); self.assertIsNone(survivor.poll())

    def test_stale_generation_foreign_executable_digest_and_unit_refused_before_signal(self):
        child = self.child(); expected = active_session.process_identity(child.pid)
        foreign = self.root/'foreign'; foreign.write_bytes(b'other')
        cases = [(dict(expected, start_ticks='0'), sys.executable, expected['executable_sha256'], lambda: None),
                 (expected, foreign, expected['executable_sha256'], lambda: None),
                 (expected, sys.executable, '0'*64, lambda: None),
                 (expected, sys.executable, expected['executable_sha256'], Mock(side_effect=ValueError('unit changed'))),
                 (expected, sys.executable, expected['executable_sha256'], Mock(side_effect=PermissionError('query refused')))]
        for identity, executable, digest, validate in cases:
            with self.subTest(identity=identity, executable=executable, digest=digest):
                with patch.object(recovery.signal, 'pidfd_send_signal') as signal_call:
                    with self.assertRaises((ValueError, PermissionError)):
                        recovery.kill_bound(identity, executable, digest, validate)
                    signal_call.assert_not_called()
                self.assertIsNone(child.poll())

    def test_crash_lifecycle_requires_exact_identity_failed_and_restart_reason(self):
        row = {'id': 'old', 'campaign_id': 'camp', 'provider': 'ollama', 'model': active_provider.MODEL,
               'status': 'SESSION_STATUS_FAILED', 'error_message': 'daemon restarted'}
        recovery.crashed_session({'session': row}, 'old', 'camp')
        for key, value in [('id', 'other'), ('status', 'SESSION_STATUS_RUNNING'), ('error_message', 'provider failed'),
                           ('external', True), ('provider', 'mock'), ('campaign_id', 'other')]:
            changed = dict(row, **{key: value})
            with self.assertRaises(ValueError): recovery.crashed_session({'session': changed}, 'old', 'camp')

    def test_native_mode_refuses_other_platforms_and_mixed_flags_before_mutation(self):
        for options in [dict(target='aarch64-apple-darwin'), dict(target='x86_64-unknown-linux-gnu', linux_package='appimage'),
                        dict(target='x86_64-unknown-linux-gnu', login_shell_proof=True)]:
            target = options.pop('target')
            with patch.object(app, 'require_clean_host'):
                with self.assertRaises(ValueError):
                    app.native(self.root, {}, target, self.root/'out', fresh_setup=True,
                               existing_user='service-recovery', **options)

    def test_fresh_readback_uses_explicit_lifecycle_validator_without_idle_validator(self):
        fixture = Mock(); fixture.readback.return_value = {'receipts': {}, 'selected_mtime_ns': {}}
        state = {'installed': True, 'loaded': True, 'socket_reachable': True, 'daemon_pid': 12}
        with patch.object(app, 'command', return_value=state):
            self.assertEqual(app.fresh_setup_readback(self.root/'installer', self.root, {}, service_recovery=fixture)['service'], state)
        fixture.readback.assert_called_once_with()

    def test_durable_restart_event_requires_one_exact_owned_transition(self):
        row = {'id': 'event', 'session_id': 'old', 'campaign_id': 'camp',
               'kind': 'session_status_changed', 'message': 'daemon restarted',
               'old_status': 'RUNNING', 'new_status': 'FAILED', 'sequence_number': '3', 'timestamp': 'observed'}
        self.assertEqual(recovery.checked_restart_event({'events': [row]}, 'old', 'camp'), row)
        for key, value in [('session_id', 'other'), ('campaign_id', 'other'), ('old_status', 'WORKING'),
                           ('new_status', 'STOPPED'), ('sequence_number', '0'), ('timestamp', '')]:
            with self.assertRaises(ValueError):
                recovery.checked_restart_event({'events': [dict(row, **{key: value})]}, 'old', 'camp')
        for events in [[], [row, row]]:
            with self.assertRaises(ValueError): recovery.checked_restart_event({'events': events}, 'old', 'camp')
