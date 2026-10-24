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

    def test_selected_file_metadata_and_replacement_preservation_are_enforced(self):
        fixture = recovery.Fixture.__new__(recovery.Fixture)
        fixture.managed = self.root
        binary = self.root/'obey'; binary.write_bytes(b'authenticated selected payload')
        (self.root/'state.db').write_bytes(b'receipt fixture')
        fixture.unit = self.root/'unit'; fixture.unit.write_text('unit')
        fixture.config = self.root/'config'; fixture.config.write_text('config')
        fixture.unit_before = recovery.owned_regular(fixture.unit)
        fixture.config_before = recovery.owned_regular(fixture.config)
        selected = {'receipts': [], 'files': [{'path': str(binary), 'hash': hashlib.sha256(binary.read_bytes()).hexdigest()}]}
        fixture.files_before = {str(binary): recovery.owned_regular(binary)}
        fixture.baseline = {'receipts': selected, 'mtimes': {str(binary): binary.stat().st_mtime_ns},
                            'preserved': {'known': True}, 'lifecycle': {'known': True}}
        fixture.fixture = {}
        with patch.object(recovery, 'checked_receipts', return_value=selected), patch.object(recovery.existing_obey, 'settings_readback',
                return_value=({}, {'known': True}, {'known': True}, 'observed')):
            fixture.preserved()
            mode = binary.stat().st_mode
            binary.chmod(mode ^ 0o100)
            with self.assertRaisesRegex(ValueError, 'physical identities'): fixture.preserved()
            binary.chmod(mode)
            replacement = self.root/'replacement'; replacement.write_bytes(binary.read_bytes())
            os.utime(replacement, ns=(binary.stat().st_atime_ns, fixture.baseline['mtimes'][str(binary)]))
            os.replace(replacement, binary)
            with self.assertRaisesRegex(ValueError, 'physical identities'): fixture.preserved()

    def test_both_event_readbacks_use_released_singular_kind_and_json_contract(self):
        client = active_session.SessionClient()
        client.obey = self.root/'obey'; client.environment = {}; client.fixture = {'camp_id': 'camp'}
        with patch.object(active_session, 'quiet', return_value={'events': []}) as quiet:
            self.assertEqual(client.lifecycle_events('old'), {'events': []})
        quiet.assert_called_once_with([client.obey, '--no-color', 'session', 'events', 'old',
            '--campaign', 'camp', '--kind', 'session_status_changed', '--limit', '100', '--json'], {}, json_output=True)

    def test_quiet_failure_retains_only_fixed_metadata_and_canonical_grpc_tokens(self):
        result = subprocess.CompletedProcess([], 1, 'PRIVATE MODEL OUTPUT',
            'rpc error: code = NotFound desc = PRIVATE MODEL OUTPUT; rpc error: code = SecretToken')
        with patch.object(active_session.subprocess, 'run', return_value=result):
            with self.assertRaises(active_session.SessionOperationFailure) as caught:
                active_session.quiet(['secret argument'], {})
        self.assertEqual(caught.exception.diagnostics['returncode'], 1)
        self.assertEqual(caught.exception.diagnostics['canonical_grpc_codes'], ['NotFound'])
        self.assertNotIn('PRIVATE', str(caught.exception))
        self.assertNotIn('PRIVATE', str(caught.exception.diagnostics))
        self.assertNotIn('secret argument', str(caught.exception))

    def campaign_database(self):
        import sqlite3
        from contextlib import closing
        database = self.root/'daemon.db'
        with closing(sqlite3.connect(database)) as connection:
            connection.execute('create table campaigns(id text, path text)')
            connection.commit()
        camp = self.root/'camp'; camp.mkdir()
        return database, camp

    def test_readonly_campaign_identity_path_absence_and_ambiguity(self):
        import sqlite3
        from contextlib import closing
        database, camp = self.campaign_database()
        self.assertIsNone(recovery.campaign_readiness(database, 'expected', camp))
        with closing(sqlite3.connect(database)) as connection:
            connection.execute('insert into campaigns values (?,?)', ('expected', str(camp)))
            connection.commit()
        self.assertEqual(recovery.campaign_readiness(database, 'expected', camp)['matching_rows'], 1)
        with self.assertRaises(ValueError): recovery.campaign_readiness(database, 'expected', self.root/'foreign')
        with closing(sqlite3.connect(database)) as connection:
            connection.execute('insert into campaigns values (?,?)', ('expected', str(camp)))
            connection.commit()
        with self.assertRaises(ValueError): recovery.campaign_readiness(database, 'expected', camp)
        link = self.root/'linked.db'; link.symlink_to(database)
        with self.assertRaises(ValueError): recovery.campaign_readiness(link, 'expected', camp)
        missing = self.root/'absent.db'
        with self.assertRaises(FileNotFoundError): recovery.campaign_readiness(missing, 'expected', camp)
        self.assertFalse(missing.exists())

    def test_readiness_wait_observes_actual_row_arrival_without_session_retry(self):
        import sqlite3
        import threading
        from contextlib import closing
        database, camp = self.campaign_database()
        failures = []
        def ingest():
            try:
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute('insert into campaigns values (?,?)', ('expected', str(camp)))
                    connection.commit()
            except Exception as error:
                failures.append(error)
        timer = threading.Timer(.05, ingest); timer.start()
        try:
            record = {}
            self.assertEqual(recovery.wait_campaign(database, 'expected', camp, record)['matching_rows'], 1)
        finally:
            timer.join(timeout=5)
        self.assertFalse(failures)
        self.assertTrue(record['database_read_only'])
        self.assertTrue(record['observations'][-1]['matching_id_and_path'])

    def test_failure_context_queries_are_failure_only_and_never_export_arguments(self):
        fixture = recovery.Fixture.__new__(recovery.Fixture)
        fixture.obey = self.root/'obey'; fixture.environment = {}; fixture.fixture = {'camp_id': 'camp', 'fixture': self.root}
        fixture.database = self.root/'daemon.db'; fixture.report = {}
        fixture.supervisor = Mock(return_value={'MainPID': 12})
        fixture.provider_readiness = Mock(side_effect=RuntimeError('PRIVATE PROVIDER TEXT'))
        with patch.object(active_session, 'quiet', return_value='ok'):
            self.assertEqual(fixture.call('session', 'send', 'session', 'PRIVATE PROMPT'), 'ok')
        fixture.supervisor.assert_not_called(); fixture.provider_readiness.assert_not_called()
        failure = active_session.SessionOperationFailure(subprocess.CompletedProcess([], 1, '', 'rpc error: code = NotFound'))
        with patch.object(active_session, 'quiet', side_effect=failure), patch.object(recovery.existing_obey, 'service', return_value={'installed': True}), patch.object(recovery, 'campaign_readiness', return_value=None):
            with self.assertRaises(active_session.SessionOperationFailure):
                fixture.call('session', 'create', '--agent', 'PRIVATE ARGUMENT')
        self.assertEqual(fixture.report['cli_failure']['operation'], 'session/create')
        self.assertEqual(fixture.report['failure_only_readiness']['campaign'], None)
        self.assertEqual(fixture.report['failure_only_readiness']['provider'], {'query_failure_type': 'RuntimeError'})
        self.assertNotIn('PRIVATE', str(fixture.report))
