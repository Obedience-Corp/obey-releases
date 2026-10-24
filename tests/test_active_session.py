import copy
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import active_provider as provider
import active_session as active
import verify_app_candidate as app


class ActiveSessionContracts(unittest.TestCase):
    def setUp(self):
        if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
            raise RuntimeError('active-session mutation contracts require Docker')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def session(self):
        return {'session': {'id': 'session', 'campaign_id': 'camp', 'provider': 'ollama',
                'model': provider.MODEL, 'status': 'SESSION_STATUS_RUNNING'}}

    def turns(self):
        return {'schema_version': 'obey.turn.v1', 'has_more': False, 'turns': [{
            'id': 'turn', 'session_id': 'session', 'campaign_id': 'camp', 'status': 'completed',
            'finished_at': '2026-10-24T00:00:00Z', 'current_attempt_number': 1, 'usage': {'tokens_output': 2},
            'latest_attempt': {'state': 'completed', 'provider': 'ollama', 'model': provider.MODEL}}]}

    def test_completed_real_provider_turn_requires_identity_attempt_and_usage(self):
        active.checked_turns(self.turns(), 'session', 'camp', 1)
        for key, value in [('session_id', 'other'), ('campaign_id', 'other'), ('status', 'failed'),
                           ('error_code', 'provider_failed'), ('finished_at', ''), ('current_attempt_number', 0),
                           ('usage', {'tokens_output': 0}), ('latest_attempt', {'state': 'running'})]:
            document = self.turns(); document['turns'][0][key] = value
            with self.assertRaises(ValueError, msg=key):
                active.checked_turns(document, 'session', 'camp', 1)
        for key, value in [('schema_version', 'unknown'), ('has_more', True), ('turns', None)]:
            document = self.turns(); document[key] = value
            with self.assertRaises(ValueError): active.checked_turns(document, 'session', 'camp', 1)
        document = self.turns(); document['turns'] *= 2
        with self.assertRaises(ValueError): active.checked_turns(document, 'session', 'camp', 2)

    def test_external_failed_and_wrong_provider_sessions_never_count_as_real_continuity(self):
        active.checked_session(self.session(), 'session', 'camp', 'SESSION_STATUS_RUNNING')
        for key, value in [('external', True), ('id', 'other'), ('campaign_id', 'other'), ('provider', 'mock'),
                           ('model', 'other'), ('status', 'SESSION_STATUS_FAILED'), ('error_message', 'failure')]:
            document = self.session(); document['session'][key] = value
            with self.assertRaises(ValueError):
                active.checked_session(document, 'session', 'camp', 'SESSION_STATUS_RUNNING')

    def test_provider_text_is_not_printed_on_success_or_failure(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(active.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'MODEL TEXT', '')):
            self.assertEqual(active.quiet(['obey', 'session', 'send'], {}), 'MODEL TEXT')
        with contextlib.redirect_stdout(output), patch.object(active.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, 'MODEL TEXT', 'MODEL TEXT')):
            with self.assertRaisesRegex(RuntimeError, 'output withheld') as error:
                active.quiet(['obey'], {})
            self.assertNotIn('MODEL TEXT', str(error.exception))
        self.assertEqual(output.getvalue(), '')

    def test_actual_process_identity_is_stable_and_hashes_running_executable(self):
        first = active.process_identity(os.getpid())
        self.assertEqual(first, active.process_identity(os.getpid()))
        self.assertEqual(first['pid'], os.getpid())
        self.assertEqual(len(first['executable_sha256']), 64)
        for invalid in [0, -1, True, '1']:
            with self.assertRaises(ValueError): active.process_identity(invalid)

    def test_session_and_turn_readback_request_cli_json_without_exporting_output(self):
        fixture = active.Fixture.__new__(active.Fixture)
        fixture.obey = self.root/'obey'
        fixture.environment = {}
        fixture.fixture = {'camp_id': 'camp'}

        def cli(arguments, **kwargs):
            operation = arguments[3]
            document = self.session() if operation == 'info' else self.turns()
            # Real CLI defaults to human-readable output; only --json returns
            # the schema consumed by the readback validation.
            output = json.dumps(document) if '--json' in arguments else 'Session: session\n'
            return subprocess.CompletedProcess(arguments, 0, output, '')

        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(active.subprocess, 'run', side_effect=cli):
            self.assertEqual(fixture.session_info('session', 'SESSION_STATUS_RUNNING')['id'], 'session')
            self.assertEqual(fixture.turn_readback('session', 1)[0]['id'], 'turn')
        self.assertEqual(output.getvalue(), '')

    def test_archive_digest_and_size_are_checked_before_extraction(self):
        archive = self.root / 'bad'; archive.write_bytes(b'bad')
        with patch.object(provider.subprocess, 'Popen') as launch:
            with self.assertRaises(ValueError): provider.extract_cpu(archive, self.root/'runtime', '0'*64, 3)
            launch.assert_not_called()
        self.assertFalse((self.root/'runtime').exists())

    def test_cpu_archive_filter_excludes_gpu_and_drains_decoder(self):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w') as archive:
            for name in ['bin/ollama', 'lib/ollama/libcpu.so', 'lib/ollama/cuda_v12/libgpu.so']:
                member = tarfile.TarInfo(name); member.size = 3; member.mode = 0o755
                archive.addfile(member, io.BytesIO(b'cpu'))
        data = payload.getvalue() + b'padding'
        original = self.root/'archive'; original.write_bytes(data)
        decoder = Mock(stdout=io.BytesIO(data)); decoder.wait.return_value=0; decoder.poll.return_value=0
        with patch.object(provider.subprocess, 'Popen', return_value=decoder):
            provider.extract_cpu(original, self.root/'runtime', hashlib.sha256(data).hexdigest(), len(data))
        self.assertEqual((self.root/'runtime/bin/ollama').read_bytes(), b'cpu')
        self.assertTrue((self.root/'runtime/lib/ollama/libcpu.so').exists())
        self.assertFalse((self.root/'runtime/lib/ollama/cuda_v12').exists())
        self.assertTrue(decoder.stdout.closed)

    def test_stop_and_safe_idle_state_requires_preserved_durable_work(self):
        fixture = active.Fixture.__new__(active.Fixture)
        fixture.fixture = {'camp_id': 'camp'}; fixture.session = 'session'; fixture.expect_pending = True
        fixture.turns = [dict(id='one'), dict(id='two')]
        fixture.call = Mock(); fixture.session_info = Mock(); fixture.turn_readback = Mock(return_value=copy.deepcopy(fixture.turns))
        fixture.stop_for_idle()
        fixture.call.assert_called_once_with('session', 'stop', 'session', '--campaign', 'camp')
        self.assertFalse(fixture.expect_pending)
        fixture.expect_pending = True; fixture.turn_readback.return_value = []
        with self.assertRaisesRegex(ValueError, 'normal session stop'): fixture.stop_for_idle()
        self.assertTrue(fixture.expect_pending)

    def test_second_turn_requires_first_turn_unchanged(self):
        fixture = active.Fixture.__new__(active.Fixture)
        fixture.session = 'session'; fixture.turns = [{'id': 'one', 'status': 'completed'}]
        fixture.send = Mock(return_value=[{'id': 'one', 'status': 'failed'}, {'id': 'two'}])
        with self.assertRaisesRegex(ValueError, 'changed the first'): fixture.after_update()

    def test_native_readback_rejects_early_restart_lost_work_and_wrong_idle_runtime(self):
        fixture = active.Fixture.__new__(active.Fixture)
        fixture.managed = self.root; fixture.installer = self.root/'installer'; fixture.environment = {}
        fixture.obey = self.root/'obey'; fixture.session = 'session'; fixture.expect_pending = True
        fixture.fixture = {}; fixture.session_info = Mock()
        fixture.turns = [{'id': 'original-completed'}]; fixture.turn_readback = Mock(return_value=copy.deepcopy(fixture.turns))
        unit = self.root/'obey.service'; unit.write_bytes(b'owned unit')
        rows=[]
        for name, package in [('obey',active.existing_obey.OBEY),('ob',active.existing_obey.OBEY),('camp','suite')]:
            path=self.root/name; path.write_bytes(('new '+name).encode())
            rows.append({'path':str(path),'hash':hashlib.sha256(path.read_bytes()).hexdigest(),'receipt_pkg_id':package})
        selected={'receipts':[{'package_id':active.existing_obey.OBEY,'version':'0.2.3'},{'package_id':'suite','version':'current'}],'files':rows}
        before=copy.deepcopy(selected); before['receipts'][0]['version']='0.2.2'
        for row in before['files']:
            if row['receipt_pkg_id']==active.existing_obey.OBEY: row['hash']='old-'+row['path']
        fixture.original_process={'pid':42,'start_ticks':'100','executable_sha256':'old-obey'}
        fixture.report={'existing_before':{'receipts':before,'mtimes':{row['path']:Path(row['path']).stat().st_mtime_ns for row in rows},
                        'observed_at':'2026-10-24T00:00:00Z','unit':{'path':str(unit),'sha256':hashlib.sha256(unit.read_bytes()).hexdigest(),'mtime_ns':unit.stat().st_mtime_ns}}}
        service={'installed':True,'loaded':True,'socket_reachable':True,'daemon_pid':42,'unit_path':str(unit)}
        settings={'pendingObeyRestart':True}; lifecycle={'lastUpdateCheckAt':'2026-10-24T00:00:01Z','setupCompletedAt':'2026-10-24T00:00:01Z'}
        newer={'pid':43,'start_ticks':'200','executable_sha256':rows[0]['hash']}
        with patch.object(active,'checked_receipts',return_value=selected), patch.object(active,'command',return_value={}), patch.object(active,'checked_status'), \
             patch.object(active.existing_obey,'service',return_value=service), patch.object(active.existing_obey,'settings_readback',return_value=(settings,{},lifecycle,'2026-10-24T00:00:02Z')), \
             patch.object(active,'process_identity',return_value=fixture.original_process) as process:
            fixture.readback()
            unit_stat=unit.stat(); os.utime(unit,ns=(unit_stat.st_atime_ns,unit_stat.st_mtime_ns+1000000))
            fixture.readback()  # The supported deferred install refreshes the same definition.
            process.return_value=newer
            with self.assertRaisesRegex(ValueError,'restarted the daemon'): fixture.readback()
            process.return_value=fixture.original_process; fixture.turn_readback.return_value=[]
            with self.assertRaisesRegex(ValueError,'changed completed real work'): fixture.readback()
            fixture.turn_readback.return_value=copy.deepcopy(fixture.turns)
            fixture.expect_pending=False; settings['pendingObeyRestart']=False
            with self.assertRaisesRegex(ValueError,'did not launch'): fixture.readback()
            process.return_value=dict(newer,executable_sha256='wrong')
            with self.assertRaisesRegex(ValueError,'did not launch'): fixture.readback()
            process.return_value=newer; fixture.readback()
            camp=self.root/'camp'; st=camp.stat(); os.utime(camp,ns=(st.st_atime_ns,st.st_mtime_ns+1000000))
            with self.assertRaisesRegex(ValueError,'another selected executable'): fixture.readback()

    def test_wrong_native_targets_and_mixed_modes_fail_before_mutation(self):
        for target, package in [('aarch64-apple-darwin','both'), ('x86_64-pc-windows-msvc','both'), ('x86_64-unknown-linux-gnu','appimage')]:
            with patch.object(app, 'require_clean_host'):
                with self.assertRaisesRegex(ValueError, 'Linux Deb'):
                    app.native(self.root, {}, target, self.root/'output', linux_package=package,
                               fresh_setup=True, existing_user='older-active')
        self.assertFalse((self.root/'output').exists())


if __name__ == '__main__':
    unittest.main()
