import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing, ExitStack
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import external_suite as external
import verify_selected_components as selected
import verify_app_candidate as app


class ExternalSuite(unittest.TestCase):
    def setUp(self):
        if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
            raise RuntimeError('external suite filesystem contracts require isolated Docker')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        (self.home / 'bin').mkdir()
        self.files = []
        for tool, package in [('obey', 'obedience-corp/obey'), ('ob', 'obedience-corp/obey'), ('camp-app', 'obedience-corp/camp-app')]:
            path = self.home / 'bin' / tool
            path.write_bytes(('owned ' + tool).encode())
            self.files.append((package, str(path), hashlib.sha256(path.read_bytes()).hexdigest(), 493))
        with closing(sqlite3.connect(self.home / 'state.db')) as db:
            with db:
                db.execute('create table receipts(package_id text,version text,source text,channel text)')
                db.execute('create table receipt_files(receipt_pkg_id text,path text,hash text,mode int)')
                db.executemany('insert into receipts values(?,?,?,?)', [('obedience-corp/obey', '0.2.3', 'official-obey', 'stable'), ('obedience-corp/camp-app', '0.1.0', 'official-obey', 'stable')])
                db.executemany('insert into receipt_files values(?,?,?,?)', self.files)

    def status(self, version='0.3.24'):
        camp, fest = ('0.10.1', '0.8.0') if version == '0.3.10' else ('0.16.2', '0.9.8')
        tools = [{'tool': name, 'path': '/usr/bin/' + name, 'version': live, 'present': True,
                  'package': external.SUITE, 'origin': 'package', 'bundle': 'v' + version}
                 for name, live in [('camp', camp), ('fest', fest)]]
        tools += [{'tool': name, 'path': str(self.home / 'bin' / name), 'version': live,
                   'present': True, 'receipt_version': '0.2.3' if name == 'ob' else live,
                   'protocol_major': 1, 'capabilities': ['status', 'open'], 'origin': 'managed',
                   'package': 'obedience-corp/camp-app' if name == 'camp-app' else 'obedience-corp/obey'}
                  for name, live in [('obey', '0.2.3'), ('ob', '0.1.0'), ('camp-app', '0.1.0')]]
        return {'ok': True, 'data': {'tools': tools}}

    def test_optin_external_selection_is_exact_and_default_still_requires_managed_suite(self):
        for version in ['0.3.10', '0.3.24']:
            document = self.status(version)
            selected.checked_status(document, self.home, external_suite=version)
            result = selected.checked_receipts(self.home, external_suite=version)
            self.assertEqual(len(result['receipts']), 2)
            self.assertEqual(len(result['files']), 3)
            with self.assertRaises(ValueError):
                selected.checked_status(document, self.home)
            with self.assertRaises(ValueError):
                selected.checked_receipts(self.home)
            for field, value in [('path', '/foreign/camp'), ('version', '0.1.0'), ('origin', 'managed'),
                                 ('bundle', 'v0.3.9'), ('receipt_version', '0.3.24'),
                                 ('package', 'foreign/package'), ('error', 'probe failed')]:
                changed = copy.deepcopy(document)
                changed['data']['tools'][0][field] = value
                with self.assertRaises(ValueError, msg=field):
                    selected.checked_status(changed, self.home, external_suite=version)

    def test_suite_receipt_or_orphan_files_and_corrupt_owned_payload_are_rejected(self):
        with closing(sqlite3.connect(self.home / 'state.db')) as db:
            with db:
                db.execute('insert into receipts values(?,?,?,?)', (external.SUITE, '0.3.24', 'official-obey', 'stable'))
        with self.assertRaises(ValueError):
            selected.checked_receipts(self.home, external_suite='0.3.24')
        with closing(sqlite3.connect(self.home / 'state.db')) as db:
            with db:
                db.execute('delete from receipts where package_id=?', (external.SUITE,))
                db.execute('update receipt_files set receipt_pkg_id=? where path=?', (external.SUITE, str(self.home/'bin/obey')))
        with self.assertRaises(ValueError):
            selected.checked_receipts(self.home, external_suite='0.3.24')
        with closing(sqlite3.connect(self.home / 'state.db')) as db:
            with db:
                db.execute('update receipt_files set receipt_pkg_id=? where path=?', ('obedience-corp/obey', str(self.home/'bin/obey')))
        (self.home/'bin/obey').write_bytes(b'foreign changed bytes')
        with self.assertRaises(ValueError):
            selected.checked_receipts(self.home, external_suite='0.3.24')

    def test_physical_files_require_regular_bytes_and_preserve_metadata(self):
        path = self.home / 'external'
        path.write_bytes(b'public package executable')
        before = external.physical(path)
        self.assertEqual(external.physical(path), before)
        path.write_bytes(b'changed executable')
        self.assertNotEqual(external.physical(path), before)
        link = self.home / 'linked'; link.symlink_to(path)
        with self.assertRaises(ValueError):
            external.physical(link)

    def test_package_absence_is_distinct_from_query_failure_and_foreign_identity(self):
        missing = subprocess.CompletedProcess([], 1, '', 'dpkg-query: no packages found matching obedience-festival\n')
        with patch.object(external.subprocess, 'run', return_value=missing):
            self.assertIsNone(external.package_info({}))
        for result in [subprocess.CompletedProcess([], 1, '', 'permission denied'),
                       subprocess.CompletedProcess([], 2, '', 'status database unavailable'),
                       subprocess.CompletedProcess([], 0, 'foreign\t0.3.24\tinstall ok installed\n', '')]:
            with patch.object(external.subprocess, 'run', return_value=result):
                with self.assertRaises((RuntimeError, ValueError)):
                    external.package_info({})

    def test_first_launch_refuses_any_settings_including_a_seeded_timestamp(self):
        fixture = external.Fixture.__new__(external.Fixture)
        fixture.settings = self.home / 'settings.json'
        fixture.settings.write_text(json.dumps({'lastUpdateCheckAt': '2026-10-24T00:00:00Z'}))
        with patch.object(external, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'must not create App settings'):
                fixture.before_launch()
            command.assert_not_called()

    def test_cleanup_handles_partial_install_and_refuses_replaced_package(self):
        fixture = external.Fixture.__new__(external.Fixture)
        fixture.attempted_install = True; fixture.installed = False
        fixture.environment = {}; fixture.version = '0.3.24'; fixture.note_record = None; fixture.report = {}
        with patch('corrupt_receipts.quiescent'), patch.object(external, 'package_info', side_effect=[{'version': '0.3.24', 'state': 'install ok unpacked'}, None]), patch.object(external.os.path, 'lexists', return_value=False), patch.object(external, 'command') as command:
            fixture.cleanup()
            self.assertTrue(fixture.report['package_cleanup_verified'])
            self.assertEqual(command.call_args.args[0], ['sudo', '-n', '/usr/bin/dpkg', '--purge', 'obedience-festival'])
        with patch('corrupt_receipts.quiescent'), patch.object(external, 'package_info', return_value={'version': '9.0.0'}), patch.object(external, 'command') as command:
            with self.assertRaisesRegex(RuntimeError, 'replaced'):
                fixture.cleanup()
            command.assert_not_called()

    def test_native_installs_suite_before_app_and_cleans_each_attempted_package(self):
        import verify_app_upgrade as upgrade
        from test_app_candidate import manifest, VERSION
        for failure in ('suite', 'app', 'after-app'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                document = dict(manifest(), installer_basename='festival-app-installer')
                image = next(row['name'] for row in document['targets']['x86_64-unknown-linux-gnu']
                             if row['name'].endswith('.AppImage'))
                (root/image).write_bytes(b'original image fixture')
                events = []
                fixture = Mock(report={})
                def seed():
                    events.append('suite-install')
                    if failure == 'suite': raise RuntimeError('suite install failed')
                def install(*args, **kwargs):
                    self.assertEqual(events, ['suite-install'])
                    events.append('app-install')
                    if failure == 'app': raise RuntimeError('app install failed')
                def unchanged():
                    events.append('suite-preserved')
                    return {'original_files': 'unchanged'}
                def command(arguments, *args, **kwargs):
                    return 'festival-app' if arguments[-1] == 'Package' else VERSION
                fixture.install_package.side_effect = seed
                fixture.unchanged.side_effect = unchanged
                fixture.cleanup.side_effect = lambda: events.append('suite-cleanup')
                with ExitStack() as stack:
                    stack.enter_context(patch.object(app, 'require_clean_host'))
                    stack.enter_context(patch.object(app, 'native_platform', return_value='linux/amd64'))
                    stack.enter_context(patch.object(app, 'verify_signature'))
                    stack.enter_context(patch.object(app, 'verify_optional_signature', return_value=True))
                    stack.enter_context(patch.object(app.shutil, 'which', return_value=None))
                    stack.enter_context(patch.object(upgrade, 'default_home_layout', return_value=root/'managed'))
                    stack.enter_context(patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')))
                    stack.enter_context(patch.object(app, 'command', side_effect=command))
                    stack.enter_context(patch.object(external, 'Fixture', return_value=fixture))
                    stack.enter_context(patch.object(app, 'install_deb', side_effect=install))
                    stack.enter_context(patch.object(app, 'apt_command', side_effect=lambda *a, **k: events.append('app-purge')))
                    stack.enter_context(patch.object(app, 'extract_appimage_observers', side_effect=RuntimeError('after-app failure')))
                    stack.enter_context(patch.dict(os.environ, {'RUNNER_TEMP': str(root)}))
                    with self.assertRaisesRegex(RuntimeError, failure + (' failure' if failure == 'after-app' else ' install failed')):
                        app.native(root, document, 'x86_64-unknown-linux-gnu', root/'proof',
                                   fresh_setup=True, existing_user='external-suite-current')
                expected = ['suite-install']
                if failure != 'suite': expected += ['app-install']
                if failure == 'after-app': expected += ['suite-preserved']
                if failure != 'suite': expected += ['app-purge']
                self.assertEqual(events, expected + ['suite-cleanup'])
                fixture.prepare_existing_cli.assert_not_called()
                proof = json.loads((root/'proof/proof.json').read_text())
                self.assertFalse(proof['external_suite_compatibility_verified'])
                self.assertEqual(proof['external_suite_preexisted_app_install'], failure == 'after-app')
                self.assertNotIn('cleanup_failure', proof)

    def test_existing_cli_preparation_refuses_absent_or_changed_suite_before_commands(self):
        fixture = external.Fixture.__new__(external.Fixture)
        fixture.installed = False
        with patch.object(external, 'command') as invoked:
            with self.assertRaisesRegex(RuntimeError, 'must be installed'):
                fixture.prepare_existing_cli()
            invoked.assert_not_called()
        fixture.installed = True
        fixture.unchanged = Mock(side_effect=ValueError('suite changed'))
        with patch.object(external, 'command') as invoked:
            with self.assertRaisesRegex(ValueError, 'suite changed'):
                fixture.prepare_existing_cli()
            invoked.assert_not_called()

    def test_first_app_cannot_rewrite_other_current_package_receipts_or_executables(self):
        baseline = selected.checked_receipts(self.home, external_suite='0.3.24')
        fixture = external.Fixture.__new__(external.Fixture)
        fixture.report = {'managed_receipts_before_app': baseline,
                          'managed_physical_before_app': [external.physical(row['path']) for row in baseline['files']]}
        fixture.non_suite_preserved(copy.deepcopy(baseline))
        added_suite = copy.deepcopy(baseline)
        added_suite['receipts'].append({'package_id': external.SUITE, 'version': '0.3.24'})
        added_suite['files'].append({'receipt_pkg_id': external.SUITE, 'path': '/new/managed/camp'})
        fixture.non_suite_preserved(added_suite)
        changed = copy.deepcopy(baseline); changed['receipts'][0]['version'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'already-current non-suite package'):
            fixture.non_suite_preserved(changed)
        path = self.home / 'bin/obey'
        old = path.stat(); os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns + 1000000000))
        with self.assertRaisesRegex(ValueError, 'rewrote the already-current'):
            fixture.non_suite_preserved(copy.deepcopy(baseline))

    def test_readback_proves_unthrottled_background_or_required_foreground_path(self):
        from existing_obey import utc_now
        stamp = utc_now()
        fixture = external.Fixture.__new__(external.Fixture)
        fixture.settings = self.home / 'settings.json'
        fixture.version = '0.3.24'
        fixture.report = {'before_app_utc': stamp}
        fixture.settings.write_text(json.dumps({'lastUpdateCheckAt': stamp, 'setupCompletedAt': None}))
        self.assertEqual(fixture.settings_readback()['settings']['lastUpdateCheckAt'], stamp)
        fixture.settings.write_text(json.dumps({'lastUpdateCheckAt': stamp, 'setupCompletedAt': stamp}))
        with self.assertRaisesRegex(ValueError, 'foreground setup'):
            fixture.settings_readback()
        fixture.version = '0.3.9'
        fixture.settings_readback()
        fixture.settings.write_text(json.dumps({'lastUpdateCheckAt': stamp, 'setupCompletedAt': None}))
        with self.assertRaisesRegex(ValueError, 'did not complete foreground'):
            fixture.settings_readback()
        fixture.settings.write_text(json.dumps({'setupCompletedAt': None}))
        with self.assertRaises(ValueError):
            fixture.settings_readback()

    def test_final_readback_requires_unchanged_responsive_service_and_all_state(self):
        fixture = external.Fixture.__new__(external.Fixture)
        service = {'installed': True, 'loaded': True, 'socket_reachable': True, 'daemon_pid': 42}
        fixture.report = {'service_before_app': service}
        fixture.unchanged = Mock(return_value={'package': 'unchanged'})
        reading = {'service': service, 'receipt': 'unchanged'}
        fixture.finish(reading, copy.deepcopy(reading))
        changed = copy.deepcopy(reading); changed['receipt'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'App relaunch changed'):
            fixture.finish(reading, changed)
        for invalid in [None, 0, 'true', False]:
            changed = copy.deepcopy(reading); changed['service']['loaded'] = invalid
            with self.assertRaisesRegex(ValueError, 'responsive managed service'):
                fixture.finish(changed, changed)
        changed = copy.deepcopy(reading); changed['service']['daemon_pid'] = 99
        with self.assertRaisesRegex(ValueError, 'already-ready CLI service'):
            fixture.finish(changed, changed)

    def test_wrong_platform_and_mixed_journeys_refused_before_fixture_mutation(self):
        for target, package in [('aarch64-apple-darwin', 'both'), ('x86_64-pc-windows-msvc', 'both'), ('x86_64-unknown-linux-gnu', 'appimage')]:
            with patch.object(app, 'require_clean_host'):
                with self.assertRaisesRegex(ValueError, 'Linux Deb'):
                    app.native(self.home, {}, target, self.home/'out', linux_package=package,
                               fresh_setup=True, existing_user='external-suite-current')
        self.assertFalse((self.home/'out').exists())


if __name__ == '__main__':
    unittest.main()
