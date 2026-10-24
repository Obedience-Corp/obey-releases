"""Actual malformed integration preferences and guarded rollback, Docker only."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('integration fixture filesystem tests require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import corrupt_integrations as integrations
import verify_app_candidate as app


class CorruptIntegrationContracts(unittest.TestCase):
    def preferences(self, root):
        home = root/'managed'; home.mkdir()
        (home/'integrations.json').write_text('{"disabled": false, "files": ["fixture-profile"], "helpers": []}\n')
        return home

    def test_actual_json_failure_and_exact_manual_restore_after_partial_journey(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); home = self.preferences(root)
            path = home/'integrations.json'; original = path.read_bytes(); mtime = path.stat().st_mtime_ns
            report = {}; fixture = integrations.Fixture(home, root/'private', report)
            try:
                fixture.corrupt()
                with self.assertRaises(json.JSONDecodeError): json.loads(path.read_bytes())
                self.assertTrue(fixture.unchanged_corruption()['unchanged'])
                raise RuntimeError('owned App launch failed after fixture mutation')
            except RuntimeError:
                fixture.restore()
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(path.stat().st_mtime_ns, mtime)
            self.assertEqual(json.loads(path.read_bytes())['disabled'], False)
            self.assertTrue(report['restored']); self.assertFalse(report['backup_uploaded'])
            fixture.restore()
            self.assertTrue(fixture.healthy()['unchanged'])
            path.write_bytes(original + b' ')
            with self.assertRaisesRegex(ValueError, 'reopen changed'): fixture.healthy()

    def test_foreign_replacement_metadata_and_changed_corruption_are_not_overwritten(self):
        for change in ('replacement', 'bytes', 'mode'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); home = self.preferences(root)
                fixture = integrations.Fixture(home, root/'private', {}); fixture.corrupt()
                if change == 'replacement':
                    replacement = root/'foreign'; replacement.write_bytes(fixture.broken)
                    os.replace(replacement, fixture.path)
                elif change == 'bytes': fixture.path.write_bytes(b'foreign bytes' + fixture.broken[13:])
                else: fixture.path.chmod(0o444)
                observed = fixture.path.read_bytes()
                with self.assertRaises(ValueError): fixture.restore()
                self.assertEqual(fixture.path.read_bytes(), observed)
                self.assertFalse(fixture.restored)

    def test_links_and_backup_tampering_refused(self):
        for case in ('symlink', 'hardlink', 'backup-link', 'backup-bytes'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); home = self.preferences(root); path = home/'integrations.json'
                original = path.read_bytes()
                if case == 'symlink':
                    moved = root/'foreign'; path.rename(moved); path.symlink_to(moved)
                elif case == 'hardlink': os.link(path, root/'foreign')
                elif case == 'backup-link': (root/'private').symlink_to(home, target_is_directory=True)
                if case != 'backup-bytes':
                    with self.assertRaises(ValueError): integrations.Fixture(home, root/'private', {})
                    self.assertEqual(path.read_bytes(), original)
                else:
                    fixture = integrations.Fixture(home, root/'private', {}); fixture.corrupt()
                    fixture.backup.write_bytes(b'foreign' + original[7:])
                    with self.assertRaisesRegex(ValueError, 'backup'): fixture.restore()
                    self.assertEqual(path.read_bytes(), fixture.broken)

    def test_installer_and_visible_app_error_must_match_injected_corruption(self):
        baseline = {'ok': False, 'error': {'code': 'E_SETUP_INTEGRATIONS', 'message': 'read integration preferences: invalid character'}}
        self.assertEqual(integrations.checked_error(baseline, 1)['code'], 'E_SETUP_INTEGRATIONS')
        for bad, exit_code in ((baseline, 0), ({'ok': True}, 1),
                               ({'ok': False, 'error': {'message': 'read integration preferences'}}, 1),
                               ({'ok': False, 'error': {'code': 'E_OTHER', 'message': 'permission denied'}}, 1)):
            with self.assertRaises(ValueError): integrations.checked_error(bad, exit_code)
        window = {'visible_names': ['Getting this machine ready', 'Configure terminal commands and agent connections', 'read integration preferences: invalid character']}
        self.assertTrue(integrations.error_window(window))
        for missing in window['visible_names']:
            self.assertFalse(integrations.error_window({'visible_names': [x for x in window['visible_names'] if x != missing]}))
        self.assertFalse(integrations.error_window({'visible_names': ['Licenses', 'License key']}))

    def test_windows_filetime_conversion_preserves_ticks_and_refuses_rounding(self):
        low, high = integrations.windows_filetime(0)
        self.assertEqual((high << 32) | low, 116444736000000000)
        low, high = integrations.windows_filetime(100)
        self.assertEqual((high << 32) | low, 116444736000000001)
        for value in (1, True, 1.0, -11644473600000000000, 2**80):
            with self.assertRaises(ValueError): integrations.windows_filetime(value)

    def test_wrong_native_scope_refused_before_artifact_or_package_changes(self):
        with patch.object(app, 'require_clean_host'):
            with self.assertRaisesRegex(ValueError, 'native Windows'):
                app.native(Path('/unused'), {}, 'x86_64-unknown-linux-gnu', Path('/unused'), fresh_setup=True, existing_user='corrupt-integrations')
