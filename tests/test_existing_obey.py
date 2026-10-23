"""Existing-user fixture mutations and preservation failures, container-only."""
import copy
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('existing-user filesystem tests require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import existing_obey
from verify_selected_components import checked_receipts, PACKAGES
import test_selected_components as fixtures


class ExistingObeyContracts(unittest.TestCase):
    def test_real_historical_fixture_changes_only_two_owned_files_and_matching_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            home = fixtures.SelectedContracts().fixture(Path(directory))
            before = checked_receipts(home)
            payloads = {'obey': b'authentic-old-obey-fixture', 'ob': b'authentic-old-ob-fixture', 'LICENSE': b'license'}
            old = existing_obey.place_old_payloads(home, payloads)
            self.assertEqual(next(row['version'] for row in old['receipts'] if row['package_id'] == existing_obey.OBEY), '0.2.2')
            for row in old['files']:
                path = Path(row['path'])
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), row['hash'])
                if row['receipt_pkg_id'] != existing_obey.OBEY:
                    self.assertIn(row, before['files'])
            with self.assertRaisesRegex(ValueError, 'selection/version'):
                checked_receipts(home)
            self.assertEqual(PACKAGES[existing_obey.OBEY], '0.2.3')

    def test_foreign_replacement_is_rejected_before_any_fixture_write(self):
        with tempfile.TemporaryDirectory() as directory:
            home = fixtures.SelectedContracts().fixture(Path(directory))
            foreign = home / 'bin/obey'; foreign.write_bytes(b'foreign-content')
            original_ob = (home / 'bin/ob').read_bytes()
            with self.assertRaisesRegex(ValueError, 'differs from'):
                existing_obey.place_old_payloads(home, {'obey': b'old', 'ob': b'old', 'LICENSE': b'license'})
            self.assertEqual(foreign.read_bytes(), b'foreign-content')
            self.assertEqual((home / 'bin/ob').read_bytes(), original_ob)

    def test_running_service_prevents_replacement(self):
        existing_obey.require_stopped({'installed': False, 'loaded': False, 'socket_reachable': False})
        for key in ('installed', 'loaded', 'socket_reachable'):
            with self.assertRaises(RuntimeError):
                existing_obey.require_stopped({key: True})

    def test_missing_or_falsey_nonboolean_service_state_never_authorizes_replacement(self):
        with self.assertRaises(RuntimeError): existing_obey.require_stopped({})
        baseline = {'installed': False, 'loaded': False, 'socket_reachable': False}
        for key in baseline:
            missing = dict(baseline); del missing[key]
            with self.assertRaises(RuntimeError): existing_obey.require_stopped(missing)
            for value in (None, 0, '', [], 'false'):
                invalid = dict(baseline); invalid[key] = value
                with self.assertRaises(RuntimeError): existing_obey.require_stopped(invalid)

    def state(self):
        return {'preserved': {'settings': {'lastUpdateCheckAt': 'recent'}, 'files': {'foreign': 'hash'}},
                'receipts': {'receipts': [{'package_id': existing_obey.OBEY, 'version': '0.2.3'}, {'package_id': 'suite', 'version': 'current'}],
                             'files': [{'receipt_pkg_id': existing_obey.OBEY, 'path': 'obey', 'hash': 'new-a'},
                                       {'receipt_pkg_id': existing_obey.OBEY, 'path': 'ob', 'hash': 'new-b'},
                                       {'receipt_pkg_id': 'suite', 'path': 'camp', 'hash': 'same'}]},
                'mtimes': {'obey': 2, 'ob': 2, 'camp': 1}, 'service': {'daemon_pid': 20},
                'unit': {'path': 'unit', 'sha256': 'unit-hash', 'mtime_ns': 1}, 'pending_obey_restart': False}

    def test_current_noop_rejects_rewrite_restart_receipt_or_settings_change(self):
        before = self.state()
        existing_obey.compare(before, copy.deepcopy(before), 'current')
        mutations = [lambda s: s['mtimes'].update(ob=3), lambda s: s['service'].update(daemon_pid=21),
                     lambda s: s['unit'].update(mtime_ns=2), lambda s: s['preserved']['files'].update(foreign='changed'),
                     lambda s: s['receipts']['files'][0].update(hash='changed'), lambda s: s.update(pending_obey_restart=True)]
        for mutate in mutations:
            after = copy.deepcopy(before); mutate(after)
            with self.assertRaises(ValueError): existing_obey.compare(before, after, 'current')

    def test_old_migration_requires_both_replacements_and_idle_restart(self):
        after = self.state(); before = copy.deepcopy(after)
        before['service']['daemon_pid'] = 10
        before['receipts']['receipts'][0]['version'] = '0.2.2'
        for row in before['receipts']['files'][:2]: row['hash'] = 'old-' + row['path']
        existing_obey.compare(before, after, 'older-idle')
        bad = copy.deepcopy(after); bad['service']['daemon_pid'] = 10
        with self.assertRaisesRegex(ValueError, 'old daemon'): existing_obey.compare(before, bad, 'older-idle')
        bad = copy.deepcopy(after); bad['receipts']['files'][1]['hash'] = 'old-ob'
        with self.assertRaisesRegex(ValueError, 'both replaced'): existing_obey.compare(before, bad, 'older-idle')
        bad = copy.deepcopy(after); bad['mtimes']['camp'] = 2
        with self.assertRaisesRegex(ValueError, 'rewritten'): existing_obey.compare(before, bad, 'older-idle')
