"""Real SQLite and persisted rollback filesystem cases, Docker only."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
if os.environ.get('CANDIDATE_TEST_CONTAINER')!='1' or not Path('/.dockerenv').exists():
    raise RuntimeError('receipt filesystem contracts require Docker')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import corrupt_receipts as receipts
import test_selected_components as selected


class ReceiptCorruptionContracts(unittest.TestCase):
    def fixture(self, root):
        home=selected.SelectedContracts().fixture(root)
        with closing(sqlite3.connect(home/'state.db')) as db:
            db.execute('PRAGMA journal_mode=WAL').fetchall()
        return home

    def test_actual_sqlite_corruption_preserved_exact_manual_restore(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=self.fixture(root);report={}
            fixture=receipts.Fixture(home,root/'private',report,dict(os.environ))
            fixture.corrupt()
            self.assertEqual(len(fixture.broken),len(fixture.original))
            self.assertEqual(fixture.broken[16:],fixture.original[16:])
            with self.assertRaises(sqlite3.DatabaseError):
                with closing(sqlite3.connect(home/'state.db')) as db:db.execute('select * from receipts').fetchall()
            fixture.unchanged();fixture.restore();fixture.healthy()
            self.assertEqual(fixture.path.read_bytes(),fixture.original)
            self.assertEqual(fixture.path.stat().st_mtime_ns,fixture.info.st_mtime_ns)
            self.assertTrue(report['restored']);self.assertFalse(report['product_recovery_verified'])

    def test_recovered_readonly_zero_wal_is_recorded_but_transaction_bytes_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=self.fixture(root)
            fixture=receipts.Fixture(home,root/'private',{},dict(os.environ))
            fixture.corrupt();fixture.restore()
            # The unchanged existing live validator can create ephemeral files.
            receipts.checked_receipts(home)
            self.assertEqual(Path(str(fixture.path)+'-wal').stat().st_size,0)
            fixture.healthy()
            self.assertEqual(fixture.report['recovered_readonly_sidecars']['-wal']['bytes'],0)
            Path(str(fixture.path)+'-wal').write_bytes(b'unknown transaction frame')
            with self.assertRaisesRegex(ValueError,'nonempty WAL'):fixture.healthy()
            self.assertEqual(Path(str(fixture.path)+'-wal').read_bytes(),b'unknown transaction frame')

    def test_immutable_validator_refuses_sidecars_and_does_not_create_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=self.fixture(root)
            receipts.checked_receipts(home,immutable=True)
            self.assertEqual({p.name for p in home.glob('state.db*')},{'state.db'})
            Path(str(home/'state.db')+'-wal').write_bytes(b'outstanding transaction')
            with self.assertRaisesRegex(ValueError,'immutable receipt read refuses'):
                receipts.checked_receipts(home,immutable=True)

    def test_realistic_selected_executable_size_is_not_limited_as_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=self.fixture(root)
            executable=home/'bin/camp';executable.write_bytes(b'large selected executable fixture' * 65536)
            self.assertGreater(executable.stat().st_size,receipts.MAX_BYTES)
            with closing(sqlite3.connect(home/'state.db')) as db:
                with db:db.execute('update receipt_files set hash=? where path=?',(hashlib.sha256(executable.read_bytes()).hexdigest(),str(executable)))
            fixture=receipts.Fixture(home,root/'private',{},dict(os.environ))
            fixture.corrupt();fixture.restore();fixture.healthy()
            self.assertEqual(executable.stat().st_size,len(b'large selected executable fixture')*65536)

    def test_outstanding_sidecars_or_live_installer_refuse_before_backup(self):
        for case in ('-wal','-shm','-journal','process'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);home=self.fixture(root);before=(home/'state.db').read_bytes()
                if case!='process':Path(str(home/'state.db')+case).write_bytes(b'unknown outstanding SQLite state')
                with patch.object(receipts,'quiescent',side_effect=ValueError('running App')) if case=='process' else patch.object(receipts,'quiescent',return_value={}):
                    with self.assertRaises(ValueError):receipts.Fixture(home,root/'private',{},dict(os.environ))
                self.assertEqual((home/'state.db').read_bytes(),before);self.assertFalse((root/'private').exists())

    def test_unknown_changes_and_live_process_refuse_rollback(self):
        for case in ('bytes','inode','mode','backup','sidecar','process'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);home=self.fixture(root)
                fixture=receipts.Fixture(home,root/'private',{},dict(os.environ));fixture.corrupt()
                if case=='bytes':fixture.path.write_bytes(b'unknown user DB')
                elif case=='inode':
                    p=root/'other';p.write_bytes(fixture.broken);os.replace(p,fixture.path)
                elif case=='mode':fixture.path.chmod(0o444)
                elif case=='backup':fixture.backup.write_bytes(b'unknown backup')
                elif case=='sidecar':Path(str(fixture.path)+'-wal').write_bytes(b'new writer')
                before=fixture.path.read_bytes()
                with patch.object(receipts,'quiescent',side_effect=ValueError('running App')) if case=='process' else patch.object(receipts,'quiescent',return_value={}):
                    with self.assertRaises(ValueError):fixture.restore()
                self.assertEqual(fixture.path.read_bytes(),before);self.assertFalse(fixture.restored)

    def test_partial_write_failure_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=self.fixture(root)
            fixture=receipts.Fixture(home,root/'private',{},dict(os.environ))
            def failure(*args):
                fixture.path.write_bytes(b'partial mutation');raise OSError('original failure')
            with patch.object(fixture,'replace',side_effect=failure):
                with self.assertRaisesRegex(OSError,'original failure'):fixture.corrupt()
            with self.assertRaisesRegex(ValueError,'incomplete'):fixture.restore()
            self.assertEqual(fixture.path.read_bytes(),b'partial mutation')
