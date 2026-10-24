"""Real SQLite and persisted rollback filesystem cases, Docker only."""
from contextlib import closing
import hashlib
import copy
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
import verify_app_candidate as app
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

    def test_actual_incomplete_status_contract_retains_healthy_live_tool_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=self.fixture(root)
            fixture=receipts.Fixture(home,root/'private',{},dict(os.environ));fixture.corrupt()
            data={'home':str(home),'bin_dir':str(home/'bin'),'marketplace_source':'official-obey','origin':'managed',
                  'prerequisites':[{'name':'git','present':True}],
                  'tools':[{'tool':'camp','present':True,'version':'0.16.2','path':str(home/'bin/camp'),'receipt_version':'0.3.24'}]}
            before={'installer_status':{'ok':True,'data':data},'receipts':fixture.receipts,'mtimes':{name:row['mtime_ns'] for name,row in fixture.physical.items()}}
            document={'ok':True,'data':copy.deepcopy(data)}
            document['data']['setup']={'signals_incomplete':True}
            document['data']['tools'][0].pop('receipt_version')
            try:
                with patch.object(receipts,'command',return_value=document):
                    self.assertEqual(receipts.probe(root/'festival',fixture,before,{},root),document)
                for kind in ('signal','tool','receipt','route'):
                    bad=copy.deepcopy(document)
                    if kind=='signal':bad['data']['setup']['signals_incomplete']=False
                    elif kind=='tool':bad['data']['tools'][0]['version']='unrelated'
                    elif kind=='receipt':bad['data']['tools'][0]['receipt_version']='0.3.24'
                    else:bad['data']['home']='/another/home'
                    with patch.object(receipts,'command',return_value=bad),self.assertRaises(ValueError):
                        receipts.probe(root/'festival',fixture,before,{},root)
            finally:fixture.restore()

    def test_authenticated_specific_unreadable_state_row_is_required(self):
        row='Read what this machine hasFailed'+receipts.MESSAGE+receipts.CODE+'Retry'
        names=['Getting this machine ready','A step did not finish. Its detail is below.',row]
        self.assertTrue(receipts.error_window({'uia_verified':True,'visible_names':names}))
        for changed in [row.replace('Read what this machine has','Configure terminal commands and agent connections'),
                        row.replace(receipts.CODE,'E_UNKNOWN'),row.replace(receipts.MESSAGE,'Something failed'),row+'lookalike']:
            self.assertFalse(receipts.error_window({'uia_verified':True,'visible_names':names[:2]+[changed]}))
        self.assertFalse(receipts.error_window({'uia_verified':False,'visible_names':names}))

    def test_corrupt_receipt_mode_rejects_other_platform_before_execution(self):
        with patch.object(app,'require_clean_host'),self.assertRaisesRegex(ValueError,'native Windows'):
            app.native(Path('/unused'),{},'x86_64-unknown-linux-gnu',Path('/unused'),fresh_setup=True,existing_user='corrupt-receipts')

    def test_unreadable_database_still_requires_other_physical_user_and_service_preservation(self):
        import existing_obey
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=self.fixture(root)
            fixture=receipts.Fixture(home,root/'private',{},dict(os.environ));fixture.corrupt()
            campaign=root/'camp';campaign.mkdir();unit=root/'unit';unit.write_bytes(b'owned registered unit')
            service={'installed':True,'loaded':True,'socket_reachable':True,'daemon_pid':77,'unit_path':str(unit)}
            preserved={'settings':{'fontSize':17},'preserved_files':{'owned-note':'known-sha'}}
            lifecycle={'setupCompletedAt':None,'lastUpdateCheckAt':'2026-10-24T00:00:00Z'}
            before={'preserved':preserved,'lifecycle':lifecycle,'pending_obey_restart':False,'service':service,
                    'unit':{'path':str(unit),'sha256':hashlib.sha256(unit.read_bytes()).hexdigest(),'mtime_ns':unit.stat().st_mtime_ns}}
            existing={'managed_home':home,'camp':home/'bin/camp','camp_id':'owned-id','fixture':campaign}
            with patch.object(existing_obey,'settings_readback',return_value=({},preserved,lifecycle,'now')) as settings, \
                 patch.object(existing_obey,'service',return_value=service) as observed_service, \
                 patch.object(receipts,'command',return_value=[{'id':'owned-id','path':str(campaign)}]) as camps:
                try:
                    result=receipts.preserved_user(existing,before,fixture,{})
                    self.assertFalse(result['receipt_rows_readable']);self.assertEqual(len(result['physical_files']),5)
                    self.assertEqual(result['receipt_database']['sha256'],receipts.sha(fixture.broken))
                    settings.return_value=({},{'settings':{'fontSize':99}},lifecycle,'now')
                    with self.assertRaisesRegex(ValueError,'user state'):receipts.preserved_user(existing,before,fixture,{})
                    settings.return_value=({},preserved,lifecycle,'now')
                    observed_service.return_value=dict(service,daemon_pid=88)
                    with self.assertRaisesRegex(ValueError,'service/unit'):receipts.preserved_user(existing,before,fixture,{})
                    observed_service.return_value=service;camps.return_value=[]
                    with self.assertRaisesRegex(ValueError,'registered camp'):receipts.preserved_user(existing,before,fixture,{})
                    camps.return_value=[{'id':'owned-id','path':str(campaign)}]
                    target=home/'bin/fest';data=target.read_bytes();info=target.stat()
                    try:
                        target.write_bytes(b'unknown selected replacement')
                        with self.assertRaisesRegex(ValueError,'physical files'):receipts.preserved_user(existing,before,fixture,{})
                    finally:
                        target.write_bytes(data);os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns))
                finally:fixture.restore()
