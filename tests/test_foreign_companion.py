"""Receipt-aware foreign-file substitution and preservation, Docker only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('foreign companion filesystem contracts require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import foreign_companion as foreign
import verify_app_candidate as app
import test_selected_components as selected
from verify_selected_components import checked_receipts


class ForeignCompanionContracts(unittest.TestCase):
    def test_only_windows_fixed_executable_filename_bits_are_reconciled(self):
        values = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o666, st_uid=3, st_gid=4, st_nlink=1)
        info = SimpleNamespace(**values)
        expected = dict(values, st_mode=stat.S_IFREG | 0o777)
        self.assertEqual(foreign.descriptor_identity(info, 'camp-app.exe', windows=True), expected)
        self.assertEqual(foreign.descriptor_identity(info, 'camp-app.exe', windows=False), values)
        readonly = SimpleNamespace(**dict(values, st_mode=stat.S_IFREG | 0o444))
        self.assertNotEqual(foreign.descriptor_identity(readonly, 'camp-app.exe', windows=True), expected)
        for changed in ('st_ino', 'st_dev', 'st_uid', 'st_gid', 'st_nlink'):
            other = SimpleNamespace(**dict(values, **{changed: 99}))
            self.assertNotEqual(foreign.descriptor_identity(other, 'camp-app.exe', windows=True), expected)
        with self.assertRaises(ValueError):
            foreign.descriptor_identity(info, 'other.exe', windows=True)

    def prepare(self, root):
        home = selected.SelectedContracts().fixture(root)
        source = root/'festival'; source.write_bytes(b'known public Installer fixture bytes; never executed in unit contracts')
        return home, source

    def test_substitution_retains_real_receipt_and_exact_manual_original_restore(self):
        self.check_substitution('festival')
        self.check_substitution('festival-app-installer')

    def check_substitution(self, installer_name):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); home, source = self.prepare(root)
            if source.name != installer_name:
                source = source.rename(root/installer_name)
            before = checked_receipts(home)
            mtime = (home/'bin/camp-app').stat().st_mtime_ns
            report = {}; fixture = foreign.Fixture(home, source, root/'private', report)
            try:
                fixture.substitute()
                self.assertEqual(foreign.receipt_metadata(home), before)
                self.assertEqual(fixture.path.read_bytes(), source.read_bytes())
                self.assertTrue(fixture.unchanged()['preserved'])
                with self.assertRaisesRegex(ValueError, 'differs from'): checked_receipts(home)
                for row in before['files']:
                    if row['receipt_pkg_id'] != foreign.COMPANION:
                        self.assertEqual(hashlib.sha256(Path(row['path']).read_bytes()).hexdigest(), row['hash'])
            finally: fixture.restore()
            self.assertEqual(checked_receipts(home), before)
            self.assertEqual(fixture.path.stat().st_mtime_ns, mtime)
            self.assertTrue(fixture.healthy()['unchanged'])
            self.assertFalse(report['backup_uploaded'])

    def test_partial_substitution_retains_original_error_and_refuses_unknown_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);home,source=self.prepare(root);report={}
            fixture=foreign.Fixture(home,source,root/'private',report)
            def interrupted_write(*arguments):
                fixture.path.write_bytes(b'partial owned write')
                raise OSError('original injected disk-write failure')
            with patch.object(fixture,'write',side_effect=interrupted_write):
                with self.assertRaisesRegex(OSError,'original injected disk-write failure'):
                    fixture.substitute()
            self.assertEqual(report['substitution_stage'],'writing')
            with self.assertRaisesRegex(ValueError,'did not complete.*unknown partial state'):
                fixture.restore()
            self.assertEqual(fixture.path.read_bytes(),b'partial owned write')
            self.assertFalse(fixture.restored)

    def test_preexisting_foreign_symlink_hardlink_or_source_link_never_mutated(self):
        for case in ('foreign', 'symlink', 'hardlink', 'source-link'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);home,source=self.prepare(root);target=home/'bin/camp-app'
                if case == 'foreign': target.write_bytes(b'existing unrelated user content')
                elif case == 'symlink':
                    original=root/'original';target.rename(original);target.symlink_to(original)
                elif case == 'hardlink':os.link(target,root/'other')
                else:
                    original=root/'source-original';source.rename(original);source.symlink_to(original)
                contents=target.read_bytes()
                with self.assertRaises(ValueError):foreign.Fixture(home,source,root/'private',{})
                self.assertEqual(target.read_bytes(),contents)
                self.assertFalse((root/'private').exists())

    def test_windows_junction_parent_is_refused_before_backup_or_target_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);home,source=self.prepare(root)
            original=(home/'bin/camp-app').read_bytes()
            with patch.object(Path,'is_junction',lambda path:path==home/'bin'),self.assertRaisesRegex(ValueError,'redirected'):
                foreign.Fixture(home,source,root/'private',{})
            self.assertEqual((home/'bin/camp-app').read_bytes(),original)
            self.assertFalse((root/'private').exists())

    def test_unknown_changes_refuse_rollback_without_overwriting_them(self):
        for case in ('target-bytes','target-inode','target-mtime','backup-bytes','target-mode'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);home,source=self.prepare(root)
                fixture=foreign.Fixture(home,source,root/'private',{});fixture.substitute()
                if case=='target-bytes':fixture.path.write_bytes(b'foreign user replacement')
                elif case=='target-inode':
                    replacement=root/'other';replacement.write_bytes(fixture.foreign);os.replace(replacement,fixture.path)
                elif case=='target-mtime':os.utime(fixture.path,ns=(1,1))
                elif case=='backup-bytes':fixture.backup.write_bytes(b'unknown original')
                else:fixture.path.chmod(0o444)
                before=fixture.path.read_bytes()
                with self.assertRaises(ValueError):fixture.restore()
                self.assertEqual(fixture.path.read_bytes(),before)
                self.assertFalse(fixture.restored)

    def test_actual_probe_contract_requires_incompatibility_and_explicit_foreign_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);home,source=self.prepare(root)
            fixture=foreign.Fixture(home,source,root/'private',{});fixture.substitute()
            status={'ok':True,'data':{'tools':[{'tool':'camp-app','path':str(fixture.path),'present':True,
                     'receipt_version':'0.1.0','error':'version --json refused: unknown flag'}]}}
            update={'ok':True,'data':{'package':foreign.COMPANION,'action':'unmanaged',
                    'upgrade':'E_PLUGIN_FOREIGN: preserved '+str(fixture.path)}}
            try:
                with patch.object(foreign,'command',side_effect=[status,update]):
                    self.assertEqual(foreign.probe(source,fixture,{},root)['update']['action'],'unmanaged')
                for bad in [dict(update,ok=False),{'ok':True,'data':dict(update['data'],action='upgraded')},
                            {'ok':True,'data':dict(update['data'],upgrade='preserved something else')}]:
                    with patch.object(foreign,'command',side_effect=[status,bad]),self.assertRaises(ValueError):foreign.probe(source,fixture,{},root)
                good=copy.deepcopy(status);good['data']['tools'][0]['error']=''
                with patch.object(foreign,'command',return_value=good),self.assertRaises(ValueError):foreign.probe(source,fixture,{},root)
            finally:fixture.restore()

    def test_specific_failed_update_row_and_way_out_are_required(self):
        observed={'tool':{'path':'C:\\owned\\camp-app.exe','error':'unknown flag: --json'}}
        message='camp-app at C:\\owned\\camp-app.exe could not be checked: unknown flag: --json. '+foreign.WAY_OUT
        row='Update anything older than this app needsFailed'+message
        window={'uia_verified':True,'visible_names':['Getting this machine ready','A step did not finish. Its detail is below.',row]}
        self.assertTrue(foreign.error_window(window,observed))
        for altered in [dict(window,uia_verified=False),dict(window,visible_names=window['visible_names'][1:]),
                        dict(window,visible_names=[row.replace('Update anything older than this app needs','Install selected app packages')]),
                        dict(window,visible_names=[*window['visible_names'][:2],row.replace(foreign.WAY_OUT,'Everything is ready')])]:
            self.assertFalse(foreign.error_window(altered,observed))

    def test_during_failure_receipts_other_files_service_and_user_state_stay_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);home,source=self.prepare(root);original=checked_receipts(home)
            unit=root/'service';unit.write_bytes(b'owned registered unit')
            service={'installed':True,'loaded':True,'socket_reachable':True,'daemon_pid':55,'unit_path':str(unit)}
            preserved={'foreign-file':'unchanged'};lifecycle={'lastUpdateCheckAt':'2026-10-24T00:00:00Z','setupCompletedAt':None}
            before={'receipts':original,'mtimes':{row['path']:Path(row['path']).stat().st_mtime_ns for row in original['files']},
                    'preserved':preserved,'lifecycle':lifecycle,'pending_obey_restart':False,'service':service,
                    'unit':{'path':str(unit),'sha256':hashlib.sha256(unit.read_bytes()).hexdigest(),'mtime_ns':unit.stat().st_mtime_ns}}
            campaign=root/'camp';campaign.mkdir()
            setup={'managed_home':home,'camp':home/'bin/camp','camp_id':'fixture-id','fixture':campaign}
            fixture=foreign.Fixture(home,source,root/'private',{});fixture.substitute()
            try:
                with patch('existing_obey.settings_readback',return_value=({},preserved,lifecycle,'now')),patch('existing_obey.service',return_value=service),patch.object(foreign,'command',return_value=[{'id':'fixture-id','path':str(campaign)}]):
                    result=foreign.preserved_user(setup,before,fixture,{})
                    self.assertEqual(result['receipt_metadata'],original)
                    self.assertNotEqual(result['foreign_file']['sha256'],next(row['hash'] for row in original['files'] if row['receipt_pkg_id']==foreign.COMPANION))
                    (home/'bin/fest').write_bytes(b'changed other selected tool')
                    with self.assertRaisesRegex(ValueError,'physical file'):foreign.preserved_user(setup,before,fixture,{})
            finally:fixture.restore()

    def test_nonwindows_native_mode_refused_before_any_package_execution(self):
        with patch.object(app,'require_clean_host'),self.assertRaisesRegex(ValueError,'native Windows'):
            app.native(Path('/unused'),{},'x86_64-unknown-linux-gnu',Path('/unused'),fresh_setup=True,existing_user='foreign-companion')
