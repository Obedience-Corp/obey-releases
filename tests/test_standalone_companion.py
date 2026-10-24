import copy
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import standalone_companion as standalone
import verify_app_candidate as app
from verify_selected_components import checked_receipts, checked_status
import test_selected_components as selected_tests


class StandaloneCompanionContracts(unittest.TestCase):
    def setUp(self):
        if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
            raise RuntimeError('standalone mutation tests require Docker')
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def managed(self):
        home = selected_tests.SelectedContracts().fixture(self.root)
        with closing(sqlite3.connect(home/'state.db')) as db:
            db.execute("delete from receipt_files where receipt_pkg_id='obedience-corp/camp-app'")
            db.execute("delete from receipts where package_id='obedience-corp/camp-app'")
            db.commit()
        (home/'bin/camp-app').unlink()
        return home

    def test_two_receipt_optin_keeps_default_strict_and_refuses_adoption_extra_or_mixed(self):
        home = self.managed()
        self.assertEqual(len(checked_receipts(home, standalone_companion=True)['receipts']), 2)
        with self.assertRaises(ValueError): checked_receipts(home)
        with self.assertRaises(ValueError): checked_receipts(home, standalone_companion=True, external_suite='0.3.24')
        with closing(sqlite3.connect(home/'state.db')) as db:
            db.execute("insert into receipts values ('obedience-corp/camp-app','0.1.0','official-obey','stable')")
            db.commit()
        with self.assertRaises(ValueError): checked_receipts(home, standalone_companion=True)

    def document(self, home):
        tools = []
        for name,version,package,receipt in [('camp','0.16.2','festival','0.3.24'),('fest','0.9.8','festival','0.3.24'),
                                            ('obey','0.2.3','obey','0.2.3'),('ob','0.1.0','obey','0.2.3')]:
            tools.append({'tool':name,'version':version,'path':str(home/'bin'/name),'present':True,
                          'package':'obedience-corp/'+package,'receipt_version':receipt,'origin':'managed'})
        tools.append({'tool':'camp-app','version':'0.1.0','path':str(self.root/'.local/bin/camp-app'),
                      'present':True,'package':'obedience-corp/camp-app','origin':'leftover',
                      'protocol_major':1,'capabilities':['open','status']})
        return {'ok':True,'data':{'tools':tools}}

    def test_standalone_status_requires_exact_bind_ownership_protocol_and_other_managed_paths(self):
        home = self.managed(); document = self.document(home)
        with patch.object(Path,'home',return_value=self.root):
            checked_status(document,home,standalone_companion=True)
            with self.assertRaises(ValueError): checked_status(document,home)
            for key,value in [('origin','managed'),('receipt_version','0.1.0'),('path','/foreign/camp-app'),
                              ('protocol_major',2),('capabilities',['open']),('version','9.0.0')]:
                wrong = copy.deepcopy(document); wrong['data']['tools'][-1][key]=value
                with self.assertRaises(ValueError): checked_status(wrong,home,standalone_companion=True)
            wrong=copy.deepcopy(document);wrong['data']['tools'][3]['path']='/foreign/ob'
            with self.assertRaises(ValueError):checked_status(wrong,home,standalone_companion=True)

    def test_bind_identity_refuses_foreign_target_or_regular_copy(self):
        binary=self.root/'camp-app';binary.write_bytes(b'published fixture')
        bind=self.root/'bind';bind.symlink_to(binary)
        before=standalone.bind_state(bind,binary)
        self.assertEqual(before,standalone.bind_state(bind,binary))
        bind.unlink();other=self.root/'other';other.write_bytes(binary.read_bytes());bind.symlink_to(other)
        with self.assertRaises(ValueError):standalone.bind_state(bind,binary)
        bind.unlink();bind.write_bytes(binary.read_bytes())
        with self.assertRaises(ValueError):standalone.bind_state(bind,binary)

    def test_unreceipted_managed_duplicate_is_refused(self):
        home=self.managed();(home/'bin/camp-app').write_bytes(b'duplicate')
        fixture=standalone.Fixture.__new__(standalone.Fixture);fixture.managed=home
        with self.assertRaisesRegex(ValueError,'duplicated'):fixture.state(None)

    def test_partial_preparation_cleanup_never_claims_preservation_or_overwrites_unknown_state(self):
        environment={'PATH':'original'}
        fixture=standalone.Fixture(self.root,self.root/'managed',environment,self.root,{})
        fixture.cleanup()
        self.assertNotIn('standalone_preserved_after_app_uninstall',fixture.report)
        self.assertEqual(environment['PATH'],'original')

    def test_native_selector_refuses_other_formats_platforms_or_proof_combinations(self):
        for options in [dict(target='x86_64-pc-windows-msvc'),dict(target='x86_64-unknown-linux-gnu',linux_package='appimage'),
                        dict(target='x86_64-unknown-linux-gnu',login_shell_proof=True)]:
            target=options.pop('target')
            with patch.object(app,'require_clean_host'):
                with self.assertRaises(ValueError):app.native(self.root,{},target,self.root/'out',fresh_setup=True,existing_user='standalone-companion',**options)

    def test_published_camp_configuration_path_matches_default_and_xdg_contract(self):
        with patch.object(Path, 'home', return_value=self.root):
            self.assertEqual(standalone.camp_config_directory({}), self.root/'.obey/campaign')
            self.assertEqual(standalone.camp_config_directory({'XDG_CONFIG_HOME': ''}), self.root/'.obey/campaign')
            self.assertEqual(standalone.camp_config_directory({'XDG_CONFIG_HOME': str(self.root/'xdg')}), self.root/'xdg/obey/campaign')
