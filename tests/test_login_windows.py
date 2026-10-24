"""Wrapper/console readback negatives are filesystem-isolated contract tests."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('Windows login contract fixtures require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import login_windows
import windows_console


class WindowsLoginContracts(unittest.TestCase):
    def test_foreign_same_version_wrapper_and_wrong_external_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            managed=Path(directory); (managed/'bin').mkdir(); native=managed/'bin/camp'; native.write_bytes(b'official')
            body='\n command actual-camp @args\n'
            data={'foreign':['sentinel'], 'native_path':str(native), 'kind':'Function', 'definition':body, 'version_output':'v0.16.2\n'}
            result=login_windows.validate_tool(data,'camp',managed,'sentinel',body.replace('\n','\r\n'))
            self.assertTrue(result['installed_wrapper_verified'])
            foreign=managed/'foreign'; foreign.write_bytes(b'foreign')
            for changes in [{'definition':"'v0.16.2'"}, {'native_path':str(foreign)}, {'kind':'Alias'}, {'foreign':['lost']}, {'version_output':'v0.16.1'}]:
                broken=dict(data,**changes)
                with self.assertRaises(ValueError): login_windows.validate_tool(broken,'camp',managed,'sentinel',body)

    def test_plain_commands_cannot_be_replaced_by_same_version_functions(self):
        with tempfile.TemporaryDirectory() as directory:
            managed=Path(directory); (managed/'bin').mkdir(); native=managed/'bin/obey'; native.write_bytes(b'official')
            data={'foreign':['kept'], 'native_path':str(native), 'kind':'Application', 'definition':None, 'version_output':'v0.2.3'}
            self.assertEqual(login_windows.validate_tool(data,'obey',managed,'kept')['dispatch'],'executable')
            data['kind']='Function'
            with self.assertRaisesRegex(ValueError,'shadowed'):login_windows.validate_tool(data,'obey',managed,'kept')

    def test_actual_console_metadata_must_exclude_redirected_or_probe_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            shell=Path(directory)/'pwsh.exe'; shell.write_bytes(b'shell')
            good={'guard':{'host':'ConsoleHost','input_redirected':False,'user_interactive':True,'probe_marker':None,'startup_flags':['-NoLogo']},
                  'console_process':{'pid':123,'started':'456','path':str(shell)}}
            self.assertEqual(windows_console.validate_startup(good,shell)['pid'],123)
            for changes in [{'input_redirected':True},{'user_interactive':False},{'probe_marker':'1'}, {'startup_flags':['-NoLogo','-EncodedCommand','bad']}, {'host':'ServerRemoteHost'}]:
                bad=copy.deepcopy(good);bad['guard'].update(changes)
                with self.assertRaises(ValueError):windows_console.validate_startup(bad,shell)
