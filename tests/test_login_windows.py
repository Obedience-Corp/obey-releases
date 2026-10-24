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

    def test_conpty_eof_requires_actual_exit_eof_and_known_status(self):
        class ReadFailure(Exception): pass
        class Terminal:
            alive=False; eof=True; status=0
            def read(self, blocking): raise ReadFailure('Standard out reached EOF')
            def isalive(self): return self.alive
            def iseof(self): return self.eof
            def get_exitstatus(self): return self.status
        terminal=Terminal()
        self.assertIsNone(windows_console.read_terminal(terminal,ReadFailure))
        for changes in [{'alive':True},{'eof':False},{'status':None},{'status':False}]:
            broken=Terminal()
            for key,value in changes.items():setattr(broken,key,value)
            with self.assertRaises(ReadFailure):windows_console.read_terminal(broken,ReadFailure)
        terminal.status=7
        self.assertIsNone(windows_console.read_terminal(terminal,ReadFailure))
        # EOF doesn't convert a failed shell exit to success: its status remains
        # available to the adapter's strict nonzero return-code propagation.
        self.assertEqual(terminal.get_exitstatus(),7)

    def test_conpty_drain_preserves_trailing_chunks_and_rejects_unrelated_error(self):
        import io
        class ReadFailure(Exception): pass
        class Terminal:
            def __init__(self):self.eof=False;self.chunks=iter(['tail\x1b[31m','last','Standard out reached EOF'])
            def read(self,blocking):
                value=next(self.chunks)
                if value=='Standard out reached EOF':
                    self.eof=True
                    raise ReadFailure(value)
                return value
            def isalive(self):return False
            def get_exitstatus(self):return 0
            def iseof(self):return self.eof
        output=io.BytesIO()
        windows_console.drain_terminal(Terminal(),ReadFailure,output)
        self.assertEqual(output.getvalue(),b'tail\x1b[31mlast')
        terminal=Terminal()
        def fail(blocking):raise ReadFailure('unrelated failure')
        terminal.read=fail
        with self.assertRaisesRegex(ReadFailure,'unrelated'):
            windows_console.drain_terminal(terminal,ReadFailure,io.BytesIO())

    def test_conpty_async_empty_and_already_consumed_eof_finish_drain(self):
        import io
        class ReadFailure(Exception):pass
        class Terminal:
            eof=False
            def isalive(self):return False
            def get_exitstatus(self):return 0
            def iseof(self):return self.eof
            def read(self,blocking):self.eof=True;return ''
        terminal=Terminal()
        self.assertIsNone(windows_console.read_terminal(terminal,ReadFailure))
        # A previous read consumed EOF. The next drain must use authoritative
        # queue/reader/pipe EOF rather than wait for another one-shot event.
        def forbidden(blocking):raise AssertionError('already drained')
        terminal.read=forbidden
        windows_console.drain_terminal(terminal,ReadFailure,io.BytesIO())

    def test_empty_conpty_error_requires_post_error_proven_eof_and_retains_diagnostics(self):
        class ReadFailure(Exception):pass
        class Terminal:
            alive=False;status=0;eof=False
            def isalive(self):return self.alive
            def get_exitstatus(self):return self.status
            def iseof(self):return self.eof
            def read(self,blocking):self.eof=True;raise ReadFailure('')
        terminal=Terminal();records=[]
        self.assertIsNone(windows_console.read_terminal(terminal,ReadFailure,records.append))
        self.assertEqual(records,[{'alive':False,'status':0,'iseof':True,'event':'read-error','error_type':'ReadFailure','error':''}])
        for changes in [{'alive':True},{'status':None}]:
            terminal=Terminal()
            for key,value in changes.items():setattr(terminal,key,value)
            with self.assertRaises(ReadFailure):windows_console.read_terminal(terminal,ReadFailure)
        terminal=Terminal()
        def unrelated(blocking):terminal.eof=True;raise ReadFailure('unrelated')
        terminal.read=unrelated
        with self.assertRaisesRegex(ReadFailure,'unrelated'):windows_console.read_terminal(terminal,ReadFailure)
        terminal=Terminal()
        def no_eof(blocking):raise ReadFailure('')
        terminal.read=no_eof
        with self.assertRaises(ReadFailure):windows_console.read_terminal(terminal,ReadFailure)
