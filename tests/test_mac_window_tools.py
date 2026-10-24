"""Compiler/query separation and negative contracts in filesystem isolation."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('macOS tool filesystem fixtures require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import mac_window_tools as tools


class MacWindowToolsContracts(unittest.TestCase):
    def prepared(self, root, calls):
        work=root/'work';work.mkdir();output=root/'proof';output.mkdir()
        frontend=root/'swift-frontend';frontend.write_bytes(b'owned compiler')
        compiler=root/'swiftc';compiler.symlink_to(frontend)
        sdk=root/'MacOSX.sdk';sdk.mkdir()
        environment={'CANDIDATE_NATIVE_DISPOSABLE':'1','CANDIDATE_RUNNER_KIND':'github-hosted'}
        def command(arguments, environment, **kwargs):
            values=[str(value) for value in arguments];calls.append((values,kwargs))
            if values[:2]==['xcrun','--find']:return str(compiler)+'\n'
            if values[-1]=='--show-sdk-path':return str(sdk)+'\n'
            if values[-1]=='--show-sdk-version':return '15.0\n'
            if values[-1]=='--version':return 'fixture Swift compiler\n'
            if '-o' in values:
                Path(values[values.index('-o')+1]).write_bytes(('compiled '+values[-1]).encode())
                return ''
            if values[0].endswith('owned-mac-query'):
                return [{'kCGWindowOwnerPID':int(values[1]),'kCGWindowNumber':17}]
            return 'Normal AppKit termination requested'
        with patch.object(tools.sys,'platform','darwin'),patch.object(tools,'command',side_effect=command):
            prepared=tools.prepare(work,output,environment)
        return prepared,output,environment,command

    def test_prepare_compiles_once_and_queries_only_run_prepared_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            calls=[];prepared,output,environment,command=self.prepared(Path(directory),calls)
            self.assertEqual(sum('-o' in call[0] for call in calls),2)
            with patch.object(tools,'command',side_effect=command):
                self.assertEqual(prepared.query(10,environment)[0]['kCGWindowNumber'],17)
                prepared.query(11,environment)
                prepared.quit(10,Path(directory)/'Owned.app',environment)
            self.assertEqual(sum('-o' in call[0] for call in calls),2)
            self.assertTrue(all(call[1]['timeout']==10 for call in calls if call[0][0].endswith('owned-mac-query')))
            record=json.loads((output/'mac-window-tools.json').read_text())
            self.assertTrue(record['complete'])
            self.assertEqual(Path(record['compiler']).name,'swiftc')
            self.assertEqual(Path(record['compiler_resolved_path']).name,'swift-frontend')
            self.assertTrue(all(Path(call[0][0]).name=='swiftc' for call in calls if '-o' in call[0]))
            self.assertTrue(all(call[0][call[0].index('-sdk')+1]==record['sdk_path'] for call in calls if '-o' in call[0]))
            self.assertEqual(record['sdk_version'],'15.0')
            self.assertTrue(record['prepared_before_app_launch'])
            self.assertEqual(set(record['helpers']),{'query','quit'})
            self.assertTrue(all(len(row['source_sha256'])==len(row['binary_sha256'])==64 for row in record['helpers'].values()))

    def test_foreign_windows_invalid_pid_and_changed_helper_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            prepared,_,environment,_=self.prepared(Path(directory),[])
            for pid in (0,-1,True,'10'):
                with self.assertRaises(ValueError):prepared.query(pid,environment)
            with patch.object(tools,'command',return_value=[{'kCGWindowOwnerPID':99}]):
                with self.assertRaisesRegex(ValueError,'foreign'):prepared.query(10,environment)
            prepared.query_binary.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'identity changed'):prepared.query(10,environment)

    def test_compiler_failure_retains_incomplete_build_without_query_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);work=root/'work';work.mkdir();output=root/'proof';output.mkdir()
            compiler=root/'swiftc';compiler.write_bytes(b'compiler')
            sdk=root/'MacOSX.sdk';sdk.mkdir()
            def command(arguments,environment,**kwargs):
                if arguments[:2]==['xcrun','--find']:return str(compiler)
                if arguments[-1]=='--show-sdk-path':return str(sdk)
                if arguments[-1]=='--show-sdk-version':return '15.0'
                if arguments[-1]=='--version':return 'fixture compiler'
                raise RuntimeError('compiler failed before App launch')
            with patch.object(tools.sys,'platform','darwin'),patch.object(tools,'command',side_effect=command):
                with self.assertRaisesRegex(RuntimeError,'compiler failed'):
                    tools.prepare(work,output,{'CANDIDATE_NATIVE_DISPOSABLE':'1','CANDIDATE_RUNNER_KIND':'github-hosted'})
            record=json.loads((output/'mac-window-tools.json').read_text())
            self.assertFalse(record['complete'])
            self.assertIn('compiler failed',record['failure'])

    def test_operator_or_non_native_context_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError,'disposable'):
                tools.prepare(Path(directory),Path(directory),{})
