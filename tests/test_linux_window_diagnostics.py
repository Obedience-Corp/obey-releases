import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('filesystem tests require Docker')
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_window_diagnostics as diagnostics
import verify_app_candidate as app


class LinuxWindowDiagnosticsTests(unittest.TestCase):
    def test_process_snapshot_limits_scope_to_root_and_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for pid, parent in [(10,1),(11,10),(12,11),(99,1)]:
                directory = root / str(pid); directory.mkdir()
                fields = ['S',str(parent),'10','10'] + ['0'] * 15 + [str(pid*100)]
                (directory/'stat').write_text(str(pid)+' (owned app) '+' '.join(fields))
                (directory/'exe').symlink_to('/owned/app')
                (directory/'cwd').symlink_to('/owned')
            snapshot = diagnostics.process_inventory(10,root)
            self.assertEqual([item['pid'] for item in snapshot],[10,11,12])
            self.assertEqual(snapshot[0]['start_ticks'],1000)
            self.assertFalse(any('cmdline' in item or 'environment' in item for item in snapshot))

    def test_probe_failures_are_retained_without_signaling_any_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); process = Mock(pid=10); process.poll.return_value=None
            result = Mock(returncode=1,stdout='owned display tree',stderr='no matching window')
            with patch.object(diagnostics,'process_inventory',return_value=[{'pid':10,'start_ticks':1000}]), patch.object(diagnostics.subprocess,'run',side_effect=[result,FileNotFoundError('wmctrl absent'),result,result,result]):
                path = diagnostics.capture_failure(process,root/'a.png',{'DISPLAY':':99','WAYLAND_DISPLAY':'wayland-0','GH_TOKEN':'must-not-leak'},RuntimeError('owned App window timed out'))
            record=json.loads(path.read_text())
            self.assertTrue(record['diagnostic_only'])
            self.assertEqual(record['display'],':99')
            self.assertEqual(record['display_selection']['WAYLAND_DISPLAY'],'wayland-0')
            self.assertNotIn('must-not-leak',path.read_text())
            self.assertIn('wmctrl absent',record['probes'][1]['error'])
            process.kill.assert_not_called();process.terminate.assert_not_called()

    def test_queries_only_bounded_numeric_windows_and_reports_stale_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            process=Mock(pid=10);process.poll.return_value=None
            found=Mock(returncode=0,stdout='17\n18\n17\n--root\n0\n4294967296\n19\n20\n21\n',stderr='')
            result=Mock(returncode=0,stdout='Map State: IsUnMapped',stderr='')
            with patch.object(diagnostics,'process_inventory',side_effect=[
                    [{'pid':10,'start_ticks':1000}],[{'pid':10,'start_ticks':2000}]]), \
                    patch.object(diagnostics.subprocess,'run',side_effect=[found]+[result]*12) as run:
                path=diagnostics.capture_failure(process,Path(temporary)/'a.png',{'DISPLAY':':99'},RuntimeError('original window failure'))
            record=json.loads(path.read_text())
            self.assertEqual(record['owned_pid_window_ids'],['17','18','19','20','21'])
            self.assertTrue(record['window_queries_truncated'])
            per_window=[call.args[0] for call in run.call_args_list if '-id' in call.args[0]]
            self.assertEqual([args[2] for args in per_window],['17','17','18','18','19','19','20','20'])
            self.assertTrue(any('WM_STATE' in args for args in per_window))
            self.assertFalse(record['post_probe_root_identity_verified'])
            self.assertIn('stale',record['post_probe_identity_error'])
            self.assertEqual(record['failure'],'original window failure')
            process.kill.assert_not_called();process.terminate.assert_not_called()

    def test_exhausted_diagnostic_budget_records_failure_without_more_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            process=Mock(pid=10);process.poll.return_value=1
            with patch.object(diagnostics.time,'monotonic',side_effect=[0,31,31,31,31,31]), \
                    patch.object(diagnostics.subprocess,'run') as run:
                path=diagnostics.capture_failure(process,Path(temporary)/'a.png',{'DISPLAY':':99'},RuntimeError('original window failure'))
            run.assert_not_called()
            record=json.loads(path.read_text())
            self.assertTrue(all('error' in probe for probe in record['probes']))
            self.assertEqual(record['failure'],'original window failure')

    def test_diagnostic_error_never_masks_original_window_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            process=Mock(pid=10);process.poll.return_value=None
            with patch.object(app,'wait_until',side_effect=RuntimeError('original owned window failure')), patch.object(app,'capture_linux_failure',side_effect=OSError('diagnostic write failed')):
                with self.assertRaisesRegex(RuntimeError,'original owned window failure'):
                    app.window_capture(process,'x86_64-unknown-linux-gnu',Path(temporary)/'a.png',{'DISPLAY':':99'})
