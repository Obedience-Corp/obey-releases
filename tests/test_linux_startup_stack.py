import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('filesystem tests require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_startup_stack as stack


class StartupStackTests(unittest.TestCase):
    def test_mixed_uid_or_gid_credentials_are_refused(self):
        for text in ('Uid: 10001 0 10001 10001\nGid: 10001 10001 10001 10001\n',
                     'Uid: 10001 10001 10001 10001\nGid: 10001 0 10001 10001\n'):
            with patch.object(stack.Path, 'read_text', return_value=text):
                with self.assertRaisesRegex(ValueError, 'mixed process credentials'):
                    stack.owner_identity(42)

    def test_exited_stale_or_stopped_process_is_never_attached(self):
        for code, birth, state in [(0, 100, 'S'), (None, 101, 'S'), (None, 100, 'T')]:
            with self.subTest(code=code, birth=birth, state=state), \
                    patch.object(stack, 'identity', return_value={'start_ticks': birth, 'state': state}), \
                    patch.object(stack.subprocess, 'run') as run:
                process = Mock(pid=42); process.poll.return_value = code
                result = stack.capture(process, 100, Path('/never-created'), {})
                self.assertIn('skipped', result)
                run.assert_not_called()

    def test_missing_debugger_records_failure_without_changing_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Mock(pid=42); process.poll.side_effect = [None, 0]
            with patch.object(stack, 'identity', return_value={'start_ticks': 100, 'state': 'S'}), \
                    patch.object(stack, 'owner_identity', return_value={'Uid':10001, 'Gid':10001}), \
                    patch.object(stack.subprocess, 'run', side_effect=FileNotFoundError('no debugger')) as run:
                result = stack.capture(process, 100, Path(temporary)/'stack.log',
                                       {'PATH': '/usr/bin', 'SECRET': 'do-not-copy'})
            self.assertIn('no debugger', result['error'])
            self.assertNotIn('SECRET', run.call_args.kwargs['env'])
            self.assertIn('set auto-load off', result['command'])
            self.assertIn('bt -no-filters -frame-arguments none', ' '.join(result['command']))
            process.kill.assert_not_called(); process.terminate.assert_not_called()
