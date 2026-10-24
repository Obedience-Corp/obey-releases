"""Guest failure cleanup must not signal unrelated processes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('guest process/file controls require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_guest


class GuestCleanup(unittest.TestCase):
    def test_password_is_not_typed_into_existing_session_or_non_greeter(self):
        for replies, message in ((['{"session": "already active"}'], 'already logged-in'),
                                 (['null', 'false'], 'active LightDM greeter')):
            with self.subTest(replies=replies):
                guest = linux_guest.Guest.__new__(linux_guest.Guest)
                guest.ssh = Mock(side_effect=[SimpleNamespace(stdout=value) for value in replies])
                guest.qmp_commands = Mock()
                with self.assertRaisesRegex(RuntimeError, message):
                    guest.login('onlyfixture123')
                guest.qmp_commands.assert_not_called()

    def test_failed_journey_releases_only_its_owned_process_and_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
            foreign = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
            try:
                guest = linux_guest.Guest.__new__(linux_guest.Guest)
                guest.process = owned
                guest.error_log = (Path(temporary) / 'qemu.log').open('w')
                result = guest.close()
                self.assertTrue(result['owned_process_stopped'])
                self.assertTrue(result['forced_stop'])
                self.assertTrue(guest.error_log.closed)
                self.assertIsNone(foreign.poll())
                self.assertFalse(guest.close()['forced_stop'])
            finally:
                for process in (owned, foreign):
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=10)

    def test_non_disposable_scope_refuses_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'proof'
            with self.assertRaisesRegex(RuntimeError, 'disposable GitHub-hosted'):
                linux_guest.prove(output, {})
            self.assertFalse(output.exists())
