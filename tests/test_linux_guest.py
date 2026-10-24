"""Guest failure cleanup must not signal unrelated processes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('guest process/file controls require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_guest


class GuestCleanup(unittest.TestCase):
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
