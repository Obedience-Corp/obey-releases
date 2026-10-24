"""Profile mutations and actual pty children run only in filesystem isolation."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('login-shell tests require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import login_shell


class LoginShellContracts(unittest.TestCase):
    def test_foreign_profile_bytes_survive_fixture_append(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); profile = home / '.bash_profile'
            original = b'# user profile\nexport USER_PREFERENCE=keep\n'
            profile.write_bytes(original)
            fixture = login_shell.seed_profile(profile, home, 'bash')
            self.assertTrue(profile.read_bytes().startswith(original))
            self.assertEqual(profile.read_bytes(), fixture['seeded'])
            self.assertIn(fixture['function'].encode(), profile.read_bytes())
            self.assertNotIn('TOKEN', profile.read_text())

    def test_profile_escape_symlink_and_foreign_parent_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); home = root / 'home'; home.mkdir()
            foreign = root / 'foreign'; foreign.mkdir(); target = foreign / 'rc'; target.write_bytes(b'keep')
            for path in [target, home / '..' / 'foreign/rc']:
                with self.assertRaisesRegex(ValueError, 'outside'):
                    login_shell.seed_profile(path, home, 'bash')
            (home / 'config').symlink_to(foreign, target_is_directory=True)
            with self.assertRaises(ValueError): login_shell.seed_profile(home / 'config/rc', home, 'bash')
            self.assertEqual(target.read_bytes(), b'keep')

    def test_resolution_requires_real_expected_file_version_and_foreign_function(self):
        with tempfile.TemporaryDirectory() as directory:
            managed = Path(directory); (managed / 'bin').mkdir(); expected = managed / 'bin/camp'; expected.write_bytes(b'official')
            marker = 'FA0027_test'
            def data(path=expected, version='0.16.2', value='kept'):
                return f'{marker}_PROFILE\r\n{value}\r\n{marker}_PATH\r\n{path}\r\n{marker}_VERSION\r\n{version}\r\n{marker}_END\r\n'.encode()
            self.assertTrue(login_shell.parse_probe(data(), marker, 'kept', 'camp', managed)['profile_sentinel_verified'])
            foreign = managed / 'foreign'; foreign.write_bytes(b'foreign')
            for raw in [data(path=foreign), data(version='0.16.1'), data(value='lost'), data()+f'{marker}_END\n'.encode(), data().replace(f'{marker}_PATH'.encode(), b'missing')]:
                with self.assertRaises(ValueError): login_shell.parse_probe(raw, marker, 'kept', 'camp', managed)

    def test_real_pty_preserves_ansi_and_reaps_timed_out_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'normal.log'
            login_shell.pty_run([sys.executable, '-c', "print('\\x1b[31mreal terminal\\x1b[0m', flush=True)"], dict(os.environ), output)
            self.assertIn(b'\x1b[31mreal terminal\x1b[0m', output.read_bytes())
            timed = root / 'timeout.log'
            with self.assertRaisesRegex(RuntimeError, 'bounded'):
                login_shell.pty_run([sys.executable, '-c', 'import os,time; print(os.getpid(),flush=True); time.sleep(30)'], dict(os.environ), timed, timeout=2)
            child = int(timed.read_text().strip())
            with self.assertRaises(ProcessLookupError): os.kill(child, 0)

    def test_failed_exec_does_not_return_into_native_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'bad.log'
            with self.assertRaisesRegex(RuntimeError, 'command failed'):
                login_shell.pty_run(['/definitely/not/an/executable'], dict(os.environ), output)
            self.assertIn(b'could not start', output.read_bytes())
