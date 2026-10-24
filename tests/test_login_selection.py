import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('shell-selection filesystem tests require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import login_shell
from verify_app_candidate import checked_login_selection


class LoginSelectionContracts(unittest.TestCase):
    def test_explicit_edition_uses_stock_system_path_not_path_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stock = root/'System32/WindowsPowerShell/v1.0/powershell.exe'
            stock.parent.mkdir(parents=True); stock.write_bytes(b'fixture path only')
            response = {'major': 5, 'version': '5.1.26100.1', 'profile': str(root/'profile.ps1')}
            for key in ('SystemRoot', 'SYSTEMROOT'):
                with self.subTest(key=key), patch.object(login_shell, 'command', return_value=response) as run, patch.object(login_shell.shutil, 'which', side_effect=AssertionError('foreign PATH queried')):
                    shell, kind, actual = login_shell.windows_runtime({key: str(root), 'PATH': '/foreign'}, 'windows-powershell')
                self.assertTrue(Path(shell).samefile(stock))
                self.assertEqual(kind, 'powershell'); self.assertEqual(actual, response)
                self.assertEqual(run.call_args.args[0][0], str(stock))
            with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
                login_shell.windows_runtime({'SystemRoot': str(root), 'SYSTEMROOT': '/foreign'}, 'windows-powershell')

    def test_missing_relative_and_wrong_edition_refused(self):
        with patch.object(login_shell, 'command', side_effect=AssertionError('unvalidated executable ran')):
            for root in ('', 'relative/root', '/missing/windows'):
                with self.subTest(root=root), self.assertRaises(RuntimeError):
                    login_shell.windows_runtime({'SystemRoot': root}, 'windows-powershell')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); stock = root/'System32/WindowsPowerShell/v1.0/powershell.exe'
            stock.parent.mkdir(parents=True); stock.write_bytes(b'fixture path only')
            for response in ({'major': 7, 'version': '7.5.4'}, {'major': 5, 'version': '5.0.1'}):
                with self.subTest(response=response), patch.object(login_shell, 'command', return_value=response), self.assertRaises(RuntimeError):
                    login_shell.windows_runtime({'SystemRoot': str(root)}, 'windows-powershell')

    def test_default_keeps_existing_powershell7_selection(self):
        value = {'major': 7, 'version': '7.5.4', 'profile': '/fixture/profile.ps1'}
        with patch.object(login_shell.shutil, 'which', return_value='/fixture/pwsh'), patch.object(login_shell, 'command', return_value=value):
            self.assertEqual(login_shell.windows_runtime({}, 'default'), ('/fixture/pwsh', 'pwsh', value))

    def test_explicit_shell_requires_matching_unseeded_native_login_mode(self):
        checked_login_selection('windows-powershell', True, True, 'x86_64-pc-windows-msvc', 'none', False)
        for target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
            checked_login_selection('zsh', True, True, target, 'none', False)
        cases = [('windows-powershell', False, True, 'x86_64-pc-windows-msvc', 'none', False),
                 ('windows-powershell', True, True, 'x86_64-unknown-linux-gnu', 'none', False),
                 ('zsh', True, True, 'x86_64-pc-windows-msvc', 'none', False),
                 ('zsh', True, False, 'aarch64-apple-darwin', 'none', False),
                 ('zsh', True, True, 'aarch64-apple-darwin', 'current', False),
                 ('zsh', True, True, 'aarch64-apple-darwin', 'none', True),
                 ('arbitrary-shell', True, True, 'aarch64-apple-darwin', 'none', False)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                checked_login_selection(*case)


if __name__ == '__main__':
    unittest.main()
