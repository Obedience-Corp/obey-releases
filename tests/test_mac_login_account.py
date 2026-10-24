"""Account mutation contracts; native macOS controls separately exercise dscl."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import mac_login_account as account


class MacLoginAccountTests(unittest.TestCase):
    def fixture(self, shell='/bin/bash', environment_shell='/bin/bash'):
        before = {'uid': 501, 'home': '/Users/fixture', 'shell': shell}
        environment = {} if environment_shell is None else {'SHELL': environment_shell}
        return account.Account('fixture', before, environment, {}), dict(before)

    def test_selection_and_restoration_contract_preserves_original_environment(self):
        for shell in ('/bin/bash', '/bin/zsh'):
            with self.subTest(shell=shell):
                fixture, state = self.fixture(shell, None)
                def change(before, after):
                    self.assertEqual(state['shell'], before)
                    state['shell'] = after
                with patch.object(account, 'read_account', side_effect=lambda *_: dict(state)), patch.object(fixture, 'change', side_effect=change):
                    fixture.activate()
                    self.assertEqual(state['shell'], '/bin/zsh')
                    self.assertEqual(fixture.environment['SHELL'], '/bin/zsh')
                    fixture.restore()
                    self.assertEqual(state, fixture.original)
                    self.assertNotIn('SHELL', fixture.environment)
                    self.assertTrue(fixture.record['restored'])

    def test_failed_change_that_already_mutated_restores_before_propagating(self):
        fixture, state = self.fixture()
        def change(before, after):
            self.assertEqual(state['shell'], before)
            state['shell'] = after
            if after == '/bin/zsh':
                raise RuntimeError('failed after actual mutation')
        with patch.object(account, 'read_account', side_effect=lambda *_: dict(state)), patch.object(fixture, 'change', side_effect=change):
            with self.assertRaisesRegex(RuntimeError, 'failed after actual mutation'):
                fixture.activate()
        self.assertEqual(state, fixture.original)
        self.assertEqual(fixture.environment['SHELL'], '/bin/bash')
        self.assertTrue(fixture.record['restored'])

    def test_unexpected_account_or_shell_is_not_overwritten(self):
        for change in ({'uid': 999}, {'home': '/Users/foreign'}, {'shell': '/bin/fish'}):
            fixture, state = self.fixture()
            fixture.attempted = True
            state.update(change)
            with self.subTest(change=change), patch.object(account, 'read_account', return_value=state), patch.object(fixture, 'change') as mutate:
                with self.assertRaises(RuntimeError):
                    fixture.restore()
                mutate.assert_not_called()

    def test_account_attributes_must_be_complete_unique_and_absolute(self):
        for text in ('UniqueID: 501\nUserShell: /bin/bash\n',
                     'UniqueID: 501\nNFSHomeDirectory: /Users/a\nUserShell: /bin/bash\nUserShell: /bin/zsh\n',
                     'UniqueID: 501\nNFSHomeDirectory: relative\nUserShell: /bin/bash\n'):
            with self.subTest(text=text), patch.object(account, 'command', return_value=text):
                with self.assertRaises(ValueError):
                    account.read_account('fixture', {})


if __name__ == '__main__':
    unittest.main()
