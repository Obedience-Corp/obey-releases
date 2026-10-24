"""Account mutation contracts; native macOS controls separately exercise dscl."""
from pathlib import Path
from types import SimpleNamespace
import pwd
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
                with patch.object(account, 'read_account', side_effect=lambda *_: dict(state)), patch.object(fixture, 'change', side_effect=change), patch.object(account, 'wait_passwd', return_value={}):
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
        with patch.object(account, 'read_account', side_effect=lambda *_: dict(state)), patch.object(fixture, 'change', side_effect=change), patch.object(account, 'wait_passwd', return_value={}):
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


    def test_passwd_timeout_after_real_change_restores_before_propagation(self):
        fixture, state = self.fixture()
        def change(before, after):
            self.assertEqual(state['shell'], before)
            state['shell'] = after
        with patch.object(account, 'read_account', side_effect=lambda *_: dict(state)), patch.object(fixture, 'change', side_effect=change), \
                patch.object(account, 'wait_passwd', side_effect=[RuntimeError('convergence timeout'), {}]):
            with self.assertRaisesRegex(RuntimeError, 'convergence timeout'):
                fixture.activate()
        self.assertEqual(state, fixture.original)
        self.assertEqual(fixture.environment['SHELL'], '/bin/bash')
        self.assertTrue(fixture.record['restored'])

    def owner(self, shell='/bin/zsh', **changes):
        return SimpleNamespace(**dict({'pw_name': 'fixture', 'pw_uid': 501,
                                      'pw_dir': '/Users/fixture', 'pw_shell': shell}, **changes))

    def test_passwd_delayed_convergence_preserves_actual_observations_and_identity(self):
        expected = {'uid': 501, 'home': '/Users/fixture', 'shell': '/bin/zsh'}
        observations = []
        with patch.object(pwd, 'getpwuid', side_effect=[self.owner('/bin/bash'), self.owner()]), patch.object(account.time, 'sleep'):
            result = account.wait_passwd('fixture', expected, '/bin/bash', observations)
        self.assertEqual([row['shell'] for row in observations], ['/bin/bash', '/bin/zsh'])
        self.assertEqual(result['shell'], '/bin/zsh')

    def test_passwd_timeout_foreign_identity_shell_and_query_errors_still_fail(self):
        expected = {'uid': 501, 'home': '/Users/fixture', 'shell': '/bin/zsh'}
        with patch.object(pwd, 'getpwuid', return_value=self.owner('/bin/bash')), patch.object(account.time, 'monotonic', side_effect=[0, 16]):
            with self.assertRaisesRegex(RuntimeError, 'timeout'):
                account.wait_passwd('fixture', expected, '/bin/bash', [])
        for change in [{'pw_name': 'foreign'}, {'pw_uid': 999}, {'pw_dir': '/Users/foreign'}, {'pw_shell': '/bin/fish'}]:
            with self.subTest(change=change), patch.object(pwd, 'getpwuid', return_value=self.owner(**change)), patch.object(account.time, 'sleep') as sleep:
                with self.assertRaises(RuntimeError): account.wait_passwd('fixture', expected, '/bin/bash', [])
                sleep.assert_not_called()
        with patch.object(pwd, 'getpwuid', side_effect=KeyError('query failed')):
            with self.assertRaises(KeyError): account.wait_passwd('fixture', expected, '/bin/bash', [])


if __name__ == '__main__':
    unittest.main()
