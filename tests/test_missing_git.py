import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import missing_git
from missing_git import removal_plan


class GitRemovalPlanTests(unittest.TestCase):
    def test_missing_git_mode_refuses_other_platform_seed_and_login_paths(self):
        import verify_app_candidate as app
        baseline = dict(target='x86_64-unknown-linux-gnu', fresh_setup=True,
                        linux_package='both', existing_user='none', login_shell_proof=False,
                        missing_git_manual=True)
        for change in ({'target': 'aarch64-apple-darwin'}, {'fresh_setup': False},
                       {'linux_package': 'appimage'}, {'existing_user': 'current'},
                       {'login_shell_proof': True}):
            with self.subTest(change=change), patch.object(app, 'require_clean_host'), self.assertRaises(ValueError):
                app.native(Path('/never-used'), {}, output=Path('/never-created'), **dict(baseline, **change))

    def test_prerequisite_requires_one_real_boolean_git_row(self):
        baseline = {'ok': True, 'data': {'prerequisites': [{'name': 'git', 'present': False}]}}
        output = Mock()
        with patch.object(missing_git, 'command', return_value=baseline):
            self.assertEqual(missing_git.git_status('/owned/festival', {}, False, output), baseline['data']['prerequisites'][0])
        for row in ([], [{'name': 'git', 'present': 0}], [{'name': 'git', 'present': None}],
                    baseline['data']['prerequisites']*2, [{'name': 'git', 'present': True}]):
            with self.subTest(row=row), patch.object(missing_git, 'command', return_value={'ok': True, 'data': {'prerequisites': row}}), self.assertRaises(RuntimeError):
                missing_git.git_status('/owned/festival', {}, False, output)

    def test_exact_git_and_dependent_lfs_only(self):
        before = {'git': '1:2.43.0-1', 'git-lfs': '3.4.1-1', 'foreign': '1'}
        self.assertEqual(removal_plan('Remv git-lfs [3.4.1-1]\nRemv git [1:2.43.0-1]\n', before),
                         {'git': '1:2.43.0-1', 'git-lfs': '3.4.1-1'})

    def test_observed_hosted_reverse_dependencies_require_exact_installed_versions(self):
        before = {'gh': '2.102.0', 'git-lfs': '3.8.0', 'git-ftp': '1.6.0+dfsg-1',
                  'ubuntu-server': '1.539.2', 'git': '1:2.55.0-0ppa1~ubuntu24.04.2'}
        plan = ''.join(f'Remv {name} [{version}]\n' for name, version in before.items())
        self.assertEqual(removal_plan(plan, before), before)
        with self.assertRaises(ValueError):
            removal_plan(plan.replace('2.102.0', '2.101.0'), before)
        with self.assertRaises(ValueError):
            removal_plan(plan + 'Remv unrelated [1]\n', dict(before, unrelated='1'))

    def test_foreign_change_install_duplicate_missing_and_version_mismatch_refused(self):
        with self.assertRaises(ValueError):
            removal_plan('Remv git-lfs [1]\n', {'git-lfs': '1'})
        for text in ('Remv git [1]\nRemv foreign [1]\n', 'Inst git [1]\n',
                     'Remv git [1]\nRemv git [1]\n', 'Remv git-lfs [1]\n',
                     'Remv git [2]\n', 'Remv git:amd64 [1]\n', 'Remv git\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                removal_plan(text, {'git': '1', 'git-lfs': '1', 'foreign': '1'})


if __name__ == '__main__':
    unittest.main()
