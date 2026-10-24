"""Rollback archive member mismatches must fail before package removal."""
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('rollback file fixtures require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import git_rollback as rollback


class GitRollbackTests(unittest.TestCase):
    def test_default_lfs_block_reordering_preserves_all_foreign_bytes(self):
        entries = [b'\tclean = git-lfs clean -- %f\n', b'\tsmudge = git-lfs smudge -- %f\n',
                   b'\tprocess = git-lfs filter-process\n', b'\trequired = true\n']
        foreign = b'[fixture]\n# keep exact comment\n\tkeep = yes\n'
        for ordered in (entries, list(reversed(entries))):
            block = b'[filter "lfs"]\n' + b''.join(ordered)
            self.assertEqual(rollback.without_default_lfs(block+foreign), foreign)
            self.assertEqual(rollback.without_default_lfs(foreign+block), foreign)
            for changed in (block+block, block+b'\tcustom = no\n',
                            block.replace(b'required = true', b'required = false'),
                            block+b'# foreign comment inside the section\n'):
                with self.assertRaises(ValueError):
                    rollback.without_default_lfs(changed)

    def test_config_symlink_file_and_ancestor_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict(os.environ, HOME=str(root)):
                target = root/'foreign'; target.write_bytes(b'unchanged')
                link = root/'.gitconfig'; link.symlink_to(target)
                with self.assertRaisesRegex(ValueError, 'regular'):
                    rollback.config_files(dict(os.environ, XDG_CONFIG_HOME=str(root/'config')))
                link.unlink()
                (root/'config').symlink_to(root/'foreign-config')
                with self.assertRaisesRegex(ValueError, 'ancestor'):
                    rollback.config_files(dict(os.environ, XDG_CONFIG_HOME=str(root/'config')))
                self.assertEqual(target.read_bytes(), b'unchanged')

    def inspect(self, path, expected, change=None):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w') as archive:
            info = archive.gettarinfo(str(path), arcname=str(path).lstrip('/'))
            if change:
                change(info)
            if info.isfile():
                archive.addfile(info, io.BytesIO(path.read_bytes()))
            else:
                archive.addfile(info)
        def decompress(arguments, **options):
            options['stdout'].write(payload.getvalue())
            return subprocess.CompletedProcess(arguments, 0, stderr=b'')
        with patch.object(rollback.subprocess, 'run', side_effect=decompress):
            rollback.check_archive(Path('/owned/rollback.deb'), expected, {})

    def test_archive_bytes_permissions_ownership_and_links_must_match_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'binary'; path.write_bytes(b'original executable')
            expected = {str(path): rollback.file_state(path)}
            self.inspect(path, expected)
            for change in (lambda info: setattr(info, 'mode', 0o777),
                           lambda info: setattr(info, 'uid', info.uid + 1)):
                with self.assertRaisesRegex(ValueError, 'differs'):
                    self.inspect(path, expected, change)
            path.write_bytes(b'altered executable')
            with self.assertRaisesRegex(ValueError, 'differs'):
                self.inspect(path, expected)
            link = Path(temporary)/'link'; link.symlink_to('binary')
            expected = {str(link): rollback.file_state(link)}
            self.inspect(link, expected)
            with self.assertRaisesRegex(ValueError, 'differs'):
                self.inspect(link, expected, lambda info: setattr(info, 'linkname', 'foreign'))

    def test_missing_members_extended_attributes_and_unsafe_archive_names_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'binary'
            with self.assertRaises(FileNotFoundError):
                rollback.file_state(path)
            self.assertEqual(rollback.file_state(path, absent=True), {'kind': 'absent'})
            path.write_bytes(b'owned')
            expected = {str(path): rollback.file_state(path)}
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                self.inspect(path, expected, lambda info: setattr(info, 'name', '../foreign'))
            os.setxattr(path, 'user.fixture', b'cannot lose this attribute')
            with self.assertRaisesRegex(ValueError, 'extended attributes'):
                rollback.file_state(path)


if __name__ == '__main__':
    unittest.main()
