"""Exercise the real privileged, fixed-path config helper in disposable Docker."""
import json
import os
from pathlib import Path
import subprocess
import sys

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('system Git configuration mutation requires isolated Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import git_rollback


def verify_config_rollback(root):
    path = Path('/etc/gitconfig')
    original = path.read_bytes()
    original_mode = path.stat().st_mode & 0o7777
    entries = [b'\tclean = git-lfs clean -- %f\n', b'\tsmudge = git-lfs smudge -- %f\n',
               b'\tprocess = git-lfs filter-process\n', b'\trequired = true\n']
    foreign = b'# exact foreign comment\n[fixture]\n\tkeep = original\n'
    baseline = foreign+b'[filter "lfs"]\n'+b''.join(entries)
    reordered = foreign+b'[filter "lfs"]\n'+b''.join(reversed(entries))
    def write(data):
        # Test-only preparation; production helper has no arbitrary-path writer.
        subprocess.run(['sudo', '/usr/bin/python3', '-c',
                        'import pathlib,sys; p=pathlib.Path("/etc/gitconfig"); p.write_bytes(sys.stdin.buffer.read())'],
                       input=data, check=True, capture_output=True)
    def restore(backup, before, observed, error=None):
        result = subprocess.run(['sudo', '--preserve-env=CANDIDATE_NATIVE_DISPOSABLE,CANDIDATE_RUNNER_KIND',
                                 '/usr/bin/python3', '-I', git_rollback.__file__, '--restore-system-config',
                                 str(backup), json.dumps(before), json.dumps(observed), str(os.getuid())],
                                capture_output=True, text=True, timeout=15)
        if error:
            assert result.returncode and error in result.stderr, result.stderr
        else:
            assert result.returncode == 0, result.stderr
    try:
        write(baseline)
        cache = root/'config-backup'; cache.mkdir()
        before = git_rollback.file_state(path)
        backup = git_rollback.backup_system_config(cache, before)
        write(reordered)
        restore(backup, before, git_rollback.file_state(path))
        assert path.read_bytes() == baseline and git_rollback.file_state(path) == before
        write(reordered.replace(b'keep = original', b'keep = foreign-change'))
        observed = git_rollback.file_state(path)
        restore(backup, before, observed, 'unrelated change')
        assert git_rollback.file_state(path) == observed
        write(reordered)
        observed = git_rollback.file_state(path)
        restore(backup, before, dict(observed, sha256='0'*64), 'target changed')
        assert git_rollback.file_state(path) == observed
        restore(backup, dict(before, mode=0o600), observed, 'ownership or permissions changed')
        assert git_rollback.file_state(path) == observed
        backup.write_bytes(b'tampered backup')
        restore(backup, before, observed, 'backup changed')
        assert git_rollback.file_state(path) == observed
        backup.write_bytes(baseline)
        victim = root/'foreign-target'; victim.write_bytes(b'unchanged')
        subprocess.run(['sudo', 'rm', '--', str(path)], check=True, capture_output=True)
        subprocess.run(['sudo', 'ln', '-s', '--', str(victim), str(path)], check=True, capture_output=True)
        restore(backup, before, observed, 'Too many levels of symbolic links')
        assert victim.read_bytes() == b'unchanged' and path.is_symlink()
        subprocess.run(['sudo', 'rm', '--', str(path)], check=True, capture_output=True)
        absent_cache = root/'absent-config-backup'; absent_cache.mkdir()
        absent = {'kind': 'absent'}
        absent_backup = git_rollback.backup_system_config(absent_cache, absent)
        write(b'[filter "lfs"]\n'+b''.join(reversed(entries)))
        restore(absent_backup, absent, git_rollback.file_state(path))
        assert not path.exists()
        print('Actual fixed-path Git config restoration PASS; exact bytes/absence, foreign-change, tamper and symlink refusal', flush=True)
    finally:
        if path.is_symlink():
            subprocess.run(['sudo', 'rm', '--', str(path)], check=True, capture_output=True)
        write(original)
        subprocess.run(['sudo', 'chmod', oct(original_mode)[2:], str(path)], check=True, capture_output=True)
