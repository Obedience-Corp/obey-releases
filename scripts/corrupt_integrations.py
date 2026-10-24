"""Explicit owned integration-preference corruption/manual restoration for disposable native proof.

No product configuration is repaired here. The fixture owns both the initial selected
installation and its private, digest-bound rollback bytes. Backups stay in the
owned temporary directory; proof artifacts contain only hashes and readbacks.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

MARKER = b'FA0027-BROKEN-JSON!'
MAX_BYTES = 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(info):
    return {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')}


def regular(path):
    path = Path(path)
    if not path.is_absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('integration fixture refuses symlink preferences/backup ancestors')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 2 <= info.st_size <= MAX_BYTES:
        raise ValueError('integration fixture requires one bounded regular preferences/backup')
    if hasattr(os, 'geteuid') and info.st_uid != os.geteuid():
        raise ValueError('integration fixture refuses a foreign preferences/backup owner')
    return info


class Fixture:
    def __init__(self, managed, private_root, report):
        if not ((os.environ.get('CANDIDATE_TEST_CONTAINER') == '1' and Path('/.dockerenv').exists()) or
                (os.name == 'nt' and os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') == '1' and
                 os.environ.get('CANDIDATE_RUNNER_KIND') == 'github-hosted')):
            raise RuntimeError('integration corruption requires an owned disposable fixture')
        self.path = Path(managed) / 'integrations.json'
        self.backup = Path(private_root) / 'integration-preferences.backup'
        self.report = report
        self.restored = False
        self.corrupted = False
        self.info = regular(self.path)
        self.original = self.path.read_bytes()
        if len(self.original) > MAX_BYTES - len(MARKER):
            raise ValueError('integration preferences leave no bounded corruption space')
        document = json.loads(self.original)
        if not isinstance(document, dict) or type(document.get('disabled')) is not bool:
            raise ValueError('integration fixture requires valid original integration preferences')
        if any(part.is_symlink() for part in (self.backup.parent, *self.backup.parent.parents)):
            raise ValueError('integration fixture refuses symlink backup ancestors')
        self.backup.parent.mkdir(mode=0o700)
        with self.backup.open('xb') as stream:
            stream.write(self.original)
        self.backup.chmod(0o600)
        self.backup_identity = identity(regular(self.backup))
        self.broken = MARKER + self.original
        self.report.update(path=str(self.path), original_sha256=sha(self.original),
                           corrupted_sha256=sha(self.broken), bytes=len(self.original),
                           corruption='fixture-only invalid JSON prefix in owned integration preferences',
                           restoration='manual digest-bound owned backup after normal App quit',
                           backup_uploaded=False, restored=False)

    def corrupt(self):
        # Caller owns this object before any preferences mutation, so even a
        # later assertion/launch failure retains its rollback in finally.
        self.corrupted = True
        self.replace(self.original, self.broken)

    def replace(self, expected, replacement, restore_times=False):
        current = regular(self.path)
        if identity(current) != identity(self.info):
            raise ValueError('owned integration preferences identity or metadata changed')
        flags = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        descriptor = os.open(self.path, flags)
        try:
            if identity(os.fstat(descriptor)) != identity(self.info):
                raise ValueError('integration preferences changed before descriptor acquisition')
            with os.fdopen(descriptor, 'r+b', closefd=False) as stream:
                if stream.read(MAX_BYTES + 1) != expected:
                    raise ValueError('integration preferences differs from authenticated fixture bytes')
                stream.seek(0)
                stream.write(replacement)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
            if restore_times:
                os.utime(descriptor, ns=(self.info.st_atime_ns, self.info.st_mtime_ns))
            if identity(os.fstat(descriptor)) != identity(self.info):
                raise ValueError('integration preferences identity changed during fixture write')
        finally:
            os.close(descriptor)

    def unchanged_corruption(self):
        if identity(regular(self.path)) != identity(self.info) or self.path.read_bytes() != self.broken:
            raise ValueError('App changed or replaced the corrupted integration preferences')
        return {'sha256': sha(self.broken), 'unchanged': True}

    def restore(self):
        if self.restored or not self.corrupted:
            return
        if identity(regular(self.backup)) != self.backup_identity or self.backup.read_bytes() != self.original:
            raise ValueError('integration rollback backup identity or digest changed')
        self.replace(self.broken, self.original, restore_times=True)
        self.restored = True
        self.report.update(restored=True, restored_sha256=sha(self.path.read_bytes()),
                           original_mtime_restored=self.path.stat().st_mtime_ns == self.info.st_mtime_ns)
        if self.report['restored_sha256'] != self.report['original_sha256'] or not self.report['original_mtime_restored']:
            raise ValueError('integration rollback did not restore exact bytes and mtime')

    def healthy(self):
        if (not self.restored or identity(regular(self.path)) != identity(self.info) or
                self.path.read_bytes() != self.original or self.path.stat().st_mtime_ns != self.info.st_mtime_ns):
            raise ValueError('reopen changed the manually restored integration preferences')
        return {'sha256': sha(self.original), 'mtime_ns': self.info.st_mtime_ns, 'unchanged': True}


def checked_error(document, exit_code):
    error = document.get('error', {})
    if (exit_code == 0 or document.get('ok') is not False or not isinstance(error.get('code'), str) or not error.get('code') or
            'read integration preferences' not in error.get('message', '').lower()):
        raise ValueError('actual Installer did not report the injected integration corruption')
    return {'code': error['code'], 'message': error['message'], 'exit': exit_code}


def installer_error(installer, environment, output):
    arguments = [str(installer), '--managed', 'setup', 'integrations', '--check', '--json']
    result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=60)
    (output / 'corrupt-integration-installer.json').write_text(json.dumps(
        {'command': arguments, 'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    return checked_error(json.loads(result.stdout), result.returncode)


def error_window(window):
    names = window.get('visible_names', [])
    return ('Getting this machine ready' in names and 'Configure terminal commands and agent connections' in names and
            any('read integration preferences' in name.lower() for name in names))


def unchanged_user(fixture, before, installer, environment):
    import existing_obey
    # The receipt database is healthy throughout this distinct JSON-state case.
    # Reuse full selected receipt/file, service, camp and settings readback.
    after = existing_obey.ready_readback(fixture, installer, environment, '0.2.3')
    if after is None:
        raise ValueError('integration failure lost the responsive installed service')
    existing_obey.compare(before, after, 'current')
    return after
