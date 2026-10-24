"""Owned receipt-database corruption and explicit known-backup restoration.

This fixture never reconstructs receipts. An App or Installer process, SQLite
sidecar, changed file or unknown partial write makes restoration fail closed.
"""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat

from corrupt_integrations import identity, regular, restore_times, sha, MAX_BYTES
from foreign_companion import owned_file as owned_executable
from verify_candidate import command
from verify_selected_components import checked_receipts

HEADER = b'FA0027_BAD_DB___'
SQLITE_HEADER = b'SQLite format 3\0'


def quiescent(environment):
    if os.name == 'nt':
        script = "$ErrorActionPreference='Stop'; $rows=@(Get-CimInstance Win32_Process -Filter \"Name='festival.exe' OR Name='festival-app.exe'\" | Select-Object ProcessId,Name); ConvertTo-Json -InputObject $rows -Compress"
        rows = json.loads(command(['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], environment))
        if not isinstance(rows, list):
            raise ValueError('invalid App/Installer process inventory')
    else:
        # Filesystem contracts run only in an owned container, not the operator.
        rows = []
        for proc in Path('/proc').iterdir():
            if proc.name.isdecimal():
                try:
                    name = (proc/'comm').read_text().strip()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if name in ('festival', 'festival-app'):
                    rows.append(name)
    if rows:
        raise ValueError('receipt fixture requires no running App or Installer process: '+json.dumps(rows))
    return {'app_installer_processes': [], 'verified': True}


def owned(path):
    if any(p.is_junction() for p in (path, *path.parents)):
        raise ValueError('receipt fixture refuses junction file/ancestors')
    return regular(path)


class Fixture:
    def __init__(self, managed, private_root, report, environment):
        if not ((os.environ.get('CANDIDATE_TEST_CONTAINER') == '1' and Path('/.dockerenv').exists()) or
                (os.name == 'nt' and os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') == '1' and
                 os.environ.get('CANDIDATE_RUNNER_KIND') == 'github-hosted')):
            raise RuntimeError('receipt corruption requires an owned disposable fixture')
        self.path = Path(managed)/'state.db'
        self.environment, self.report = environment, report
        self.backup = Path(private_root)/'receipt-database.backup'
        self.corrupted = self.restored = False
        self.stage = 'prepared'
        report['stage'] = self.stage
        self.no_sidecars()
        report['before_backup_quiescent'] = quiescent(environment)
        self.info = owned(self.path)
        self.original = self.path.read_bytes()
        if not self.original.startswith(SQLITE_HEADER):
            raise ValueError('receipt fixture requires the original SQLite header')
        self.receipts = checked_receipts(Path(managed), immutable=True)
        self.physical = {row['path']: {'sha256': row['hash'], 'mtime_ns': owned_executable(Path(row['path'])).st_mtime_ns} for row in self.receipts['files']}
        self.valid_database()
        self.no_sidecars()
        if self.path.read_bytes() != self.original or identity(owned(self.path)) != identity(self.info):
            raise ValueError('receipt validation changed the original database')
        if any(p.is_symlink() or p.is_junction() for p in (self.backup.parent, *self.backup.parent.parents)):
            raise ValueError('receipt fixture refuses redirected private backup')
        self.backup.parent.mkdir(mode=0o700)
        with self.backup.open('xb') as stream:
            stream.write(self.original)
        self.backup.chmod(0o600)
        self.backup_identity = identity(owned(self.backup))
        self.broken = HEADER + self.original[len(SQLITE_HEADER):]
        report.update(path=str(self.path), original_sha256=sha(self.original), corrupted_sha256=sha(self.broken),
                      backup_uploaded=False, restored=False, product_recovery_verified=False,
                      corruption='fixture-only invalid SQLite header; all remaining bytes preserved')

    def no_sidecars(self, *, recovered_live_read=False):
        found = {suffix: Path(str(self.path)+suffix) for suffix in ('-wal', '-shm', '-journal') if os.path.lexists(str(self.path)+suffix)}
        if not found:
            return {}
        # Only after exact restoration, readonly consumers can leave empty WAL
        # and an ephemeral index. Never ignore transaction bytes or delete them.
        if not recovered_live_read or set(found) != {'-wal', '-shm'}:
            raise ValueError('receipt fixture refuses outstanding SQLite WAL/SHM/journal state')
        evidence = {}
        for suffix, path in found.items():
            info = path.lstat()
            if path.is_symlink() or path.is_junction() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('receipt sidecar identity is not an owned regular file')
            if hasattr(os, 'geteuid') and info.st_uid != os.geteuid():
                raise ValueError('receipt sidecar belongs to another user')
            if (suffix == '-wal' and info.st_size != 0) or (suffix == '-shm' and not 1 <= info.st_size <= MAX_BYTES):
                raise ValueError('receipt fixture refuses nonempty WAL or invalid shared index')
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
            try:
                if identity(os.fstat(fd)) != identity(info):
                    raise ValueError('receipt sidecar changed during open')
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    data = stream.read(MAX_BYTES+1)
                if len(data) != info.st_size or os.fstat(fd).st_mtime_ns != info.st_mtime_ns:
                    raise ValueError('receipt sidecar changed during bounded read')
            finally:
                os.close(fd)
            evidence[suffix] = {'identity': identity(info), 'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns, 'sha256': sha(data)}
        return evidence

    def valid_database(self):
        with closing(sqlite3.connect(self.path.as_uri()+'?mode=ro&immutable=1', uri=True)) as db:
            if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise ValueError('original receipt database failed integrity check')

    def replace(self, expected, replacement, times=False):
        self.no_sidecars()
        self.report.setdefault('quiescence_checks', []).append(quiescent(self.environment))
        if identity(owned(self.path)) != identity(self.info):
            raise ValueError('receipt database identity/permissions changed')
        fd = os.open(self.path, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        try:
            if identity(os.fstat(fd)) != identity(self.info):
                raise ValueError('receipt database changed during descriptor acquisition')
            with os.fdopen(fd, 'r+b', closefd=False) as stream:
                if stream.read(MAX_BYTES+1) != expected:
                    raise ValueError('receipt fixture refuses unknown database bytes')
                stream.seek(0);stream.write(replacement);stream.truncate();stream.flush();os.fsync(fd)
            if times:
                restore_times(fd, self.info)
            if identity(os.fstat(fd)) != identity(self.info):
                raise ValueError('receipt database metadata changed during held write')
        finally:
            os.close(fd)

    def corrupt(self):
        self.corrupted = True
        self.stage = 'writing'
        self.report['stage'] = self.stage
        self.replace(self.original, self.broken)
        self.stage = 'corrupted'
        self.broken_mtime = self.path.stat().st_mtime_ns
        self.report.update(stage=self.stage, corrupted_mtime_ns=self.broken_mtime)

    def unchanged(self):
        self.no_sidecars()
        if (self.stage != 'corrupted' or identity(owned(self.path)) != identity(self.info) or
                self.path.read_bytes() != self.broken or self.path.stat().st_mtime_ns != self.broken_mtime):
            raise ValueError('App or Installer changed the corrupted receipt database')
        return {'sha256': sha(self.broken), 'mtime_ns': self.broken_mtime, 'unchanged': True}

    def restore(self):
        if self.restored or not self.corrupted:
            return
        if self.stage != 'corrupted':
            raise ValueError('receipt corruption incomplete; refusing unknown partial state')
        self.unchanged()
        if identity(owned(self.backup)) != self.backup_identity or self.backup.read_bytes() != self.original:
            raise ValueError('receipt backup identity/digest changed')
        self.replace(self.broken, self.original, times=True)
        self.restored = True
        self.stage = 'restored'
        self.healthy()
        self.report.update(stage=self.stage, restored=True, restored_sha256=sha(self.path.read_bytes()),
                           original_mtime_restored=True)

    def healthy(self):
        sidecars = self.no_sidecars(recovered_live_read=True)
        if (not self.restored or identity(owned(self.path)) != identity(self.info) or
                self.path.read_bytes() != self.original or self.path.stat().st_mtime_ns != self.info.st_mtime_ns):
            raise ValueError('receipt database exact restoration did not persist')
        # Exact original main bytes plus no WAL frames imply the original
        # validated logical receipts. Do not assert immutable on a live App DB.
        for name, expected in self.physical.items():
            path = Path(name)
            if owned_executable(path).st_mtime_ns != expected['mtime_ns'] or sha(path.read_bytes()) != expected['sha256']:
                raise ValueError('restored receipt-owned selected physical file changed')
        if self.no_sidecars(recovered_live_read=True) != sidecars:
            raise ValueError('receipt sidecars changed during recovered readback')
        if (identity(owned(self.path)) != identity(self.info) or self.path.read_bytes() != self.original or
                self.path.stat().st_mtime_ns != self.info.st_mtime_ns):
            raise ValueError('receipt database changed during recovered readback')
        self.report['recovered_readonly_sidecars'] = sidecars
        return {'sha256': sha(self.original), 'mtime_ns': self.info.st_mtime_ns, 'receipts': self.receipts}
