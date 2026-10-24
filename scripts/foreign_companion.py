"""Fixture-owned foreign replacement, preservation and explicit manual rollback.

Only the candidate's real authenticated bundled Installer is substituted. Its
version-parser refusal is not a mock companion or a forged release version.
"""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat

from corrupt_integrations import identity, restore_times, sha
from verify_candidate import command
from verify_selected_components import checked_receipts, PACKAGES

COMPANION = 'obedience-corp/camp-app'
MAX_BYTES = 128 * 1024 * 1024
WAY_OUT = 'The app does not replace a copy it did not install: update it through its own installer, or remove it so setup can install the marketplace release.'


def owned_file(path):
    path = Path(path)
    if not path.is_absolute() or any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise ValueError('foreign fixture refuses redirected file or parent')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= MAX_BYTES:
        raise ValueError('foreign fixture requires one bounded regular owned file')
    if hasattr(os, 'geteuid') and info.st_uid != os.geteuid():
        raise ValueError('foreign fixture refuses another user owner')
    return info


class Fixture:
    def __init__(self, managed, installer, private_root, report):
        if not ((os.environ.get('CANDIDATE_TEST_CONTAINER') == '1' and Path('/.dockerenv').exists()) or
                (os.name == 'nt' and os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') == '1' and
                 os.environ.get('CANDIDATE_RUNNER_KIND') == 'github-hosted')):
            raise RuntimeError('foreign replacement requires an owned disposable fixture')
        self.managed = Path(managed)
        selected = checked_receipts(self.managed)
        rows = [row for row in selected['files'] if row['receipt_pkg_id'] == COMPANION]
        self.path = self.managed/'bin'/('camp-app.exe' if os.name == 'nt' else 'camp-app')
        if len(rows) != 1 or Path(rows[0]['path']) != self.path:
            raise ValueError('foreign fixture requires exactly the verified owned companion')
        self.info = owned_file(self.path)
        source = Path(installer)
        owned_file(source)
        if source.name != ('festival.exe' if os.name == 'nt' else 'festival') or source.samefile(self.path):
            raise ValueError('foreign fixture source must be the separate verified bundled Installer')
        self.original, self.foreign = self.path.read_bytes(), source.read_bytes()
        if sha(self.original) != rows[0]['hash'] or self.foreign == self.original:
            raise ValueError('foreign fixture source/original identity is not distinct')
        self.backup = Path(private_root)/'companion.backup'
        if any(p.is_symlink() or p.is_junction() for p in (self.backup.parent, *self.backup.parent.parents)):
            raise ValueError('foreign fixture refuses redirected private backup')
        self.backup.parent.mkdir(mode=0o700)
        with self.backup.open('xb') as stream:
            stream.write(self.original)
        self.backup.chmod(0o600)
        self.backup_identity = identity(owned_file(self.backup))
        self.report = report
        self.replaced = self.restored = False
        self.foreign_mtime_ns = None
        report["substitution_stage"] = "prepared"
        report.update(path=str(self.path), original_sha256=sha(self.original), foreign_sha256=sha(self.foreign),
                      foreign_source_path=str(source), foreign_source='authenticated candidate bundled Installer; fixture substitution only',
                      receipt=rows[0], backup_uploaded=False, restored=False)

    def write(self, expected, replacement, times=False):
        if identity(owned_file(self.path)) != identity(self.info):
            raise ValueError('foreign fixture target identity changed')
        descriptor = os.open(self.path, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        try:
            if identity(os.fstat(descriptor)) != identity(self.info):
                raise ValueError('foreign fixture changed before descriptor acquisition')
            with os.fdopen(descriptor, 'r+b', closefd=False) as stream:
                if stream.read(MAX_BYTES + 1) != expected:
                    raise ValueError('foreign fixture refuses unknown replacement bytes')
                stream.seek(0); stream.write(replacement); stream.truncate(); stream.flush(); os.fsync(descriptor)
            if times:
                restore_times(descriptor, self.info)
            if identity(os.fstat(descriptor)) != identity(self.info):
                raise ValueError('foreign fixture metadata changed during owned write')
        finally:
            os.close(descriptor)

    def substitute(self):
        self.replaced = True
        self.report["substitution_stage"] = "writing"
        self.write(self.original, self.foreign)
        self.foreign_mtime_ns = self.path.stat().st_mtime_ns
        self.report.update(foreign_mtime_ns=self.foreign_mtime_ns, substitution_stage='substituted')

    def unchanged(self):
        if (identity(owned_file(self.path)) != identity(self.info) or self.path.read_bytes() != self.foreign or
                self.path.stat().st_mtime_ns != self.foreign_mtime_ns):
            raise ValueError('App changed the foreign companion replacement')
        return {'sha256': sha(self.foreign), 'mtime_ns': self.foreign_mtime_ns, 'preserved': True}

    def restore(self):
        if self.restored or not self.replaced:
            return
        if self.foreign_mtime_ns is None:
            raise ValueError('foreign substitution did not complete; refusing unknown partial state')
        if identity(owned_file(self.backup)) != self.backup_identity or self.backup.read_bytes() != self.original:
            raise ValueError('foreign companion backup identity/digest changed')
        if self.path.stat().st_mtime_ns != self.foreign_mtime_ns:
            raise ValueError('foreign replacement mtime changed before rollback')
        self.write(self.foreign, self.original, times=True)
        self.restored = True
        self.report.update(restored=True, substitution_stage="restored", restored_sha256=sha(self.path.read_bytes()),
                           original_mtime_restored=self.path.stat().st_mtime_ns == self.info.st_mtime_ns)
        self.healthy()

    def healthy(self):
        if (not self.restored or identity(owned_file(self.path)) != identity(self.info) or
                self.path.read_bytes() != self.original or self.path.stat().st_mtime_ns != self.info.st_mtime_ns):
            raise ValueError('manual companion restoration did not persist exact original state')
        return {'sha256': sha(self.original), 'mtime_ns': self.info.st_mtime_ns, 'unchanged': True}


def receipt_metadata(managed):
    with closing(sqlite3.connect((Path(managed)/'state.db').as_uri()+'?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        return {'receipts': [dict(row) for row in db.execute('select * from receipts order by package_id')],
                'files': [dict(row) for row in db.execute('select * from receipt_files order by path')]}


def probe(installer, fixture, environment, output):
    status = command([installer, '--managed', 'status', '--plugin', COMPANION, '--json'], environment, json_output=True)
    (output/'foreign-companion-status.json').write_text(json.dumps(status, indent=2)+'\n')
    rows = [row for row in status.get('data', {}).get('tools', []) if row.get('tool') == 'camp-app']
    if (status.get('ok') is not True or len(rows) != 1 or rows[0].get('present') is not True or
            Path(rows[0].get('path', '')) != fixture.path or not rows[0].get('error') or
            rows[0].get('receipt_version') != PACKAGES[COMPANION]):
        raise ValueError('actual Installer did not observe the incompatible foreign companion')
    update = command([installer, '--managed', 'update', COMPANION, '--json'], environment, json_output=True)
    (output/'foreign-companion-preservation.json').write_text(json.dumps(update, indent=2)+'\n')
    result = update.get('data', {})
    if (update.get('ok') is not True or result.get('action') != 'unmanaged' or result.get('package') != COMPANION or
            str(fixture.path) not in result.get('upgrade', '') or 'E_PLUGIN_FOREIGN' not in result.get('upgrade', '')):
        raise ValueError('actual Installer did not preserve the foreign selected companion')
    fixture.unchanged()
    return {'tool': rows[0], 'update': result}


def error_window(window, observed):
    tool = observed['tool']
    message = f"camp-app at {tool['path']} could not be checked: {tool['error']}. " + WAY_OUT
    expected = 'Update anything older than this app needsFailed' + message
    names = window.get('visible_names', [])
    return (window.get('uia_verified') is True and 'Getting this machine ready' in names and
            'A step did not finish. Its detail is below.' in names and expected in names)


def preserved_user(fixture, before, foreign, environment):
    import existing_obey
    foreign.unchanged()
    metadata = receipt_metadata(fixture['managed_home'])
    if metadata != before['receipts']:
        raise ValueError('foreign failure changed selected receipt metadata')
    observed_files = []
    for row in metadata['files']:
        path = Path(row['path']); owned_file(path)
        expected_hash = sha(foreign.foreign) if path == foreign.path else row['hash']
        expected_mtime = foreign.foreign_mtime_ns if path == foreign.path else before['mtimes'][str(path)]
        if sha(path.read_bytes()) != expected_hash or path.stat().st_mtime_ns != expected_mtime:
            raise ValueError('foreign failure changed a selected physical file')
        observed_files.append({'path': str(path), 'sha256': expected_hash, 'mtime_ns': expected_mtime})
    settings, preserved, lifecycle, _ = existing_obey.settings_readback(fixture)
    if (preserved != before['preserved'] or lifecycle != before['lifecycle'] or
            settings.get('pendingObeyRestart', False) != before['pending_obey_restart']):
        raise ValueError('foreign failure changed user settings or files')
    camps = command([fixture['camp'], 'list', '--format', 'json'], environment, json_output=True)
    if not any(row['id'] == fixture['camp_id'] and Path(row['path']).resolve() == fixture['fixture'].resolve() for row in camps):
        raise ValueError('foreign failure lost registered camp')
    obey = fixture['managed_home']/'bin'/('obey.exe' if os.name == 'nt' else 'obey')
    service = existing_obey.service(obey, environment)
    unit = Path(service['unit_path'])
    if (not all(service.get(key) is True for key in ('installed', 'loaded', 'socket_reachable')) or
            service.get('daemon_pid') != before['service']['daemon_pid'] or str(unit) != before['unit']['path'] or
            unit.is_symlink() or sha(unit.read_bytes()) != before['unit']['sha256'] or unit.stat().st_mtime_ns != before['unit']['mtime_ns']):
        raise ValueError('foreign failure changed the responsive owned service/unit')
    return {'receipt_metadata': metadata, 'physical_files': observed_files, 'preserved': preserved,
            'lifecycle': lifecycle, 'service': service, 'unit': before['unit'],
            'foreign_file': foreign.unchanged(), 'registered_camp_id': fixture['camp_id']}
