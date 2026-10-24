"""Explicit public Debian suite fixtures for original App compatibility journeys."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from verify_candidate import command, wait_until
from verify_selected_components import checked_bootstrap, checked_status, checked_receipts, fetch

SPECS = {
    'external-suite-old': ('0.3.9', 31575640, '74154bc2ebe8d35098d209156d20f4117f5acd6ec0050f0a4e32dfd24a5a3f33', '0.9.1', '0.7.0'),
    'external-suite-minimum': ('0.3.10', 31611390, 'd676fa77ae20773771e2475c08ff5222fbfbafb1177e984bf052cd9aa8cd463f', '0.10.1', '0.8.0'),
    'external-suite-current': ('0.3.24', 32913268, 'a5299b615bec4aa331b4ae1af123a31e6d4fc14606f8b8b4191c7cf9ba2cab2c', '0.16.2', '0.9.8'),
}
PACKAGE = 'obedience-festival'
SUITE = 'obedience-corp/festival'
TOOLS = ('camp', 'fest', 'festival')


def physical(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 128 * 1024 * 1024:
        raise ValueError('external package member is not a bounded regular file')
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mtime_ns': info.st_mtime_ns, 'mode': stat.S_IMODE(info.st_mode),
            'uid': info.st_uid, 'gid': info.st_gid, 'device': info.st_dev, 'inode': info.st_ino}


def package_info(environment):
    result = subprocess.run(['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\t${Status}\n', PACKAGE],
                            env=dict(environment, LC_ALL="C"), text=True, capture_output=True, timeout=30)
    if result.returncode == 1 and not result.stdout.strip() and result.stderr.strip() == 'dpkg-query: no packages found matching ' + PACKAGE:
        return None
    if result.returncode != 0:
        raise RuntimeError('cannot establish exact external suite package state')
    fields = result.stdout.strip().split('\t')
    if len(fields) != 3 or fields[0] != PACKAGE:
        raise ValueError('ambiguous external suite package identity')
    return {'package': fields[0], 'version': fields[1], 'state': fields[2]}


class Fixture:
    def __init__(self, root, installer, managed, environment, output, report, scenario):
        if (sys.platform != 'linux' or os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
                os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted' or scenario not in SPECS):
            raise RuntimeError('external suite installation requires an owned disposable Linux runner')
        self.version, self.size, self.digest, self.camp, self.fest = SPECS[scenario]
        self.root, self.installer, self.managed = Path(root), Path(installer), Path(managed)
        self.environment, self.output, self.report = environment, Path(output), report
        self.settings = Path.home() / '.obey/festival-app/settings.json'
        self.note = Path.home() / '.fa0027-external-suite-preserve.txt'
        if package_info(environment) is not None or any(os.path.lexists('/usr/bin/' + name) for name in TOOLS):
            raise RuntimeError('refusing preexisting external suite/package files')
        if os.path.lexists(self.settings) or os.path.lexists(self.note):
            raise RuntimeError('external first-launch fixture refuses preexisting App settings/note')
        self.attempted_install = False
        self.installed = False
        self.original = None
        self.note_record = None
        report.update({'version': self.version, 'package': PACKAGE, 'first_launch_settings_absent': True,
                       'seeded_background_timestamp': False, 'managed_correction_expected': self.version == '0.3.9'})

    @property
    def external_mode(self):
        return None if self.version == '0.3.9' else self.version

    def install_package(self):
        """Install the existing user's Suite before the App package exists."""
        name = f'obedience-festival_{self.version}_amd64.deb'
        base = f'https://github.com/Obedience-Corp/festival/releases/download/v{self.version}/'
        payload, checksums = fetch(base + name), fetch(base + 'checksums.txt')
        if len(payload) != self.size or checked_bootstrap(payload, checksums, name) != self.digest:
            raise ValueError('public external suite differs from pinned artifact')
        archive = self.root / name
        with archive.open('xb') as stream:
            stream.write(payload)
        fields = command(['/usr/bin/dpkg-deb', '-f', archive, 'Package', 'Version', 'Architecture'], self.environment)
        if fields.splitlines() != [f'Package: {PACKAGE}', f'Version: {self.version}', 'Architecture: amd64']:
            raise ValueError('external Debian package identity mismatch')
        self.report['public_package'] = {'url': base + name, 'bytes': len(payload), 'sha256': self.digest}
        (self.output / 'external-suite-checksums.txt').write_bytes(checksums)
        self.attempted_install = True
        command(['sudo', '-n', '/usr/bin/dpkg', '--install', archive], self.environment, timeout=120)
        self.require_package()
        self.installed = True
        self.original = [physical('/usr/bin/' + name) for name in TOOLS]
        self.note.write_text('FA0027: unrelated existing CLI user data must survive.\n')
        self.note_record = physical(self.note)
        self.report['before_app_package_install'] = self.unchanged()

    def prepare_existing_cli(self):
        """Seed CLI/service state only after the App's private Installer exists."""
        if not self.installed:
            raise RuntimeError('external suite must be installed before preparing existing CLI state')
        self.unchanged()
        # These are real existing CLI tools, not seeded App settings. A working
        # integration/service is necessary to exercise Ready -> background on
        # the first App launch rather than masking it through setup completion.
        for target in ('obey', 'obedience-corp/camp-app'):
            result = command([self.installer, '--managed', 'install', target, '--no-restart', '--json'],
                             self.environment, timeout=240, json_output=True)
            if result.get('ok') is not True:
                raise RuntimeError('existing selected CLI fixture installation failed')
        result = command([self.installer, '--managed', 'setup', 'integrations', '--json'], self.environment,
                         timeout=120, json_output=True)
        if result.get('ok') is not True or result.get('data', {}).get('schema') != 'festival-integrations/v1' or result['data'].get('ready') is not True:
            raise ValueError('existing CLI integrations are not ready before App launch')
        self.report['integrations_before_app'] = result
        obey = self.managed / 'bin/obey'
        command([obey, 'service', 'install'], self.environment, timeout=120)
        def responsive():
            state = command([obey, 'service', 'status', '--json'], self.environment, json_output=True)
            if (all(state.get(key) is True for key in ('installed', 'loaded', 'socket_reachable')) and
                    type(state.get('daemon_pid')) is int and state['daemon_pid'] > 0):
                return state
            return None
        self.report['service_before_app'] = wait_until('existing CLI service ready before first App launch', responsive, seconds=120)
        self.before_launch()

    def require_package(self):
        actual = package_info(self.environment)
        if actual != {'package': PACKAGE, 'version': self.version, 'state': 'install ok installed'}:
            raise ValueError('external suite package identity/state changed')
        return actual

    def unchanged(self):
        self.require_package()
        files = [physical('/usr/bin/' + name) for name in TOOLS]
        if files != self.original or physical(self.note) != self.note_record:
            raise ValueError('App changed external suite files or unrelated existing data')
        return {'package': self.require_package(), 'files': files, 'foreign_note': self.note_record}

    def before_launch(self):
        if os.path.lexists(self.settings):
            raise ValueError('fixture must not create App settings or a background-check timestamp')
        status = command([self.installer, '--managed', 'status', '--plugin', 'obedience-corp/camp-app', '--json'],
                         self.environment, json_output=True)
        if status.get('ok') is not True or status.get('data', {}).get('setup', {}).get('signals_incomplete'):
            raise ValueError('external suite fixture status is unreadable')
        for name, version in [('camp', self.camp), ('fest', self.fest)]:
            rows = [row for row in status['data']['tools'] if row.get('tool') == name]
            if len(rows) != 1 or rows[0].get('path') != '/usr/bin/' + name or rows[0].get('version') != version or rows[0].get('bundle') not in (self.version, 'v' + self.version) or rows[0].get('origin') != 'package' or rows[0].get('present') is not True or rows[0].get('error') or rows[0].get('receipt_version'):
                raise ValueError('pre-App status did not resolve the exact receiptless external suite')
        self.report['managed_receipts_before_app'] = checked_receipts(self.managed, external_suite=self.version)
        self.report['managed_physical_before_app'] = [physical(row['path']) for row in self.report['managed_receipts_before_app']['files']]
        from existing_obey import utc_now
        self.report['before_app_utc'] = utc_now()
        self.report['status_before_app'] = status
        self.report['before_app'] = self.unchanged()

    def non_suite_preserved(self, receipts):
        expected = self.report['managed_receipts_before_app']
        actual = {'receipts': [row for row in receipts['receipts'] if row['package_id'] != SUITE],
                  'files': [row for row in receipts['files'] if row['receipt_pkg_id'] != SUITE]}
        if actual != expected:
            raise ValueError('App changed the already-current non-suite package receipts/files')
        physical_now = [physical(row['path']) for row in actual['files']]
        if physical_now != self.report['managed_physical_before_app']:
            raise ValueError('App rewrote the already-current non-suite executable identities')
        return {'receipts': actual, 'physical': physical_now}

    def settings_readback(self):
        from existing_obey import utc_time, utc_now
        before = physical(self.settings)
        data = self.settings.read_bytes()
        if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != before['sha256'] or physical(self.settings) != before:
            raise ValueError('App settings are not a stable bounded readback')
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError('App settings did not contain an object')
        checked = utc_time(value.get('lastUpdateCheckAt'))
        if not utc_time(self.report['before_app_utc']) <= checked <= utc_time(utc_now()):
            raise ValueError('App did not complete the normal first-launch check in the observed window')
        if self.external_mode is None:
            if value.get('setupCompletedAt') != value.get('lastUpdateCheckAt'):
                raise ValueError('outdated external tools did not complete foreground setup')
        elif value.get('setupCompletedAt') is not None:
            raise ValueError('compatible fixture ran foreground setup instead of the unthrottled Ready/background path')
        return {'physical': before, 'settings': value}

    def readback(self):
        status = command([self.installer, '--managed', 'status', '--plugin', 'obedience-corp/camp-app', '--json'],
                         self.environment, json_output=True)
        checked_status(status, self.managed, external_suite=self.external_mode)
        if self.external_mode is None:
            for name in ('camp', 'fest'):
                rows = [row for row in status['data']['tools'] if row.get('tool') == name]
                if len(rows) != 1 or rows[0].get('path') != str(self.managed / 'bin' / name) or rows[0].get('origin') != 'managed' or rows[0].get('package') != SUITE or rows[0].get('receipt_version') != '0.3.24':
                    raise ValueError('outdated external suite did not resolve the corrected managed copy')
        receipts = checked_receipts(self.managed, external_suite=self.external_mode)
        if self.external_mode is not None and any(os.path.lexists(self.managed / 'bin' / name) for name in TOOLS):
            raise ValueError('compatible external suite was unnecessarily adopted into managed files')
        return {'installer_status': status, 'receipts': receipts,
                'selected_mtime_ns': {row['path']: Path(row['path']).stat().st_mtime_ns for row in receipts['files']},
                'external_suite': self.unchanged(), 'app_settings': self.settings_readback(),
                'non_suite_preserved': self.non_suite_preserved(receipts)}

    def finish(self, before, after):
        for reading in (before, after):
            service = reading.get('service', {})
            if (any(service.get(key) is not True for key in ('installed', 'loaded', 'socket_reachable')) or
                    type(service.get('daemon_pid')) is not int or service['daemon_pid'] <= 0):
                raise ValueError('external suite proof requires the actual installed responsive managed service')
        if before.get('service') != self.report['service_before_app']:
            raise ValueError('App unnecessarily changed the already-ready CLI service')
        if before != after:
            raise ValueError('App relaunch changed external-suite selection, receipts, files or service')
        self.report['after_reopen'] = self.unchanged()
        self.report['normal_first_launch_no_app_settings'] = True

    def cleanup(self):
        if not self.attempted_install:
            return
        from corrupt_receipts import quiescent
        quiescent(self.environment)
        actual = package_info(self.environment)
        if actual is not None:
            if actual['version'] != self.version:
                raise RuntimeError('refusing to remove a replaced external fixture package')
            if self.installed:
                self.report['before_package_cleanup'] = self.unchanged()
            command(['sudo', '-n', '/usr/bin/dpkg', '--purge', PACKAGE], self.environment, timeout=120)
        if package_info(self.environment) is not None or any(os.path.lexists('/usr/bin/' + name) for name in TOOLS):
            raise RuntimeError('owned external suite package cleanup is incomplete')
        if self.note_record is not None:
            if physical(self.note) != self.note_record:
                raise RuntimeError('refusing to remove a changed foreign-note fixture')
            self.note.unlink()
        self.report['package_cleanup_verified'] = True
