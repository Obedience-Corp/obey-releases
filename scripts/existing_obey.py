"""Explicit old/current managed-user fixtures for original public App journeys.

Only called after the native verifier's fresh disposable-account guard. Historical
bytes come from their real public release; receipt editing is fixture preparation,
never reported as an Installer operation or a product migration.
"""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from verify_candidate import command, checked_payloads, native_platform, wait_until
from verify_selected_components import PACKAGES, checked_bootstrap, checked_receipts, checked_status, fetch
from app_upgrade_contract import verify_persisted

OBEY = 'obedience-corp/obey'
COMPANION = 'obedience-corp/camp-app'
MACHINES = {'aarch64-apple-darwin': 'macOS-arm64', 'x86_64-apple-darwin': 'macOS-x86_64',
            'x86_64-unknown-linux-gnu': 'linux-x86_64', 'x86_64-pc-windows-msvc': 'windows-x86_64'}


def service(binary, environment):
    return command([binary, 'service', 'status', '--json'], environment, json_output=True)


def require_stopped(state):
    if any(state.get(key) is not False for key in ('installed', 'loaded', 'socket_reachable')):
        raise RuntimeError('fixture refuses to replace bytes before owned service cleanup')


def place_old_payloads(managed, payloads):
    """Replace only the two verified receipt-owned fixture files, then their receipt."""
    before = checked_receipts(managed)
    suffix = '.exe' if os.name == 'nt' else ''
    names = {'obey' + suffix, 'ob' + suffix}
    if set(payloads) != names | {'LICENSE'}:
        raise ValueError('unexpected historical payload inventory')
    rows = [row for row in before['files'] if row['receipt_pkg_id'] == OBEY]
    if {Path(row['path']).name for row in rows} != names or len(rows) != 2:
        raise ValueError('historical fixture requires exactly two owned Obey commands')
    with closing(sqlite3.connect(managed / 'state.db')) as db:
        with db:
            for row in rows:
                path = Path(row['path'])
                temporary = path.with_name(path.name + '.fa0027-seed')
                with temporary.open('xb') as stream:
                    stream.write(payloads[path.name])
                temporary.chmod(row['mode'])
                os.replace(temporary, path)
                db.execute('update receipt_files set hash=? where receipt_pkg_id=? and path=?',
                           (hashlib.sha256(payloads[path.name]).hexdigest(), OBEY, str(path)))
            db.execute('update receipts set version=? where package_id=?', ('0.2.2', OBEY))
    return checked_receipts(managed, obey_version='0.2.2')


def seed(root, installer, managed, target, environment, output, report, scenario):
    from verify_app_upgrade import bootstrap_fixture
    if scenario not in ('older-idle', 'current', 'missing-companion'):
        raise ValueError('unsupported existing-user scenario')
    fixture = bootstrap_fixture(root, environment, MACHINES[target], managed)
    report['selected_packages_preseeded'] = True
    report['existing_seed_method'] = 'official latest install; explicit historical bytes/receipt fixture when older-idle'
    suffix = '.exe' if os.name == 'nt' else ''
    obey = managed / 'bin' / ('obey' + suffix)
    if scenario == 'older-idle':
        name = 'obey-0.2.2-' + MACHINES[target] + '.tar.gz'
        base = 'https://github.com/Obedience-Corp/obey-releases/releases/download/v0.2.2/'
        archive_bytes, checksums = fetch(base + name), fetch(base + 'checksums.txt')
        digest = checked_bootstrap(archive_bytes, checksums, name)
        archive = root / name
        archive.write_bytes(archive_bytes)
        payloads = checked_payloads(archive, digest, os.name == 'nt')
        report['historical_seed'] = {'url': base + name, 'sha256': digest,
                                     'receipt_method': 'explicit fixture version/hash replacement after owned service uninstall'}
        (output / 'historical-checksums.txt').write_bytes(checksums)
        command([obey, 'service', 'uninstall'], environment, timeout=120)
        report['seed_service_stopped'] = service(obey, environment)
        require_stopped(report['seed_service_stopped'])
        place_old_payloads(managed, payloads)
        info = command([obey, 'version', '--json'], environment, json_output=True)
        if info.get('version') != '0.2.2' or info.get('platform') != native_platform():
            raise ValueError('historical runtime version/platform mismatch')
        report['historical_runtime'] = info
        command([obey, 'service', 'install'], environment, timeout=120)
    # Lifecycle bookkeeping is not a user preference. Keep the recent check in
    # the original evidence and validate its transition separately below.
    settings = dict(fixture['settings'], lastUpdateCheckAt=utc_now())
    fixture['settings_path'].write_text(json.dumps(settings, indent=2) + '\n')
    fixture['settings_evidence'] = output / 'existing-settings.jsonl'
    version = '0.2.2' if scenario == 'older-idle' else PACKAGES[OBEY]
    report['existing_before'] = wait_until('seeded idle existing user',
        lambda: ready_readback(fixture, installer, environment, version), seconds=120)
    before = report['existing_before']
    elapsed = utc_time(before['observed_at']) - utc_time(before['lifecycle']['lastUpdateCheckAt'])
    if not 0 <= elapsed.total_seconds() < 24 * 60 * 60:
        raise ValueError('existing fixture did not seed a recent background check')
    if scenario == 'missing-companion':
        report['missing_companion_fixture'] = remove_owned_companion(managed)
        status = command([installer, '--managed', 'status', '--plugin', COMPANION, '--json'], environment, json_output=True)
        report['partial_status_before_launch'] = status
        companions = [row for row in status.get('data', {}).get('tools', []) if row.get('tool') == 'camp-app']
        if not status.get('ok') or len(companions) != 1 or companions[0].get('present') is not False:
            raise ValueError('missing companion fixture is not observable through actual Installer status')
    return fixture


def remove_owned_companion(managed):
    selected = checked_receipts(managed)
    rows = [row for row in selected['files'] if row['receipt_pkg_id'] == COMPANION]
    expected = managed / 'bin' / ('camp-app.exe' if os.name == 'nt' else 'camp-app')
    if len(rows) != 1 or Path(rows[0]['path']) != expected:
        raise ValueError('partial fixture requires exactly one receipt-owned companion command')
    # checked_receipts verifies regular-file ownership and the current hash;
    # never remove a foreign replacement, symlink or a directory.
    expected.unlink()
    if expected.exists() or expected.is_symlink():
        raise ValueError('owned companion was not absent before App launch')
    return {'path': str(expected), 'original_sha256': rows[0]['hash'],
            'receipt': rows[0], 'absent_before_launch': True}


def utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def utc_time(value):
    if not isinstance(value, str):
        raise ValueError('missing lifecycle UTC timestamp')
    result = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    if result.strftime('%Y-%m-%dT%H:%M:%SZ') != value:
        raise ValueError('invalid lifecycle UTC timestamp')
    return result


def settings_readback(fixture):
    path = fixture['settings_path']
    if path.is_symlink() or not path.is_file():
        raise ValueError('existing settings must remain a regular file')
    actual = json.loads(path.read_text())
    observed_at = utc_now()
    # Preserve the actual settings even when the following assertion rejects
    # them, so a failed native proof can distinguish lost preferences from
    # legitimate setup bookkeeping without guessing from a stack trace.
    with fixture['settings_evidence'].open('a') as stream:
        stream.write(json.dumps({'observed_at': observed_at, 'settings': actual}) + '\n')
    preserved = verify_persisted(fixture['snapshot'], path, fixture['settings'])
    lifecycle = {key: actual.get(key) for key in ('lastUpdateCheckAt', 'setupCompletedAt')}
    utc_time(lifecycle['lastUpdateCheckAt'])
    if lifecycle['setupCompletedAt'] is not None:
        utc_time(lifecycle['setupCompletedAt'])
    return actual, preserved, lifecycle, observed_at


def ready_readback(fixture, installer, environment, version):
    # Only service startup is retryable. Invalid receipts, paths or retained files
    # fail immediately rather than becoming an apparent slow launch.
    obey = fixture['managed_home'] / 'bin' / ('obey.exe' if os.name == 'nt' else 'obey')
    state = service(obey, environment)
    if not (all(state.get(key) is True for key in ('installed', 'loaded', 'socket_reachable'))
            and type(state.get('daemon_pid')) is int and state['daemon_pid'] > 0):
        return None
    selected = checked_receipts(fixture['managed_home'], obey_version=version)
    status = command([installer, '--managed', 'status', '--plugin', 'obedience-corp/camp-app', '--json'], environment, json_output=True)
    checked_status(status, fixture['managed_home'], obey_version=version)
    sessions = command([obey, 'session', 'list', '--campaign', fixture['camp_id'], '--json'], environment, json_output=True)
    if sessions not in ([], None):
        raise ValueError('idle migration fixture unexpectedly contains sessions')
    settings, preserved, lifecycle, observed_at = settings_readback(fixture)
    camps = command([fixture['camp'], 'list', '--format', 'json'], environment, json_output=True)
    if not any(row['id'] == fixture['camp_id'] and Path(row['path']).resolve() == fixture['fixture'].resolve() for row in camps):
        raise ValueError('existing user lost registered camp')
    unit = Path(state['unit_path'])
    if unit.is_symlink() or not unit.is_file() or not unit.resolve().is_relative_to(Path.home().resolve()):
        raise ValueError('existing-user service unit is not an owned regular file')
    unit_state = {'path': str(unit), 'sha256': hashlib.sha256(unit.read_bytes()).hexdigest(), 'mtime_ns': unit.stat().st_mtime_ns}
    return {'receipts': selected, 'mtimes': {row['path']: Path(row['path']).stat().st_mtime_ns for row in selected['files']},
            'service': state, 'installer_status': status, 'preserved': preserved,
            'unit': unit_state, 'sessions': sessions, 'pending_obey_restart': settings.get('pendingObeyRestart', False),
            'lifecycle': lifecycle, 'observed_at': observed_at}


def compare(before, after, scenario):
    if before['preserved'] != after['preserved']:
        raise ValueError('existing-user settings or foreign files changed')
    changed = COMPANION if scenario == 'missing-companion' else OBEY
    def stable_rows(state, key):
        return [row for row in state['receipts'][key] if row.get('package_id', row.get('receipt_pkg_id')) != changed]
    if any(stable_rows(before, key) != stable_rows(after, key) for key in ('receipts', 'files')):
        raise ValueError('selected repair/migration changed another package')
    for row in before['receipts']['files']:
        if row['receipt_pkg_id'] != changed or scenario == 'current':
            if before['mtimes'][row['path']] != after['mtimes'][row['path']]:
                raise ValueError('current selected executable was needlessly rewritten')
    if scenario == 'current':
        if before['lifecycle'] != after['lifecycle']:
            raise ValueError('current setup needlessly changed lifecycle timestamps')
        if before['receipts'] != after['receipts'] or before['service']['daemon_pid'] != after['service']['daemon_pid'] or before['unit'] != after['unit']:
            raise ValueError('current setup changed receipts or restarted the daemon')
    else:
        completed = utc_time(after['lifecycle']['setupCompletedAt'])
        checked = utc_time(after['lifecycle']['lastUpdateCheckAt'])
        if not (utc_time(before['observed_at']) <= completed == checked <= utc_time(after['observed_at'])):
            raise ValueError('migration completion timestamps do not match the observed setup window')
        if scenario == 'missing-companion':
            if before['receipts']['files'] != after['receipts']['files']:
                raise ValueError('companion repair did not restore the exact original file identities')
            if before['service']['daemon_pid'] != after['service']['daemon_pid'] or before['unit'] != after['unit']:
                raise ValueError('companion repair needlessly restarted or rewrote the Obey service')
        else:
            if before['service']['daemon_pid'] == after['service']['daemon_pid']:
                raise ValueError('idle migration left the old daemon running')
            old = {row['path']: row['hash'] for row in before['receipts']['files'] if row['receipt_pkg_id'] == OBEY}
            new = {row['path']: row['hash'] for row in after['receipts']['files'] if row['receipt_pkg_id'] == OBEY}
            if old.keys() != new.keys() or any(old[path] == new[path] for path in old):
                raise ValueError('old Obey command bytes were not both replaced')
    if after['pending_obey_restart']:
        raise ValueError('idle existing-user setup retained a pending restart')
