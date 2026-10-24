"""Real managed work across an App-driven Obey update and deferred restart."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import active_provider
import existing_obey
from verify_candidate import command
from verify_selected_components import checked_receipts, checked_status


def quiet(arguments, environment, timeout=120, json_output=False):
    # Provider replies and session summaries must never reach exported logs.
    result = subprocess.run([str(item) for item in arguments], env=environment,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('real session CLI operation failed (output withheld)')
    return json.loads(result.stdout) if json_output else result.stdout


def checked_session(document, session, camp, status):
    row = document.get('session', {})
    if (row.get('id') != session or row.get('campaign_id') != camp or row.get('provider') != 'ollama' or
            row.get('model') != active_provider.MODEL or row.get('external', False) is not False or
            row.get('status') != status or row.get('error_message')):
        raise ValueError('managed provider session identity/lifecycle changed')
    return {name: row.get(name, False if name == 'external' else None)
            for name in ('id', 'campaign_id', 'provider', 'model', 'status', 'external')}


def checked_turns(document, session, camp, count):
    rows = document.get('turns')
    if (document.get('schema_version') != 'obey.turn.v1' or document.get('has_more') is not False or
            not isinstance(rows, list) or len(rows) != count or len({row.get('id') for row in rows}) != count):
        raise ValueError('real durable turn inventory is incomplete')
    for row in rows:
        attempt = row.get('latest_attempt', {})
        if (not row.get('id') or row.get('session_id') != session or row.get('campaign_id') != camp or
                row.get('status') != 'completed' or row.get('error_code') or row.get('error_message') or
                not row.get('finished_at') or row.get('current_attempt_number') != 1 or
                attempt.get('state') != 'completed' or attempt.get('provider') != 'ollama' or
                attempt.get('model') != active_provider.MODEL or attempt.get('error_code') or
                attempt.get('error_message') or row.get('usage', {}).get('tokens_output', 0) <= 0):
            raise ValueError('real provider turn did not durably complete')
    return sorted(rows, key=lambda row: row['id'])


def digest_rows(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def process_identity(pid):
    if type(pid) is not int or pid <= 0:
        raise ValueError('service has no concrete daemon PID')
    root = Path('/proc') / str(pid)
    def birth():
        value = (root / 'stat').read_text()
        return value[value.rindex(')') + 2:].split()[19]
    start = birth()
    with (root / 'exe').open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if birth() != start:
        raise ValueError('daemon changed during process observation')
    return {'pid': pid, 'start_ticks': start, 'executable_sha256': digest}


class SessionClient:
    """Shared real-provider CLI calls; fixtures retain their own lifecycle validators."""
    def call(self, *arguments, json_output=False):
        flags = ['--json'] if json_output else []
        return quiet([self.obey, '--no-color', *arguments, *flags], self.environment, json_output=json_output)

    def create_session(self):
        text = self.call('session', 'create', '--campaign', self.fixture['camp_id'], '--provider', 'ollama',
                         '--model', active_provider.MODEL, '--agent', 'release-continuity-proof',
                         '--mode', 'discussion', '--workdir', self.fixture['fixture'])
        matches = re.findall(r'^Session:\s+(\S+)\s*$', text, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError('real provider session creation returned ambiguous identity')
        return matches[0]

    def session_info(self, session, status):
        return checked_session(self.call('session', 'info', session, '--campaign', self.fixture['camp_id'], json_output=True),
                               session, self.fixture['camp_id'], status)

    def lifecycle_events(self, session):
        return self.call('session', 'events', session, '--campaign', self.fixture['camp_id'],
                         '--kind', 'session_status_changed', '--limit', '100', json_output=True)

    def turn_readback(self, session, count):
        return checked_turns(self.call('session', 'turns', session, '--campaign', self.fixture['camp_id'], json_output=True),
                             session, self.fixture['camp_id'], count)

    def send(self, session, count):
        self.call('session', 'send', session, '/no_think Reply only OK. Do not use tools.', '--campaign', self.fixture['camp_id'])
        rows = self.turn_readback(session, count)
        self.session_info(session, 'SESSION_STATUS_RUNNING')
        self.provider.check_cpu()
        return rows


class Fixture(SessionClient):
    def __init__(self, root, installer, managed, target, environment, output, report):
        active_provider.require_isolation()
        if target != 'x86_64-unknown-linux-gnu':
            raise ValueError('live native App update proof currently requires Linux x64')
        self.root, self.installer, self.managed = Path(root), Path(installer), Path(managed)
        self.environment, self.output, self.report = environment, Path(output), report
        self.provider = active_provider.Provider(self.root / 'active-provider', environment, report.setdefault('provider', {}))
        self.obey = self.managed / 'bin/obey'
        self.session = self.new_session = None
        self.expect_pending = True
        self.turns = []

    def seed(self):
        self.provider.start()
        self.config = Path.home() / '.obey/daemon.yaml'
        self.config.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(self.config):
            raise RuntimeError('live-session fixture refuses preexisting provider configuration')
        value = {'network': {'enabled': False}, 'providers': {'ollama': {'type': 'ollama', 'enabled': True,
                 'base_url': self.provider.endpoint, 'options': {'num_ctx': 4096, 'num_predict': 64,
                 'temperature': 0, 'keep_alive': '1m'}}}}
        with self.config.open('x') as stream:
            json.dump(value, stream)
        # This existing path authenticates public historical bytes and explicitly
        # records its receipt fixture; its idle-only validation stays unchanged.
        self.fixture = existing_obey.seed(self.root, self.installer, self.managed, 'x86_64-unknown-linux-gnu',
                                         self.environment, self.output, self.report, 'older-idle')
        from app_upgrade_contract import persisted_snapshot
        self.fixture['snapshot'].update(persisted_snapshot([self.config]))
        self.report['existing_seed_method'] += '; real managed provider session created before App'
        self.session = self.create_session()
        self.turns = self.send(self.session, 1)
        state = existing_obey.service(self.obey, self.environment)
        self.original_process = process_identity(state['daemon_pid'])
        expected = next(row['hash'] for row in self.report['existing_before']['receipts']['files'] if row['path'] == str(self.obey))
        if self.original_process['executable_sha256'] != expected:
            raise ValueError('active fixture is not running the old public Obey bytes')
        self.report['active_before_app'] = {'session': self.session_info(self.session, 'SESSION_STATUS_RUNNING'),
            'process': self.original_process, 'completed_turns': 1, 'turns_sha256': digest_rows(self.turns)}

    def readback(self):
        selected = checked_receipts(self.managed)
        status = command([self.installer, '--managed', 'status', '--plugin', 'obedience-corp/camp-app', '--json'],
                         self.environment, json_output=True)
        checked_status(status, self.managed)
        service = existing_obey.service(self.obey, self.environment)
        if any(service.get(key) is not True for key in ('installed', 'loaded', 'socket_reachable')):
            raise ValueError('active-session service is not responsive')
        process = process_identity(service.get('daemon_pid'))
        settings, preserved, lifecycle, observed = existing_obey.settings_readback(self.fixture)
        if settings.get('pendingObeyRestart', False) is not self.expect_pending:
            raise ValueError('App pending restart does not match active/idle state')
        baseline = self.report['existing_before']
        for kind, key in [('receipts', 'package_id'), ('files', 'receipt_pkg_id')]:
            old = [row for row in baseline['receipts'][kind] if row[key] != existing_obey.OBEY]
            new = [row for row in selected[kind] if row[key] != existing_obey.OBEY]
            if old != new:
                raise ValueError('live Obey update changed another selected package')
        for row in selected['files']:
            if row['receipt_pkg_id'] != existing_obey.OBEY and Path(row['path']).stat().st_mtime_ns != baseline['mtimes'][row['path']]:
                raise ValueError('live update rewrote another selected executable')
        old_hashes = {row['path']: row['hash'] for row in baseline['receipts']['files'] if row['receipt_pkg_id'] == existing_obey.OBEY}
        new_hashes = {row['path']: row['hash'] for row in selected['files'] if row['receipt_pkg_id'] == existing_obey.OBEY}
        if old_hashes.keys() != new_hashes.keys() or any(old_hashes[key] == new_hashes[key] for key in old_hashes):
            raise ValueError('App did not replace both old Obey command payloads')
        if self.expect_pending:
            if process != self.original_process:
                raise ValueError('App restarted the daemon while its real session was active')
            unit = Path(service['unit_path'])
            unit_state = {'path': str(unit), 'sha256': hashlib.sha256(unit.read_bytes()).hexdigest(),
                          'mtime_ns': unit.stat().st_mtime_ns}
            # Obey's documented install contract refreshes the unit even when
            # restart is deferred. Preserve its definition, not the old mtime.
            if unit.is_symlink() or any(unit_state[key] != baseline['unit'][key] for key in ('path', 'sha256')):
                raise ValueError('deferred update changed the service definition')
            self.report['service_unit_after_refresh'] = unit_state
            completed = existing_obey.utc_time(lifecycle['setupCompletedAt'])
            if not existing_obey.utc_time(baseline['observed_at']) <= completed == existing_obey.utc_time(lifecycle['lastUpdateCheckAt']) <= existing_obey.utc_time(observed):
                raise ValueError('active update did not complete setup inside the observed window')
            self.session_info(self.session, 'SESSION_STATUS_RUNNING')
        else:
            if process == self.original_process or process['executable_sha256'] != new_hashes[str(self.obey)]:
                raise ValueError('safe-idle restart did not launch the updated public runtime')
            self.session_info(self.session, 'SESSION_STATUS_STOPPED')
        turns = self.turn_readback(self.session, len(self.turns))
        if turns != self.turns:
            raise ValueError('App update/restart changed completed real work')
        return {'receipts': selected, 'installer_status': status, 'service': service,
                'selected_mtime_ns': {row['path']: Path(row['path']).stat().st_mtime_ns for row in selected['files']},
                'process': process, 'preserved': preserved, 'pending_obey_restart': self.expect_pending,
                'lifecycle': lifecycle, 'observed_at': observed, 'completed_turns': len(turns), 'turns_sha256': digest_rows(turns)}

    def after_update(self):
        first = self.turns
        self.turns = self.send(self.session, 2)
        if any(row not in self.turns for row in first):
            raise ValueError('second real turn changed the first durable turn')
        self.report['active_after_update'] = self.readback()

    def stop_for_idle(self):
        self.call('session', 'stop', self.session, '--campaign', self.fixture['camp_id'])
        self.session_info(self.session, 'SESSION_STATUS_STOPPED')
        if self.turn_readback(self.session, 2) != self.turns:
            raise ValueError('normal session stop changed durable work')
        self.expect_pending = False

    def finish(self):
        self.report['idle_after_restart'] = self.readback()
        self.new_session = self.create_session()
        new_turns = self.send(self.new_session, 1)
        self.call('session', 'stop', self.new_session, '--campaign', self.fixture['camp_id'])
        self.session_info(self.new_session, 'SESSION_STATUS_STOPPED')
        if self.turn_readback(self.session, 2) != self.turns:
            raise ValueError('new daemon work changed the prior session turns')
        self.report['new_daemon_provider_turn'] = {'session_id': self.new_session, 'completed_turns': 1,
                                                  'turns_sha256': digest_rows(new_turns)}
        self.report['real_session_survived_update'] = True
        self.report['safe_idle_restart_verified'] = True

    def cleanup(self):
        # The native verifier uninstalls its owned Obey service before this call.
        self.provider.close()
