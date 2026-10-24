"""Owned Linux service crash, supervisor recovery, and new real provider work.

The App is stopped by the caller before crash(). No session CLI is used between
SIGKILL and systemd/socket recovery; service status is a read-only observer.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import time

import active_provider
import active_session as active
import existing_obey
from verify_candidate import command
from verify_selected_components import checked_receipts, checked_status

PROPERTIES = {'MainPID', 'NRestarts', 'ActiveState', 'SubState', 'Restart', 'FragmentPath'}


def checked_unit(text, unit):
    rows = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key not in PROPERTIES or key in rows:
            raise ValueError('unexpected or ambiguous supervisor properties')
        rows[key] = value
    if (set(rows) != PROPERTIES or rows['FragmentPath'] != str(unit) or
            rows['Restart'] != 'always' or rows['ActiveState'] != 'active' or rows['SubState'] != 'running'):
        raise ValueError('owned supervisor is not active with automatic crash recovery')
    for key in ('MainPID', 'NRestarts'):
        if not rows[key].isascii() or not rows[key].isdigit():
            raise ValueError('supervisor identity/counter is not an integer')
        rows[key] = int(rows[key])
    if rows['MainPID'] <= 0:
        raise ValueError('supervisor has no live main process')
    return rows


def owned_regular(path):
    path = Path(path)
    for parent in [path, *path.parents]:
        if parent.is_symlink():
            raise ValueError('owned service path contains a symbolic link')
    value = path.stat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_nlink != 1:
        raise ValueError('service file is not exclusively owned by the disposable user')
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mtime_ns': value.st_mtime_ns, 'mode': value.st_mode, 'uid': value.st_uid,
            'gid': value.st_gid, 'device': value.st_dev, 'inode': value.st_ino}


def bound_process(pid, executable, expected_hash):
    info = active.process_identity(pid)
    if info['executable_sha256'] != expected_hash or not os.path.samefile(Path('/proc')/str(pid)/'exe', executable):
        raise ValueError('supervisor process does not execute the receipt-owned public bytes')
    status = (Path('/proc')/str(pid)/'status').read_text().splitlines()
    uid = next(line.split()[1:] for line in status if line.startswith('Uid:'))
    if uid != [str(os.getuid())] * 4:
        raise ValueError('daemon is not owned by the disposable user')
    return info


def kill_bound(expected, executable, expected_hash, revalidate):
    """Signal only a held kernel identity after a second complete ownership check."""
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise RuntimeError('Linux pidfd signaling is required; no PID fallback')
    descriptor = os.pidfd_open(expected['pid'], 0)
    try:
        # Hold the executable as well as the process identity during revalidation.
        with (Path('/proc')/str(expected['pid'])/'exe').open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != expected_hash:
                raise ValueError('held daemon executable changed')
            if bound_process(expected['pid'], executable, expected_hash) != expected:
                raise ValueError('daemon generation changed before crash injection')
            revalidate()
            signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
            poll = select.poll(); poll.register(descriptor, select.POLLIN)
            if not any(flags & select.POLLIN for _, flags in poll.poll(10000)):
                raise RuntimeError('held daemon did not exit after crash injection')
    finally:
        os.close(descriptor)


def crashed_session(document, session, camp):
    row = document.get('session', {})
    if row.get('error_message') != 'daemon restarted':
        raise ValueError('crashed session lacks the published restart diagnostic')
    clean = dict(row); clean.pop('error_message', None)
    return active.checked_session({'session': clean}, session, camp, 'SESSION_STATUS_FAILED')


def checked_restart_event(document, session, camp):
    matches = [row for row in document.get('events', []) if row.get('kind') == 'session_status_changed'
               and row.get('message') == 'daemon restarted']
    if len(matches) != 1:
        raise ValueError('durable history lacks one unambiguous crash transition')
    row = matches[0]
    if (row.get('session_id') != session or row.get('campaign_id') != camp or
            row.get('old_status') != 'RUNNING' or row.get('new_status') != 'FAILED' or
            not str(row.get('sequence_number', '')).isdigit() or int(row['sequence_number']) <= 0 or
            not row.get('id') or not row.get('timestamp')):
        raise ValueError('durable crash transition identity/lifecycle is invalid')
    # Export only the known lifecycle marker, never arbitrary provider events.
    return {key: row[key] for key in ('id', 'session_id', 'campaign_id', 'kind', 'message',
                                      'old_status', 'new_status', 'sequence_number', 'timestamp')}


class Fixture(active.SessionClient):
    def __init__(self, root, installer, managed, target, environment, output, report):
        active_provider.require_isolation()
        if target != 'x86_64-unknown-linux-gnu':
            raise ValueError('service recovery currently requires native Linux x64')
        self.root, self.installer, self.managed = Path(root), Path(installer), Path(managed)
        self.environment, self.output, self.report = environment, Path(output), report
        self.provider = active_provider.Provider(self.root/'recovery-provider', environment, report.setdefault('provider', {}))
        self.obey = self.managed/'bin/obey'
        self.session = self.new_session = None
        self.recovered = None

    def seed(self):
        self.provider.start()
        self.config = Path.home()/'.obey/daemon.yaml'
        self.config.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(self.config):
            raise ValueError('service recovery refuses existing provider configuration')
        with self.config.open('x') as stream:
            json.dump({'network': {'enabled': False}, 'providers': {'ollama': {'type': 'ollama', 'enabled': True,
                'base_url': self.provider.endpoint, 'options': {'num_ctx': 4096, 'num_predict': 64,
                'temperature': 0, 'keep_alive': '1m'}}}}, stream)
        self.fixture = existing_obey.seed(self.root, self.installer, self.managed,
            'x86_64-unknown-linux-gnu', self.environment, self.output, self.report, 'current')
        from app_upgrade_contract import persisted_snapshot
        self.fixture['snapshot'].update(persisted_snapshot([self.config]))
        self.baseline = self.report['existing_before']
        self.baseline['preserved'] = existing_obey.settings_readback(self.fixture)[1]
        self.expected_hash = next(row['hash'] for row in self.baseline['receipts']['files'] if row['path'] == str(self.obey))
        self.unit = Path.home()/'.config/systemd/user/obey.service'
        self.unit_before = owned_regular(self.unit)
        if f'ExecStart="{self.obey}" serve --daemon-mode\n' not in self.unit.read_text():
            raise ValueError('service unit does not launch the exact owned daemon')
        self.config_before = owned_regular(self.config)
        self.session = self.create_session()
        self.turns = self.send(self.session, 1)
        self.original = self.supervisor()
        self.original_process = bound_process(self.original['MainPID'], self.obey, self.expected_hash)
        self.report['before_app'] = self.readback()

    def supervisor(self):
        return checked_unit(command(['systemctl', '--user', 'show', 'obey.service', '--no-pager',
            *['--property='+key for key in sorted(PROPERTIES)]], self.environment), self.unit)

    def preserved(self):
        selected = checked_receipts(self.managed)
        if selected != self.baseline['receipts']:
            raise ValueError('service recovery changed selected receipts or file bytes')
        mtimes = {row['path']: Path(row['path']).stat().st_mtime_ns for row in selected['files']}
        if mtimes != self.baseline['mtimes'] or owned_regular(self.unit) != self.unit_before or owned_regular(self.config) != self.config_before:
            raise ValueError('service recovery rewrote packages, unit or provider configuration')
        settings, preserved, lifecycle, _ = existing_obey.settings_readback(self.fixture)
        if (preserved != self.baseline['preserved'] or lifecycle != self.baseline['lifecycle'] or
                settings.get('pendingObeyRestart', False)):
            raise ValueError('service recovery changed unrelated settings/camp state')
        return {'receipts': selected, 'selected_mtime_ns': mtimes, 'preserved': preserved, 'lifecycle': lifecycle,
                'unit': self.unit_before, 'provider_config': self.config_before}

    def readback(self):
        result = self.preserved()
        state = existing_obey.service(self.obey, self.environment)
        if not all(state.get(key) is True for key in ('installed', 'loaded', 'socket_reachable')):
            raise ValueError('service recovery daemon is not responsive')
        supervisor = self.supervisor()
        process = bound_process(supervisor['MainPID'], self.obey, self.expected_hash)
        expected = self.recovered or self.original_process
        if process != expected or state.get('daemon_pid') != process['pid']:
            raise ValueError('App changed the observed service generation')
        status = command([self.installer, '--managed', 'status', '--plugin', existing_obey.COMPANION, '--json'],
                         self.environment, json_output=True)
        checked_status(status, self.managed)
        if self.recovered:
            session = crashed_session(self.call('session', 'info', self.session, '--campaign', self.fixture['camp_id'], json_output=True),
                                      self.session, self.fixture['camp_id'])
        else:
            session = self.session_info(self.session, 'SESSION_STATUS_RUNNING')
        turns = self.turn_readback(self.session, 1)
        if turns != self.turns:
            raise ValueError('crash recovery changed completed durable work')
        return dict(result, service=state, supervisor=supervisor, process=process, session=session,
                    completed_turns=1, turns_sha256=active.digest_rows(turns), installer_status=status)

    def crash(self):
        # Caller has completed normal App quit. All checks before signaling are
        # read-only and the held pidfd prevents a replacement PID being targeted.
        self.report['before_crash'] = self.readback()
        def revalidate():
            self.preserved()
            if self.supervisor() != self.original:
                raise ValueError('supervisor identity changed before crash injection')
        kill_bound(self.original_process, self.obey, self.expected_hash, revalidate)
        deadline = time.monotonic() + 90
        observations = self.report['supervisor_observations_before_session_cli'] = []
        while time.monotonic() < deadline:
            try:
                supervisor = self.supervisor()
                state = existing_obey.service(self.obey, self.environment)
                observations.append({'supervisor': supervisor, 'service': state})
                if (supervisor['MainPID'] != self.original['MainPID'] and supervisor['NRestarts'] > self.original['NRestarts'] and
                        all(state.get(key) is True for key in ('installed', 'loaded', 'socket_reachable')) and
                        state.get('daemon_pid') == supervisor['MainPID']):
                    self.recovered = bound_process(supervisor['MainPID'], self.obey, self.expected_hash)
                    break
            except (ValueError, OSError, RuntimeError) as error:
                observations.append({'not_ready': str(error)})
            time.sleep(.5)
        self.report['supervisor_observations_before_session_cli'] = observations
        if self.recovered is None:
            raise RuntimeError('supervisor failed to recover without a client start/restart')
        self.report['after_autonomous_recovery'] = self.readback()
        events = self.call('session', 'events', self.session, '--campaign', self.fixture['camp_id'],
                           '--kinds', 'session_status_changed', '--limit', '100', json_output=True)
        self.restart_event = checked_restart_event(events, self.session, self.fixture['camp_id'])
        self.report['durable_restart_event'] = self.restart_event
        self.new_session = self.create_session()
        new_turns = self.send(self.new_session, 1)
        self.call('session', 'stop', self.new_session, '--campaign', self.fixture['camp_id'])
        self.session_info(self.new_session, 'SESSION_STATUS_STOPPED')
        if self.turn_readback(self.new_session, 1) != new_turns:
            raise ValueError('normal stop changed new recovered-daemon work')
        self.report['new_real_work'] = {'session_id': self.new_session, 'completed_turns': 1,
                                       'turns_sha256': active.digest_rows(new_turns)}
        self.new_turns = new_turns
        self.report['before_app_reopen'] = self.readback()

    def finish(self):
        if not self.recovered or self.readback() != self.report['before_app_reopen']:
            raise ValueError('App reopen changed recovered service or preserved user state')
        self.session_info(self.new_session, 'SESSION_STATUS_STOPPED')
        if self.turn_readback(self.new_session, 1) != self.new_turns:
            raise ValueError('App reopen changed new durable work')
        events = self.call('session', 'events', self.session, '--campaign', self.fixture['camp_id'],
                           '--kinds', 'session_status_changed', '--limit', '100', json_output=True)
        if checked_restart_event(events, self.session, self.fixture['camp_id']) != self.restart_event:
            raise ValueError('App reopen changed durable crash lifecycle history')
        self.report['verified'] = True

    def cleanup(self):
        self.provider.close()
