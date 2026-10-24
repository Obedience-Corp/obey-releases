"""Actual selected-package transport failure, refreshed facts and same-process Retry."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3

from external_suite import physical
from linux_accessibility import ToolkitSetting
from linux_git_retry import birth, require_owner
from partial_install_proxy import PartialInstallProxy
from verify_candidate import command, wait_until

SUITE = 'obedience-corp/festival'
OBEY = 'obedience-corp/obey'
COMPANION = 'obedience-corp/camp-app'
EXPECTED = {SUITE: '0.3.24', OBEY: '0.2.3'}
TOOLS = {'camp': ('0.16.2', SUITE), 'fest': ('0.9.8', SUITE),
         'obey': ('0.2.3', OBEY), 'ob': ('0.1.0', OBEY)}


def checked_report(document, *, ready=False):
    expected_state = {'kind': 'ready'} if ready else {'kind': 'failed', 'step': 'install'}
    if (document.get('state') != expected_state or document.get('factsStale') is not False or
            document.get('blocksLaunch') is not (not ready)):
        raise ValueError('setup report does not contain truthful settled partial/ready state')
    rows = document.get('packages', [])
    packages = {row['id']: row for row in rows}
    if len(rows) != len(packages) or not {SUITE, OBEY, COMPANION} <= packages.keys():
        raise ValueError('required package review is incomplete or duplicated')
    for package in (SUITE, OBEY, COMPANION):
        row = packages[package]
        expected_ready = ready or package != COMPANION
        if row.get('selected') is not True or row.get('ready') is not expected_ready:
            raise ValueError('package readiness does not reflect the actual partial placement')
    if not ready:
        steps = [row for row in document['steps'] if row['step'] == 'install']
        if len(steps) != 1 or steps[0].get('errorCode') != 'E_ARTIFACT_DO':
            raise ValueError('expected real companion artifact transport error')
        if any(packages[p].get('result') != 'installed' for p in (SUITE, OBEY)):
            raise ValueError('earlier actual package placements are missing from results')
        if packages[COMPANION].get('result') != 'failed':
            raise ValueError('companion package must explicitly report its failed install result')
    graph = packages.get('obedience-corp/camp-graph', {})
    if graph.get('requirement') != 'optional' or graph.get('selected') is not False:
        raise ValueError('reviewable optional unselected Camp Graph row is missing')
    # Preserve actual optional rows; never declare an unselected package ready or installed.
    for row in rows:
        if row.get('selected') is False and (row.get('ready') is not False or
                row.get('plannedAction') != 'unselected' or row.get('result') is not None):
            raise ValueError('unselected package was mutated or misreported')
    return document


def partial_readback(installer, managed, environment):
    status = command([installer, '--managed', 'status', '--plugin', COMPANION, '--json'],
                     environment, json_output=True)
    if status.get('ok') is not True or status['data'].get('signals_incomplete'):
        raise ValueError('partial package status must be readable')
    tools = status['data']['tools']
    for name, (version, package) in TOOLS.items():
        rows = [row for row in tools if row.get('tool') == name]
        if (len(rows) != 1 or rows[0].get('present') is not True or
                rows[0].get('version') != version or rows[0].get('origin') != 'managed' or
                rows[0].get('path') != str(managed / 'bin' / name) or
                rows[0].get('package') != package or rows[0].get('receipt_version') != EXPECTED[package]):
            raise ValueError('partial status lost the earlier real selected tools')
    companion = [row for row in tools if row.get('tool') == 'camp-app']
    if len(companion) != 1 or companion[0].get('present') is not False or os.path.lexists(managed/'bin/camp-app'):
        raise ValueError('failed companion download unexpectedly installed a command')
    with closing(sqlite3.connect((managed/'state.db').as_uri()+'?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        receipts = [dict(row) for row in db.execute('select * from receipts order by package_id')]
        files = [dict(row) for row in db.execute('select * from receipt_files order by path')]
    if ({row['package_id']: row['version'] for row in receipts} != EXPECTED or
            any(row['source'] != 'official-obey' or row['channel'] != 'stable' for row in receipts)):
        raise ValueError('partial receipts must contain exactly the two authentic placed packages')
    if len(files) != 4 or {Path(row['path']).name for row in files} != TOOLS.keys():
        raise ValueError('partial receipt inventory differs from the four earlier executables')
    identities = []
    for row in files:
        path = Path(row['path'])
        if path != managed/'bin'/path.name or row['receipt_pkg_id'] != TOOLS[path.name][1]:
            raise ValueError('partial receipt is not bound to its actual selected path')
        value = physical(path)
        if value['sha256'] != row['hash'] or value['uid'] != os.getuid():
            raise ValueError('partial executable differs from its authentic owned receipt')
        identities.append(value)
    service = command([managed/'bin/obey', 'service', 'status', '--json'], environment, json_output=True)
    return {'status': status, 'receipts': {'receipts': receipts, 'files': files},
            'physical': identities, 'service': service}


class Fixture:
    def __init__(self, installer, managed, output, environment, report):
        if (os.name != 'posix' or not Path('/proc/net/tcp').is_file() or
                os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
                os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted'):
            raise RuntimeError('partial selected install requires disposable native Linux')
        proxy_names = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy',
                       'all_proxy', 'NO_PROXY', 'no_proxy', 'FESTIVAL_APP_SETUP_REPORT_PATH')
        if any(environment.get(name) for name in proxy_names):
            raise RuntimeError('partial transport fixture refuses inherited proxy/report settings')
        if managed.exists():
            raise RuntimeError('partial install must begin with no Installer home or selected receipts')
        self.installer, self.managed = Path(installer), Path(managed)
        self.output, self.environment, self.report = Path(output), environment, report
        self.report_path = self.output/'actual-setup-report.json'
        if self.report_path.exists():
            raise RuntimeError('partial fixture refuses a preexisting setup report')
        self.accessibility = ToolkitSetting(environment)
        self.proxy = None
        self.app = None
        self.started = None
        self.note = Path.home()/'.fa0027-partial-install-preserve.txt'
        self.note_before = None
        self.note_attempted = False
        if os.path.lexists(self.note):
            raise RuntimeError('partial fixture refuses a preexisting preservation note')

    def prepare(self):
        # Finally owns restoration even if a later preparation operation fails.
        self.accessibility.enable()
        self.note_attempted = True
        self.note.write_bytes(b'FA0027 unrelated user input must survive partial install and Retry.\n')
        self.note_before = physical(self.note)
        self.proxy = PartialInstallProxy(self.installer)
        return dict(self.environment, HTTPS_PROXY=self.proxy.url, HTTP_PROXY=self.proxy.url,
                    NO_PROXY='localhost,127.0.0.1', FESTIVAL_APP_SETUP_REPORT_PATH=str(self.report_path))

    def bind(self, app, binary):
        self.app, self.binary = app, Path(binary)
        self.started = birth(app.pid)
        require_owner(app.pid, self.started, self.binary)
        self.proxy.bind(app)
        self.report['app_identity'] = {'pid': app.pid, 'birth': self.started, 'executable': str(binary)}

    def alive(self):
        if self.app.poll() is not None:
            raise RuntimeError('partial install App exited or restarted before same-process Retry')
        require_owner(self.app.pid, self.started, self.binary)

    def read_report(self):
        try:
            before = self.report_path.read_bytes()
            if len(before) > 1024*1024:
                raise ValueError('actual setup report exceeds observation bound')
            document = json.loads(before)
            if self.report_path.read_bytes() != before:
                return None
            return document
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def ui(self, action):
        import linux_setup_retry
        return command(['/usr/bin/python3', '-I', Path(linux_setup_retry.__file__).resolve(),
                        '--pid', str(self.app.pid), '--birth', str(self.started),
                        '--executable', self.binary, '--action', action], self.environment,
                       timeout=30, json_output=True)

    def fail_and_retry(self, capture):
        def failed():
            self.alive()
            value = self.read_report()
            if value and value.get('state') == {'kind': 'ready'}:
                raise RuntimeError('App bypassed the targeted transport fault; partial scenario unproved')
            return value if value and value.get('state') == {'kind': 'failed', 'step': 'install'} else None
        document = wait_until('real selected companion transport failure', failed, seconds=600)
        checked_report(document)
        self.report['failed_setup'] = document
        self.report['partial_before_retry'] = partial_readback(self.installer, self.managed, self.environment)
        self.report['proxy_at_failure'] = self.proxy.evidence()
        self.report['failed_window'] = capture(self.output/'partial-selected-install.png')
        def inspect():
            self.alive()
            try:
                return self.ui('inspect')
            except RuntimeError:
                return None
        self.report['retry_inspected'] = wait_until('actual failed Install row and normal Retry', inspect, seconds=60)
        if physical(self.note) != self.note_before:
            raise ValueError('partial failure changed unrelated user input')
        self.proxy.recover()
        self.alive()
        self.report['retry_action'] = self.ui('retry')
        def completed():
            self.alive()
            value = self.read_report()
            return value if value and value.get('state') == {'kind': 'ready'} else None
        self.report['ready_setup'] = checked_report(wait_until('same-process real Retry completes setup',
                                                              completed, seconds=600), ready=True)
        self.report['same_process_retry_verified'] = True

    def preserved(self, reading):
        before = self.report['partial_before_retry']
        actual = reading['receipts']
        earlier = {'receipts': [r for r in actual['receipts'] if r['package_id'] in EXPECTED],
                   'files': [r for r in actual['files'] if r['receipt_pkg_id'] in EXPECTED]}
        if earlier != before['receipts'] or [physical(row['path']) for row in earlier['files']] != before['physical']:
            raise ValueError('Retry/reopen rewrote the earlier successful package receipts or physical files')
        if physical(self.note) != self.note_before:
            raise ValueError('Retry/reopen changed unrelated user input')
        if before.get('service', {}).get('socket_reachable') is True:
            if (reading.get('service', {}).get('daemon_pid') != before['service'].get('daemon_pid') or
                    reading['service'].get('socket_reachable') is not True):
                raise ValueError('Retry/reopen unnecessarily restarted the already-responsive service')
        self.report['proxy_after_retry'] = self.proxy.evidence()
        if (self.report['proxy_after_retry']['ownership_errors'] or
                any(row['outcome'] == 'denied' for row in self.report['proxy_after_retry']['requests'])):
            raise ValueError('transport attribution failed; no partial install claim allowed')

    def close(self):
        errors = []
        if self.proxy is not None:
            try:
                self.proxy.close()
                self.report['proxy_cleanup'] = self.proxy.evidence()
            except BaseException as error:
                errors.append(str(error))
        try:
            self.accessibility.restore()
            self.report['accessibility_restored'] = self.accessibility.read() == self.accessibility.original
        except BaseException as error:
            errors.append(str(error))
        if self.note_attempted and self.note_before is None:
            errors.append('refusing unknown/partial preservation-note cleanup')
        if self.note_before is not None:
            try:
                from corrupt_receipts import quiescent
                quiescent(self.environment)
                if physical(self.note) != self.note_before:
                    raise RuntimeError('refusing cleanup of changed preservation note')
                self.note.unlink()
                self.report['preservation_note_cleanup'] = True
            except BaseException as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError('; '.join(errors))
