"""Actual standalone companion predates App install; compatible PATH copy is reused."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile

import existing_obey
from service_recovery import owned_regular
from verify_candidate import command, wait_until
from verify_selected_components import checked_bootstrap, checked_receipts, checked_status, fetch

INSTALLER_SHA = 'ae68d564dd6b5ed7877161598ffdb413d4a1f71e4cc6f16976b69b81bd379199'
COMPANION_SHA = 'e8fb88f8c7ac49ea530a5fad5fdcb70e4ba8bfac08bcde3f234c839979fe3afc'
BINARY_SHA = 'bc0044606d1a6071b7d11d26e59709c0102c7368efce333d78eb98171583a873'
SOURCE = 'f33d081e0ade7f1faaa739047025a3382fe900bb'


def camp_config_directory(environment):
    return (Path(environment['XDG_CONFIG_HOME'])/'obey/campaign'
            if environment.get('XDG_CONFIG_HOME') else Path.home()/'.obey/campaign')


def bind_state(bind, binary):
    info = bind.lstat()
    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
            os.readlink(bind) != str(binary) or bind.resolve() != binary.resolve()):
        raise ValueError('standalone bind is not the exact self-installer-owned symbolic link')
    return {'path': str(bind), 'target': os.readlink(bind), 'mode': info.st_mode,
            'uid': info.st_uid, 'gid': info.st_gid, 'device': info.st_dev,
            'inode': info.st_ino, 'mtime_ns': info.st_mtime_ns}


class Fixture:
    def __init__(self, root, managed, environment, output, report):
        self.root, self.managed = Path(root), Path(managed)
        self.environment, self.output, self.report = environment, Path(output), report
        self.plugin = Path.home()/'.obey/plugins/camp-app'
        self.bind = Path.home()/'.local/bin/camp-app'
        self.binary = self.plugin/'bin/camp-app'
        self.preferences = self.plugin/'user-settings.json'
        self.optional = Path.home()/'.obey/plugins/camp-buzz/user-config.json'
        self.settings = Path.home()/'.obey/festival-app/settings.json'
        self.original_path = environment['PATH']
        self.installer = None
        self.before = None

    def install_before_app(self):
        for path in (self.plugin, self.bind, self.optional, self.settings, self.managed/'state.db'):
            if os.path.lexists(path):
                raise RuntimeError('standalone fixture refuses preexisting user or managed state')
        self.environment['PATH'] = str(self.bind.parent)+os.pathsep+str(self.managed/'bin')+os.pathsep+self.original_path
        base = 'https://github.com/Obedience-Corp/festival-installer/releases/download/v0.3.8/'
        data = fetch(base+'festival-linux-amd64')
        if checked_bootstrap(data, fetch(base+'checksums.txt'), 'festival-linux-amd64') != INSTALLER_SHA:
            raise ValueError('standalone seed Installer differs from authentic public 0.3.8')
        self.bootstrap = self.root/'standalone-bootstrap'
        self.bootstrap.write_bytes(data); self.bootstrap.chmod(0o755)
        installs = self.report['preexisting_managed_installs'] = []
        for target in ('festival', 'obey'):
            result = command([self.bootstrap, '--managed', 'install', target, '--no-shell-setup', '--no-restart', '--json'], self.environment, timeout=240, json_output=True)
            if result.get('ok') is not True:
                raise ValueError('authentic selected CLI preparation failed')
            installs.append(result)
        base = 'https://github.com/Obedience-Corp/obey-releases/releases/download/camp-app-v0.1.0/'
        name = 'camp-app-0.1.0-linux-amd64.tar.gz'; data = fetch(base+name)
        if len(data) != 1927631 or checked_bootstrap(data, fetch(base+'checksums.txt'), name) != COMPANION_SHA:
            raise ValueError('standalone companion differs from authentic published artifact')
        archive = self.root/name; archive.write_bytes(data)
        with tarfile.open(archive, 'r:gz') as source:
            member = source.getmember('camp-app')
            if not member.isfile() or not member.mode & 0o111:
                raise ValueError('public companion archive lacks its executable')
            payload = source.extractfile(member).read()
        if hashlib.sha256(payload).hexdigest() != BINARY_SHA:
            raise ValueError('standalone binary differs from the published source-qualified bytes')
        executable = self.root/'standalone-source'; executable.write_bytes(payload); executable.chmod(0o755)
        version = command([executable, 'version', '--json'], self.environment, json_output=True)
        if version.get('ok') is not True or any(version['data'].get(k) != v for k,v in {'version':'0.1.0','commit':SOURCE,'protocolMajor':1}.items()):
            raise ValueError('actual standalone source/version/protocol differs')
        installed = command([executable, 'install', '--source', executable, '--json'], self.environment, json_output=True)
        expected = {str(self.binary), str(self.bind), str(self.plugin/'receipt.json')}
        if installed.get('ok') is not True or set(installed['data'].get('ownedPaths', [])) != expected:
            raise ValueError('actual standalone self-install did not establish the declared ownership')
        self.report['standalone_self_install'] = installed
        self.preferences.write_text('{"theme":"preserve-user-choice"}\n')
        self.optional.parent.mkdir(parents=True, exist_ok=True)
        self.optional.write_text('{"fixture":"unselected-user-plugin-config"}\n')
        self.watched = [self.binary, self.plugin/'receipt.json', self.preferences, self.optional]
        # These are actual CLI-created preexisting Camp files, not App-created proof.
        config = camp_config_directory(self.environment)
        self.watched += [config/'registry.json', config/'starter.json', Path.home()/'campaigns/festival/.campaign/campaign.yaml']
        integration = command([self.bootstrap, '--managed', 'setup', 'integrations', '--enable', '--json'], self.environment, json_output=True)
        if not integration.get('ok') or integration['data'].get('ready') is not True:
            raise ValueError('existing CLI integrations are not ready')
        self.obey = self.managed/'bin/obey'
        def responsive():
            value = existing_obey.service(self.obey, self.environment)
            return value if all(value.get(k) is True for k in ('installed','loaded','socket_reachable')) else None
        self.service_before = wait_until('preexisting current standalone fixture service', responsive, seconds=120)
        self.unit_before = owned_regular(self.service_before['unit_path'])
        self.before = self.snapshot()
        self.receipts_before = checked_receipts(self.managed, standalone_companion=True)
        self.files_before = {row['path']:owned_regular(row['path']) for row in self.receipts_before['files']}
        self.report['before_app_package_install'] = self.state(self.bootstrap)
        self.prepared_at = existing_obey.utc_now()
        self.report.update(installer_sha256=INSTALLER_SHA, companion_archive_sha256=COMPANION_SHA,
                           standalone_binary_sha256=BINARY_SHA, no_app_settings_before_first_launch=not self.settings.exists(),
                           optional_fixture_scope='preserved unselected user configuration; not optional plugin functionality')

    def snapshot(self):
        return {'bind': bind_state(self.bind, self.binary),
                'files': {str(path):owned_regular(path) for path in self.watched}}

    def state(self, installer):
        if os.path.lexists(self.managed/'bin/camp-app'):
            raise ValueError('App adopted or duplicated the standalone companion into managed files')
        receipts = checked_receipts(self.managed, standalone_companion=True)
        files = {row['path']:owned_regular(row['path']) for row in receipts['files']}
        if receipts != self.receipts_before or files != self.files_before or self.snapshot() != self.before:
            raise ValueError('App changed preexisting standalone/config/unselected or managed CLI state')
        service = existing_obey.service(self.obey, self.environment)
        unit = owned_regular(service['unit_path'])
        if (any(service.get(k) != self.service_before.get(k) for k in ('installed','loaded','socket_reachable','daemon_pid','unit_path','socket_path')) or
                any(unit[k] != self.unit_before[k] for k in ('path','sha256','mode','uid','gid'))):
            raise ValueError('standalone reuse restarted or changed the preexisting service definition')
        status = command([installer,'--managed','status','--plugin','obedience-corp/camp-app','--json'],self.environment,json_output=True)
        checked_status(status,self.managed,standalone_companion=True)
        version = command([self.managed/'bin/camp','app','version','--json'],self.environment,json_output=True)
        if not version.get('ok') or version['data'].get('commit') != SOURCE:
            raise ValueError('Camp did not execute the original standalone companion')
        return {'receipts':receipts,'selected_mtime_ns':{path:row['mtime_ns'] for path,row in files.items()},
                'physical_files':files,'standalone':self.before,'service':service,'unit':unit,
                'selected_status':[row for row in status['data']['tools'] if row['tool'] in ('camp','fest','obey','ob','camp-app')],
                'camp_app_version':version['data']}

    def after_package_install(self, installer):
        if hashlib.sha256(Path(installer).read_bytes()).hexdigest() != INSTALLER_SHA:
            raise ValueError('candidate bundled Installer is not the expected authentic 0.3.8')
        self.installer = installer
        self.report['after_app_package_install'] = self.state(installer)

    def readback(self):
        result = self.state(self.installer)
        if not self.settings.is_file():
            raise RuntimeError('App first-launch settings not persisted yet')
        value = json.loads(self.settings.read_text())
        if not value.get('lastUpdateCheckAt'):
            raise RuntimeError('App first-launch background check not complete yet')
        checked = existing_obey.utc_time(value['lastUpdateCheckAt'])
        if not existing_obey.utc_time(self.prepared_at) <= checked <= existing_obey.utc_time(existing_obey.utc_now()):
            raise ValueError('App did not perform a new first-launch check')
        if value.get('setupCompletedAt') is not None:
            raise ValueError('current compatible standalone fixture unexpectedly ran foreground repair')
        result['app_settings'] = value
        return result

    def finish(self, before, after):
        if before != after:
            raise ValueError('normal App reopen changed standalone reuse or current selected state')
        self.report['after_app_reopen'] = self.state(self.installer)
        self.report['verified'] = True

    def cleanup(self):
        # App/service teardown runs first. Standalone user files must still exist.
        if self.before is not None:
            if self.snapshot() != self.before:
                raise ValueError('App uninstall changed the preexisting standalone/config state')
            if (checked_receipts(self.managed, standalone_companion=True) != self.receipts_before or
                    {row['path']:owned_regular(row['path']) for row in self.receipts_before['files']} != self.files_before):
                raise ValueError('App uninstall changed preexisting managed CLI state')
            self.report['standalone_preserved_after_app_uninstall'] = True
        self.environment['PATH'] = self.original_path
