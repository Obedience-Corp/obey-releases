"""Owned APT Git absence fixture for an explicit disposable desktop journey."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time

from verify_candidate import command
import git_rollback

# Exact reverse-dependency closure observed on the disposable hosted image.
# No autoremove or arbitrary additional package removal is permitted.
ALLOWED = {'git', 'git-lfs', 'git-ftp', 'gh', 'ubuntu-server'}


def git_status(installer, environment, present, output):
    value = command([installer, '--managed', 'status', '--json'], environment, json_output=True)
    rows = [row for row in value.get('data', {}).get('prerequisites', []) if row.get('name') == 'git']
    if value.get('ok') is not True or len(rows) != 1 or rows[0].get('present') is not present:
        raise RuntimeError('bundled Installer Git prerequisite differs from fixture state')
    output.write_text(json.dumps(value, indent=2)+'\n')
    return rows[0]


def interact(process, executable, environment, action):
    from linux_git_retry import birth
    expected = birth(process.pid)
    helper = Path(__file__).with_name('linux_git_retry.py').resolve()
    arguments = ['/usr/bin/python3', '-I', helper, '--pid', str(process.pid),
                 '--birth', str(expected), '--executable', executable.resolve(), '--action', action]
    # Inspect may wait for accessibility publication. The actual action is
    # invoked once only, after identity is checked again inside the helper.
    deadline = time.monotonic()+45
    while True:
        if process.poll() is not None or birth(process.pid) != expected:
            raise RuntimeError('App exited or changed identity before Git Retry')
        try:
            result = command(arguments, environment, timeout=10, json_output=True)
            if result.get('pid') != process.pid or result.get('birth') != expected or result.get('retry_action_invoked') is not (action == 'retry'):
                raise RuntimeError('invalid owned Git Retry observation')
            return result
        except (RuntimeError, json.JSONDecodeError):
            if action != 'inspect' or time.monotonic() >= deadline:
                raise
            time.sleep(.2)


def installed(environment):
    text = command(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\\n'], environment)
    result = {}
    for row in text.splitlines():
        name, version, state = row.split('\t')
        if state == 'installed':
            if name in result:
                raise ValueError('duplicate installed package identity')
            result[name] = version
    return result


def removal_plan(text, before):
    removed = {}
    for line in text.splitlines():
        if line.startswith(('Inst ', 'Conf ')):
            raise ValueError('Git removal unexpectedly installs or configures packages')
        if line.startswith('Remv '):
            match = re.fullmatch(r'Remv ([a-z0-9+.-]+) \[([^\]]+)\](?: .*)?', line)
            if not match or match[1] not in ALLOWED or match[1] in removed or before.get(match[1]) != match[2]:
                raise ValueError('Git removal affects foreign or ambiguous package state')
            removed[match[1]] = match[2]
    if 'git' not in removed or not before.get('git') or removed['git'] != before['git']:
        raise ValueError('Git removal plan does not contain the installed Git package')
    return removed


class Fixture:
    def __init__(self, cache, output, environment):
        if (os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
                os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted' or
                not Path('/etc/debian_version').exists()):
            raise RuntimeError('Git removal requires explicit disposable hosted Debian account')
        self.environment = dict(environment, LC_ALL='C', LANG='C')
        self.cache, self.output = cache.resolve(), output
        self.cache.mkdir()
        self.before = installed(self.environment)
        self.archives = []
        self.attempted_removal = False
        self.restored = False
        self.accessibility_original = None
        self.git = Path(shutil.which('git', path=environment.get('PATH')) or '')
        if not self.git.is_absolute() or self.git.resolve() != Path('/usr/bin/git').resolve():
            raise RuntimeError('refusing foreign Git executable')
        owner = command(['dpkg-query', '-S', '/usr/bin/git'], self.environment).strip()
        if owner != 'git: /usr/bin/git':
            raise RuntimeError('Git executable is not owned by the expected APT package')
        self.git_sha = hashlib.sha256(self.git.read_bytes()).hexdigest()
        plan = self.apt(['--simulate', '--no-auto-remove', 'remove', 'git'], 60)
        self.removed = removal_plan(plan, self.before)
        self.retained_packages = set(self.before).difference(self.removed)
        (output/'missing-git-removal-plan.log').write_text(plan)
        self.files_before = {name: git_rollback.package_files(name, self.environment, self.retained_packages)
                             for name in self.removed}
        self.config_before = git_rollback.config_files(self.environment)
        self.config_backup = git_rollback.backup_system_config(self.cache, self.config_before['/etc/gitconfig'])
        (output/'missing-git-baseline-files.json').write_text(json.dumps(
            {'packages': self.files_before, 'git_config': self.config_before}, indent=2)+'\n')
        # Hosted images delete vendor sources/archive caches after provisioning.
        # Reconstruct explicit local rollback packages, verifying every member
        # against the installed baseline before any package is removed.
        for name, version in sorted(self.removed.items()):
            self.cache_package(name)
        for path in sorted(self.cache.glob('*.deb')):
            fields = command(['dpkg-deb', '-f', path, 'Package', 'Version'], self.environment).splitlines()
            values = dict(row.split(': ', 1) for row in fields)
            if values.get('Package') not in self.removed or values.get('Version') != self.removed[values['Package']]:
                raise ValueError('unexpected Git restoration archive')
            git_rollback.check_archive(path, self.files_before[values['Package']], self.environment)
            self.archives.append({'path': path, 'package': values['Package'], 'version': values['Version'],
                                  'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        if {entry['package'] for entry in self.archives} != set(self.removed) or len(self.archives) != len(self.removed):
            raise ValueError('exact Git restoration archives are incomplete')
        if installed(self.environment) != self.before:
            raise RuntimeError('Git rollback preparation changed installed packages')
        self.record('prepared')

    def apt(self, args, seconds):
        return command(['sudo', 'timeout', '--signal=TERM', '--kill-after=15s', f'{seconds}s',
                        'apt-get', *args], self.environment, timeout=seconds+45)

    def cache_package(self, name):
        # fakeroot -u preserves existing ownership in archive metadata without
        # creating root-owned files in this normal user's private cache.
        return command(['timeout', '--signal=TERM', '--kill-after=15s', '120s',
                        'bash', '-euc', 'cd -- "$1"; exec fakeroot -u dpkg-repack --tag=none "$2"',
                        'fa0027-git-rollback', self.cache, name], self.environment, timeout=165)

    def enable_accessibility(self):
        value = command(['gsettings', 'get', 'org.gnome.desktop.interface', 'toolkit-accessibility'], self.environment).strip()
        if value not in ('true', 'false'):
            raise RuntimeError('desktop accessibility setting is not a boolean')
        self.accessibility_original = value
        command(['gsettings', 'set', 'org.gnome.desktop.interface', 'toolkit-accessibility', 'true'], self.environment)
        if command(['gsettings', 'get', 'org.gnome.desktop.interface', 'toolkit-accessibility'], self.environment).strip() != 'true':
            raise RuntimeError('normal desktop accessibility activation failed')

    def restore_accessibility(self):
        if self.accessibility_original is not None:
            command(['gsettings', 'set', 'org.gnome.desktop.interface', 'toolkit-accessibility', self.accessibility_original], self.environment)
            if command(['gsettings', 'get', 'org.gnome.desktop.interface', 'toolkit-accessibility'], self.environment).strip() != self.accessibility_original:
                raise RuntimeError('desktop accessibility setting restoration failed')

    def record(self, stage):
        record = {'stage': stage, 'removed_packages': self.removed, 'original_git_sha256': self.git_sha,
                  'archive_provenance': 'locally-reconstructed-installed-baseline; not original vendor archives',
                  'restore_archives': [{key: str(value) for key, value in entry.items()} for entry in self.archives],
                  'attempted_removal': self.attempted_removal, 'restored': self.restored,
                  'original_toolkit_accessibility': self.accessibility_original}
        (self.output/'missing-git-package-fixture.json').write_text(json.dumps(record, indent=2)+'\n')

    def remove(self):
        if installed(self.environment) != self.before:
            raise RuntimeError('package state changed before controlled Git removal')
        if ({name: git_rollback.package_files(name, self.environment, self.retained_packages)
             for name in self.removed} != self.files_before
                or git_rollback.config_files(self.environment) != self.config_before):
            raise RuntimeError('package files or Git configuration changed before controlled removal')
        plan = self.apt(['--simulate', '--no-auto-remove', 'remove', 'git'], 60)
        if removal_plan(plan, self.before) != self.removed:
            raise RuntimeError('Git removal plan changed after archive preparation')
        self.attempted_removal = True
        self.record('removal-started')
        self.apt(['--no-auto-remove', '-y', 'remove', 'git'], 300)
        expected = {name: version for name, version in self.before.items() if name not in self.removed}
        if installed(self.environment) != expected or shutil.which('git', path=self.environment.get('PATH')):
            raise RuntimeError('actual Git absence or unrelated package preservation failed')
        self.record('git-absent')

    def restore(self):
        if not self.attempted_removal or self.restored:
            return
        for entry in self.archives:
            if hashlib.sha256(entry['path'].read_bytes()).hexdigest() != entry['sha256']:
                raise ValueError('Git restoration archive changed')
        command(['sudo', 'timeout', '--signal=TERM', '--kill-after=15s', '300s',
                 'dpkg', '--install', *[entry['path'] for entry in self.archives]], self.environment, timeout=345)
        if installed(self.environment) != self.before or hashlib.sha256(self.git.read_bytes()).hexdigest() != self.git_sha:
            raise RuntimeError('Git restoration did not preserve exact package and executable identities')
        command([self.git, '--version'], self.environment)
        files = {name: git_rollback.package_files(name, self.environment, self.retained_packages)
                 for name in self.removed}
        configs = git_rollback.config_files(self.environment)
        (self.output/'missing-git-postinstall-files.json').write_text(json.dumps(
            {'packages': files, 'git_config': configs}, indent=2)+'\n')
        system = '/etc/gitconfig'
        if configs[system] != self.config_before[system]:
            # Git LFS maintainer scripts recreate the same four default keys in
            # nondeterministic order. Restore original bytes only after the
            # fixed-path helper excludes every unrelated config change.
            if any(configs[path] != self.config_before[path] for path in configs if path != system):
                raise RuntimeError('user Git configuration changed during package restoration')
            command(['sudo', '--preserve-env=CANDIDATE_NATIVE_DISPOSABLE,CANDIDATE_RUNNER_KIND',
                     '/usr/bin/python3', '-I', Path(git_rollback.__file__).resolve(),
                     '--restore-system-config', self.config_backup, json.dumps(self.config_before[system]),
                     json.dumps(configs[system]), str(os.getuid())], self.environment, timeout=15)
            configs = git_rollback.config_files(self.environment)
        (self.output/'missing-git-restored-files.json').write_text(json.dumps(
            {'packages': files, 'git_config': configs}, indent=2)+'\n')
        if files != self.files_before or configs != self.config_before:
            changed = {name: sorted(path for path in set(files[name]) | set(self.files_before[name])
                                   if files[name].get(path) != self.files_before[name].get(path))[:20]
                       for name in self.removed if files[name] != self.files_before[name]}
            changed_configs = sorted(path for path in set(configs) | set(self.config_before)
                                     if configs.get(path) != self.config_before.get(path))
            raise RuntimeError('restoration changed package bytes/ownership/modes or Git configuration: '
                               + repr({'packages': changed, 'git_config': changed_configs}))
        self.restored = True
        self.record('restored')
