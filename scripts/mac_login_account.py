"""Owned disposable macOS account setup for actual Zsh login verification."""
import os
from pathlib import Path
import re
import sys

from verify_candidate import command, require_disposable

ZSH = '/bin/zsh'


def read_account(username, environment):
    text = command(['/usr/bin/dscl', '.', '-read', '/Users/' + username,
                    'UniqueID', 'NFSHomeDirectory', 'UserShell'], environment)
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition(': ')
        if not separator or key in values:
            raise ValueError('ambiguous disposable account attributes')
        values[key] = value.strip()
    if set(values) != {'UniqueID', 'NFSHomeDirectory', 'UserShell'} or not values['UniqueID'].isdigit():
        raise ValueError('incomplete disposable account attributes')
    if not all(Path(values[key]).is_absolute() for key in ('NFSHomeDirectory', 'UserShell')):
        raise ValueError('disposable account path is not absolute')
    return {'uid': int(values['UniqueID']), 'home': values['NFSHomeDirectory'], 'shell': values['UserShell']}


class Account:
    def __init__(self, username, original, environment, report):
        self.username, self.original, self.environment = username, original, environment
        self.original_environment_shell = environment.get('SHELL')
        self.attempted = False
        self.record = report['mac_login_account'] = {
            'username': username, 'before': original, 'target_shell': ZSH,
            'environment_shell_before': self.original_environment_shell,
            'attempted_change': False, 'restored': False}

    def current(self):
        current = read_account(self.username, self.environment)
        if any(current[key] != self.original[key] for key in ('uid', 'home')):
            raise RuntimeError('disposable account identity changed during login-shell proof')
        return current

    def change(self, before, after):
        command(['/usr/bin/sudo', '-n', '/usr/bin/dscl', '.', '-change',
                 '/Users/' + self.username, 'UserShell', before, after],
                self.environment, timeout=30)

    def activate(self):
        if self.current() != self.original:
            raise RuntimeError('login shell changed before owned account setup')
        self.attempted = True
        self.record['attempted_change'] = self.original['shell'] != ZSH
        try:
            if self.original['shell'] != ZSH:
                self.change(self.original['shell'], ZSH)
            after = self.current()
            if after['shell'] != ZSH:
                raise RuntimeError('macOS account did not retain selected Zsh shell')
            self.environment['SHELL'] = ZSH
            self.record['after_selection'] = after
        except BaseException:
            # A failed dscl process may already have changed the record. Restore
            # before rethrowing because the caller has no returned fixture yet.
            self.restore()
            raise

    def restore(self):
        if not self.attempted or self.record['restored']:
            return
        current = self.current()
        if current['shell'] == ZSH and self.original['shell'] != ZSH:
            self.change(ZSH, self.original['shell'])
        elif current['shell'] != self.original['shell']:
            raise RuntimeError('refusing to overwrite an unexpected account shell during cleanup')
        restored = self.current()
        if restored != self.original:
            raise RuntimeError('original macOS login account was not restored')
        if self.original_environment_shell is None:
            self.environment.pop('SHELL', None)
        else:
            self.environment['SHELL'] = self.original_environment_shell
        self.record.update(restored=True, after_restore=restored)


def prepare(environment, report):
    require_disposable()
    if sys.platform != 'darwin' or os.getuid() == 0:
        raise RuntimeError('Zsh account fixture requires a normal disposable macOS user')
    import pwd
    owner = pwd.getpwuid(os.getuid())
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', owner.pw_name):
        raise ValueError('unsafe disposable account name')
    original = read_account(owner.pw_name, environment)
    if original['uid'] != os.getuid() or Path(original['home']).resolve() != Path.home().resolve():
        raise RuntimeError('directory-service account differs from the owned login user')
    if ZSH not in Path('/etc/shells').read_text().splitlines() or not os.access(ZSH, os.X_OK):
        raise RuntimeError('system Zsh is not an installed permitted login shell')
    fixture = Account(owner.pw_name, original, environment, report)
    fixture.activate()
    return fixture
