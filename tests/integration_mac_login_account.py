"""Actual hosted-account selection, Zsh login and cleanup after a real mutation."""
import json
import os
from pathlib import Path
import pwd
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import mac_login_account as account
from login_shell import pty_run
from verify_candidate import require_disposable

require_disposable()
if sys.platform != 'darwin' or os.getuid() == 0:
    raise RuntimeError('account control requires normal disposable macOS user')
output = Path(os.environ['RUNNER_TEMP'])/'mac-login-account-proof'
output.mkdir()
environment = dict(os.environ)
report = {}
fixture = None
try:
    fixture = account.prepare(environment, report)
    owner = pwd.getpwuid(os.getuid())
    if owner.pw_shell != account.ZSH:
        raise RuntimeError('actual passwd lookup did not select Zsh after account change')
    pty_run([owner.pw_shell, '-lic', '[[ $SHELL == /bin/zsh && -o interactive && -o login ]] || exit 9; print -r -- FA0027_REAL_ZSH_LOGIN'],
            environment, output/'zsh-login.terminal.log')
    if b'FA0027_REAL_ZSH_LOGIN' not in (output/'zsh-login.terminal.log').read_bytes():
        raise RuntimeError('real Zsh login output absent')
    report['actual_zsh_login'] = True
finally:
    try:
        if fixture is not None:
            fixture.restore()
    finally:
        (output/'proof.json').write_text(json.dumps(report, indent=2)+'\n')
print('Actual account Zsh selection, passwd lookup, interactive login and original restoration PASS', flush=True)

# Propagate a failure after the real Directory Services write, then exercise
# prepare's self-cleanup before it can return a fixture to its caller.
if fixture.original['shell'] != account.ZSH:
    original_command = account.command
    def change_then_fail(arguments, environment, **kwargs):
        result = original_command(arguments, environment, **kwargs)
        if '-change' in arguments and arguments[-1] == account.ZSH:
            raise RuntimeError('injected failure after real account change')
        return result
    failed = {}
    try:
        with patch.object(account, 'command', side_effect=change_then_fail):
            try:
                account.prepare(environment, failed)
            except RuntimeError as error:
                if str(error) != 'injected failure after real account change':
                    raise
            else:
                raise AssertionError('real account mutation failure did not propagate')
        if not failed['mac_login_account']['restored'] or account.read_account(fixture.username, environment) != fixture.original:
            raise AssertionError('partial account mutation did not restore original record')
        print('Actual partial account mutation restored before propagating failure PASS', flush=True)
    finally:
        (output/'partial-failure.json').write_text(json.dumps(failed, indent=2)+'\n')
else:
    (output/'partial-failure.json').write_text(json.dumps({
        'exercised': False, 'reason': 'baseline account already uses Zsh'})+'\n')
    raise RuntimeError('native partial-mutation control requires a non-Zsh baseline; not exercised')
