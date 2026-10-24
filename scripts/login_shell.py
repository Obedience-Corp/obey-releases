"""Fresh disposable-account profile preservation and ordinary shell readback."""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import time
import uuid

from verify_candidate import command

TOOLS = {'camp': ('0.16.2', ['version', '--short']),
         'fest': ('0.9.8', ['version', '--short']),
         'obey': ('0.2.3', ['version', '--short']),
         'ob': ('0.1.0', ['--version']),
         'camp-app': ('0.1.0', ['version', '--json'])}


def owned_profile(path, home):
    if not path.is_absolute() or not path.resolve().is_relative_to(home.resolve()):
        raise ValueError('login profile is outside the disposable home')
    current = path
    while current != home:
        if current.is_symlink():
            raise ValueError('login profile has a symlink component')
        current = current.parent
    if path.exists() and not path.is_file():
        raise ValueError('login profile is not a regular file')


def seed_profile(path, home, shell):
    owned_profile(path, home)
    original = path.read_bytes() if path.exists() else b''
    token = uuid.uuid4().hex[:12]
    function = 'fa0027_keep_' + token
    value = 'FA0027-profile-' + token
    declaration = (f"\n# FA0027 foreign user profile fixture\nfunction {function} {{ '{value}' }}\n"
                   if shell in ('pwsh', 'powershell') else
                   f"\n# FA0027 foreign user profile fixture\n{function}() {{ printf '%s\\n' '{value}'; }}\n")
    seeded = original + declaration.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('ab') as stream:
        stream.write(declaration.encode())
    if path.read_bytes() != seeded:
        raise ValueError('login profile changed concurrently while seeding the foreign fixture')
    return {'path': path, 'seeded': seeded, 'function': function, 'value': value,
            'original_sha256': hashlib.sha256(original).hexdigest(),
            'seeded_sha256': hashlib.sha256(seeded).hexdigest()}


def prepare(environment, report):
    if os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted':
        raise RuntimeError('login proof requires the disposable native fresh account')
    home = Path.home().resolve()
    if os.name == 'nt':
        shell = shutil.which('pwsh', path=environment.get('PATH'))
        if not shell:
            raise RuntimeError('ordinary PowerShell is unavailable')
        name = 'pwsh'
        runtime = command([shell, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
                           '@{profile=$PROFILE.CurrentUserAllHosts;major=$PSVersionTable.PSVersion.Major;version=$PSVersionTable.PSVersion.ToString()} | ConvertTo-Json -Compress'], environment, json_output=True)
        if runtime.get('major') != 7:
            raise RuntimeError('this proof covers installed PowerShell7 only')
        profile = Path(runtime['profile'])
    else:
        import pwd
        shell = pwd.getpwuid(os.getuid()).pw_shell
        name = Path(shell).name
        runtime = {'version': name}
        if name == 'bash':
            profile = next((home / n for n in ('.bash_profile', '.bash_login', '.profile') if (home / n).exists()), home / '.bash_profile')
        elif name == 'zsh':
            text = command([shell, '-c', "printf '\\nFA0027_ZDOTDIR=%s\\n' \"${ZDOTDIR:-$HOME}\""], environment)
            found = re.findall(r'^FA0027_ZDOTDIR=(.+)$', text, re.MULTILINE)
            if len(found) != 1:
                raise RuntimeError('actual zsh startup directory is ambiguous')
            profile = Path(found[0]) / '.zshrc'
        else:
            raise RuntimeError('actual login shell is unsupported by this proof: ' + name)
    fixture = seed_profile(profile, home, name)
    fixture.update(shell=shell, kind=name, runtime=runtime['version'])
    report['login_profile_fixture'] = {key: str(fixture[key]) for key in
        ('path', 'shell', 'kind', 'runtime', 'function', 'value', 'original_sha256', 'seeded_sha256')}
    return fixture


def script_for(fixture, tool):
    if tool not in TOOLS or not re.fullmatch(r'fa0027_keep_[0-9a-f]{12}', fixture['function']):
        raise ValueError('invalid fixed login probe')
    marker = 'FA0027_' + fixture['function'][12:]
    if fixture['kind'] in ('pwsh', 'powershell'):
        args = ' '.join("'" + arg + "'" for arg in TOOLS[tool][1])
        script = f"""$ErrorActionPreference='Stop'
'{marker}_PROFILE'; {fixture['function']}
'{marker}_PATH'; $resolved=Get-Command '{tool}' -ErrorAction Stop
if ($resolved.CommandType -ne 'Application') {{ throw 'required command is shadowed' }}
$resolved.Source
'{marker}_VERSION'; & '{tool}' {args}
if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
'{marker}_END'
"""
        return [fixture['shell'], '-NoLogo', '-NonInteractive', '-EncodedCommand', base64.b64encode(script.encode('utf-16-le')).decode()], marker
    script = (f"printf '%s\\n' '{marker}_PROFILE'; {fixture['function']} || exit 91; "
              f"printf '%s\\n' '{marker}_PATH'; command -v {shlex.quote(tool)} || exit 92; "
              f"printf '%s\\n' '{marker}_VERSION'; {shlex.join([tool] + TOOLS[tool][1])} || exit 93; "
              f"printf '%s\\n' '{marker}_END'")
    return [fixture['shell'], '-l', '-i', '-c', script], marker


def pty_run(args, environment, output, timeout=60):
    import pty
    import select
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.execve(args[0], args, environment)
        except BaseException:
            os.write(2, b'owned login executable could not start\n')
            os._exit(127)
    status = None
    count = 0
    deadline = time.monotonic() + timeout
    try:
        with output.open('xb') as stream:
            while True:
                if time.monotonic() >= deadline:
                    raise RuntimeError('owned login shell exceeded its bounded execution window')
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO: raise
                        chunk = b''
                    if not chunk: break
                    stream.write(chunk); stream.flush(); count += len(chunk)
                    if count > 1024 * 1024:
                        raise RuntimeError('owned login shell output exceeded its limit')
                if status is None:
                    waited, candidate = os.waitpid(pid, os.WNOHANG)
                    if waited: status = candidate
                if status is not None and not ready: break
        if status is None:
            while time.monotonic() < deadline:
                waited, candidate = os.waitpid(pid, os.WNOHANG)
                if waited: status = candidate; break
                time.sleep(0.05)
        if status is None: raise RuntimeError('owned login shell did not exit')
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError('ordinary login shell command failed; original terminal output retained')
    finally:
        if status is None:
            # This unreaped child owns the fresh pty session/group; never target
            # an application, process name, or an unrelated session.
            try: os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            os.waitpid(pid, 0)
        os.close(master)


def parse_probe(data, marker, value, tool, managed):
    text = data.decode('utf-8')
    markers = [marker + suffix for suffix in ('_PROFILE', '_PATH', '_VERSION', '_END')]
    lines = text.splitlines()
    if any(lines.count(item) != 1 for item in markers):
        raise ValueError('ordinary login output has missing or ambiguous evidence markers')
    indices = [lines.index(item) for item in markers]
    if indices != sorted(indices): raise ValueError('login evidence markers are out of order')
    foreign = lines[indices[0]+1:indices[1]]
    paths = lines[indices[1]+1:indices[2]]
    version = '\n'.join(lines[indices[2]+1:indices[3]])
    expected = managed / 'bin' / (tool + ('.exe' if os.name == 'nt' else ''))
    if foreign != [value] or len(paths) != 1 or not Path(paths[0]).is_absolute() or not expected.is_file() or not Path(paths[0]).is_file() or not os.path.samefile(paths[0], expected):
        raise ValueError('new login shell lost its foreign profile or resolved an unexpected command')
    if not re.search(r'(?<![0-9.])' + re.escape(TOOLS[tool][0]) + r'(?![0-9.])', version):
        raise ValueError('ordinary shell command reported an unexpected version')
    return {'path': paths[0], 'version_output': version, 'profile_sentinel_verified': True}


def verify(fixture, managed, installer, environment, output, stage):
    owned_profile(fixture['path'], Path.home().resolve())
    data = fixture['path'].read_bytes()
    if not data.startswith(fixture['seeded']):
        raise ValueError('App terminal setup altered foreign profile bytes')
    integrations = command([installer, '--managed', 'setup', 'integrations', '--check', '--json'], environment, json_output=True)
    info = integrations.get('data', {})
    if not integrations.get('ok') or info.get('ready') is not True or info.get('disabled') is not False:
        raise ValueError('App terminal integration is not ready for an ordinary new shell')
    records = {}
    for tool in TOOLS:
        args, marker = script_for(fixture, tool)
        path = output / f'{stage}-login-{tool}.terminal.log'
        if os.name == 'nt':
            from verify_app_candidate import stop_owned
            with path.open('xb') as stream:
                process = subprocess.Popen(args, env=environment, stdout=stream, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 60
                try:
                    while process.poll() is None:
                        if time.monotonic() >= deadline or path.stat().st_size > 1024 * 1024:
                            raise RuntimeError('owned PowerShell probe exceeded execution/output bounds')
                        time.sleep(0.1)
                except BaseException as original:
                    try: stop_owned(process, environment)
                    except Exception as cleanup:
                        raise RuntimeError(f"PowerShell probe failed: {original}; owned cleanup failed: {cleanup}") from original
                    raise
                if process.returncode: raise RuntimeError('ordinary PowerShell command failed; output retained')
        else:
            pty_run(args, environment, path)
        records[tool] = parse_probe(path.read_bytes(), marker, fixture['value'], tool, managed)
    return {'shell': fixture['shell'], 'runtime': fixture['runtime'], 'mode': 'ordinary installed PowerShell7 profile startup' if os.name == 'nt' else 'interactive login shell in owned pty',
            'profile': str(fixture['path']), 'foreign_profile_prefix_sha256': fixture['seeded_sha256'],
            'after_profile_sha256': hashlib.sha256(data).hexdigest(), 'profile_mtime_ns': fixture['path'].stat().st_mtime_ns,
            'integrations': integrations, 'commands': records}
