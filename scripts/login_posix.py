"""Verify ordinary POSIX command dispatch, including the installed navigation wrappers."""
import base64
import binascii
import hashlib
import os
from pathlib import Path
import shlex
import sys
import tempfile


def sections(data, marker, names):
    # Preserve original terminal bytes on disk. Only CR/LF line endings are
    # normalized for comparison; unexpected ANSI/output inside evidence fails.
    lines = data.decode('utf-8').splitlines()
    labels = [marker + '_' + name for name in (*names, 'END')]
    if any(lines.count(label) != 1 for label in labels):
        raise ValueError('POSIX shell evidence markers are missing or ambiguous')
    positions = [lines.index(label) for label in labels]
    if positions != sorted(positions):
        raise ValueError('POSIX shell evidence markers are out of order')
    return {name: lines[positions[i] + 1:positions[i + 1]] for i, name in enumerate(names)}


def definition_dump(tool):
    # Capture builtin output before the terminal's CR/LF processing. The
    # ordinary command still executes through its unchanged installed wrapper.
    encoder = "import base64,sys; print(base64.b64encode(sys.stdin.buffer.read()).decode('ascii'))"
    return f'builtin typeset -f {shlex.quote(tool)} | {shlex.join([sys.executable, "-I", "-c", encoder])}'


def definition_bytes(lines):
    try:
        # Only transport line boundaries are joined; source whitespace and CR
        # bytes are encoded, retained and compared exactly after decoding.
        value = base64.b64decode(''.join(lines), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError('POSIX function definition encoding is invalid') from error
    if not value:
        raise ValueError('POSIX function definition is empty')
    return value


def probe_script(fixture, tool, marker, arguments):
    quoted = shlex.quote(tool)
    # Resolve the command builtin's external dispatch in a subshell. Removing
    # only the wrapper there preserves the parent invocation and, unlike a
    # forced PATH search, includes an existing shell command-hash override.
    resolver = (f'(if builtin typeset -f {quoted} >/dev/null 2>&1; '
                f'then builtin unset -f {quoted} || exit 96; fi; builtin command -v {quoted})')
    return (
        f"printf '%s\\n' '{marker}_PROFILE'; {fixture['function']} || exit 91; "
        f"printf '%s\\n' '{marker}_PATH'; {resolver} || exit 92; "
        f"printf '%s\\n' '{marker}_KIND'; "
        f"if builtin alias {quoted} >/dev/null 2>&1; then printf 'alias\\n'; "
        f"elif builtin typeset -f {quoted} >/dev/null 2>&1; then printf 'function\\n'; "
        "else printf 'executable\\n'; fi; "
        f"printf '%s\\n' '{marker}_DEFINITION'; "
        f"if builtin typeset -f {quoted} >/dev/null 2>&1; then {definition_dump(tool)}; fi; "
        f"printf '%s\\n' '{marker}_VERSION'; {shlex.join([tool, *arguments])} || exit 93; "
        f"printf '%s\\n' '{marker}_END'"
    )


def reference_definition(fixture, tool, expected, environment, output, stage, marker):
    from login_shell import pty_run
    destination = output / f'{stage}-login-{tool}.reference.terminal.log'
    # A reference must not source the profile being checked, import its shell
    # functions, or inherit BASH_ENV/ENV. Only the authenticated installed
    # executable generates this definition. The ordinary probe is unchanged.
    clean = {key: value for key, value in environment.items()
             if key not in ('BASH_ENV', 'ENV', 'ZDOTDIR') and not key.startswith('BASH_FUNC_')}
    with tempfile.TemporaryDirectory(prefix='login-reference-', dir=output) as directory:
        clean['HOME'] = directory
        clean['ZDOTDIR'] = directory
        clean['PATH'] = str(expected.parent) + os.pathsep + clean.get('PATH', os.defpath)
        flags = ['--noprofile', '--norc'] if fixture['kind'] == 'bash' else ['-f']
        # Installer initializes these system completion facilities before
        # evaluating the generated Zsh integration. Match that prerequisite in
        # the isolated reference only, keeping ordinary security checks enabled.
        completion = ('autoload -Uz compinit; compinit -D || exit 97; '
                      'autoload -Uz bashcompinit; bashcompinit || exit 98; '
                      if fixture['kind'] == 'zsh' else '')
        script = (
            completion + '__fa_init=$("$1" shell-init "$2") || exit 94; '
            'eval "$__fa_init" || exit 95; '
            f"printf '%s\\n' '{marker}_DEFINITION'; "
            + definition_dump(tool) + '; '
            f"printf '%s\\n' '{marker}_END'"
        )
        pty_run([fixture['shell'], *flags, '-c', script, 'fa0027-reference',
                 str(expected), fixture['kind']], clean, destination)
    definition = sections(destination.read_bytes(), marker, ('DEFINITION',))['DEFINITION']
    if not definition:
        raise ValueError('installed executable did not generate its navigation wrapper')
    return definition_bytes(definition)


def verify_tool(fixture, tool, managed, environment, output, stage):
    import re
    from login_shell import TOOLS, pty_run
    from login_version import version_record
    if fixture['kind'] not in ('bash', 'zsh') or tool not in TOOLS:
        raise ValueError('unsupported POSIX shell probe')
    if not re.fullmatch(r'fa0027_keep_[0-9a-f]{12}', fixture['function']):
        raise ValueError('invalid POSIX shell profile sentinel')
    expected = managed / 'bin' / tool
    if not expected.is_absolute() or not expected.is_file():
        raise ValueError('expected managed executable is missing')
    marker = 'FA0027_' + fixture['function'][12:]
    path = output / f'{stage}-login-{tool}.terminal.log'
    script = probe_script(fixture, tool, marker, TOOLS[tool][1])
    # Do not change PATH/HOME, source helpers ourselves, bypass functions, or
    # inject the expected executable into the ordinary user's invocation.
    pty_run([fixture['shell'], '-l', '-i', '-c', script], environment, path)
    result = sections(path.read_bytes(), marker, ('PROFILE', 'PATH', 'KIND', 'DEFINITION', 'VERSION'))
    if result['PROFILE'] != [fixture['value']]:
        raise ValueError('ordinary POSIX shell lost its foreign profile function')
    paths = result['PATH']
    if (len(paths) != 1 or not Path(paths[0]).is_absolute()
            or not Path(paths[0]).is_file() or not os.path.samefile(paths[0], expected)):
        raise ValueError('ordinary POSIX shell resolved an unexpected external executable')
    definition = result['DEFINITION']
    wrapper = tool in ('camp', 'fest')
    if result['KIND'] != ['function' if wrapper else 'executable']:
        raise ValueError('ordinary POSIX command is shadowed or missing its intended wrapper')
    if wrapper:
        reference = reference_definition(fixture, tool, expected, environment, output, stage, marker)
        definition = definition_bytes(definition)
        if definition != reference:
            raise ValueError('ordinary POSIX wrapper differs from the installed executable definition')
    elif definition:
        raise ValueError('ordinary POSIX executable has an unexpected function definition')
    version = '\n'.join(result['VERSION'])
    return {'path': paths[0], 'version_output': version_record(tool, version), 'profile_sentinel_verified': True,
            'dispatch': result['KIND'][0], 'installed_wrapper_verified': wrapper,
            'wrapper_sha256': hashlib.sha256(definition).hexdigest() if wrapper else None}
