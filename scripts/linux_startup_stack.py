"""Failure-only native stack sampling of the verifier's already-owned App.

Attaching briefly suspends the process. This is diagnostic evidence after a
failed launch, never a launch aid or a replacement for the original result.
"""
import json
from pathlib import Path
import subprocess


def identity(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    return {'start_ticks': int(fields[19]), 'state': fields[0]}


def owner_identity(pid):
    rows = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    result = {}
    for name in ('Uid', 'Gid'):
        values = [int(value) for value in rows[name].split()]
        if len(values) != 4 or len(set(values)) != 1:
            raise ValueError('refusing App with changing or mixed process credentials')
        result[name] = values[0]
    return result


def capture(process, expected_start_ticks, output, environment, *, elevated=True):
    record = {'diagnostic_only': True, 'pid': process.pid,
              'expected_start_ticks': expected_start_ticks}
    # Popen owns this unreaped child. Do not look up or attach by executable
    # name; an exited child or changed birth is never eligible for sampling.
    if process.poll() is not None:
        return dict(record, skipped='owned App has exited')
    before = identity(process.pid)
    if before['start_ticks'] != expected_start_ticks:
        return dict(record, skipped='owned App birth changed')
    if before['state'] in ('T', 't', 'Z', 'X'):
        return dict(record, skipped='owned App is already stopped or exiting')
    owner = owner_identity(process.pid)
    record['requested_debugger_identity'] = owner
    # Do not load user init files, binary-provided Python pretty printers, or
    # remote debuginfo. No locals, argument values, memory, or core dump.
    debugger = ['/usr/bin/gdb', '--nx', '--nh', '--batch',
                '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
                '-ex', 'set pagination off', '-p', str(process.pid),
                '-ex', "python print('FA0027_DEBUGGER_IDENTITY ' + __import__('json').dumps({line.split(':')[0]: line.split(':',1)[1].strip() for line in __import__('pathlib').Path('/proc/self/status').read_text().splitlines() if line.split(':')[0] in ('Uid','Gid','CapEff','CapInh','CapBnd','CapAmb')}))",
                '-ex', 'thread apply all bt -no-filters -frame-arguments none 16',
                '-ex', 'detach']
    # FUSE restricts a user mount to its owner's UID, including denial to root.
    # Keep that filesystem identity while granting only the debugger process
    # SYS_PTRACE. No file capabilities, mount options or kernel policy change.
    debugger = ['/usr/bin/setpriv', f"--reuid={owner['Uid']}", f"--regid={owner['Gid']}",
                '--clear-groups', '--inh-caps=-all,+sys_ptrace',
                '--ambient-caps=-all,+sys_ptrace', '--bounding-set=-all,+sys_ptrace',
                '--no-new-privs', *debugger]
    # timeout owns the debugger even if the outer Python observation expires.
    # Killing a ptrace tracer releases its tracees; the native fixture verifies
    # that a timed-out debugger leaves its owned child running and untraced.
    arguments = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=2s', '12s', *debugger]
    if elevated:
        arguments = ['/usr/bin/sudo', '-n', *arguments]
    record['command'] = arguments
    clean_environment = {key: environment[key] for key in ('PATH', 'HOME', 'LANG') if key in environment}
    clean_environment.update(DEBUGINFOD_URLS='', LC_ALL='C')
    with output.open('wb') as stream:
        try:
            result = subprocess.run(arguments, env=clean_environment, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=18)
            record['exit'] = result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            record['error'] = str(error)
    record['stack_file'] = output.name
    record['bytes'] = output.stat().st_size
    markers = [line.removeprefix('FA0027_DEBUGGER_IDENTITY ') for line in output.read_text(errors='replace').splitlines()
               if line.startswith('FA0027_DEBUGGER_IDENTITY ')]
    if len(markers) == 1:
        observed = json.loads(markers[0])
        record['debugger_identity'] = observed
        record['debugger_identity_verified'] = (
            all([int(value) for value in observed[name].split()] == [owner[name]] * 4 for name in ('Uid', 'Gid'))
            and all(int(observed[name], 16) == 1 << 19 for name in ('CapEff', 'CapInh', 'CapBnd', 'CapAmb')))
    else:
        record['debugger_identity_verified'] = False
    record['after_returncode'] = process.poll()
    if record['after_returncode'] is None:
        after = identity(process.pid)
        record['after_identity_verified'] = after['start_ticks'] == expected_start_ticks
        record['after_state'] = after['state']
        status = Path(f'/proc/{process.pid}/status').read_text().splitlines()
        record['after_tracer_pid'] = int(next(line.split(':', 1)[1] for line in status if line.startswith('TracerPid:')))
    return record
