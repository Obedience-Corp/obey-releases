"""Failure-only native stack sampling of the verifier's already-owned App.

Attaching briefly suspends the process. This is diagnostic evidence after a
failed launch, never a launch aid or a replacement for the original result.
"""
from pathlib import Path
import subprocess


def identity(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    return {'start_ticks': int(fields[19]), 'state': fields[0]}


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
    # Do not load user init files, binary-provided Python pretty printers, or
    # remote debuginfo. No locals, argument values, memory, or core dump.
    debugger = ['/usr/bin/gdb', '--nx', '--nh', '--batch',
                '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
                '-ex', 'set pagination off', '-p', str(process.pid),
                '-ex', 'thread apply all bt -no-filters -frame-arguments none 16',
                '-ex', 'detach']
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
    record['after_returncode'] = process.poll()
    if record['after_returncode'] is None:
        after = identity(process.pid)
        record['after_identity_verified'] = after['start_ticks'] == expected_start_ticks
        record['after_state'] = after['state']
        status = Path(f'/proc/{process.pid}/status').read_text().splitlines()
        record['after_tracer_pid'] = int(next(line.split(':', 1)[1] for line in status if line.startswith('TracerPid:')))
    return record
