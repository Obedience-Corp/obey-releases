"""Owned installed winpty console transport; never changes a startup guard."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from verify_candidate import command


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def find_backend(environment):
    candidates = [shutil.which('winpty', path=environment.get('PATH'))]
    git = shutil.which('git', path=environment.get('PATH'))
    if git: candidates.append(str(Path(git).parent.parent / 'usr/bin/winpty.exe'))
    if environment.get('ProgramFiles'):
        candidates.append(str(Path(environment['ProgramFiles']) / 'Git/usr/bin/winpty.exe'))
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and Path(candidate).name.lower() == 'winpty.exe':
            return Path(candidate).resolve()
    raise RuntimeError('installed Git-for-Windows winpty console transport is unavailable')


def validate_startup(document, shell):
    guard = document.get('guard', {})
    if (guard.get('host') != 'ConsoleHost' or guard.get('input_redirected') is not False
            or guard.get('user_interactive') is not True or guard.get('probe_marker')
            or [x.lower() for x in guard.get('startup_flags', [])] != ['-nologo']):
        raise ValueError('PowerShell did not use ordinary interactive console startup')
    identity = document.get('console_process', {})
    if (type(identity.get('pid')) is not int or identity['pid'] <= 0
            or not str(identity.get('started', '')).isdigit()
            or not Path(identity.get('path', '')).is_file() or not os.path.samefile(identity['path'], shell)):
        raise ValueError('ordinary console identity does not match the owned PowerShell')
    return identity


def process_birth(process):
    import ctypes
    from ctypes import wintypes
    creation, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
    read = ctypes.WinDLL('kernel32', use_last_error=True).GetProcessTimes
    read.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    read.restype = wintypes.BOOL
    if not read(wintypes.HANDLE(int(process._handle)), *map(ctypes.byref, (creation, exited, kernel, user))):
        raise ctypes.WinError(ctypes.get_last_error())
    # FILETIME starts in1601; .NET DateTime ticks start in0001 (100ns units).
    return str((creation.dwHighDateTime << 32 | creation.dwLowDateTime) + 504911232000000000)


def run_prompt(shell, body, environment, output, stem, timeout=60):
    if os.name != 'nt' or environment.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or environment.get('CANDIDATE_RUNNER_KIND') != 'github-hosted':
        raise RuntimeError('ordinary Windows console proof requires a disposable hosted account')
    if environment.get('FESTIVAL_INTEGRATION_PROBE'):
        raise RuntimeError('ordinary console must not use the integration readiness override')
    if not re.fullmatch('[a-z0-9-]+', stem): raise ValueError('invalid fixed console evidence label')
    backend = find_backend(environment)
    script = output / (stem + '.prompt.ps1')
    result = output / (stem + '.console.json')
    raw = output / (stem + '.terminal.log')
    ready = output / (stem + '.started.json')
    acknowledge = output / (stem + '.owned')
    adapter_record = output / (stem + '.adapter.json')
    for path in [script, result, raw, ready, acknowledge, adapter_record, Path(str(result) + '.tmp'), Path(str(ready) + '.tmp')]:
        if path.exists() or path.is_symlink(): raise RuntimeError('refusing existing console evidence output')
    script.write_text("""$ErrorActionPreference='Stop'
$owned=Get-Process -Id $PID
$record=[ordered]@{
  ok=$false
  console_process=@{pid=$PID;started=$owned.StartTime.ToUniversalTime().Ticks.ToString();path=$owned.Path}
  guard=@{host=$Host.Name;input_redirected=[Console]::IsInputRedirected;user_interactive=[Environment]::UserInteractive;
    probe_marker=$env:FESTIVAL_INTEGRATION_PROBE;startup_flags=@([Environment]::GetCommandLineArgs() | Select-Object -Skip 1)}
}
try {
""" + f"[IO.File]::WriteAllText({quote(str(ready)+'.tmp')},($record | ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))\n[IO.File]::Move({quote(str(ready)+'.tmp')},{quote(ready)})\n$limit=[DateTime]::UtcNow.AddSeconds(15)\nwhile (-not (Test-Path -LiteralPath {quote(acknowledge)})) {{ if ([DateTime]::UtcNow -gt $limit) {{ throw 'owned console acknowledgement timed out' }}; Start-Sleep -Milliseconds 50 }}\n" + """  $record.data = & {
""" + body + """
  }
  $record.ok=$true
} catch { $record.error=$_.ToString() }
$json=$record | ConvertTo-Json -Depth 16 -Compress
""" + f"[IO.File]::WriteAllText({quote(str(result)+'.tmp')},$json,[Text.UTF8Encoding]::new($false))\n[IO.File]::Move({quote(str(result)+'.tmp')},{quote(result)})\n")
    processes = Path(__file__).with_name('windows_owned_processes.ps1')
    observer = [shell, '-NoProfile', '-NonInteractive', '-File', processes]
    process = None
    snapshot = []
    root_identity = None
    transport = {'backend': str(backend), 'backend_sha256': hashlib.sha256(backend.read_bytes()).hexdigest(),
                 'ordinary_startup_verified': False, 'owned_console_exit_verified': False}
    def capture_owned():
        rows = command(observer, dict(environment, APP_PROOF_PROCESS_MODE='snapshot',
                       APP_PROOF_PROCESS_PID=str(process.pid)), json_output=True, timeout=10)
        if not any(row == root_identity for row in rows):
            raise RuntimeError('console adapter exited before an authenticated tree snapshot')
        known = {(row['pid'], row['started']): row for row in snapshot}
        for row in rows:
            if type(row.get('pid')) is not int or not str(row.get('started', '')).isdigit():
                raise ValueError('invalid owned console tree snapshot')
            known[(row['pid'], row['started'])] = row
        snapshot[:] = list(known.values())
        transport['owned_processes'] = snapshot
        transport['ownership_snapshot_complete'] = True

    try:
        with raw.open('xb') as stream:
            # winpty gives pwsh a real owned console. Only its adapter sees
            # redirected pipes; the child has no -Command/-File/-EncodedCommand,
            # -NonInteractive or readiness-marker startup override.
            process = subprocess.Popen([str(backend), '-Xallow-non-tty', str(shell), '-NoLogo'],
                env=environment, stdin=subprocess.PIPE, stdout=stream, stderr=subprocess.STDOUT)
            transport['adapter_pid'] = process.pid
            root_identity = {'pid': process.pid, 'started': process_birth(process)}
            snapshot.append(root_identity)
            adapter_record.write_text(json.dumps(root_identity))
            capture_owned()
            process.stdin.write((f"& {quote(script)}\r\n").encode()); process.stdin.flush()
            deadline = time.monotonic() + 30
            while not ready.is_file():
                if process.poll() is not None: raise RuntimeError('ordinary console exited before startup identity')
                if time.monotonic() >= deadline or raw.stat().st_size > 4 * 1024 * 1024:
                    raise RuntimeError('ordinary console startup exceeded its bounds')
                time.sleep(0.1)
            identity = validate_startup(json.loads(ready.read_text(encoding='utf-8-sig')), shell)
            capture_owned()
            if not any(row.get('pid') == identity['pid'] and row.get('started') == identity['started'] for row in snapshot):
                raise ValueError('ordinary PowerShell is not in the owned adapter process tree')
            acknowledge.write_text('owned console identity verified\n')
            transport['ordinary_startup_verified'] = True
            deadline = time.monotonic() + timeout
            refresh = time.monotonic() + 1
            while not result.is_file():
                if process.poll() is not None: raise RuntimeError('ordinary console exited before its structured readback')
                if time.monotonic() >= deadline or raw.stat().st_size > 4 * 1024 * 1024:
                    raise RuntimeError('owned interactive console exceeded execution/output bounds')
                if time.monotonic() >= refresh:
                    try: capture_owned()
                    except RuntimeError:
                        if process.poll() is not None:
                            raise RuntimeError('ordinary console exited before its structured readback')
                        raise
                    refresh = time.monotonic() + 1
                time.sleep(0.1)
            document = json.loads(result.read_text(encoding='utf-8-sig'))
            identity = validate_startup(document, shell)
            capture_owned()
            if not any(row.get('pid') == identity['pid'] and row.get('started') == identity['started'] for row in snapshot):
                raise ValueError('interactive PowerShell is not in the owned console process tree')
            transport['owned_processes'] = snapshot
            transport['ordinary_startup_verified'] = True
            process.stdin.write(b'exit\r\n'); process.stdin.flush()
            process.wait(timeout=20)
            command(observer, dict(environment, APP_PROOF_PROCESS_MODE='verify',
                    APP_PROOF_PROCESS_IDENTITIES=json.dumps(snapshot)), timeout=30)
            transport['owned_console_exit_verified'] = True
            if document.get('ok') is not True:
                raise RuntimeError('ordinary console readback failed: ' + document.get('error', 'unknown error'))
            if process.returncode: raise RuntimeError('ordinary console adapter returned failure')
            return document
    except BaseException as original:
        transport['failure'] = str(original)
        failures = []
        if snapshot:
            try:
                if process is not None and process.poll() is None:
                    try: capture_owned()
                    except Exception as capture: transport['final_snapshot_error'] = str(capture)
                cleanup = [shell, '-NoProfile', '-NonInteractive', '-File', Path(__file__).with_name('windows_console_cleanup.ps1')]
                command(cleanup, dict(environment, APP_CONSOLE_IDENTITIES=json.dumps(snapshot)), timeout=40)
                command(observer, dict(environment, APP_PROOF_PROCESS_MODE='verify',
                        APP_PROOF_PROCESS_IDENTITIES=json.dumps(snapshot)), timeout=30)
                transport['tracked_console_cleanup_verified'] = True
            except Exception as cleanup: failures.append(str(cleanup))
        if process is not None and process.poll() is None:
            # The Popen handle is owned even if the first birth/tree observation
            # failed. This stops only that exact adapter object, never a PID name.
            try: process.kill(); process.wait(timeout=10)
            except Exception as cleanup: failures.append(str(cleanup))
        if not transport.get('ownership_snapshot_complete') and process is not None:
            failures.append('console tree ownership could not be established; no descendant cleanup claim')
        if failures:
            transport['cleanup_failure'] = '; '.join(failures)
            raise RuntimeError(f'ordinary console failed: {original}; cleanup: {transport["cleanup_failure"]}') from original
        raise
    finally:
        if process is not None and process.stdin is not None:
            try: process.stdin.close()
            except BrokenPipeError as close: transport['stdin_close_error'] = str(close)
        (output / (stem + '.transport.json')).write_text(json.dumps(transport, indent=2) + '\n')
