"""Owned native WinPTY console transport; never changes a startup guard."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import time

from verify_candidate import command


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def find_backend(environment):
    from importlib.metadata import version
    import winpty._winpty as backend
    if version('pywinpty') != '3.1.0':
        raise RuntimeError('ordinary console requires pinned pywinpty 3.1.0')
    return Path(backend.__file__).resolve()


def read_terminal(terminal, read_error, diagnostics=None, eof_deadline=None):
    def state():
        alive = terminal.isalive()
        status = terminal.get_exitstatus()
        # The synchronous WinPTY reader may hold a blocking ReadFile on this
        # pipe. A concurrent PeekNamedPipe/iseof can block and starve stdin.
        # Live or unknown-status EOF is unobserved, never acceptance evidence.
        eof = terminal.iseof() if alive is False and type(status) is int else None
        return {'alive': alive, 'status': status, 'iseof': eof}
    def drained(value):
        return value['alive'] is False and type(value['status']) is int and value['iseof'] is True
    before = state()
    if drained(before):
        if diagnostics: diagnostics(dict(before, event='drained-before-read'))
        return None
    try:
        chunk = terminal.read(blocking=False)
        if not chunk:
            after = state()
            if drained(after):
                if diagnostics: diagnostics(dict(after, event='drained-after-empty-read'))
                return None
        return chunk
    except read_error as error:
        after = state()
        if diagnostics:
            diagnostics(dict(after, event='read-error', error_type=type(error).__name__, error=str(error)))
        # Pinned async NTSTATUS -> HRESULT.message() can yield an empty error.
        # Only these two observed EOF forms with independently proven full EOF
        # and actual shell exit are accepted; unrelated errors remain failures.
        if str(error) in ('Standard out reached EOF', ''):
            # The queued async reader error can be observed before its reader
            # exit event/cleanup closes ConPTY output. Wait only for that proven
            # post-exit transition, within the caller's existing drain deadline.
            while (after['alive'] is False and type(after['status']) is int
                    and not drained(after) and eof_deadline is not None
                    and time.monotonic() < eof_deadline):
                time.sleep(0.01)
                after = state()
            if diagnostics:
                diagnostics(dict(after, event='post-error-eof-readback', error=str(error)))
            if drained(after): return None
        raise


def drain_terminal(terminal, read_error, stream, timeout=10, diagnostics=None):
    deadline = time.monotonic() + timeout
    while True:
        chunk = read_terminal(terminal, read_error, diagnostics, deadline)
        if chunk is None: return
        if chunk:
            stream.write(chunk.encode('utf-8')); stream.flush()
        if time.monotonic() >= deadline:
            raise RuntimeError('native PTY terminal output drain exceeded its bound')
        time.sleep(0.01)


def pty_adapter(shell, status_path):
    """Separate owned process: fixed-size native WinPTY, never a TTY ioctl."""
    import codecs
    import ctypes
    import msvcrt
    from ctypes import wintypes
    from winpty import PTY
    from winpty._winpty import WinptyError
    from winpty.enums import Backend
    terminal = PTY(120, 40, backend=Backend.WinPTY)
    extension = find_backend(os.environ)
    expected_dll = extension.parent / 'winpty.dll'
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    loaded = kernel.GetModuleHandleW
    loaded.argtypes = [wintypes.LPCWSTR]
    loaded.restype = wintypes.HMODULE
    dll = loaded('winpty.dll')
    if not dll:
        raise RuntimeError('native WinPTY backend DLL is not loaded')
    filename = kernel.GetModuleFileNameW
    filename.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    filename.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    length = filename(wintypes.HMODULE(dll), buffer, len(buffer))
    if not length or length == len(buffer) or not os.path.samefile(buffer.value, expected_dll):
        raise RuntimeError('native WinPTY loaded an unexpected DLL')
    files = [extension, expected_dll, extension.parent / 'winpty-agent.exe']
    inventory = [{'path':str(path), 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in files]
    Path(status_path + '.backend.json').write_text(json.dumps({
        'backend':'WinPTY', 'loaded_dll':buffer.value, 'files':inventory}) + '\n')
    if not terminal.spawn(shell, cmdline=subprocess.list2cmdline([shell, '-NoLogo']), cwd=os.getcwd(),
                          env='\0'.join(f'{k}={v}' for k, v in os.environ.items()) + '\0'):
        raise RuntimeError('WinPTY failed to spawn ordinary PowerShell')
    # Poll the adapter's owned anonymous input pipe. A blocked daemon reader on
    # sys.stdin could hold Python's buffered-IO lock during interpreter shutdown.
    peek = ctypes.WinDLL('kernel32', use_last_error=True).PeekNamedPipe
    peek.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                     wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    peek.restype = wintypes.BOOL
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(sys.stdin.fileno()))
    def diagnostic(document):
        with Path(status_path + '.eof.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(document) + '\n')
    decode = codecs.getincrementaldecoder('utf-8')()
    while terminal.isalive():
        available = wintypes.DWORD()
        if not peek(handle, None, 0, None, ctypes.byref(available), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if available.value:
            value = os.read(sys.stdin.fileno(), min(available.value, 65536))
            if not value:
                raise RuntimeError('WinPTY controller input closed before shell exit')
            text = decode.decode(value)
            if text: terminal.write(text)
        chunk = read_terminal(terminal, WinptyError, diagnostic, time.monotonic() + 10)
        if chunk:
            sys.stdout.buffer.write(chunk.encode('utf-8')); sys.stdout.buffer.flush()
        time.sleep(0.01)
    status = terminal.get_exitstatus()
    Path(status_path).write_text(json.dumps({'shell_pid': terminal.pid, 'shell_returncode': status,
        'backend': 'WinPTY', 'columns': 120, 'rows': 40}) + '\n')
    if type(status) is not int:
        raise RuntimeError('WinPTY shell exit status unavailable')
    # Drain every queued terminal chunk, not merely one final read. Only the
    # pinned dependency's exact EOF after proven shell exit ends this drain.
    drain_terminal(terminal, WinptyError, sys.stdout.buffer, diagnostics=diagnostic)
    return status


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
    shell_exit = output / (stem + '.shell-exit.json')
    eof_diagnostics = Path(str(shell_exit) + '.eof.jsonl')
    backend_record = Path(str(shell_exit) + '.backend.json')
    for path in [script, result, raw, ready, acknowledge, adapter_record, shell_exit, eof_diagnostics, backend_record, Path(str(result) + '.tmp'), Path(str(ready) + '.tmp')]:
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
                 'backend_name': 'pywinpty-3.1.0-WinPTY', 'dimensions': [120, 40], 'eof_diagnostics_file': eof_diagnostics.name,
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
            # Only this separate adapter sees redirected pipes. The spawned
            # PowerShell receives a fixed-size native WinPTY and normal startup.
            process = subprocess.Popen([sys.executable, '-u', str(Path(__file__).resolve()),
                '--pty-adapter', str(shell), str(shell_exit)], env=environment, stdin=subprocess.PIPE,
                stdout=stream, stderr=subprocess.STDOUT)
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
            exit_record = json.loads(shell_exit.read_text())
            if exit_record.get('shell_pid') != identity['pid'] or exit_record.get('shell_returncode') != 0:
                raise RuntimeError('ordinary console shell did not report a successful owned exit')
            transport['shell_exit'] = exit_record
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
        if process is not None:
            transport['adapter_returncode'] = process.poll()
        if backend_record.is_file():
            transport['native_backend'] = json.loads(backend_record.read_text())
        if shell_exit.is_file():
            transport['shell_exit'] = json.loads(shell_exit.read_text())
        if process is not None and process.stdin is not None:
            try: process.stdin.close()
            except BrokenPipeError as close: transport['stdin_close_error'] = str(close)
        (output / (stem + '.transport.json')).write_text(json.dumps(transport, indent=2) + '\n')


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] != '--pty-adapter':
        raise SystemExit('invalid fixed WinPTY adapter invocation')
    raise SystemExit(pty_adapter(sys.argv[2], sys.argv[3]))
