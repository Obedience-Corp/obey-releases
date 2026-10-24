"""Read-only evidence on the fixture's isolated X display; never a launch fallback."""
import json
import os
from pathlib import Path
import subprocess
import time


def process_inventory(root_pid, proc=Path('/proc')):
    def read(pid):
        directory = proc / str(pid)
        raw = (directory / 'stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        result = {'pid': pid, 'parent_pid': int(fields[1]), 'session': int(fields[3]),
                  'state': fields[0], 'start_ticks': int(fields[19])}
        for name in ('exe', 'cwd'):
            try: result[name] = os.readlink(directory / name)
            except OSError as error: result[name + '_error'] = str(error)
        return result
    root = read(root_pid)
    entries = {}
    for directory in proc.iterdir():
        if not directory.name.isdecimal():
            continue
        try: entries[int(directory.name)] = read(int(directory.name))
        except (OSError, ValueError, IndexError): continue
    owned = {root_pid}
    while True:
        expanded = owned | {pid for pid, entry in entries.items() if entry['parent_pid'] in owned}
        if expanded == owned: break
        owned = expanded
    if read(root_pid)['start_ticks'] != root['start_ticks']:
        raise RuntimeError('App root PID identity changed during diagnostic snapshot')
    return [entries[pid] for pid in sorted(owned) if pid in entries]


def capture_failure(process, output, environment, error):
    record = {'diagnostic_only': True, 'failure': str(error), 'root_pid': process.pid,
              'root_returncode': process.poll(), 'display': environment.get('DISPLAY'),
              'display_selection': {name: environment[name] for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'XDG_SESSION_TYPE', 'GDK_BACKEND', 'XDG_RUNTIME_DIR') if environment.get(name)}}
    if record['root_returncode'] is None:
        try: record['root_and_descendants'] = process_inventory(process.pid)
        except (OSError, ValueError, IndexError, RuntimeError) as failure: record['process_snapshot_error'] = str(failure)
    # This X display was created by the proof and refused if it already existed.
    # Only display-selector values are recorded; no full environment, credentials,
    # command arguments or unrelated OS logs are dumped.
    commands = [['xdotool', 'search', '--pid', str(process.pid)], ['wmctrl', '-lpG'], ['xwininfo', '-root', '-tree'],
                ['xprop', '-root', '_NET_SUPPORTING_WM_CHECK', '_NET_CLIENT_LIST', '_NET_ACTIVE_WINDOW'],
                ['import', '-window', 'root', str(output.with_name(output.stem + '.diagnostic-desktop.png'))]]
    record['probes'] = []
    deadline = time.monotonic() + 30
    def run_probe(arguments):
        probe = {'command': arguments}
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(arguments, 30)
            result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=min(5, remaining))
            probe.update(exit=result.returncode, stdout=result.stdout[:65536], stderr=result.stderr[:65536])
        except (OSError, subprocess.TimeoutExpired) as failure:
            probe['error'] = str(failure)
        record['probes'].append(probe)
        return probe
    for arguments in commands:
        run_probe(arguments)
    search = record['probes'][0]
    windows = []
    if search.get('exit') == 0:
        for value in search['stdout'].splitlines():
            if value.isascii() and value.isdecimal() and 0 < int(value) <= 0xffffffff:
                value = str(int(value))
                if value not in windows: windows.append(value)
    record['owned_pid_window_ids'] = windows
    record['window_queries_truncated'] = len(windows) > 4
    for window in windows[:4]:
        run_probe(['xwininfo', '-id', window])
        run_probe(['xprop', '-id', window, '_NET_WM_PID', 'WM_STATE', '_NET_WM_STATE', '_NET_WM_WINDOW_TYPE'])
    record['post_probe_root_returncode'] = process.poll()
    if record['post_probe_root_returncode'] is None and record.get('root_and_descendants'):
        try:
            before = next(row for row in record['root_and_descendants'] if row['pid'] == process.pid)
            after = next(row for row in process_inventory(process.pid) if row['pid'] == process.pid)
            record['post_probe_root_identity_verified'] = before['start_ticks'] == after['start_ticks']
            if not record['post_probe_root_identity_verified']:
                record['post_probe_identity_error'] = 'App root PID birth changed; window attribution is stale'
        except (OSError, ValueError, IndexError, KeyError, StopIteration, RuntimeError) as failure:
            record['post_probe_identity_error'] = str(failure)
    destination = output.with_name(output.stem + '.window-diagnostics.json')
    destination.write_text(json.dumps(record, indent=2) + '\n')
    return destination
