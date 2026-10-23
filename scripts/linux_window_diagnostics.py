"""Read-only evidence on the fixture's isolated X display; never a launch fallback."""
import json
import os
from pathlib import Path
import subprocess


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
                ['import', '-window', 'root', str(output.with_name(output.stem + '.diagnostic-desktop.png'))]]
    record['probes'] = []
    for arguments in commands:
        probe = {'command': arguments}
        try:
            result = subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=10)
            probe.update(exit=result.returncode, stdout=result.stdout[:65536], stderr=result.stderr[:65536])
        except (OSError, subprocess.TimeoutExpired) as failure:
            probe['error'] = str(failure)
        record['probes'].append(probe)
    destination = output.with_name(output.stem + '.window-diagnostics.json')
    destination.write_text(json.dumps(record, indent=2) + '\n')
    return destination
