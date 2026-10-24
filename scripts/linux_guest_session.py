"""Read an actual local Xfce login, its X11 access and existing user bus.

Invoked read-only inside the owned guest; never creates a session or supplies
DISPLAY/DBUS values in place of the desktop's actual environment.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess


def command(arguments, environment=None):
    return subprocess.run(arguments, env=environment, text=True, capture_output=True,
                          check=True, timeout=15).stdout.strip()


def active_greeter():
    session = command(['loginctl', 'show-seat', 'seat0', '-p', 'ActiveSession', '--value'])
    if not session:
        return False
    text = command(['loginctl', 'show-session', session, '-p', 'Name', '-p', 'Class',
                    '-p', 'Remote', '-p', 'Active', '-p', 'Service', '--no-pager'])
    state = dict(row.split('=', 1) for row in text.splitlines())
    return (state.get('Name') == 'lightdm' and state.get('Class') == 'greeter'
            and state.get('Remote') == 'no' and state.get('Active') == 'yes'
            and state.get('Service') == 'lightdm-greeter')


def process_identity(proc, scope, executable='xfce4-session'):
    if proc.stat().st_uid != os.getuid() or (proc / 'exe').resolve() != Path('/usr/bin') / executable:
        raise RuntimeError('Xfce session process identity differs from the expected user/executable')
    groups = (proc / 'cgroup').read_text()
    if not any(scope in row.split(':', 2)[2].split('/') for row in groups.splitlines()):
        raise RuntimeError('Xfce process is outside the selected local logind session scope')
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'start_ticks': int(fields[19]), 'cgroup': groups, 'uid': proc.stat().st_uid}


def desktop_windows(environment, scope):
    """Require the actual mapped desktop and panel, not just an early WM atom."""
    owners = {}
    for name in ('xfdesktop', 'xfce4-panel'):
        found = subprocess.run(['pgrep', '-u', str(os.getuid()), '-x', name],
                               capture_output=True, text=True, timeout=10)
        if found.returncode == 1:
            return []
        if found.returncode != 0 or len(found.stdout.split()) != 1:
            raise RuntimeError('ambiguous desktop component process: ' + name)
        pid = int(found.stdout.strip())
        proc = Path('/proc') / str(pid)
        owners[pid] = (name, proc, process_identity(proc, scope, name))
    listing = command(['xprop', '-root', '_NET_CLIENT_LIST_STACKING'], environment)
    windows = re.findall(r'0x[0-9a-fA-F]+', listing)
    if len(windows) > 128:
        raise RuntimeError('unexpected clean desktop window count')
    visible = []
    for window in windows:
        values = command(['xprop', '-id', window, '_NET_WM_PID', '_NET_WM_WINDOW_TYPE'], environment)
        match = re.search(r'_NET_WM_PID\(CARDINAL\) = ([0-9]+)', values)
        if match is None or int(match[1]) not in owners:
            continue
        pid = int(match[1])
        name, proc, identity = owners[pid]
        expected = '_NET_WM_WINDOW_TYPE_DESKTOP' if name == 'xfdesktop' else '_NET_WM_WINDOW_TYPE_DOCK'
        if expected not in values:
            continue
        geometry = command(['xwininfo', '-id', window], environment)
        if 'Map State: IsViewable' not in geometry:
            continue
        if process_identity(proc, scope, name) != identity:
            raise RuntimeError('desktop component identity changed during window readback')
        visible.append({'process': name, 'pid': pid, 'identity': identity,
                        'window_id': window, 'window_type': expected, 'mapped': True})
    return visible


def read_session():
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise RuntimeError('desktop readback requires the ordinary guest user')
    sessions = []
    listing = command(['loginctl', 'list-sessions', '--no-legend', '--no-pager'])
    for row in listing.splitlines():
        session_id = row.split()[0]
        try:
            values = command(['loginctl', 'show-session', session_id, '--no-pager',
                              '-p', 'Id', '-p', 'User', '-p', 'Name', '-p', 'Type', '-p', 'Class',
                              '-p', 'Active', '-p', 'State', '-p', 'Remote', '-p', 'Service', '-p', 'Display', '-p', 'Scope'])
        except subprocess.CalledProcessError:
            # A greeter/SSH session can disappear between list and show while
            # local login completes. Never count that disappearing session.
            continue
        properties = dict(line.split('=', 1) for line in values.splitlines())
        if (properties.get('User') == str(os.getuid()) and properties.get('Type') == 'x11'
                and properties.get('Class') == 'user' and properties.get('Remote') == 'no'
                and properties.get('Active') == 'yes' and properties.get('State') == 'active'
                and properties.get('Service') == 'lightdm'):
            sessions.append(properties)
    if not sessions:
        return None
    if len(sessions) != 1:
        raise RuntimeError('ambiguous active local graphical sessions')
    selected = sessions[0]
    found = subprocess.run(['pgrep', '-u', str(os.getuid()), '-x', 'xfce4-session'],
                           capture_output=True, text=True, timeout=10)
    if found.returncode == 1:
        return None
    if found.returncode != 0 or len(found.stdout.split()) != 1:
        raise RuntimeError('ambiguous or unreadable owned Xfce session process')
    pid = int(found.stdout.strip())
    proc = Path('/proc') / str(pid)
    if not re.fullmatch(r'session-[a-zA-Z0-9]+\.scope', selected.get('Scope', '')):
        raise RuntimeError('local session has no explicit systemd session scope')
    identity = process_identity(proc, selected['Scope'])
    # Select only non-secret session routing values, never dump process env.
    names = {'DISPLAY', 'XAUTHORITY', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR', 'XDG_SESSION_ID'}
    environment = {}
    for entry in (proc / 'environ').read_bytes().split(b'\0'):
        key, separator, value = entry.partition(b'=')
        if separator and key.decode() in names:
            environment[key.decode()] = value.decode()
    if not re.fullmatch(r':[0-9]+(?:\.[0-9]+)?', environment.get('DISPLAY', '')):
        raise RuntimeError('local desktop did not expose an X11 display')
    if selected.get('Display') != environment['DISPLAY'] or environment.get('XDG_SESSION_ID') != selected['Id']:
        raise RuntimeError('desktop environment and logind session disagree')
    runtime = Path(environment.get('XDG_RUNTIME_DIR', ''))
    if runtime != Path('/run/user') / str(os.getuid()) or runtime.stat().st_uid != os.getuid():
        raise RuntimeError('desktop runtime directory belongs to another user')
    bus = runtime / 'bus'
    if (not stat.S_ISSOCK(bus.stat().st_mode) or bus.stat().st_uid != os.getuid()
            or environment.get('DBUS_SESSION_BUS_ADDRESS') != 'unix:path=' + str(bus)):
        raise RuntimeError('desktop does not use its owned systemd user bus')
    authority = Path(environment.get('XAUTHORITY', str(Path.home() / '.Xauthority')))
    if not authority.is_file() or authority.stat().st_uid != os.getuid():
        raise RuntimeError('desktop X authority is absent or foreign')
    environment['XAUTHORITY'] = str(authority)
    child_environment = dict(os.environ, **environment)
    command(['xdpyinfo'], child_environment)
    wm_check = command(['xprop', '-root', '_NET_SUPPORTING_WM_CHECK'], child_environment)
    window = re.search(r'window id # (0x[0-9a-fA-F]+)$', wm_check)
    if window is None:
        return None
    wm_name = command(['xprop', '-id', window[1], '_NET_WM_NAME'], child_environment)
    if '"Xfwm4"' not in wm_name:
        raise RuntimeError('local desktop does not expose its expected Xfce window manager')
    bus_id = command(['gdbus', 'call', '--session', '--dest', 'org.freedesktop.DBus',
                      '--object-path', '/org/freedesktop/DBus', '--method', 'org.freedesktop.DBus.GetId'], child_environment)
    views = desktop_windows(child_environment, selected['Scope'])
    if process_identity(proc, selected['Scope']) != identity:
        raise RuntimeError('Xfce process changed during desktop access checks')
    return {'session': selected, 'xfce_pid': pid, 'environment': environment,
            'process_identity': identity,
            'desktop_windows': views, 'desktop_ready': {view['process'] for view in views} == {'xfdesktop', 'xfce4-panel'},
            'x11_access_verified': True, 'window_manager': wm_name, 'user_bus_id': bus_id,
            'authentication': 'private fixture password through real LightDM keyboard input'}


if __name__ == '__main__':
    import sys
    print(json.dumps(active_greeter() if sys.argv[1:] == ['--greeter'] else read_session()))
