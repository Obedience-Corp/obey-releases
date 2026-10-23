"""Guard and clean only a redirected packaging fixture's own Windows service."""
import re
from pathlib import Path
from verify_candidate import command


def same_file(actual, expected):
    if not isinstance(actual, (str, Path)):
        return False
    if str(actual) == str(expected):
        return True
    try:
        return Path(actual).samefile(expected)
    except OSError:
        return False


def checked_owner(state, executable, config, data):
    tasks = state['tasks']
    artifacts = state['unit_exists'] or state['script_exists']
    if not tasks and not artifacts:
        return False
    if len(tasks) != 1 or not state['unit_exists'] or not state['script_exists']:
        raise ValueError('ambiguous or partial packaging supervisor ownership')
    unit = Path.home() / 'AppData/Local/ObedienceCorp/Obey/service-task.xml'
    if not same_file(state['unit'], unit) or not same_file(state['script'], unit.with_name('service-start.ps1')) or not re.fullmatch('[0-9a-f]{64}', state.get('script_sha256') or ''):
        raise ValueError('foreign packaging supervisor artifacts')
    task = tasks[0]
    if task['name'] != state['expected_task'] or task['path'] != '\\' or len(task['actions']) != 1:
        raise ValueError('foreign packaging supervisor task')
    action = task['actions'][0]
    expected_args = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + state['script'] + '"'
    if action['execute'].lower() != 'powershell.exe' or action['arguments'] != expected_args or not same_file(action['working_directory'], data):
        raise ValueError('foreign packaging supervisor action')
    invokes = state['invocations']
    if len(invokes) != 1 or len(invokes[0]) != 3 or not same_file(invokes[0][0], executable) or invokes[0][1:] != ['serve', '--daemon-mode']:
        raise ValueError('foreign or dynamic packaging supervisor executable')
    if len(state['config_values']) != 1 or not same_file(state['config_values'][0], config):
        raise ValueError('foreign packaging supervisor configuration')
    return True


def snapshot(executable, environment):
    unit = Path.home() / 'AppData/Local/ObedienceCorp/Obey/service-task.xml'
    return command(['pwsh', '-NoProfile', '-NonInteractive', '-File', Path(__file__).with_name('windows_packaging_service.ps1')],
                   dict(environment, APP_PROOF_UNIT=str(unit), APP_PROOF_MANAGED_EXE=str(executable)), json_output=True)


def baseline(root, environment):
    state = snapshot(root / 'managed/bin/obey.exe', environment)
    if state['tasks'] or state['unit_exists'] or state['script_exists'] or state['processes']:
        raise RuntimeError('refusing preexisting Windows packaging supervisor state')
    return state


def checked_status(state):
    if not isinstance(state, dict) or any(type(state.get(k)) is not bool for k in ('installed', 'loaded', 'socket_reachable')):
        raise ValueError('invalid packaging service status contract')
    return state


def cleanup(root, environment, report):
    executable, config, data = root / 'managed/bin/obey.exe', root / 'obey.yaml', root / 'data'
    before = snapshot(executable, environment)
    report['packaging_service_before_cleanup'] = before
    owned = checked_owner(before, executable, config, data)
    if not executable.is_file():
        if owned or before['processes']:
            raise RuntimeError('owned supervisor lost its executable before cleanup')
        return
    state = checked_status(command([executable, 'service', 'status', '--json'], environment, json_output=True))
    report['packaging_service_status_before'] = state
    if not owned and (state.get('installed') or state.get('loaded')):
        raise RuntimeError('service status has no proven packaging supervisor owner')
    try:
        if owned:
            command([executable, 'service', 'uninstall'], environment, timeout=120)
        elif state.get('socket_reachable') or before['processes']:
            # Unique fixture config/socket only: no arbitrary PID/name kill.
            command([executable, 'stop'], environment, timeout=120)
    except Exception as error:
        report['packaging_service_action_failure'] = str(error)
        raise
    finally:
        after = snapshot(executable, environment)
        report['packaging_service_after_cleanup'] = after
        status = checked_status(command([executable, 'service', 'status', '--json'], environment, json_output=True))
        report['packaging_service_status_after'] = status
    if after['tasks'] or after['unit_exists'] or after['script_exists'] or after['processes'] or any(status.get(k) for k in ('installed', 'loaded', 'socket_reachable')):
        raise RuntimeError('owned packaging supervisor or daemon remained after cleanup')
    report['redirected_packaging_service_cleanup_verified'] = True
