"""Fixed, owned-window AT-SPI interaction for the missing-Git Retry journey.

Run with the distribution Python/GI packages in a disposable desktop session.
The caller supplies an outer process timeout; no App command is injected.
"""
import argparse
import json
import os
from pathlib import Path

BUTTON = 'Install Git and continue'


def birth(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    if fields[0] in ('Z', 'X'):
        raise RuntimeError('owned App has exited')
    return int(fields[19])


def require_owner(pid, expected_birth, executable):
    if birth(pid) != expected_birth or not Path(f'/proc/{pid}/exe').samefile(executable):
        raise RuntimeError('owned App identity changed before accessibility action')


def select_button(applications, pid, api):
    """Require one visible, enabled, actual button in the owned application."""
    roots = [app for app in applications if app.get_process_id() == pid]
    if len(roots) != 1:
        raise RuntimeError('owned App accessibility application is absent or ambiguous')
    queue = [roots[0]]
    matches = []
    count = 0
    while queue:
        node = queue.pop()
        count += 1
        if count > 4000:
            raise RuntimeError('owned accessibility tree exceeds observation bound')
        if node.get_name() == BUTTON and node.get_role() == api.Role.PUSH_BUTTON:
            states = node.get_state_set()
            if all(states.contains(flag) for flag in
                   (api.StateType.ENABLED, api.StateType.SENSITIVE, api.StateType.SHOWING, api.StateType.VISIBLE)):
                matches.append(node)
        children = node.get_child_count()
        if children < 0 or children > 4000 or count + len(queue) + children > 4000:
            raise RuntimeError('owned accessibility tree has invalid child count')
        queue.extend(node.get_child_at_index(index) for index in range(children))
    if len(matches) != 1:
        raise RuntimeError('missing-Git Retry button is absent, disabled or ambiguous')
    action = matches[0].get_action_iface()
    if action is None or action.get_n_actions() != 1:
        raise RuntimeError('missing-Git Retry button lacks one normal accessibility action')
    return action, count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--birth', type=int, required=True)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--action', choices=('inspect', 'retry'), required=True)
    args = parser.parse_args()
    if (os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
            os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted' or
            args.pid <= 1 or args.birth <= 0 or not args.executable.is_absolute()):
        raise RuntimeError('Git Retry interaction requires an owned disposable hosted App')
    import gi
    gi.require_version('Atspi', '2.0')
    from gi.repository import Atspi
    Atspi.set_timeout(1000, 5000)
    require_owner(args.pid, args.birth, args.executable)
    desktop = Atspi.get_desktop(0)
    count = desktop.get_child_count()
    if count < 0 or count > 64:
        raise RuntimeError('desktop accessibility application count exceeds fixture bound')
    applications = [desktop.get_child_at_index(index) for index in range(count)]
    action, count = select_button(applications, args.pid, Atspi)
    require_owner(args.pid, args.birth, args.executable)
    invoked = False
    if args.action == 'retry':
        if action.do_action(0) is not True:
            raise RuntimeError('normal missing-Git Retry accessibility action was rejected')
        invoked = True
    print(json.dumps({'pid': args.pid, 'birth': args.birth, 'button': BUTTON,
                      'observed_nodes': count, 'retry_action_invoked': invoked}))


if __name__ == '__main__':
    main()
