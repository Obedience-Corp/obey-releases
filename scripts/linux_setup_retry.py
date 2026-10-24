"""One normal accessibility action in the authenticated failed Install setup row."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from linux_git_retry import require_owner
from linux_receipt_ui import subtree_text, visible_text

LABEL = 'Install selected app packages'
CODE = 'E_ARTIFACT_DO'


def select_retry(applications, pid, api):
    roots = [app for app in applications if app.get_process_id() == pid]
    if len(roots) != 1:
        raise RuntimeError('owned setup application is absent or ambiguous')
    queue, rows, count = [roots[0]], [], 0
    while queue:
        node = queue.pop()
        count += 1
        if count > 4000:
            raise RuntimeError('owned setup accessibility tree exceeds bound')
        if node.get_role() == api.Role.LIST_ITEM:
            texts, _ = subtree_text(node, api)
            joined = '\n'.join(texts)
            if LABEL in texts and 'Failed' in joined and CODE in joined:
                rows.append((node, texts))
        children = node.get_child_count()
        if not 0 <= children <= 4000 or count + len(queue) + children > 4000:
            raise RuntimeError('invalid setup accessibility child count')
        queue.extend(node.get_child_at_index(i) for i in range(children))
    if len(rows) != 1:
        raise RuntimeError('exact failed selected-package install row is absent or ambiguous')
    queue, matches = [rows[0][0]], []
    while queue:
        node = queue.pop()
        if node.get_role() == api.Role.PUSH_BUTTON and node.get_name() == 'Retry':
            state = node.get_state_set()
            if all(state.contains(flag) for flag in (api.StateType.ENABLED, api.StateType.SENSITIVE,
                                                     api.StateType.SHOWING, api.StateType.VISIBLE)):
                matches.append(node)
        queue.extend(node.get_child_at_index(i) for i in range(node.get_child_count()))
    if len(matches) != 1:
        raise RuntimeError('install Retry must be one visible enabled button in the failed row')
    action = matches[0].get_action_iface()
    if action is None or action.get_n_actions() != 1:
        raise RuntimeError('install Retry lacks one normal action')
    return action, {'row_text': rows[0][1], 'observed_nodes': count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--birth', required=True, type=int)
    parser.add_argument('--executable', required=True, type=Path)
    parser.add_argument('--action', choices=('inspect', 'retry'), required=True)
    args = parser.parse_args()
    if (os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
            os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted' or
            args.pid <= 1 or args.birth <= 0 or not args.executable.is_absolute()):
        raise RuntimeError('setup Retry requires an owned disposable App')
    import gi
    gi.require_version('Atspi', '2.0')
    from gi.repository import Atspi
    Atspi.set_timeout(1000, 5000)
    require_owner(args.pid, args.birth, args.executable)
    desktop = Atspi.get_desktop(0)
    count = desktop.get_child_count()
    if not 0 <= count <= 64:
        raise RuntimeError('accessibility desktop exceeds fixture bound')
    applications = [desktop.get_child_at_index(i) for i in range(count)]
    action, record = select_retry(applications, args.pid, Atspi)
    record['visible_text'], _ = visible_text(applications, args.pid, Atspi)
    require_owner(args.pid, args.birth, args.executable)
    if args.action == 'retry' and action.do_action(0) is not True:
        raise RuntimeError('normal install Retry action was rejected')
    print(json.dumps(dict(record, pid=args.pid, birth=args.birth,
                          retry_action_invoked=args.action == 'retry')))


if __name__ == '__main__':
    main()
