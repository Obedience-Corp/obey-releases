"""Read visible diagnostic text from one authenticated Linux App process."""
import argparse
import json
import os
from pathlib import Path
import sys

# The helper runs under isolated distribution Python; only its trusted sibling
# identity helper is added, never the current directory or user site packages.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from linux_git_retry import require_owner


def visible_text(applications, pid, api):
    roots = [app for app in applications if app.get_process_id() == pid]
    if len(roots) != 1:
        raise RuntimeError('owned App accessibility application is absent or ambiguous')
    queue, texts, count, total = [roots[0]], [], 0, 0
    while queue:
        node = queue.pop()
        count += 1
        if count > 4000:
            raise RuntimeError('owned accessibility tree exceeds observation bound')
        state = node.get_state_set()
        if all(state.contains(flag) for flag in (api.StateType.SHOWING, api.StateType.VISIBLE)):
            values = [node.get_name()]
            text = node.get_text_iface()
            if text is not None:
                length = api.Text.get_character_count(text)
                if not 0 <= length <= 65536:
                    raise RuntimeError('owned accessibility text exceeds observation bound')
                # Some GI releases return Accessible here; its deprecated
                # get_text() getter shadows Text.get_text(start, end).
                values.append(api.Text.get_text(text, 0, length))
            for value in values:
                if not isinstance(value, str) or len(value) > 65536:
                    raise RuntimeError('invalid owned accessibility text')
                total += len(value)
                if total > 262144:
                    raise RuntimeError('owned accessibility text exceeds total bound')
                if value and value not in texts:
                    texts.append(value)
        children = node.get_child_count()
        if children < 0 or children > 4000 or count + len(queue) + children > 4000:
            raise RuntimeError('owned accessibility tree has invalid child count')
        queue.extend(node.get_child_at_index(index) for index in range(children))
    return texts, count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--birth', type=int, required=True)
    parser.add_argument('--executable', type=Path, required=True)
    args = parser.parse_args()
    if (os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
            os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted' or
            args.pid <= 1 or args.birth <= 0 or not args.executable.is_absolute()):
        raise RuntimeError('receipt observation requires an owned disposable hosted App')
    import gi
    gi.require_version('Atspi', '2.0')
    from gi.repository import Atspi
    Atspi.set_timeout(1000, 5000)
    require_owner(args.pid, args.birth, args.executable)
    desktop = Atspi.get_desktop(0)
    count = desktop.get_child_count()
    if not 0 <= count <= 64:
        raise RuntimeError('desktop accessibility application count exceeds fixture bound')
    texts, count = visible_text([desktop.get_child_at_index(i) for i in range(count)], args.pid, Atspi)
    require_owner(args.pid, args.birth, args.executable)
    print(json.dumps({'pid': args.pid, 'birth': args.birth, 'visible_text': texts,
                      'observed_nodes': count, 'owned_accessibility_verified': True}))


if __name__ == '__main__':
    main()
