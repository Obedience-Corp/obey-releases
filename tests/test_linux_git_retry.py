import sys
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_git_retry as retry

API = SimpleNamespace(Role=SimpleNamespace(PUSH_BUTTON=1),
                      StateType=SimpleNamespace(ENABLED=1, SENSITIVE=2, SHOWING=3, VISIBLE=4))


def node(pid=42, children=(), enabled=True, button=False):
    value = Mock()
    value.get_process_id.return_value = pid
    value.get_name.return_value = retry.BUTTON if button else 'App'
    value.get_role.return_value = 1 if button else 0
    value.get_child_count.return_value = len(children)
    value.get_child_at_index.side_effect = children.__getitem__
    value.get_state_set.return_value.contains.return_value = enabled
    value.get_action_iface.return_value.get_n_actions.return_value = 1
    return value


class RetrySelectionTests(unittest.TestCase):
    def test_accepts_only_owned_unique_enabled_button(self):
        button = node(button=True)
        action, count = retry.select_button([node(pid=99, children=(node(button=True),)),
                                             node(children=(button,))], 42, API)
        self.assertIs(action, button.get_action_iface())
        self.assertEqual(count, 2)
        action.do_action.assert_not_called()

    def test_foreign_disabled_duplicate_or_ambiguous_app_refused(self):
        cases = [[node(pid=99, children=(node(button=True),))],
                 [node(children=(node(button=True, enabled=False),))],
                 [node(children=(node(button=True), node(button=True)))],
                 [node(), node()]]
        for applications in cases:
            with self.subTest(applications=applications), self.assertRaises(RuntimeError):
                retry.select_button(applications, 42, API)

    def test_unbounded_tree_and_multiple_actions_refused(self):
        root = node(); root.get_child_count.return_value = 4001
        with self.assertRaisesRegex(RuntimeError, 'child count'):
            retry.select_button([root], 42, API)
        button = node(button=True)
        button.get_action_iface.return_value.get_n_actions.return_value = 2
        with self.assertRaisesRegex(RuntimeError, 'one normal'):
            retry.select_button([node(children=(button,))], 42, API)


if __name__ == '__main__':
    unittest.main()
