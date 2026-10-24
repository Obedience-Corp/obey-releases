import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_receipt_ui as ui
import linux_accessibility as settings

API = SimpleNamespace(StateType=SimpleNamespace(SHOWING=1, VISIBLE=2),
                      Text=SimpleNamespace(
                          get_character_count=lambda text: text.get_character_count(),
                          get_text=lambda text, start, end: text.read_text(start, end)))


def node(name='', pid=42, children=(), visible=True):
    value = Mock()
    value.get_process_id.return_value = pid
    value.get_name.return_value = name
    value.get_child_count.return_value = len(children)
    value.get_child_at_index.side_effect = children.__getitem__
    value.get_state_set.return_value.contains.return_value = visible
    value.get_text_iface.return_value = None
    return value


class LinuxReceiptUI(unittest.TestCase):
    def test_reads_owned_visible_name_and_text_without_actions(self):
        text = node()
        text.get_text_iface.return_value = Mock()
        text.get_text_iface.return_value.get_character_count.return_value = 10
        text.get_text_iface.return_value.read_text.return_value = 'diagnostic'
        # Ubuntu GI exposes Accessible.get_text(), a zero-argument interface
        # getter, on this same object. The observer must dispatch via Text.
        text.get_text_iface.return_value.get_text.side_effect = AssertionError('shadowed Accessible getter')
        owned = node('owned', children=(node('hidden', visible=False), text))
        values, count = ui.visible_text([node('foreign', pid=99), owned], 42, API)
        self.assertEqual(set(values), {'owned', 'diagnostic'})
        self.assertEqual(count, 3)
        owned.get_action_iface.assert_not_called()
        text.get_action_iface.assert_not_called()

    def test_foreign_ambiguous_and_unbounded_observations_refused(self):
        for roots in ([node(pid=99)], [node(), node()]):
            with self.assertRaises(RuntimeError):
                ui.visible_text(roots, 42, API)
        unbounded = node(); unbounded.get_child_count.return_value = 4001
        with self.assertRaisesRegex(RuntimeError, 'child count'):
            ui.visible_text([unbounded], 42, API)
        with self.assertRaisesRegex(RuntimeError, 'invalid owned accessibility text'):
            ui.visible_text([node('x' * 65537)], 42, API)

    def test_failed_enable_retains_original_for_verified_restore(self):
        state = {'value': 'false', 'writes': []}
        def command(args, environment):
            if args[1] == 'get':
                return state['value']
            state['writes'].append(args[-1])
            if args[-1] == 'false':
                state['value'] = args[-1]
            return ''
        with patch.object(settings, 'command', side_effect=command):
            setting = settings.ToolkitSetting({})
            with self.assertRaisesRegex(RuntimeError, 'did not persist'):
                setting.enable()
            self.assertEqual(setting.original, 'false')
            setting.restore()
        self.assertEqual(state['writes'], ['true', 'false'])


if __name__ == '__main__':
    unittest.main()
