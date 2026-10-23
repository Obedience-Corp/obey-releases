import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('filesystem tests require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import packaging_service as service


def metadata(root):
    unit = Path.home() / 'AppData/Local/ObedienceCorp/Obey/service-task.xml'
    script = str(unit.with_name('service-start.ps1'))
    return {'unit': str(unit), 'unit_exists': True, 'script': script, 'script_exists': True,
            'script_sha256': 'a' * 64, 'expected_task': 'ObedienceCorp.Obey.owned-SID',
            'tasks': [{'name': 'ObedienceCorp.Obey.owned-SID', 'path': '\\', 'actions': [{'execute': 'powershell.exe', 'arguments': '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + script + '"', 'working_directory': str(root / 'data')}]}],
            'invocations': [[str(root / 'managed/bin/obey.exe'), 'serve', '--daemon-mode']],
            'config_values': [str(root / 'obey.yaml')], 'processes': []}


def absent(root):
    result = metadata(root)
    result.update(tasks=[], unit_exists=False, script_exists=False, invocations=[], config_values=[])
    return result


class PackagingServiceTests(unittest.TestCase):
    def test_exact_wrapper_executable_config_and_task_are_required(self):
        root = Path('/unique-owned-fixture')
        state = metadata(root)
        self.assertTrue(service.checked_owner(state, root / 'managed/bin/obey.exe', root / 'obey.yaml', root / 'data'))
        changes = [lambda s: s['tasks'][0].update(name='foreign'), lambda s: s['tasks'].append(copy.deepcopy(s['tasks'][0])),
                   lambda s: s['tasks'][0]['actions'][0].update(arguments='-File foreign.ps1'),
                   lambda s: s['tasks'][0]['actions'][0].update(execute='foreign.exe'),
                   lambda s: s.update(invocations=[['/foreign/obey.exe', 'serve', '--daemon-mode']]),
                   lambda s: s.update(config_values=['/foreign/config']), lambda s: s.update(unit='/foreign/unit'),
                   lambda s: s.update(script_exists=False), lambda s: s.update(invocations=[[None, 'serve', '--daemon-mode']])]
        for change in changes:
            damaged = copy.deepcopy(state); change(damaged)
            with self.assertRaises(ValueError):
                service.checked_owner(damaged, root / 'managed/bin/obey.exe', root / 'obey.yaml', root / 'data')

    def test_baseline_refuses_old_task_files_and_processes(self):
        root = Path('/unique-owned-fixture')
        for key, value in [('tasks', [{}]), ('script_exists', True), ('unit_exists', True), ('processes', [{'pid': 1}])]:
            state = absent(root); state[key] = value
            with patch.object(service, 'snapshot', return_value=state), self.assertRaises(RuntimeError):
                service.baseline(root, {})

    def test_foreign_task_never_invokes_uninstall(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); state = metadata(root); state['config_values'] = ['/foreign/config']
            with patch.object(service, 'snapshot', return_value=state), patch.object(service, 'command') as invoked:
                with self.assertRaises(ValueError):
                    service.cleanup(root, {}, {})
                invoked.assert_not_called()

    def test_owned_uninstall_requires_real_empty_after_readback(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); exe = root / 'managed/bin/obey.exe'; exe.parent.mkdir(parents=True); exe.write_bytes(b'owned')
            report = {}
            with patch.object(service, 'snapshot', side_effect=[metadata(root), absent(root)]), patch.object(service, 'command', side_effect=[{'installed': True, 'loaded': True, 'socket_reachable': True}, '', {'installed': False, 'loaded': False, 'socket_reachable': False}]) as invoked:
                service.cleanup(root, {}, report)
                self.assertEqual(invoked.call_args_list[1].args[0], [exe, 'service', 'uninstall'])
                self.assertTrue(report['redirected_packaging_service_cleanup_verified'])
            for key, value in [('tasks', [{}]), ('processes', [{'pid': 9}]), ('unit_exists', True)]:
                remains = absent(root); remains[key] = value
                with patch.object(service, 'snapshot', side_effect=[metadata(root), remains]), patch.object(service, 'command', side_effect=[{'installed': True, 'loaded': True, 'socket_reachable': True}, '', {'installed': False, 'loaded': False, 'socket_reachable': False}]), self.assertRaises(RuntimeError):
                    service.cleanup(root, {}, {})

    def test_detached_cleanup_uses_unique_context_stop_without_arbitrary_kill(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); exe = root / 'managed/bin/obey.exe'; exe.parent.mkdir(parents=True); exe.write_bytes(b'owned')
            before = absent(root); before['processes'] = [{'pid': 1, 'path': str(exe)}]
            with patch.object(service, 'snapshot', side_effect=[before, absent(root)]), patch.object(service, 'command', side_effect=[{'installed': False, 'loaded': False, 'socket_reachable': True}, '', {'installed': False, 'loaded': False, 'socket_reachable': False}]) as invoked:
                service.cleanup(root, {}, {})
                self.assertEqual(invoked.call_args_list[1].args[0], [exe, 'stop'])

    def test_incomplete_or_nonboolean_status_is_not_cleanup_success(self):
        for state in [{}, {'installed': False, 'loaded': False}, {'installed': 'false', 'loaded': False, 'socket_reachable': False}]:
            with self.assertRaises(ValueError):
                service.checked_status(state)

    def test_failed_uninstall_preserves_after_readback_and_stays_failed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); exe = root / 'managed/bin/obey.exe'; exe.parent.mkdir(parents=True); exe.write_bytes(b'owned')
            state = {'installed': True, 'loaded': True, 'socket_reachable': True}
            report = {}
            with patch.object(service, 'snapshot', side_effect=[metadata(root), absent(root)]), patch.object(service, 'command', side_effect=[state, RuntimeError('uninstall failed'), {'installed': False, 'loaded': False, 'socket_reachable': False}]):
                with self.assertRaisesRegex(RuntimeError, 'uninstall failed'):
                    service.cleanup(root, {}, report)
            self.assertIn('packaging_service_after_cleanup', report)
            self.assertIn('packaging_service_status_after', report)
            self.assertNotIn('redirected_packaging_service_cleanup_verified', report)
