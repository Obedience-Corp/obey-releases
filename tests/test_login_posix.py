"""Exercise actual login shells and wrapper dispatch only in filesystem isolation."""
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
import unittest

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('POSIX login tests require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import login_posix
import login_shell


class PosixLoginContracts(unittest.TestCase):
    def fixture(self, root, kind='bash', tool='camp', extra='', definition=None):
        home = root / 'home'; home.mkdir()
        managed = home / '.obey/installer'; binary = managed / 'bin' / tool
        binary.parent.mkdir(parents=True)
        output = root / 'proof'; output.mkdir()
        wrapped = tool in ('camp', 'fest')
        if definition is None:
            definition = f'{tool}() {{ FA0027_WRAPPER_CALLED=yes command {tool} "$@"; }}'
        if kind == 'zsh':
            definition += f'\ncompdef _fixture {tool}'
        version = login_shell.TOOLS[tool][0]
        binary.write_text('#!/bin/sh\n'
            'if [ "$1" = shell-init ]; then\n'
            f'  printf \'%s\\n\' {shlex.quote(definition)}\n'
            'else\n'
            + ('  [ "$FA0027_WRAPPER_CALLED" = yes ] || exit 57\n' if wrapped else '')
            + f'  printf \'v{version}\\n\'\nfi\n')
        binary.chmod(0o755)
        profile = home / ('.bash_profile' if kind == 'bash' else '.zshrc')
        profile.write_text(('autoload -Uz compinit; compinit -D\nautoload -Uz bashcompinit; bashcompinit\n' if kind == 'zsh' else '')
                           + f'export PATH={shlex.quote(str(binary.parent))}:"$PATH"\n'
                           + (f'eval "$({shlex.quote(str(binary))} shell-init {kind})"\n' if wrapped else '')
                           + extra + '\n')
        fixture = login_shell.seed_profile(profile, home, kind)
        fixture.update(kind=kind, shell=shutil.which(kind), runtime=kind)
        environment = dict(os.environ, HOME=str(home), ZDOTDIR=str(home))
        return fixture, managed, environment, output

    def test_real_bash_wrapper_and_ordinary_passthrough_survive_reopen(self):
        for tool in ('camp', 'fest', 'obey'):
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as directory:
                args = self.fixture(Path(directory), tool=tool)
                first = login_posix.verify_tool(args[0], tool, *args[1:], 'setup')
                second = login_posix.verify_tool(args[0], tool, *args[1:], 'reopen')
                self.assertEqual(first, second)
                self.assertEqual(first['installed_wrapper_verified'], tool != 'obey')
                self.assertTrue(first['profile_sentinel_verified'])

    def test_foreign_function_reporting_correct_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory), extra="camp() { printf 'v0.16.2\\n'; }")
            with self.assertRaisesRegex(ValueError, 'differs from'):
                login_posix.verify_tool(args[0], 'camp', *args[1:], 'spoof')
            self.assertIn(b'v0.16.2', (args[3] / 'spoof-login-camp.terminal.log').read_bytes())

    def test_terminal_carriage_return_cannot_change_encoded_definition(self):
        import re
        from unittest.mock import patch
        original = login_shell.pty_run
        def terminal_carriage_return(args, environment, output, **kwargs):
            original(args, environment, output, **kwargs)
            if '.reference.' not in output.name:
                raw = output.read_bytes()
                changed, count = re.subn(
                    rb'(FA0027_[^\r\n]+_DEFINITION\r\n[^\r\n]+)\r\n',
                    rb'\1\r\r\n', raw, count=1)
                self.assertEqual(count, 1)
                output.write_bytes(changed)
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory))
            with patch.object(login_shell, 'pty_run', side_effect=terminal_carriage_return):
                result = login_posix.verify_tool(args[0], 'camp', *args[1:], 'terminal-cr')
            self.assertTrue(result['installed_wrapper_verified'])
            self.assertIn(b'\r\r\n', (args[3] / 'terminal-cr-login-camp.terminal.log').read_bytes())

    def test_literal_source_carriage_return_is_preserved_and_changes_are_rejected(self):
        definition = 'camp() { FA0027_WRAPPER_CALLED=yes command camp "$@"; : "first\r\nlast"; }'
        for extra, fails in (('', False), (definition.replace('\r', ''), True)):
            with self.subTest(fails=fails), tempfile.TemporaryDirectory() as directory:
                args = self.fixture(Path(directory), definition=definition, extra=extra)
                if fails:
                    with self.assertRaisesRegex(ValueError, 'differs from'):
                        login_posix.verify_tool(args[0], 'camp', *args[1:], 'source-cr')
                else:
                    self.assertTrue(login_posix.verify_tool(args[0], 'camp', *args[1:], 'source-cr')['installed_wrapper_verified'])

    def test_malformed_encoded_definition_is_rejected(self):
        for encoded in (['not base64!'], ['\x1b[31mYQ=='], []):
            with self.assertRaises(ValueError):
                login_posix.definition_bytes(encoded)

    def test_foreign_python_module_cannot_forge_wrapper_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            foreign = root / 'foreign-python'; foreign.mkdir()
            (foreign / 'base64.py').write_text('def b64encode(value): return b"Zm9yZ2Vk"\n')
            args = self.fixture(root, extra="camp() { printf 'v0.16.2\\n'; }")
            args[2]['PYTHONPATH'] = str(foreign)
            with self.assertRaisesRegex(ValueError, 'differs from'):
                login_posix.verify_tool(args[0], 'camp', *args[1:], 'python-spoof')

    def test_wrong_external_path_fails_even_with_matching_wrapper_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            foreign = root / 'foreign'; foreign.mkdir()
            args = self.fixture(root, extra=f'export PATH={shlex.quote(str(foreign))}:"$PATH"')
            shadow = foreign / 'camp'
            shadow.write_text('#!/bin/sh\nprintf "v0.16.2\\n"\n'); shadow.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'unexpected external executable'):
                login_posix.verify_tool(args[0], 'camp', *args[1:], 'shadow')

    def test_alias_is_not_accepted_as_an_authenticated_function(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory), extra="alias camp='echo v0.16.2'")
            with self.assertRaises(ValueError):
                login_posix.verify_tool(args[0], 'camp', *args[1:], 'alias')

    def test_cached_foreign_executable_is_not_hidden_by_correct_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); foreign = root / 'foreign-camp'
            foreign.write_text('#!/bin/sh\nprintf "v0.16.2\\n"\n'); foreign.chmod(0o755)
            args = self.fixture(root, extra=f'hash -p {shlex.quote(str(foreign))} camp')
            with self.assertRaisesRegex(ValueError, 'unexpected external executable'):
                login_posix.verify_tool(args[0], 'camp', *args[1:], 'cached')

    def test_ambiguous_or_reordered_marker_evidence_is_rejected(self):
        for raw in (b'm_A\nm_END\nm_END\n', b'm_END\nm_A\n', b'm_A\n'):
            with self.assertRaises(ValueError): login_posix.sections(raw, 'm', ('A',))

    @unittest.skipUnless(shutil.which('zsh'), 'Zsh requires the additional shell test image')
    def test_real_zsh_wrapper_and_foreign_spoof(self):
        for extra, fails in (('', False), ("camp() { printf 'v0.16.2\\n'; }", True)):
            with self.subTest(fails=fails), tempfile.TemporaryDirectory() as directory:
                args = self.fixture(Path(directory), kind='zsh', extra=extra)
                if fails:
                    with self.assertRaisesRegex(ValueError, 'differs from'):
                        login_posix.verify_tool(args[0], 'camp', *args[1:], 'zsh')
                else:
                    self.assertTrue(login_posix.verify_tool(args[0], 'camp', *args[1:], 'zsh')['installed_wrapper_verified'])
