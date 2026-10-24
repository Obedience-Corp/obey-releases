import copy
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import external_suite as external
import verify_app_candidate as app


class MixedFestPath(unittest.TestCase):
    def setUp(self):
        if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
            raise RuntimeError('mixed PATH filesystem tests require isolated Docker')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self):
        fixture = external.Fixture.__new__(external.Fixture)
        fixture.root = self.root
        fixture.output = self.root / 'output'
        fixture.output.mkdir(exist_ok=True)
        fixture.report = {}
        fixture.environment = {'PATH': '/usr/bin:/bin'}
        fixture.mixed_fest = True
        fixture.version, fixture.size, fixture.digest, fixture.camp, fixture.fest = external.SPECS['external-suite-mixed-fest']
        fixture.settings = self.root / 'settings.json'
        fixture.managed = self.root / 'managed'
        fixture.installer = Path('/usr/bin/festival-app-installer')
        return fixture

    def archive(self, kind='regular'):
        executable = b'\x7fELF\x02\x01' + b'\0' * 12 + b'\x3e\x00' + b'fixture' * 12
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            member = tarfile.TarInfo('../fest' if kind == 'escaped' else 'fest')
            member.size = len(executable)
            if kind == 'symlink':
                member.type = tarfile.SYMTYPE
                member.linkname = '/foreign/fest'
                member.size = 0
            archive.addfile(member, io.BytesIO(executable) if kind != 'symlink' else None)
            if kind == 'duplicate':
                archive.addfile(member, io.BytesIO(executable))
        return stream.getvalue(), executable

    def install_shadow(self, fixture, kind='regular', corrupt=False):
        payload, executable = self.archive(kind)
        digest = hashlib.sha256(payload).hexdigest()
        checksum = ('0' * 64 if corrupt else digest) + '  festival-0.3.17-linux-x86_64.tar.gz\n'
        with patch.object(external, 'fetch', side_effect=[payload, checksum.encode()]), \
                patch.object(external, 'MIXED_FEST_ARCHIVE_SIZE', len(payload)), \
                patch.object(external, 'MIXED_FEST_ARCHIVE_SHA256', digest), \
                patch.object(external, 'command', return_value={'version': 'v0.9.1', 'bundle': 'v0.3.17'}):
            fixture.install_fest_shadow()
        return executable

    def test_mixed_requires_correction_even_though_debian_package_is_current(self):
        fixture = self.fixture()
        self.assertEqual(fixture.version, '0.3.24')
        self.assertIsNone(fixture.external_mode)
        fixture.mixed_fest = False
        self.assertEqual(fixture.external_mode, '0.3.24')

    def test_verified_archive_adds_only_the_old_fest_to_path(self):
        fixture = self.fixture()
        executable = self.install_shadow(fixture)
        shadow = Path(fixture.shadow_original['path'])
        self.assertEqual(shadow.read_bytes(), executable)
        self.assertEqual(list(shadow.parent.iterdir()), [shadow])
        self.assertEqual(fixture.environment['PATH'], str(shadow.parent) + ':/usr/bin:/bin')
        self.assertEqual(external.physical(shadow), fixture.shadow_original)
        self.assertEqual(fixture.report['mixed_fest']['live']['version'], 'v0.9.1')

    def test_corrupt_or_ambiguous_archive_never_creates_a_path_executable(self):
        for kind, corrupt in [('regular', True), ('symlink', False), ('duplicate', False), ('escaped', False)]:
            with self.subTest(kind=kind, corrupt=corrupt):
                fixture = self.fixture()
                with self.assertRaises(ValueError):
                    self.install_shadow(fixture, kind, corrupt)
                self.assertFalse((self.root / 'mixed-fest-bin').exists())
                self.assertEqual(fixture.environment['PATH'], '/usr/bin:/bin')

    def test_before_launch_requires_the_actual_mixed_paths_and_versions(self):
        fixture = self.fixture()
        self.install_shadow(fixture)
        rows = [
            {'tool': 'camp', 'present': True, 'path': '/usr/bin/camp', 'version': '0.16.2',
             'bundle': 'v0.3.24', 'origin': 'package'},
            {'tool': 'fest', 'present': True, 'path': fixture.shadow_original['path'], 'version': '0.9.1',
             'bundle': 'v0.3.17', 'origin': 'leftover'},
        ]
        status = {'ok': True, 'data': {'tools': rows}}
        with patch.object(fixture, 'require_no_starter'), patch.object(fixture, 'unchanged', return_value={}), \
                patch.object(external, 'checked_receipts', return_value={'files': []}), \
                patch.object(external, 'command', return_value=status):
            fixture.before_launch()
            self.assertEqual(fixture.report['status_before_app'], status)
        for key, value in [('path', '/usr/bin/fest'), ('version', '0.9.8'), ('bundle', 'v0.3.24'),
                           ('origin', 'package'), ('receipt_version', '0.3.24'), ('error', 'probe failed')]:
            broken = copy.deepcopy(status)
            broken['data']['tools'][1][key] = value
            with patch.object(fixture, 'require_no_starter'), patch.object(external, 'command', return_value=broken):
                with self.assertRaisesRegex(ValueError, 'exact receiptless external suite'):
                    fixture.before_launch()

    def test_owned_cleanup_restores_path_and_refuses_changed_shadow(self):
        fixture = self.fixture()
        self.install_shadow(fixture)
        fixture.attempted_install = True
        fixture.installed = False
        fixture.note_record = None
        shadow = Path(fixture.shadow_original['path'])
        original = shadow.read_bytes()
        shadow.write_bytes(b'changed foreign file')
        with patch('corrupt_receipts.quiescent'), patch.object(external, 'package_info', return_value=None), \
                patch.object(external.os.path, 'lexists', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'changed PATH Fest'):
                fixture.cleanup()
            self.assertEqual(shadow.read_bytes(), b'changed foreign file')
            # Restore the exact fixture identity, not merely its bytes, for a
            # separate successful cleanup attempt.
            shadow.write_bytes(original)
            os.utime(shadow, ns=(shadow.stat().st_atime_ns, fixture.shadow_original['mtime_ns']))
            fixture.cleanup()
        self.assertFalse(shadow.exists())
        self.assertEqual(fixture.environment['PATH'], '/usr/bin:/bin')
        self.assertTrue(fixture.report['mixed_fest_cleanup_verified'])

    def test_mixed_path_native_case_refuses_other_platforms_before_mutation(self):
        for target, package in [('aarch64-apple-darwin', 'both'), ('x86_64-pc-windows-msvc', 'both'),
                                ('x86_64-unknown-linux-gnu', 'appimage')]:
            with patch.object(app, 'require_clean_host'):
                with self.assertRaisesRegex(ValueError, 'Linux Deb'):
                    app.native(self.root, {}, target, self.root / 'out', linux_package=package,
                               fresh_setup=True, existing_user='external-suite-mixed-fest')
        self.assertFalse((self.root / 'out').exists())
