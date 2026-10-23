import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import verify_discovery_proof as proof

SOURCE = 'a' * 40


class DiscoveryProofTests(unittest.TestCase):
    def test_fixed_source_tag_and_digest(self):
        proof.checked_request('candidate-sessiondiscovery-' + SOURCE, SOURCE, 'b' * 64)
        for tag, source, digest in [('other', SOURCE, 'b' * 64), ('candidate-sessiondiscovery-' + SOURCE, '../bad', 'b' * 64), ('candidate-sessiondiscovery-' + SOURCE, SOURCE, 'BAD')]:
            with self.assertRaises(ValueError):
                proof.checked_request(tag, source, digest)

    def test_exact_manifest_and_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / proof.EXECUTABLE
            binary.write_bytes(b'internal test only')
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            manifest = {'schema': 'obey-sessiondiscovery-proof/v1', 'source_revision': SOURCE,
                        'purpose': 'internal-observer-test-only', 'go_version': 'go1.26.0',
                        'goos': 'windows', 'goarch': 'amd64', 'cgo_enabled': '0',
                        'executable': {'filename': proof.EXECUTABLE, 'sha256': digest}}
            path = directory / proof.MANIFEST
            path.write_text(json.dumps(manifest))
            proof.checked_files(directory, SOURCE, digest)
            binary.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                proof.checked_files(directory, SOURCE, digest)
            binary.write_bytes(b'internal test only')
            manifest['purpose'] = 'production'
            path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                proof.checked_files(directory, SOURCE, digest)

    def test_embedded_clean_source_target_and_test_tag(self):
        settings = {'vcs': 'git', 'vcs.revision': SOURCE, 'vcs.modified': 'false', 'GOOS': 'windows', 'GOARCH': 'amd64', 'CGO_ENABLED': '0', '-tags': 'fs_mutation_tests'}
        def document():
            return {'GoVersion': 'go1.26.0', 'Path': 'github.com/obediencecorp/obey/internal/sessiondiscovery.test', 'Settings': [{'Key': k, 'Value': v} for k, v in settings.items()]}
        proof.checked_build_info(document(), SOURCE)
        for key, value in [('vcs.revision', 'c' * 40), ('vcs.modified', 'true'), ('CGO_ENABLED', '1'), ('GOOS', 'linux'), ('-tags', '')]:
            old = settings[key]
            settings[key] = value
            with self.assertRaises(ValueError):
                proof.checked_build_info(document(), SOURCE)
            settings[key] = old
