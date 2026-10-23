"""Binary-only internal Windows observer proof; never a production release."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from verify_candidate import REPOSITORY, command, native_platform, require_disposable

EXECUTABLE = 'sessiondiscovery.test.exe'
MANIFEST = 'sessiondiscovery-proof.json'
FILTER = '^TestWindowsProcessObservationFS_'


def checked_request(tag, source, digest):
    if not re.fullmatch('[0-9a-f]{40}', source) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('invalid source or executable digest')
    if tag != 'candidate-sessiondiscovery-' + source:
        raise ValueError('draft tag must bind exact source')


def checked_files(directory, source, digest):
    if {p.name for p in directory.iterdir()} != {EXECUTABLE, MANIFEST}:
        raise ValueError('requires exact two-file proof inventory')
    if any(p.is_symlink() or not p.is_file() for p in directory.iterdir()):
        raise ValueError('proof inputs must be regular files')
    manifest = json.loads((directory / MANIFEST).read_text())
    expected = {'schema': 'obey-sessiondiscovery-proof/v1', 'source_revision': source,
                'purpose': 'internal-observer-test-only', 'go_version': 'go1.26.0',
                'goos': 'windows', 'goarch': 'amd64', 'cgo_enabled': '0',
                'executable': {'filename': EXECUTABLE, 'sha256': digest}}
    if manifest != expected:
        raise ValueError('internal proof manifest identity mismatch')
    binary = directory / EXECUTABLE
    if not 0 < binary.stat().st_size <= 256 * 1024 * 1024:
        raise ValueError('invalid proof binary size')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError('proof binary checksum mismatch')
    return manifest


def checked_build_info(document, source):
    settings = document.get('Settings', [])
    values = {item['Key']: item['Value'] for item in settings}
    expected = {'vcs': 'git', 'vcs.revision': source, 'vcs.modified': 'false',
                'GOOS': 'windows', 'GOARCH': 'amd64', 'CGO_ENABLED': '0'}
    if len(values) != len(settings) or document.get('GoVersion') != 'go1.26.0' or any(values.get(k) != v for k, v in expected.items()):
        raise ValueError('proof binary embedded build provenance mismatch')
    if document.get('Path') != 'github.com/obediencecorp/obey/internal/sessiondiscovery.test':
        raise ValueError('unexpected internal test package')
    if 'fs_mutation_tests' not in values.get('-tags', '').split(','):
        raise ValueError('missing internal filesystem test build tag')


def fetch(tag, source, digest, directory):
    metadata = json.loads(subprocess.check_output(['gh', 'release', 'view', tag, '--repo', REPOSITORY, '--json', 'isDraft,assets'], text=True))
    if not metadata['isDraft'] or len(metadata['assets']) != 2 or {a['name'] for a in metadata['assets']} != {EXECUTABLE, MANIFEST}:
        raise ValueError('requires exact unpublished internal-proof draft')
    directory.mkdir()
    subprocess.run(['gh', 'release', 'download', tag, '--repo', REPOSITORY, '--dir', str(directory), '--pattern', EXECUTABLE, '--pattern', MANIFEST], check=True)
    checked_files(directory, source, digest)


def native(directory, source, digest, output):
    require_disposable()
    if native_platform() != 'windows/amd64' or os.environ.get('OBEY_NATIVE_DISCOVERY_DISPOSABLE') != '1':
        raise RuntimeError('internal observer proof requires disposable Windows amd64')
    if os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN'):
        raise RuntimeError('native test must not receive draft credentials')
    output.mkdir()
    report = {'source_revision': source, 'executable_sha256': digest, 'test_filter': FILTER,
              'internal_observer_proof': False, 'production_daemon_readiness': False}
    try:
        report['input_manifest'] = checked_files(directory, source, digest)
        binary = (directory / EXECUTABLE).resolve()
        build = command(['go', 'version', '-m', '-json', binary], os.environ.copy(), json_output=True)
        checked_build_info(build, source)
        (output / 'buildinfo.json').write_text(json.dumps(build, indent=2) + '\n')
        # Literal selected tests only: never a user-provided executable or argv.
        try:
            completed = subprocess.run([str(binary), '-test.v', '-test.run', FILTER, '-test.timeout', '5m'], env=os.environ.copy(), capture_output=True, text=True, timeout=330)
        except subprocess.TimeoutExpired as error:
            def text(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            (output / 'tests.log').write_text(text(error.stdout) + text(error.stderr))
            raise
        result = completed.stdout
        (output / 'tests.log').write_text(result + completed.stderr)
        print(result + completed.stderr, flush=True)
        if completed.returncode:
            raise RuntimeError('internal observer tests failed')
        if not re.search(r'^--- PASS: TestWindowsProcessObservationFS_', result, re.MULTILINE) or re.search(r'^--- (?:FAIL|SKIP): TestWindowsProcessObservationFS_', result, re.MULTILINE):
            raise RuntimeError('selected native observer tests did not all execute successfully')
        report['internal_observer_proof'] = True
    except Exception as error:
        report['failure'] = str(error)
        raise
    finally:
        (output / 'proof.json').write_text(json.dumps(report, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('fetch', 'verify'), required=True)
    for name in ('tag', 'source', 'sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--directory', type=Path, default=Path('discovery-candidate'))
    parser.add_argument('--output', type=Path, default=Path('discovery-proof'))
    args = parser.parse_args()
    checked_request(args.tag, args.source, args.sha256)
    if os.environ.get('GITHUB_REPOSITORY') != REPOSITORY or os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted':
        raise RuntimeError('proof restricted to public binary repository on disposable runners')
    if args.mode == 'fetch':
        fetch(args.tag, args.source, args.sha256, args.directory)
    else:
        native(args.directory.resolve(), args.source, args.sha256, args.output.resolve())


if __name__ == '__main__':
    main()
