"""Actual isolated dpkg removal/restoration; cached transport is a fixture.

Build-time authenticated APT downloads supply the exact installed packages.
The runtime has no network. This proves cache validation and real package
transactions, not a native App journey or the production network transfer.
"""
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
from unittest.mock import patch

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('package mutation fixture requires isolated Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import missing_git

real_apt = missing_git.Fixture.apt
real_download = missing_git.Fixture.download


def cached_download(self, package, version):
    # The only replaced boundary is network transport. The actual unprivileged
    # authenticated APT download/cache verification still executes normally.
    matches = list(Path('/fixture-archives').glob(package+'_*.deb'))
    assert len(matches) == 1, matches
    shutil.copyfile(matches[0], self.cache/matches[0].name)
    return real_download(self, package, version)


with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {
        'CANDIDATE_NATIVE_DISPOSABLE':'1', 'CANDIDATE_RUNNER_KIND':'github-hosted'}):
    root = Path(temporary)
    before = missing_git.installed(os.environ)
    with patch.object(missing_git.Fixture, 'download', cached_download):
        fixture = missing_git.Fixture(root/'cache', root, os.environ)
    try:
        fixture.remove()
        assert shutil.which('git') is None
        assert missing_git.installed(os.environ) == {
            name: version for name, version in before.items() if name not in fixture.removed}
        archive = fixture.archives[0]
        original = archive['path'].read_bytes()
        archive['path'].write_bytes(b'not the authenticated cached package')
        try:
            fixture.restore()
        except ValueError as error:
            assert 'archive changed' in str(error)
        else:
            raise AssertionError('tampered restore payload accepted')
        assert not fixture.restored and shutil.which('git') is None
        archive['path'].write_bytes(original)
        fixture.restore()
        assert fixture.restored and missing_git.installed(os.environ) == before
        assert hashlib.sha256(Path('/usr/bin/git').read_bytes()).hexdigest() == fixture.git_sha
        print('Actual Git/LFS removal+exact cached restoration PASS; unrelated packages preserved; tampered cache refused', flush=True)
    finally:
        fixture.restore()
    # An apt invocation can fail after it has removed packages. The fixture
    # marks ownership before invoking apt, so the enclosing failure cleanup
    # must restore the exact state even when remove() never returns normally.
    with patch.object(missing_git.Fixture, 'download', cached_download):
        partial = missing_git.Fixture(root/'partial-cache', root, os.environ)
    def remove_then_fail(self, arguments, seconds):
        result = real_apt(self, arguments, seconds)
        if arguments == ['--no-auto-remove', '-y', 'remove', 'git']:
            raise RuntimeError('injected failure after actual APT removal')
        return result
    try:
        with patch.object(missing_git.Fixture, 'apt', remove_then_fail):
            try:
                partial.remove()
            except RuntimeError as error:
                assert str(error) == 'injected failure after actual APT removal'
            else:
                raise AssertionError('partial removal failure did not propagate')
        assert partial.attempted_removal and not partial.restored and shutil.which('git') is None
    finally:
        partial.restore()
    assert partial.restored and missing_git.installed(os.environ) == before
    print('Actual removed Git restored after propagated partial-transaction failure PASS', flush=True)
    cache_paths = [fixture.cache, partial.cache]
    for cache in cache_paths:
        assert all(path.stat().st_uid == os.getuid() for path in [cache, *cache.rglob('*')])
print('Normal controller UID owns all cache files and temporary cleanup completed PASS', flush=True)
