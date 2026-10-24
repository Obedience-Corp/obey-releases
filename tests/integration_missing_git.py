"""Actual isolated package reconstruction, removal and exact file restoration."""
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


with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {
        'CANDIDATE_NATIVE_DISPOSABLE':'1', 'CANDIDATE_RUNNER_KIND':'github-hosted'}):
    root = Path(temporary)
    home = root/'home'; home.mkdir()
    os.environ['HOME'] = str(home)
    (home/'.gitconfig').write_text('[fixture]\n\tpreserve = foreign-config-sentinel\n')
    before = missing_git.installed(os.environ)
    fixture = missing_git.Fixture(root/'cache', root, os.environ)
    try:
        fixture.remove()
        assert shutil.which('git') is None
        assert missing_git.installed(os.environ) == {
            name: version for name, version in before.items() if name not in fixture.removed}
        archive = fixture.archives[0]
        original = archive['path'].read_bytes()
        archive['path'].write_bytes(b'not the verified rollback package')
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
        print('Actual Git/LFS removal+local rollback restoration PASS; package bytes/modes/owners/links and Git config preserved; tampered cache refused', flush=True)
    finally:
        fixture.restore()
    # An apt invocation can fail after it has removed packages. The fixture
    # marks ownership before invoking apt, so the enclosing failure cleanup
    # must restore the exact state even when remove() never returns normally.
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
