"""Verify locally reconstructed package rollback bytes against installed files.

These are baseline backups, not original vendor-authenticated release archives.
No extraction is performed while validating the package filesystem tar.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import tempfile

from verify_candidate import command


def digest(stream):
    value = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        value.update(chunk)
    return value.hexdigest()


def file_state(path, absent=False):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if absent:
            return {'kind': 'absent'}
        raise
    if os.listxattr(path, follow_symlinks=False):
        raise ValueError('rollback does not support extended attributes: ' + str(path))
    result = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    if stat.S_ISREG(info.st_mode):
        with path.open('rb') as stream:
            result.update(kind='file', sha256=digest(stream))
    elif stat.S_ISDIR(info.st_mode):
        result.update(kind='directory')
    elif stat.S_ISLNK(info.st_mode):
        result.update(kind='symlink', target=os.readlink(path))
    else:
        raise ValueError('unsupported rollback package member: ' + str(path))
    return result


def package_files(name, environment):
    listing = command(['dpkg-query', '-L', name], environment)
    paths = [str(Path(line)) for line in listing.splitlines()]
    if not paths or len(paths) > 50000 or any(not Path(path).is_absolute() for path in paths):
        raise ValueError('invalid installed package file inventory')
    return {path: file_state(path) for path in sorted(set(paths))}


def config_files(environment):
    home = Path.home()
    config = Path(environment.get('XDG_CONFIG_HOME') or home/'.config')
    if not config.is_absolute():
        raise ValueError('Git config home is not absolute')
    return {str(path): file_state(path, absent=True)
            for path in (Path('/etc/gitconfig'), home/'.gitconfig', config/'git/config')}


def check_archive(archive, expected, environment):
    with tempfile.TemporaryFile() as stream:
        result = subprocess.run(['dpkg-deb', '--fsys-tarfile', str(archive)],
                                env=environment, stdout=stream, stderr=subprocess.PIPE, timeout=60)
        if result.returncode or stream.tell() > 512 * 1024 * 1024:
            raise ValueError('cannot inspect bounded rollback package filesystem')
        stream.seek(0)
        actual = {}
        with tarfile.open(fileobj=stream, mode='r:') as tar:
            for member in tar.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or len(actual) >= 50000:
                    raise ValueError('unsafe rollback archive member')
                key = '/' if str(path) == '.' else '/' + str(path)
                if key in actual:
                    raise ValueError('duplicate rollback archive member')
                value = {'mode': member.mode, 'uid': member.uid, 'gid': member.gid}
                if member.isfile() or member.islnk():
                    with tar.extractfile(member) as content:
                        value.update(kind='file', sha256=digest(content))
                elif member.isdir():
                    value.update(kind='directory')
                elif member.issym():
                    value.update(kind='symlink', target=member.linkname)
                else:
                    raise ValueError('unsupported rollback archive member')
                actual[key] = value
        if actual != expected:
            changed = sorted(key for key in set(actual) | set(expected) if actual.get(key) != expected.get(key))
            raise ValueError('rollback archive differs from installed file baseline: ' + repr(changed[:20]))
