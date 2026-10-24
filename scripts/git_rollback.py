"""Verify locally reconstructed package rollback bytes against installed files.

These are baseline backups, not original vendor-authenticated release archives.
No extraction is performed while validating the package filesystem tar.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

def digest(stream):
    value = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        value.update(chunk)
    return value.hexdigest()


def file_state(path, absent=False, directory_owners=()):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if absent:
            return {'kind': 'absent'}
        raise
    result = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    attributes = os.listxattr(path, follow_symlinks=False)
    if attributes:
        if not stat.S_ISDIR(info.st_mode) or not directory_owners:
            raise ValueError('rollback does not support extended attributes: ' + str(path))
        # This directory remains owned by installed packages outside removal.
        # Its attributes must survive in place; archives do not restore them.
        result['retained_owners'] = sorted(directory_owners)
        result['preserved_xattrs'] = {name: hashlib.sha256(os.getxattr(path, name, follow_symlinks=False)).hexdigest()
                                     for name in sorted(attributes)}
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


def retained_directory_owners(path, environment, retained_packages):
    from verify_candidate import command
    listing = command(['dpkg-query', '-S', path], environment)
    owners = set()
    for row in listing.splitlines():
        fields = row.rsplit(': ', 1)
        if len(fields) != 2 or fields[1] != path:
            raise ValueError('ambiguous shared-directory package ownership: ' + path)
        owners.update(fields[0].split(', '))
    retained = owners.intersection(retained_packages)
    if not retained:
        raise ValueError('attributed directory has no retained package owner: ' + path)
    return retained


def package_files(name, environment, retained_packages=()):
    from verify_candidate import command
    listing = command(['dpkg-query', '-L', name], environment)
    paths = [str(Path(line)) for line in listing.splitlines()]
    if not paths or len(paths) > 50000 or any(not Path(path).is_absolute() for path in paths):
        raise ValueError('invalid installed package file inventory')
    result = {}
    for path in sorted(set(paths)):
        owners = ()
        if stat.S_ISDIR(Path(path).lstat().st_mode) and os.listxattr(path, follow_symlinks=False):
            owners = retained_directory_owners(path, environment, retained_packages)
        result[path] = file_state(path, directory_owners=owners)
    return result


def config_files(environment):
    home = Path.home()
    config = Path(environment.get('XDG_CONFIG_HOME') or home/'.config')
    if not config.is_absolute():
        raise ValueError('Git config home is not absolute')
    result = {}
    for path in (Path('/etc/gitconfig'), home/'.gitconfig', config/'git/config'):
        for parent in path.parents:
            if parent.is_symlink():
                raise ValueError('Git configuration ancestor is a symlink: ' + str(parent))
        value = file_state(path, absent=True)
        if value['kind'] not in ('file', 'absent') or (value['kind'] == 'file' and path.stat().st_nlink != 1):
            raise ValueError('Git configuration must be a regular file with one link or absent: ' + str(path))
        result[str(path)] = value
    return result


def without_default_lfs(data):
    """Remove only one exact default LFS block; preserve every foreign byte."""
    header = b'[filter "lfs"]\n'
    if header not in data:
        return data
    if data.count(header) != 1:
        raise ValueError('ambiguous system Git LFS configuration')
    start = data.index(header)
    if start and data[start-1:start] != b'\n':
        raise ValueError('invalid system Git LFS section boundary')
    content = start + len(header)
    following = re.search(rb'(?m)^[ \t]*\[', data[content:])
    end = content + following.start() if following else len(data)
    lines = data[content:end].splitlines(keepends=True)
    expected = {b'\tclean = git-lfs clean -- %f\n', b'\tsmudge = git-lfs smudge -- %f\n',
                b'\tprocess = git-lfs filter-process\n', b'\trequired = true\n'}
    if len(lines) != 4 or set(lines) != expected:
        raise ValueError('system Git LFS block contains nondefault or ambiguous content')
    return data[:start] + data[end:]


def backup_system_config(cache, expected):
    path = Path('/etc/gitconfig')
    data = path.read_bytes() if expected['kind'] == 'file' else b''
    if len(data) > 1024 * 1024 or file_state(path, absent=True) != expected:
        raise ValueError('system Git configuration changed during backup')
    if expected['kind'] == 'file' and hashlib.sha256(data).hexdigest() != expected['sha256']:
        raise ValueError('system Git configuration backup differs from baseline')
    without_default_lfs(data)
    backup = cache/'system-gitconfig.original'
    with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(data)
    return backup


def restore_system_config(backup, before, observed, owner):
    """Privileged, fixed-path repair of a verified default-LFS rewrite only."""
    if (sys.platform != 'linux' or os.geteuid() != 0 or
            os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
            os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted'):
        raise RuntimeError('system Git configuration restore requires disposable hosted root helper')
    path = Path('/etc/gitconfig')
    if Path('/etc').is_symlink() or before['kind'] not in ('file', 'absent') or observed['kind'] != 'file':
        raise ValueError('unsupported system Git configuration restoration')
    with os.fdopen(os.open(backup, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 1024 * 1024):
            raise ValueError('system Git configuration backup is not a private owned file')
        original = stream.read(1024 * 1024 + 1)
        if len(original) > 1024 * 1024:
            raise ValueError('system Git configuration backup grew beyond its bound')
    if ((before['kind'] == 'absent' and original) or
            (before['kind'] == 'file' and hashlib.sha256(original).hexdigest() != before['sha256'])):
        raise ValueError('system Git configuration backup changed')
    with os.fdopen(os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK), 'r+b') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024 * 1024:
            raise ValueError('system Git configuration target is not a bounded regular file')
        current = stream.read(1024 * 1024 + 1)
        if len(current) > 1024 * 1024:
            raise ValueError('system Git configuration target grew beyond its bound')
        if (file_state(path) != observed or hashlib.sha256(current).hexdigest() != observed['sha256'] or
                (path.lstat().st_dev, path.lstat().st_ino) != (info.st_dev, info.st_ino)):
            raise ValueError('system Git configuration target changed before restoration')
        if without_default_lfs(original) != without_default_lfs(current):
            raise ValueError('system Git configuration has an unrelated change')
        if before['kind'] == 'absent':
            path.unlink()
        else:
            if any(observed[key] != before[key] for key in ('uid', 'gid', 'mode')):
                raise ValueError('system Git configuration ownership or permissions changed')
            stream.seek(0)
            stream.write(original)
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())
        if file_state(path, absent=True) != before:
            raise RuntimeError('system Git configuration did not restore exactly')


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
                if any('xattr' in key.lower() or '.acl' in key.lower() for key in member.pax_headers):
                    raise ValueError('rollback archive contains unsupported extended metadata')
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
        archive_expected = {}
        for path, value in expected.items():
            value = dict(value)
            if value['kind'] == 'directory' and value.get('retained_owners') and value.get('preserved_xattrs'):
                del value['retained_owners']
                del value['preserved_xattrs']
            archive_expected[path] = value
        if actual != archive_expected:
            changed = sorted(key for key in set(actual) | set(archive_expected)
                             if actual.get(key) != archive_expected.get(key))
            raise ValueError('rollback archive differs from installed file baseline: ' + repr(changed[:20]))


if __name__ == '__main__':
    if len(sys.argv) != 6 or sys.argv[1] != '--restore-system-config':
        raise SystemExit('expected fixed system Git configuration restoration arguments')
    restore_system_config(Path(sys.argv[2]), json.loads(sys.argv[3]), json.loads(sys.argv[4]), int(sys.argv[5]))
