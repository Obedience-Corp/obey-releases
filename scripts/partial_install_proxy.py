"""TLS-preserving, process-attributed companion download fault on disposable Linux."""
import os
from pathlib import Path
import socket
import threading

from owned_update_proxy import PUBLIC_RELEASE_TARGETS, UpdateProxy

ASSET_HOSTS = frozenset({'release-assets.githubusercontent.com', 'objects.githubusercontent.com'})


class ExitedProcess(RuntimeError):
    pass


def process(pid, proc=Path('/proc')):
    directory = proc / str(pid)
    raw = (directory / 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    if fields[0] in ('Z', 'X'):
        raise ExitedProcess('request process has exited')
    return {'pid': pid, 'parent': int(fields[1]), 'birth': int(fields[19]),
            'uid': directory.stat().st_uid}


def ancestor_chain(pid, entries, root):
    """Reject PID reuse at every parent edge, not just relative to the root."""
    chain, seen = [], set()
    while pid not in seen and pid in entries:
        seen.add(pid)
        row = entries[pid]
        chain.append(row)
        if pid == root['pid']:
            return chain if row == root else None
        parent = entries.get(row['parent'])
        if parent is None or parent['birth'] > row['birth'] or parent['uid'] != row['uid']:
            return None
        pid = parent['pid']
    return None


def peer_inode(peer, server_port, proc=Path('/proc')):
    if peer[0] != '127.0.0.1':
        raise RuntimeError('transport peer is not loopback')
    address = socket.inet_aton('127.0.0.1')[::-1].hex().upper()
    local = f'{address}:{peer[1]:04X}'
    remote = f'{address}:{server_port:04X}'
    raw = (proc / 'net/tcp').read_text()
    if len(raw) > 1024 * 1024:
        raise RuntimeError('TCP ownership table exceeds fixture bound')
    matches = [row.split()[9] for row in raw.splitlines()[1:]
               if len(row.split()) > 9 and row.split()[1:4] == [local, remote, '01']]
    if len(matches) != 1 or not matches[0].isdecimal() or int(matches[0]) <= 0:
        raise RuntimeError('transport peer socket is absent or ambiguous')
    return int(matches[0])


def request_owner(peer, server_port, root, installer, proc=Path('/proc')):
    inode = peer_inode(peer, server_port, proc)
    entries = {}
    directories = [p for p in proc.iterdir() if p.name.isdecimal()]
    if len(directories) > 16384:
        raise RuntimeError('process table exceeds fixture bound')
    for directory in directories:
        try:
            row = process(int(directory.name), proc)
            if row['uid'] == root['uid']:
                entries[row['pid']] = row
        except (FileNotFoundError, ProcessLookupError, ExitedProcess):
            continue
    if entries.get(root['pid']) != root:
        raise RuntimeError(f"owned App generation changed: expected {root}, observed {entries.get(root['pid'])}")
    found, budget = [], 65536
    for pid in entries:
        chain = ancestor_chain(pid, entries, root)
        if chain is None:
            continue
        try:
            # Release artifact HTTP is performed directly by the Go Installer.
            # Do not inspect WebKit sandbox descriptors or infer their ownership.
            try:
                if not (proc / str(pid) / 'exe').samefile(installer):
                    continue
            except PermissionError:
                continue
            descriptors = list((proc / str(pid) / 'fd').iterdir())
            budget -= len(descriptors)
            if budget < 0:
                raise RuntimeError('owned descriptor scan exceeds fixture bound')
            sockets = []
            for fd in descriptors:
                try:
                    sockets.append(os.readlink(fd))
                except FileNotFoundError:
                    continue
            if f'socket:[{inode}]' not in sockets:
                continue
            for row in chain:
                if process(row['pid'], proc) != row:
                    raise RuntimeError('request ancestry changed during ownership readback')
            arguments = (proc / str(pid) / 'cmdline').read_bytes()
            if len(arguments) > 16384:
                raise RuntimeError('request command line exceeds fixture bound')
            args = arguments.split(b'\0')
            if (len(args) != 6 or args[:2] != [os.fsencode(installer), b'install'] or
                    args[2] not in (b'festival', b'obey', b'obedience-corp/camp-app') or
                    args[3:] != [b'--json', b'--managed', b'']):
                raise RuntimeError('artifact socket is not a known selected-package install invocation')
            companion = args[2] == b'obedience-corp/camp-app'
            for row in chain:
                if process(row['pid'], proc) != row:
                    raise RuntimeError('request ancestry changed after command inspection')
            found.append({'pid': pid, 'birth': entries[pid]['birth'],
                          'companion_install': companion,
                          'ancestry': [{'pid': row['pid'], 'birth': row['birth']} for row in chain]})
        except (FileNotFoundError, ProcessLookupError):
            continue
    if len(found) != 1:
        raise RuntimeError('socket must belong to exactly one live owned App descendant')
    return found[0]


class PartialInstallProxy(UpdateProxy):
    def __init__(self, installer):
        self.installer = Path(installer)
        self.root = None
        self.root_ready = threading.Event()
        self.recovered = False
        self.attributions = []
        self.ownership_errors = []
        super().__init__(PUBLIC_RELEASE_TARGETS)
        self.allow_release_tunnels()

    def bind(self, app):
        self.root = process(app.pid)
        if self.root['uid'] != os.getuid() or app.poll() is not None:
            raise RuntimeError('transport root must be the live same-UID App')
        self.root_ready.set()

    def _allow_request(self, target, peer):
        if not super()._allow_request(target, peer):
            return False
        if target[0] not in ASSET_HOSTS:
            return True
        try:
            if not self.root_ready.wait(timeout=10):
                raise RuntimeError('owned App root was not bound before transport')
            owner = request_owner(peer, self._server.server_port, self.root, self.installer)
            with self._lock:
                blocked = owner['companion_install'] and not self.recovered
                if len(self.attributions) >= 100:
                    raise RuntimeError('request attribution budget exceeded')
                self.attributions.append(dict(owner, host=target[0], blocked=blocked))
                return not blocked
        except (OSError, ValueError, RuntimeError, IndexError) as error:
            with self._lock:
                self.ownership_errors.append(str(error))
            return False

    def recover(self):
        with self._lock:
            if (self.ownership_errors or not any(row['blocked'] for row in self.attributions) or
                    any(row['outcome'] == 'denied' for row in self._requests)):
                raise RuntimeError('targeted fault was not proved with exact ownership')
            self.recovered = True

    def evidence(self):
        with self._lock:
            return dict(self.snapshot(), attributions=list(self.attributions),
                        ownership_errors=list(self.ownership_errors), recovered=self.recovered)
