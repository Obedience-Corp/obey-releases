"""Prepare reviewed native GUI helpers before starting the App under test."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys
import time

from verify_candidate import command


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class MacWindowTools:
    query_binary: Path
    quit_binary: Path
    identity: dict

    def checked_binary(self, name):
        path = self.query_binary if name == 'query' else self.quit_binary
        if path.is_symlink() or not path.is_file() or digest(path) != self.identity['helpers'][name]['binary_sha256']:
            raise ValueError('prepared macOS helper identity changed')
        return path

    def query(self, pid, environment):
        if type(pid) is not int or pid <= 0:
            raise ValueError('invalid owned macOS window PID')
        result = command([self.checked_binary('query'), str(pid)], environment, timeout=10, json_output=True)
        if not isinstance(result, list) or any(not isinstance(row, dict) or type(row.get('kCGWindowOwnerPID')) is not int or row.get('kCGWindowOwnerPID') != pid for row in result):
            raise ValueError('macOS helper returned a foreign or malformed window')
        return result

    def quit(self, pid, bundle, environment):
        if type(pid) is not int or pid <= 0 or not Path(bundle).is_absolute():
            raise ValueError('invalid owned macOS process/bundle')
        return command([self.checked_binary('quit'), str(pid), Path(bundle)], environment, timeout=15)


def prepare(work, output, environment):
    if (sys.platform != 'darwin' or environment.get('CANDIDATE_NATIVE_DISPOSABLE') != '1'
            or environment.get('CANDIDATE_RUNNER_KIND') != 'github-hosted'):
        raise RuntimeError('native macOS GUI helpers require a disposable hosted account')
    directory = work / 'mac-verifier-tools'
    if directory.exists() or directory.is_symlink():
        raise RuntimeError('refusing preexisting macOS verifier tools')
    destination = output / 'mac-window-tools.json'
    if destination.exists() or destination.is_symlink():
        raise RuntimeError('refusing existing macOS tool build evidence')
    directory.mkdir()
    compiler = Path(command(['xcrun', '--find', 'swiftc'], environment, timeout=30).strip())
    if not compiler.is_absolute() or not compiler.is_file(): raise ValueError('installed Swift compiler is missing')
    record = {'prepared_before_app_launch': True, 'compiler': str(compiler),
              'compiler_resolved_path': str(compiler.resolve()), 'compiler_sha256': digest(compiler),
              'compiler_version': command([compiler, '--version'], environment, timeout=30),
              'compile_timeout_seconds': 180, 'query_timeout_seconds': 10,
              'helpers': {}, 'complete': False}
    began = time.monotonic()
    try:
        for name, filename in (('query', 'query_owned_mac.swift'), ('quit', 'quit_owned_mac.swift')):
            source = Path(__file__).with_name(filename)
            binary = directory / ('owned-mac-' + name)
            row = {'source': filename, 'source_sha256': digest(source)}
            record['helpers'][name] = row
            command([compiler, '-module-cache-path', directory / 'module-cache', source, '-o', binary],
                    environment, timeout=180)
            if binary.is_symlink() or not binary.is_file():
                raise ValueError('Swift compilation did not produce the owned helper')
            row['binary_sha256'] = digest(binary)
        record['complete'] = True
        return MacWindowTools(directory / 'owned-mac-query', directory / 'owned-mac-quit', record)
    except BaseException as error:
        record['failure'] = str(error)
        raise
    finally:
        record['elapsed_seconds'] = time.monotonic() - began
        destination.write_text(json.dumps(record, indent=2) + '\n')
