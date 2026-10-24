"""Task-owned CPU Ollama for the disposable native live-session journey."""
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import platform
import signal
import socket
import subprocess
import tarfile
import time
import urllib.error
import urllib.request

VERSION = '0.40.10'
MODEL = 'smollm2:135m'
MODEL_SHA = '9077fe9d2ae1a4a41a868836b56b8163731a8fe16621397028c2c76f838c6907'
RUNTIMES = {
    'x86_64': ('amd64', '1e8ad2d2a394efdd235bee74deec237badd95142ffba77588140ab2a9ecec227', 1509264197),
    'aarch64': ('arm64', '57dca26f51efc050112b733a65dea6f6c8e68da7a2946afd7c1eb8834d9eeb92', 1564567595),
}


def require_isolation():
    container = os.environ.get('CANDIDATE_TEST_CONTAINER') == '1' and Path('/.dockerenv').exists()
    native = os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') == '1' and os.environ.get('CANDIDATE_RUNNER_KIND') == 'github-hosted'
    if platform.system() != 'Linux' or platform.machine() not in RUNTIMES or not (container or native):
        raise RuntimeError('CPU provider requires an explicitly disposable Linux environment')


def extract_cpu(archive, destination, digest, size):
    with Path(archive).open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != digest or Path(archive).stat().st_size != size:
        raise ValueError('provider runtime differs from pinned official release')
    destination.mkdir()
    decoder = subprocess.Popen(['zstd', '-d', '-c', str(archive)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=decoder.stdout, mode='r|') as source:
            for member in source:
                name = PurePosixPath(member.name)
                if member.name == 'bin/ollama' or (name.parts[:2] == ('lib', 'ollama') and len(name.parts) == 3):
                    if member.isfile() or member.issym():
                        source.extract(member, destination, filter='data')
        while decoder.stdout.read(1024 * 1024):
            pass
        decoder.stdout.close()
        if decoder.wait(timeout=30):
            raise RuntimeError('provider archive decompression failed')
    finally:
        if decoder.poll() is None:
            decoder.terminate()
            decoder.wait(timeout=30)
    if not (destination / 'bin/ollama').is_file():
        raise ValueError('provider runtime has no executable')


class Provider:
    def __init__(self, root, environment, report):
        require_isolation()
        self.root, self.environment, self.report = Path(root), dict(environment), report
        self.process = self.log = None
        self.endpoint = None

    def get(self, route):
        with urllib.request.urlopen(self.endpoint + route, timeout=10) as response:
            return json.load(response)

    def start(self, archive=None):
        from app_upgrade_contract import anonymous_download
        self.root.mkdir()
        architecture, digest, size = RUNTIMES[platform.machine()]
        url = f'https://github.com/ollama/ollama/releases/download/v{VERSION}/ollama-linux-{architecture}.tar.zst'
        if archive is None:
            archive = self.root / 'runtime.tar.zst'
            anonymous_download(url, archive, size)
        extract_cpu(archive, self.root / 'runtime', digest, size)
        self.report.update(runtime_url=url, runtime_sha256=digest, runtime_bytes=size,
                           model=MODEL, model_digest=MODEL_SHA, host_provider_used=False,
                           provider_output_retained=False)
        home = self.root / 'home'; home.mkdir()
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        self.endpoint = f'http://127.0.0.1:{self.port}'
        env = {key: value for key, value in self.environment.items() if not key.startswith('OLLAMA_')}
        env.update(HOME=str(home), OLLAMA_HOST=self.endpoint, OLLAMA_MODELS=str(self.root / 'models'),
                   OLLAMA_NO_CLOUD='1', OLLAMA_NUM_PARALLEL='1', OLLAMA_CONTEXT_LENGTH='4096')
        for name, suffix in [('XDG_CONFIG_HOME', '.config'), ('XDG_DATA_HOME', '.local/share'), ('XDG_STATE_HOME', '.local/state')]:
            env[name] = str(home / suffix)
        binary = self.root / 'runtime/bin/ollama'
        self.log = (self.root / 'provider.log').open('w')
        self.process = subprocess.Popen([binary, 'serve'], env=env, stdout=self.log,
                                        stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 45
        while True:
            if self.process.poll() is not None:
                raise RuntimeError('owned CPU provider exited before readiness')
            try:
                version = self.get('/api/version')
                break
            except (urllib.error.URLError, TimeoutError, http.client.RemoteDisconnected):
                if time.monotonic() >= deadline:
                    raise RuntimeError('owned CPU provider readiness timeout')
                time.sleep(.2)
        if version != {'version': VERSION}:
            raise ValueError('owned CPU provider reports unexpected runtime version')
        result = subprocess.run([binary, 'pull', MODEL], env=env, capture_output=True, timeout=300)
        if result.returncode:
            raise RuntimeError('owned CPU provider could not pull the official model')
        models = [item for item in self.get('/api/tags')['models'] if item.get('name') == MODEL]
        if len(models) != 1 or models[0].get('digest') != MODEL_SHA:
            raise ValueError('provider model differs from pinned input')
        self.report['runtime_version'] = VERSION

    def check_cpu(self):
        if self.process.poll() is not None:
            raise RuntimeError('owned provider exited during live session')
        models = [item for item in self.get('/api/ps')['models'] if item.get('name') == MODEL]
        if len(models) != 1 or models[0].get('size_vram') != 0:
            raise ValueError('real inference did not use the qualified CPU-only model')
        self.report['cpu_only'] = True

    def close(self):
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    # This session/group was created by this fixture alone.
                    os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=30)
                with socket.socket() as probe:
                    probe.settimeout(1)
                    if probe.connect_ex(('127.0.0.1', self.port)) == 0:
                        raise RuntimeError('owned provider endpoint remains live after cleanup')
            self.report['owned_provider_exited'] = True
        finally:
            if self.log is not None:
                self.log.close()
