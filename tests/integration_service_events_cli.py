"""Actual public Obey parser control for the exact shared lifecycle argv.

No daemon/session/provider is started. --help isolates argument parsing; the
subsequent native journey is required for event JSON/lifecycle acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import active_provider
import active_session
from verify_candidate import checked_payloads
from verify_selected_components import checked_bootstrap, fetch


def main():
    active_provider.require_isolation()
    target = {'aarch64': 'linux-arm64', 'x86_64': 'linux-x86_64'}[platform.machine()]
    name = 'obey-0.2.3-'+target+'.tar.gz'
    base = 'https://github.com/Obedience-Corp/obey-releases/releases/download/v0.2.3/'
    archive_data, checksums = fetch(base+name), fetch(base+'checksums.txt')
    digest = checked_bootstrap(archive_data, checksums, name)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        archive = root/name; archive.write_bytes(archive_data)
        payload = checked_payloads(archive, digest, False)
        binary = root/'obey'; binary.write_bytes(payload['obey']); binary.chmod(0o755)
        env = dict(os.environ, HOME=str(root), XDG_CONFIG_HOME=str(root/'config'),
                   XDG_DATA_HOME=str(root/'data'), XDG_STATE_HOME=str(root/'state'))
        version = subprocess.run([binary, 'version', '--json'], env=env, capture_output=True, text=True, check=True)
        if json.loads(version.stdout).get('version') != '0.2.3':
            raise ValueError('public CLI version differs')
        client = active_session.SessionClient()
        client.obey, client.environment = binary, env
        client.fixture = {'camp_id': '00000000-0000-0000-0000-000000000001'}
        # Capture the exact argv produced by the real shared helper. Only append
        # --help to avoid dialing a daemon; no mocked Installer/session success.
        with patch.object(active_session, 'quiet', return_value=None) as capture:
            client.lifecycle_events('00000000-0000-0000-0000-000000000002')
        argv = capture.call_args.args[0]
        correct = subprocess.run([*argv, '--help'], env=env, capture_output=True, text=True)
        wrong = subprocess.run([('--kinds' if value == '--kind' else value) for value in argv]+['--help'],
                               env=env, capture_output=True, text=True)
        if correct.returncode or '--kind' not in correct.stdout or not wrong.returncode or 'unknown flag: --kinds' not in wrong.stderr:
            raise ValueError('actual public CLI did not accept exact helper argv and reject original typo')
        print(json.dumps({'scope': 'released CLI parsing only; no daemon/provider/event execution',
            'version': '0.2.3', 'target': target, 'archive_sha256': digest, 'archive_bytes': len(archive_data),
            'executable_sha256': hashlib.sha256(payload['obey']).hexdigest(),
            'shared_helper_singular_kind_exit': correct.returncode, 'original_plural_kind_exit': wrong.returncode,
            'original_plural_kind_unknown_flag': True, 'help_sha256': hashlib.sha256(correct.stdout.encode()).hexdigest()}, sort_keys=True))


if __name__ == '__main__':
    main()
