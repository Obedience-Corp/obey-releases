"""Boot a verified Ubuntu desktop baseline, cold clone it and reboot the clone.

The guest starts without Git or Obedience tools. This prepares the native test
machine and real local login; it does not claim App or consumer installation proof.
Credentials, seed disks and guest disks are private and never uploaded.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import string
import subprocess
import tempfile
import time

import linux_kvm

IMAGE_ROOT = 'https://cloud-images.ubuntu.com/minimal/releases/noble/release-20261017/'
IMAGE_NAME = 'ubuntu-24.04-minimal-cloudimg-amd64.img'
IMAGE_SHA = 'b3296484e362ba2e713489a5de6225c719d9500962bde25d15f2f21e512c7658'
SIGNER = 'D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'
KEY_URL = 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x' + SIGNER


def run(arguments, *, timeout=120, input=None, check=True):
    result = subprocess.run([str(x) for x in arguments], input=input, text=True,
                            capture_output=True, timeout=timeout)
    if check and result.returncode:
        # Never print inputs: sudo's private fixture password travels on stdin.
        raise RuntimeError(f'{Path(arguments[0]).name} exited {result.returncode}: {result.stderr[-4000:]}')
    return result


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def download(url, destination, limit):
    run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
         '--proto-redir', '=https', '--max-time', '600', '--max-filesize', str(limit),
         '--output', destination, url], timeout=610)


def image(root, report):
    keydir = root / 'keyring'; keydir.mkdir(mode=0o700)
    download(KEY_URL, root / 'cloud.asc', 100_000)
    run(['gpg', '--homedir', keydir, '--batch', '--import', root / 'cloud.asc'])
    keys = run(['gpg', '--homedir', keydir, '--batch', '--with-colons', '--fingerprint']).stdout
    if SIGNER not in [row.split(':')[9] for row in keys.splitlines() if row.startswith('fpr:')]:
        raise ValueError('downloaded Ubuntu cloud signing key fingerprint mismatch')
    for name in ('SHA256SUMS', 'SHA256SUMS.gpg'):
        download(IMAGE_ROOT + name, root / name, 100_000)
    signature = run(['gpg', '--homedir', keydir, '--batch', '--status-fd', '1', '--verify',
                     root / 'SHA256SUMS.gpg', root / 'SHA256SUMS'])
    if not any(row.startswith('[GNUPG:] VALIDSIG ' + SIGNER + ' ') for row in signature.stdout.splitlines()):
        raise ValueError('checksum manifest lacks the pinned Ubuntu cloud signature')
    expected = IMAGE_SHA + ' *' + IMAGE_NAME
    if (root / 'SHA256SUMS').read_text().splitlines().count(expected) != 1:
        raise ValueError('signed manifest does not contain the pinned image exactly once')
    destination = root / IMAGE_NAME
    download(IMAGE_ROOT + IMAGE_NAME, destination, 400_000_000)
    if digest(destination) != IMAGE_SHA:
        raise ValueError('Ubuntu cloud image digest mismatch')
    info = json.loads(run(['qemu-img', 'info', '--output=json', destination]).stdout)
    if info.get('format') != 'qcow2' or info.get('backing-filename'):
        raise ValueError('expected a standalone QCOW2 source image')
    report['image'] = {'url': IMAGE_ROOT + IMAGE_NAME, 'sha256': IMAGE_SHA,
                       'signer': SIGNER, 'signature_verified': True, 'bytes': destination.stat().st_size,
                       'signature_status': signature.stdout, 'format': info['format']}
    return destination


def credentials(root, password):
    for name in ('client', 'host'):
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', root / name])
    password_hash = run(['openssl', 'passwd', '-6', '-stdin'], input=password + '\n').stdout.strip()
    document = {
        'hostname': 'festival-clean-linux', 'manage_etc_hosts': True,
        'disable_root': True, 'ssh_pwauth': False, 'ssh_deletekeys': True,
        'ssh_keys': {'ed25519_private': (root / 'host').read_text(),
                     'ed25519_public': (root / 'host.pub').read_text().strip()},
        'users': [{'name': 'tester', 'shell': '/bin/bash', 'groups': ['sudo'],
                   'sudo': ['ALL=(ALL) ALL'], 'lock_passwd': False, 'passwd': password_hash,
                   'ssh_authorized_keys': [(root / 'client.pub').read_text().strip()]}],
        'package_update': True, 'package_upgrade': False,
        'packages': ['xorg', 'xfce4', 'lightdm', 'lightdm-gtk-greeter', 'dbus-x11', 'policykit-1-gnome'],
        'runcmd': [['systemctl', 'set-default', 'graphical.target'],
                   ['systemctl', 'start', 'lightdm']],
    }
    (root / 'user-data').write_text('#cloud-config\n' + json.dumps(document))
    (root / 'meta-data').write_text('instance-id: fa0027-clean-linux-baseline\n')
    run(['cloud-localds', root / 'seed.img', root / 'user-data', root / 'meta-data'])


READBACK = r'''
import hashlib,json,os,pathlib,shutil,subprocess
home=pathlib.Path.home()
packages=subprocess.check_output(['dpkg-query','-W','-f','${Package}\t${Version}\n'],text=True)
tools={name:shutil.which(name) for name in ('git','camp','fest','obey','ob','camp-app','festival')}
state={name:(home/name).exists() for name in ('.obey','.local/share/obey','.config/obey','.config/camp','.config/fest')}
assert os.getuid()!=0
assert not any(tools.values()),tools
assert not any(state.values()),state
assert not any(row.split('\t')[0] in ('git','git-lfs') for row in packages.splitlines())
sudo=subprocess.run(['sudo','-n','true'],capture_output=True)
assert sudo.returncode!=0,'test user unexpectedly has passwordless sudo'
desktop=subprocess.check_output(['systemctl','is-active','lightdm'],text=True).strip()
assert desktop=='active',desktop
print(json.dumps({'uid':os.getuid(),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'os_release':pathlib.Path('/etc/os-release').read_text(),'tools':tools,'ecosystem_state':state,
 'passwordless_sudo':False,'display_manager':desktop,'packages':packages,
 'package_sha256':hashlib.sha256(packages.encode()).hexdigest()}))
'''


class Guest:
    def __init__(self, root, disk, variables, seed, name):
        self.root, self.name = root, name
        self.process = None
        self.error_log = None
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        self.qmp = root / (name + '.qmp')
        self.known_hosts = root / (name + '.known_hosts')
        self.known_hosts.write_text(f'[127.0.0.1]:{self.port} ' + (root / 'host.pub').read_text())
        self.error_log = (root / (name + '-qemu.log')).open('w')
        try:
            self.process = subprocess.Popen([
                'qemu-system-x86_64', '-machine', 'q35,accel=kvm', '-cpu', 'host',
                '-m', '4096', '-smp', '2', '-display', 'none', '-vga', 'virtio',
                '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                '-drive', f'if=pflash,format=raw,file={variables}',
                '-drive', f'if=virtio,format=qcow2,file={disk}',
                '-drive', f'if=virtio,format=raw,readonly=on,file={seed}',
                '-netdev', f'user,id=n0,hostfwd=tcp:127.0.0.1:{self.port}-:22',
                '-device', 'virtio-net-pci,netdev=n0', '-device', 'virtio-rng-pci',
                '-serial', f'file:{root / (name + "-serial.log")}', '-monitor', 'none',
                '-qmp', f'unix:{self.qmp},server=on,wait=off',
            ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.error_log)
        except BaseException:
            self.error_log.close()
            raise

    def ssh(self, command, *, timeout=30, input=None, check=True):
        return run(['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                    '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={self.known_hosts}',
                    '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
                    '-i', self.root / 'client', '-p', str(self.port), 'tester@127.0.0.1', command],
                   timeout=timeout, input=input, check=check)

    def wait(self, old_boot=None):
        deadline = time.monotonic() + 600
        last_error = ''
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('owned QEMU exited before guest readiness: ' +
                                   (self.root / (self.name + '-qemu.log')).read_text()[-2000:])
            try:
                result = self.ssh('cat /proc/sys/kernel/random/boot_id', timeout=15, check=False)
                if result.returncode == 0 and (old_boot is None or result.stdout.strip() != old_boot):
                    self.ssh('cloud-init status --wait', timeout=900)
                    return json.loads(self.ssh('python3 -c ' + shlex.quote(READBACK)).stdout)
                last_error = result.stderr[-1000:]
            except subprocess.TimeoutExpired:
                last_error = 'SSH connection timed out'
            time.sleep(3)
        raise TimeoutError('guest readiness timed out: ' + last_error)

    def qmp_commands(self, commands, delay=0):
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(15)
            connection.connect(str(self.qmp))
            with connection.makefile('rwb') as stream:
                json.loads(stream.readline())
                for command in [{'execute': 'qmp_capabilities'}, *commands]:
                    stream.write(json.dumps(command).encode() + b'\n'); stream.flush()
                    for _ in range(100):
                        response = json.loads(stream.readline())
                        if 'error' in response:
                            raise RuntimeError('owned QMP command failed: ' + str(response['error']))
                        if 'return' in response:
                            break
                    else:
                        raise RuntimeError('owned QMP command did not acknowledge')
                    if delay:
                        time.sleep(delay)

    def screenshot(self, destination):
        self.qmp_commands([{'execute': 'screendump', 'arguments': {'filename': str(destination.with_suffix('.ppm'))}}])
        from PIL import Image
        with Image.open(destination.with_suffix('.ppm')) as frame:
            frame.save(destination)
        destination.with_suffix('.ppm').unlink()

    def login(self, password):
        # The qualified baseline's greeter has tester selected and the empty
        # password field focused. Use its real keyboard authentication, never
        # autologin, a new display server or an SSH-created graphical session.
        if not password or any(letter not in string.ascii_lowercase + string.digits for letter in password):
            raise ValueError('unexpected fixture keyboard alphabet')
        script = Path(__file__).with_name('linux_guest_session.py').read_text()
        if json.loads(self.ssh('python3 -', input=script).stdout) is not None:
            raise RuntimeError('refusing to type a password into an already logged-in desktop')
        if json.loads(self.ssh('python3 - --greeter', input=script).stdout) is not True:
            raise RuntimeError('password input requires the current active LightDM greeter seat')
        def key(values):
            return {'execute': 'send-key', 'arguments': {
                'keys': [{'type': 'qcode', 'data': value} for value in values], 'hold-time': 50}}
        self.qmp_commands([key(['ctrl', 'a']), *[key([letter]) for letter in password], key(['ret'])], delay=.1)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            state = json.loads(self.ssh('python3 -', input=script).stdout)
            if state is not None:
                return state
            time.sleep(1)
        raise TimeoutError('normal LightDM login did not produce an active local Xfce session')

    def capture_desktop(self, output, stem, authenticated):
        script = Path(__file__).with_name('linux_guest_session.py').read_text()
        frames = []
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            state = json.loads(self.ssh('python3 -', input=script).stdout)
            if (state is None or state['session'] != authenticated['session']
                    or state['process_identity'] != authenticated['process_identity']):
                raise RuntimeError('authenticated local desktop changed before capture')
            if state['desktop_ready']:
                destination = output / f'{stem}-{len(frames) + 1:02}.png'
                self.screenshot(destination)
                from PIL import Image
                with Image.open(destination) as frame:
                    # This only rejects blank scanout. Actual desktop identity
                    # comes from the mapped windows above and independent review.
                    nonuniform = any(low != high for low, high in frame.convert('RGB').getextrema())
                frames.append({'file': destination.name, 'nonuniform': nonuniform})
                if nonuniform:
                    after = json.loads(self.ssh('python3 -', input=script).stdout)
                    if (after is None or after['session'] != state['session']
                            or after['process_identity'] != state['process_identity']):
                        raise RuntimeError('authenticated desktop changed during frame capture')
                    unchanged = after['desktop_ready'] and after['desktop_windows'] == state['desktop_windows']
                    frames[-1]['desktop_identity_unchanged'] = unchanged
                    if unchanged:
                        return {'session_readback': after, 'frames': frames, 'selected': destination.name}
            time.sleep(1)
        # Authentication has succeeded; this is a safe diagnostic of desktop
        # startup, not a capture after failed password entry.
        self.screenshot(output / (stem + '-not-ready.png'))
        raise TimeoutError('authenticated desktop did not expose painted desktop/panel windows')

    def power(self, action, password):
        if action not in ('poweroff', 'reboot'):
            raise ValueError('unsupported guest power action')
        result = self.ssh('sudo -S -p "" /sbin/' + action, input=password + '\n', check=False)
        if result.returncode not in (0, 255):
            raise RuntimeError('guest power action failed: ' + result.stderr[-1000:])
        if action == 'poweroff':
            self.process.wait(timeout=90)
            if self.process.returncode != 0:
                raise RuntimeError('guest did not shut down cleanly')

    def close(self):
        forced = False
        if self.process is not None and self.process.poll() is None:
            forced = True
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=15)
        if self.error_log is not None:
            self.error_log.close()
        return {'owned_process_stopped': self.process is None or self.process.poll() is not None,
                'forced_stop': forced}


def prove(output, report):
    linux_kvm.probe(report.setdefault('kvm', {}))
    output.mkdir(parents=True, exist_ok=False)
    report.update(guest_baseline_verified=False, guest_clone_verified=False,
                  guest_reboot_verified=False, graphical_login_verified=False,
                  app_first_use_verified=False, consumer_trust_verified=False,
                  baseline_kind='Ubuntu minimal cloud image plus Xfce desktop; normal password sudo',
                  host_shares=False, secrets_uploaded=False)
    report['host_tools'] = run(['dpkg-query', '-W', '-f', '${Package}\t${Version}\n',
                                'qemu-system-x86', 'qemu-utils', 'ovmf', 'cloud-image-utils']).stdout
    guest = None
    with tempfile.TemporaryDirectory(prefix='clean-linux-', dir=os.environ['RUNNER_TEMP']) as temporary:
        root = Path(temporary)
        try:
            source = image(root, report)
            for name in ('cloud.asc', 'SHA256SUMS', 'SHA256SUMS.gpg'):
                shutil.copyfile(root / name, output / name)
            password = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(32))
            credentials(root, password)
            disk, variables = root / 'baseline.qcow2', root / 'baseline-vars.fd'
            run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', source, disk, '24G'])
            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
            guest = Guest(root, disk, variables, root / 'seed.img', 'baseline')
            report['baseline'] = guest.wait()
            guest.screenshot(output / 'baseline-desktop.png')
            guest.power('poweroff', password)
            report['baseline_cleanup'] = guest.close(); guest = None
            baseline_hash = digest(disk)
            variables_hash = digest(variables)
            report['guest_baseline_verified'] = True
            clone, clone_variables = root / 'clone.qcow2', root / 'clone-vars.fd'
            run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', disk, clone])
            shutil.copyfile(variables, clone_variables)
            guest = Guest(root, clone, clone_variables, root / 'seed.img', 'clone')
            report['clone'] = guest.wait(old_boot=report['baseline']['boot_id'])
            guest.screenshot(output / 'clone-desktop.png')
            if report['clone']['package_sha256'] != report['baseline']['package_sha256']:
                raise ValueError('cold clone changed the baseline package inventory')
            report['guest_clone_verified'] = True
            report['clone_login'] = guest.login(password)
            report['clone_desktop_capture'] = guest.capture_desktop(output, 'clone-logged-in', report['clone_login'])
            guest.power('reboot', password)
            report['reboot'] = guest.wait(old_boot=report['clone']['boot_id'])
            guest.screenshot(output / 'reboot-desktop.png')
            if report['reboot']['package_sha256'] != report['clone']['package_sha256']:
                raise ValueError('reboot changed the baseline package inventory')
            report['reboot_login'] = guest.login(password)
            report['reboot_desktop_capture'] = guest.capture_desktop(output, 'reboot-logged-in', report['reboot_login'])
            guest.power('poweroff', password)
            report['clone_cleanup'] = guest.close(); guest = None
            if digest(disk) != baseline_hash or digest(variables) != variables_hash:
                raise ValueError('clone execution modified the powered-off baseline')
            report.update(guest_reboot_verified=True, graphical_login_verified=True, baseline_unchanged=True)
        finally:
            if guest is not None:
                report['failure_cleanup'] = guest.close()
            # Serial logs/configuration can contain provisioning details. Retain
            # only QEMU diagnostics here; never export seed, disks, keys or config.
            for name in ('baseline', 'clone'):
                log = root / (name + '-qemu.log')
                if log.exists():
                    shutil.copyfile(log, output / (name + '-qemu.log'))
    report['private_fixture_removed'] = not root.exists()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'schema': 'linux-clean-guest/v1'}
    try:
        prove(args.output, report)
    except Exception as error:
        report['failure'] = str(error)
        raise
    finally:
        # The caller owns this output directory; do not overwrite a preexisting
        # location on guard failure. All private provisioning data stays elsewhere.
        if args.output.is_dir() and 'baseline_kind' in report:
            (args.output / 'proof.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
