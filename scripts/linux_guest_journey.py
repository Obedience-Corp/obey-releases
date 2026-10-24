"""Host-side transport for the real desktop App journey in the owned clean VM."""
import json
from pathlib import Path
import shlex
import tarfile
import time

ROOT = '/home/tester/fa0027-app-journey'


def copy(guest, source, destination, *, from_guest=False):
    from linux_guest import run
    arguments = ['scp', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                 '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={guest.known_hosts}',
                 '-i', guest.root / 'client', '-P', str(guest.port), '-r']
    remote = f'tester@127.0.0.1:'
    run([*arguments, remote + str(source) if from_guest else source,
         destination if from_guest else remote + str(destination)], timeout=600)


def prepare(guest, password, source, version, report, package='deb'):
    from app_upgrade_contract import release_identity
    release_identity(source, version)
    if package not in ('deb', 'appimage'):
        raise ValueError('invalid guest App package')
    guest.ssh('mkdir -m 700 ' + ROOT)
    bundle = guest.root / 'journey-scripts.tar'
    with tarfile.open(bundle, 'w') as archive:
        for file in sorted(Path(__file__).parent.iterdir()):
            if file.is_file() and file.suffix in ('.py', '.ps1', '.swift'):
                archive.add(file, arcname='scripts/' + file.name, recursive=False)
    copy(guest, bundle, ROOT + '/scripts.tar')
    guest.ssh('cd ' + ROOT + ' && tar -xf scripts.tar && rm scripts.tar && mkdir -m 700 evidence temporary')
    # Explicit observation tools; never install Git or ecosystem packages here.
    packages = ['minisign', 'xdotool', 'imagemagick', 'wmctrl', 'python3-gi',
                'gir1.2-atspi-2.0', 'at-spi2-core', 'gsettings-desktop-schemas',
                'libegl1', 'libegl-mesa0', 'libgles2', 'libgl1', 'libgl1-mesa-dri']
    guest.ssh('sudo -k -S -p "" timeout --signal=TERM --kill-after=15s 1200s apt-get install -y --no-install-recommends ' +
              ' '.join(packages), input=password + '\n', timeout=1245)
    from linux_guest import READBACK
    report['app_observation_baseline'] = json.loads(guest.ssh('python3 -c ' + shlex.quote(READBACK)).stdout)
    # Reuse the exact anonymous public inventory/digest validation. No GH token
    # or production/provider credential crosses the guest boundary.
    guest.ssh('cd ' + ROOT + ' && env CANDIDATE_RUNNER_KIND=github-hosted GITHUB_REPOSITORY=Obedience-Corp/obey-releases '
              'python3 scripts/verify_app_candidate.py --mode fetch-public --source ' + source +
              ' --version ' + version + ' --directory public', timeout=4200)
    config = json.dumps({'source': source, 'version': version, 'package': package})
    guest.ssh('umask 077; cat > ' + ROOT + '/config.json', input=config)
    guest.ssh('umask 077; cat > ' + ROOT + '/credential', input=password)
    runner = '''#!/bin/sh
exec /usr/bin/python3 -u ''' + ROOT + '''/scripts/linux_guest_app.py --root ''' + ROOT + ''' >> ''' + ROOT + '''/evidence/driver.log 2>&1
'''
    guest.ssh('umask 077; cat > ' + ROOT + '/run', input=runner)
    guest.ssh('chmod 700 ' + ROOT + '/run; mkdir -p /home/tester/.config/autostart')
    desktop = '[Desktop Entry]\nType=Application\nName=Festival disposable journey\nExec=' + ROOT + '/run\nTerminal=false\nOnlyShowIn=XFCE;\n'
    guest.ssh('umask 077; cat > /home/tester/.config/autostart/fa0027-journey.desktop', input=desktop)
    guest.ssh('printf install > ' + ROOT + '/stage')


def execute(guest, stage, output, report):
    if stage not in ('install', 'reboot'):
        raise ValueError('invalid guest App stage')
    guest.ssh('touch ' + ROOT + '/start')
    deadline = time.monotonic() + 2400
    while time.monotonic() < deadline:
        result = guest.ssh('cat ' + ROOT + '/evidence/' + stage + '-result.json', check=False)
        if result.returncode == 0:
            value = json.loads(result.stdout)
            report['app_' + stage + '_result'] = value
            if value.get('success') is not True:
                raise RuntimeError('actual guest App ' + stage + ' failed: ' + value.get('error', 'missing result'))
            return
        if guest.process.poll() is not None:
            raise RuntimeError('owned VM exited during App journey')
        time.sleep(5)
    raise TimeoutError('actual guest App ' + stage + ' did not complete')


def prepare_reboot(guest):
    guest.ssh('rm ' + ROOT + '/start; printf reboot > ' + ROOT + '/stage')


def retain(guest, output):
    # Copy only the explicit evidence subtree; private credential, source,
    # public binary cache, user HOME, disks and provisioning data are excluded.
    copy(guest, ROOT + '/evidence', output / 'app-journey', from_guest=True)
