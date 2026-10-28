"""Real released Installer network fault/control; never claims App UI acceptance."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('actual transport control requires disposable Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from partial_install_proxy import PartialInstallProxy
from partial_setup import partial_readback
from verify_selected_components import BETA_PACKAGES, BETA_SUITE_VERSIONS, checked_receipts, checked_status

EXPECTED = {'aarch64': 'c662189c37186e7051bfab84d06d8533afc254323b94a3ec91aea374b2af9e12',
            'x86_64': 'ae68d564dd6b5ed7877161598ffdb413d4a1f71e4cc6f16976b69b81bd379199'}
source = Path(os.environ['PARTIAL_INSTALLER'])
assert hashlib.sha256(source.read_bytes()).hexdigest() == EXPECTED[platform.machine()]
with tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary);binary=root/'festival-app-installer';shutil.copyfile(source,binary);binary.chmod(0o755)
    os.chdir(root)  # Never let Git discover the read-only worktree's host-only .git path.
    home=root/'home';home.mkdir();managed=root/'managed';config=root/'obey.yaml'
    config.write_text('data_dir: '+json.dumps(str(root/'data'))+'\ngrpc:\n  socket: '+json.dumps(str(root/'daemon.sock'))+'\nnetwork:\n  enabled: false\nwatcher:\n  enabled: false\n')
    env=dict(os.environ,HOME=str(home),FESTIVAL_HOME=str(managed),OBEY_CONFIG=str(config),
             XDG_CONFIG_HOME=str(home/'.config'),XDG_DATA_HOME=str(home/'.local/share'))
    proxy=PartialInstallProxy(binary)
    proxy.bind(SimpleNamespace(pid=os.getpid(),poll=lambda:None))
    child_env=dict(env,HTTPS_PROXY=proxy.url,HTTP_PROXY=proxy.url,NO_PROXY='localhost,127.0.0.1')
    def install(target,expected=0):
        result=subprocess.run([str(binary),'install',target,'--json','--managed'],env=child_env,
                              capture_output=True,text=True,timeout=600)
        value=json.loads(result.stdout)
        print(json.dumps({'target':target,'exit':result.returncode,'envelope':value}),flush=True)
        assert (result.returncode==0) == (expected==0),result.stderr
        return value
    try:
        network=subprocess.run(['git','ls-remote','--heads','https://github.com/Obedience-Corp/marketplace.git'],
                               env=child_env,capture_output=True,text=True,timeout=60)
        print(json.dumps({'actual_git_transport_exit':network.returncode,'stderr':network.stderr}),flush=True)
        assert network.returncode==0
        install('festival');install('obey')
        failed=install('obedience-corp/camp-app',expected=1)
        assert failed['error']['code']=='E_ARTIFACT_DO',failed
        expected = {name: version for name, version in BETA_PACKAGES.items() if name != 'obedience-corp/camp-app'}
        tools = {name: (version, 'obedience-corp/festival') for name, version in BETA_SUITE_VERSIONS.items()}
        tools.update(obey=(BETA_PACKAGES['obedience-corp/obey'], 'obedience-corp/obey'), ob=('0.1.0', 'obedience-corp/obey'))
        before=partial_readback(binary,managed,env,expected=expected,tools_expected=tools)
        proxy.recover();install('obedience-corp/camp-app')
        after=checked_receipts(managed,packages=BETA_PACKAGES)
        assert [r for r in after['receipts'] if r['package_id']!='obedience-corp/camp-app']==before['receipts']['receipts']
        assert [r for r in after['files'] if r['receipt_pkg_id']!='obedience-corp/camp-app']==before['receipts']['files']
        for row in before['physical']:
            assert hashlib.sha256(Path(row['path']).read_bytes()).hexdigest()==row['sha256']
            assert Path(row['path']).stat().st_mtime_ns==row['mtime_ns']
        status=subprocess.run([str(binary),'status','--plugin','obedience-corp/camp-app','--json','--managed'],
                              env=env,capture_output=True,text=True,check=True,timeout=30)
        checked_status(json.loads(status.stdout),managed,packages=BETA_PACKAGES,suite_versions=BETA_SUITE_VERSIONS)
        assert not proxy.evidence()['ownership_errors']
        assert not any(r['outcome']=='denied' for r in proxy.evidence()['requests'])
        print(json.dumps({'actual_released_installer':'0.3.8','before_retry':before,
                          'proxy':proxy.evidence(),'real_transport_recovery':True,'app_ui_verified':False}),flush=True)
    finally:
        print(json.dumps({'final_proxy_evidence':proxy.evidence()}),flush=True)
        proxy.close()
        obey=managed/'bin/obey'
        if obey.exists():
            for args in [('stop',),('service','uninstall')]:
                subprocess.run([str(obey),*args],env=env,capture_output=True,timeout=30)
