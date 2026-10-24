"""Actual public daemon camp ingestion before exactly one session creation."""
import hashlib,json,os,platform,re,sqlite3,subprocess,sys,tarfile,tempfile,time
from contextlib import closing
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import service_recovery
from verify_selected_components import fetch,checked_bootstrap
from verify_candidate import checked_payloads
assert Path('/.dockerenv').exists() and os.getuid()==10001
arch={'aarch64':'arm64','x86_64':'x86_64'}[platform.machine()]
with tempfile.TemporaryDirectory() as temporary:
 root=Path(temporary);home=root/'home';home.mkdir();bin=root/'bin';bin.mkdir()
 env=dict(os.environ,HOME=str(home),XDG_CONFIG_HOME=str(home/'.config'),XDG_DATA_HOME=str(home/'.local/share'),XDG_STATE_HOME=str(home/'.local/state'),PATH=str(bin)+':/usr/bin:/bin')
 base='https://github.com/Obedience-Corp/obey-releases/releases/download/v0.2.3/'
 name='obey-0.2.3-linux-'+arch+'.tar.gz'; data=fetch(base+name); sha=checked_bootstrap(data,fetch(base+'checksums.txt'),name)
 archive=root/name;archive.write_bytes(data);obey=bin/'obey';obey.write_bytes(checked_payloads(archive,sha,False)['obey']);obey.chmod(0o755)
 name='festival-0.3.24-linux-'+arch+'.tar.gz';data=fetch('https://github.com/Obedience-Corp/festival/releases/download/v0.3.24/'+name)
 wanted={'arm64':'85638bd6073821d8082939ede4a97348c249c47737baf2b6af307e5450fff0df','x86_64':'e5c59774eb6d4f35ae8b9393a066c5153bee1451027417bfc25f2e4471bc88b5'}[arch]
 assert hashlib.sha256(data).hexdigest()==wanted
 archive=root/name;archive.write_bytes(data)
 with tarfile.open(archive,'r:gz') as tar:
  members=[m for m in tar.getmembers() if m.name=='camp'];assert len(members)==1 and members[0].isfile()
  camp=bin/'camp';camp.write_bytes(tar.extractfile(members[0]).read());camp.chmod(0o755)
 config=root/'daemon.yaml';sock=root/'daemon.sock';db=root/'data/daemon.db'
 config.write_text('data_dir: '+json.dumps(str(root/'data'))+'\ngrpc:\n  socket: '+json.dumps(str(sock))+'\nnetwork:\n  enabled: false\nproviders:\n  ollama:\n    type: ollama\n    enabled: true\n    base_url: http://127.0.0.1:9\n')
 env['OBEY_CONFIG']=str(config)
 def run(args):return subprocess.run([str(x) for x in args],env=env,cwd=root,capture_output=True,text=True,timeout=30)
 with (root/'daemon.log').open('w') as log:
  daemon=subprocess.Popen([obey,'serve','--foreground','--config',config,'--no-network','--no-firewall-setup'],env=env,cwd=root,stdout=log,stderr=subprocess.STDOUT)
  try:
   deadline=time.monotonic()+30
   while not sock.exists():
    if daemon.poll() is not None:raise RuntimeError('owned daemon startup failed before sessions: '+(root/'daemon.log').read_text()[-1000:])
    if time.monotonic()>deadline:raise RuntimeError('socket not ready')
    time.sleep(.05)
   fixture=root/'ready-camp';result=run([camp,'init',fixture,'--name','FA0027 ready ingestion probe','--description','Isolated actual runtime probe','--mission','Observe daemon campaign import','--no-git','--no-skills']);assert result.returncode==0,result.stderr
   entries=json.loads(run([camp,'list','--format','json']).stdout);id=next(x['id'] for x in entries if Path(x['path'])==fixture)
   listed=run([obey,'--socket',sock,'session','list','--campaign',id,'--json']);assert listed.returncode==0 and json.loads(listed.stdout)==[]
   initially_ready=service_recovery.campaign_readiness(db,id,fixture) is not None
   record={}; matched=service_recovery.wait_campaign(db,id,fixture,record)
   assert matched['campaign_id']==id and matched['canonical_path']==str(fixture.resolve())
   created=run([obey,'--socket',sock,'session','create','--campaign',id,'--provider','ollama','--model','smollm2:135m','--agent','release-continuity-proof','--mode','discussion','--workdir',fixture])
   assert created.returncode==0, 'one actual create failed after daemon campaign readiness (output withheld)'
   report={'scope':'actual public Camp import readiness only; no provider turn/App/systemd acceptance','public_obey_sha':sha,'public_suite_sha':wanted,'idle_uuid_sessions':[],'initial_daemon_camp_ready':initially_ready,'readiness':record,'one_create_exit':created.returncode,'provider_server_started':False,'real_turn_executed':False}
  finally:
   daemon.terminate();daemon.wait(timeout=30)
  report['owned_daemon_exited']=daemon.poll() is not None
  print(json.dumps(report,sort_keys=True),flush=True)
