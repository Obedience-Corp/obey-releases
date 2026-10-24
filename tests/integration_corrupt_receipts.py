"""Actual Windows SQLite/held-file rollback and live Installer refusal control."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from corrupt_receipts import Fixture, quiescent
from verify_selected_components import PACKAGES
if (os.name!='nt' or os.environ.get('CANDIDATE_NATIVE_DISPOSABLE')!='1' or
        os.environ.get('CANDIDATE_RUNNER_KIND')!='github-hosted'):
    raise RuntimeError('requires owned native Windows control')
def stop_child(process):
    if process.poll() is None:
        process.terminate()
    try:
        return process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=5)


output=Path(os.environ['RUNNER_TEMP'])/'corrupt-receipt-control';output.mkdir()
report={'fixture_restoration_verified':False,'product_recovery_verified':False}
child=None
try:
    with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as directory:
        root=Path(directory);home=root/'managed';(home/'bin').mkdir(parents=True)
        with closing(sqlite3.connect(home/'state.db')) as db:
            db.execute('PRAGMA journal_mode=WAL').fetchall()
            with db:
                db.execute('create table receipts(package_id text,version text,source text,channel text)')
                db.execute('create table receipt_files(receipt_pkg_id text,path text,hash text,mode integer)')
                for package,version in PACKAGES.items():
                    db.execute('insert into receipts values(?,?,?,?)',(package,version,'official-obey','stable'))
                for name,package in [('camp','festival'),('fest','festival'),('obey','obey'),('ob','obey'),('camp-app','camp-app')]:
                    path=home/'bin'/(name+'.exe');path.write_bytes(('fixture data never executed '+name).encode())
                    db.execute('insert into receipt_files values(?,?,?,?)',('obedience-corp/'+package,str(path),hashlib.sha256(path.read_bytes()).hexdigest(),493))
        fixture=Fixture(home,root/'private',report,dict(os.environ));fixture.corrupt()
        try:
            with closing(sqlite3.connect(home/'state.db')) as db:db.execute('select * from receipts').fetchall()
        except sqlite3.DatabaseError as error:report['actual_sqlite_error']=str(error)
        else:raise AssertionError('corrupt receipt DB unexpectedly readable')
        fixture.unchanged()
        # This tiny owned process only writes a ready marker and sleeps. Its
        # executable name exercises the actual fixed process-inventory guard.
        source=root/'owned.cs';source.write_text('using System; using System.IO; using System.Threading; class Owned { static void Main(string[] args) { File.WriteAllText(args[0],"ready"); Thread.Sleep(60000); } }')
        compiler=Path(os.environ['SYSTEMROOT'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        executable=root/'festival.exe';ready=root/'ready'
        compiled=subprocess.run([str(compiler),'/nologo','/target:exe','/out:'+str(executable),str(source)],timeout=30,capture_output=True,text=True)
        report['owned_child_compiler']={'path':str(compiler),'returncode':compiled.returncode,'stdout':compiled.stdout,'stderr':compiled.stderr}
        if compiled.returncode:raise RuntimeError('owned Installer-name fixture compilation failed')
        child=subprocess.Popen([str(executable),str(ready)])
        report['owned_installer_pid']=child.pid
        try:
            deadline=time.monotonic()+15
            while not ready.exists():
                if child.poll() is not None or time.monotonic()>=deadline:raise RuntimeError('owned Installer-name child not ready')
                time.sleep(.1)
            try:fixture.restore()
            except ValueError as error:
                if 'running App or Installer' not in str(error):raise
                report['actual_live_installer_restore_refused']=True
                report['actual_process_refusal']=str(error)
            else:raise AssertionError('live Installer did not prevent DB restore')
            fixture.unchanged()
        finally:
            report['owned_installer_exit']=stop_child(child);child=None
        report['after_owned_child_cleanup']=quiescent(dict(os.environ))
        fixture.restore();fixture.healthy()
        report['fixture_restoration_verified']=True
finally:
    if child is not None:
        stop_child(child)
    (output/'proof.json').write_text(json.dumps(report,indent=2)+'\n')
print('Actual SQLite corruption, live Installer refusal and exact held-file Windows restoration PASS')
