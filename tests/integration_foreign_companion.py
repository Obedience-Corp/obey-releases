"""Native Windows executable metadata/rollback control; fixture bytes never run."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from foreign_companion import Fixture, identity, descriptor_identity
from verify_selected_components import PACKAGES, checked_receipts
if (os.name != 'nt' or os.environ.get('CANDIDATE_NATIVE_DISPOSABLE') != '1' or
        os.environ.get('CANDIDATE_RUNNER_KIND') != 'github-hosted'):
    raise RuntimeError('requires disposable native Windows control')
output=Path(os.environ['RUNNER_TEMP'])/'foreign-companion-control';output.mkdir()
report={'fixture_restoration_verified':False,'product_recovery_verified':False}
try:
    with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as directory:
        root=Path(directory);home=root/'managed';(home/'bin').mkdir(parents=True)
        with closing(sqlite3.connect(home/'state.db')) as db:
            db.execute('create table receipts(package_id text,version text,source text,channel text)')
            db.execute('create table receipt_files(receipt_pkg_id text,path text,hash text,mode integer)')
            for package,version in PACKAGES.items():
                db.execute('insert into receipts values(?,?,?,?)',(package,version,'official-obey','stable'))
            for name,package in [('camp','festival'),('fest','festival'),('obey','obey'),('ob','obey'),('camp-app','camp-app')]:
                path=home/'bin'/(name+'.exe');path.write_bytes(('fixture never executed '+name).encode())
                db.execute('insert into receipt_files values(?,?,?,?)',('obedience-corp/'+package,str(path),hashlib.sha256(path.read_bytes()).hexdigest(),493))
            db.commit()
        source=root/'festival.exe';source.write_bytes(b'distinct fixture source never executed')
        baseline=checked_receipts(home)
        fixture=Fixture(home,source,root/'private',report)
        with fixture.path.open('rb') as stream:
            raw=identity(os.fstat(stream.fileno()));expected=identity(fixture.path.lstat())
            report['initial_path_metadata']=expected;report['initial_handle_metadata']=raw
            assert raw['st_mode'] ^ expected['st_mode'] == 0o111
            assert descriptor_identity(os.fstat(stream.fileno()),fixture.path)==expected
        fixture.substitute();fixture.unchanged();fixture.restore();fixture.healthy()
        assert checked_receipts(home)==baseline
        # A read-only change after acquisition remains a refusal, not reconciled.
        readonly=Fixture(home,source,root/'readonly-private',{})
        readonly.path.chmod(0o444)
        try:
            try:readonly.write(readonly.original,readonly.foreign)
            except ValueError:report['readonly_refused']=True
            else:raise AssertionError('read-only metadata change accepted')
        finally:readonly.path.chmod(0o666)
        replaced=Fixture(home,source,root/'replacement-private',{})
        alternate=root/'alternate.exe';alternate.write_bytes(replaced.original)
        os.replace(alternate,replaced.path)
        before=replaced.path.read_bytes()
        try:replaced.write(replaced.original,replaced.foreign)
        except ValueError:report['replacement_refused']=True
        else:raise AssertionError('replacement file identity accepted')
        assert replaced.path.read_bytes()==before
        report['fixture_restoration_verified']=True
finally:(output/'proof.json').write_text(json.dumps(report,indent=2)+'\n')
print('Native executable path/handle identity, exact rollback and readonly/replacement refusals PASS')
