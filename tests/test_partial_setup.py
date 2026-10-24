import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import partial_install_proxy as proxy
import partial_setup as setup
import linux_setup_retry as ui


class AttributionTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        installer = root/'festival-app-installer';installer.write_bytes(b'identity-only test executable')
        proc = root/'proc';(proc/'net').mkdir(parents=True)
        (proc/'net/tcp').write_text('header\n 0: 0100007F:C350 0100007F:04D2 01 0 0 0 0 0 12345\n')
        def process(pid, parent, birth, state='S', target=True):
            d=proc/str(pid);(d/'fd').mkdir(parents=True)
            fields=[state,str(parent),'0','0']+['0']*15+[str(birth)]
            (d/'stat').write_text(f'{pid} (fixture process) '+' '.join(fields))
            (d/'exe').symlink_to(installer if target else Path(sys.executable))
            (d/'cmdline').write_bytes(os.fsencode(installer)+b'\0install\0obedience-corp/camp-app\0--json\0--managed\0')
            return d
        process(100,1,10,target=False)
        child=process(200,100,20);(child/'fd/7').symlink_to('socket:[12345]')
        process(300,1,5,state='Z',target=False)  # An unrelated zombie is not an attribution failure.
        return proc, installer, proxy.process(100,proc), process

    def test_exact_socket_and_birth_validated_installer_with_unrelated_zombie(self):
        with tempfile.TemporaryDirectory() as d:
            proc, installer, root, _=self.fixture(d)
            result=proxy.request_owner(('127.0.0.1',50000),1234,root,installer,proc)
            self.assertTrue(result['companion_install']);self.assertEqual(result['pid'],200)
            self.assertEqual(result['ancestry'],[{'pid':200,'birth':20},{'pid':100,'birth':10}])

    def test_reused_parent_root_generation_duplicate_owner_and_wrong_argv_refused(self):
        for case in ('root','edge','duplicate','argv'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as d:
                proc, installer, root, create=self.fixture(d)
                if case=='root':root=dict(root,birth=9)
                elif case=='edge':
                    text=(proc/'200/stat').read_text();(proc/'200/stat').write_text(text.replace('S 100 ','S 400 '));create(400,100,25)
                elif case=='duplicate':
                    other=create(400,100,21);(other/'fd/7').symlink_to('socket:[12345]')
                else:
                    (proc/'200/cmdline').write_bytes(b'foreign\0install\0obedience-corp/camp-app\0--json\0--managed\0')
                with self.assertRaises(RuntimeError):proxy.request_owner(('127.0.0.1',50000),1234,root,installer,proc)

    def test_foreign_peer_and_duplicate_tcp_socket_refused(self):
        with tempfile.TemporaryDirectory() as d:
            proc,_,_,_=self.fixture(d)
            with self.assertRaises(RuntimeError):proxy.peer_inode(('192.0.2.1',50000),1234,proc)
            text=(proc/'net/tcp').read_text();(proc/'net/tcp').write_text(text+text.splitlines()[1]+'\n')
            with self.assertRaises(RuntimeError):proxy.peer_inode(('127.0.0.1',50000),1234,proc)

    def test_policy_blocks_only_authenticated_companion_assets_then_recovers(self):
        value=proxy.PartialInstallProxy(Path(sys.executable))
        value.root_ready.set();value.root={}
        peer=('127.0.0.1',50000)
        try:
            with patch.object(proxy,'request_owner',return_value={'pid':200,'birth':20,'companion_install':False}):
                self.assertTrue(value._allow_request(('release-assets.githubusercontent.com',443),peer))
            with patch.object(proxy,'request_owner',return_value={'pid':201,'birth':21,'companion_install':True}):
                self.assertFalse(value._allow_request(('release-assets.githubusercontent.com',443),peer))
                value.recover()
                self.assertTrue(value._allow_request(('release-assets.githubusercontent.com',443),peer))
        finally:value.close()
        self.assertEqual(value.evidence()['active_connections'],0)

    def test_unknown_ownership_blocks_transport_and_disqualifies_recovery(self):
        value=proxy.PartialInstallProxy(Path(sys.executable));value.root_ready.set();value.root={}
        try:
            with patch.object(proxy,'request_owner',side_effect=PermissionError('query refused')):
                self.assertFalse(value._allow_request(('release-assets.githubusercontent.com',443),('127.0.0.1',50000)))
            with self.assertRaises(RuntimeError):value.recover()
            self.assertTrue(value.evidence()['ownership_errors'])
        finally:value.close()

    def test_unrelated_denied_target_disqualifies_recovery(self):
        value=proxy.PartialInstallProxy(Path(sys.executable))
        try:
            value.attributions.append({'blocked':True})
            value._record(('<unselected>',0),'denied')
            with self.assertRaises(RuntimeError):value.recover()
        finally:value.close()


def report():
    return {'state':{'kind':'failed','step':'install'},'factsStale':False,'blocksLaunch':True,
            'steps':[{'step':'install','errorCode':'E_ARTIFACT_DO'}],
            'packages':[{'id':p,'selected':True,'ready':p!=setup.COMPANION,
                         'result':'installed' if p!=setup.COMPANION else 'failed'}
                        for p in [setup.SUITE,setup.OBEY,setup.COMPANION]]+
                       [{'id':'obedience-corp/camp-graph','requirement':'optional','selected':False,
                         'ready':False,'plannedAction':'unselected','result':None}]}


class PartialReportTests(unittest.TestCase):
    def test_truthful_partial_facts_and_meaningful_refusals(self):
        self.assertEqual(setup.checked_report(report()),report())
        for change in ('stale','lost','companion','optional','optional-missing','result','code','duplicate'):
            r=report()
            if change=='stale':r['factsStale']=True
            elif change=='lost':r['packages'][0]['ready']=False
            elif change=='companion':r['packages'][2]['ready']=True
            elif change=='optional':r['packages'][3]['result']='installed'
            elif change=='optional-missing':r['packages'].pop()
            elif change=='result':r['packages'][2]['result']=None
            elif change=='code':r['steps'][0]['errorCode']='E_OTHER'
            else:r['packages'].append(copy.deepcopy(r['packages'][0]))
            with self.subTest(change=change),self.assertRaises(ValueError):setup.checked_report(r)

    def test_same_bytes_rewritten_mtime_or_receipt_change_is_not_preservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);binary=root/'camp';binary.write_bytes(b'original authentic bytes')
            note=root/'note';note.write_bytes(b'user input')
            receipt={'package_id':setup.SUITE,'version':'0.3.24'}
            file={'receipt_pkg_id':setup.SUITE,'path':str(binary)}
            before={'receipts':{'receipts':[receipt],'files':[file]},'physical':[setup.physical(binary)]}
            fixture=setup.Fixture.__new__(setup.Fixture)
            fixture.report={'partial_before_retry':before};fixture.note=note;fixture.note_before=setup.physical(note)
            fixture.proxy=Mock();fixture.proxy.evidence.return_value={'ownership_errors':[],'requests':[]}
            reading={'receipts':copy.deepcopy(before['receipts'])}
            fixture.preserved(reading)
            os.utime(binary,ns=(binary.stat().st_atime_ns,binary.stat().st_mtime_ns+1000000))
            with self.assertRaisesRegex(ValueError,'physical'):fixture.preserved(reading)
            reading['receipts']['receipts'][0]['version']='0.3.25'
            with self.assertRaisesRegex(ValueError,'receipts'):fixture.preserved(reading)

    def test_ready_without_a_targeted_fault_fails_instead_of_claiming_recovery(self):
        fixture=setup.Fixture.__new__(setup.Fixture);fixture.alive=Mock()
        fixture.read_report=Mock(return_value={'state':{'kind':'ready'}})
        with self.assertRaisesRegex(RuntimeError,'bypassed'):fixture.fail_and_retry(Mock())

    def test_partial_mode_rejects_wrong_platform_seed_and_combined_journeys(self):
        import verify_app_candidate as app
        invalid=[{'target':'aarch64-apple-darwin'}, {'linux_package':'appimage'},
                 {'existing_user':'current'}, {'login_shell_proof':True}, {'missing_git_manual':True},
                 {'guest_context':object()}, {'fresh_setup':False}]
        for changes in invalid:
            args=dict(target='x86_64-unknown-linux-gnu',fresh_setup=True,public_root=Path('/public'),partial_install_retry=True)
            args.update(changes)
            with self.subTest(changes=changes),patch.object(app,'require_clean_host'),self.assertRaises(ValueError):
                app.native(Path('/unused'),{},output=Path('/unused'),**args)


API=SimpleNamespace(Role=SimpleNamespace(PUSH_BUTTON=1,LIST_ITEM=2),
                    StateType=SimpleNamespace(ENABLED=1,SENSITIVE=2,SHOWING=3,VISIBLE=4))


def node(name='',children=(),role=0,pid=42,enabled=True):
    n=Mock();n.get_name.return_value=name;n.get_role.return_value=role;n.get_process_id.return_value=pid
    n.get_child_count.return_value=len(children);n.get_child_at_index.side_effect=children.__getitem__
    n.get_state_set.return_value.contains.return_value=enabled;n.get_text_iface.return_value=None
    n.get_action_iface.return_value.get_n_actions.return_value=1
    return n


def row(buttons=1,label=ui.LABEL,enabled=True):
    return node(children=[node(label),node('Failed'),node(ui.CODE)]+
                [node('Retry',role=1,enabled=enabled) for _ in range(buttons)],role=2)


class RetryTests(unittest.TestCase):
    def test_exact_failed_row_and_one_normal_action(self):
        action,evidence=ui.select_retry([node(children=[row()])],42,API)
        self.assertIn(ui.LABEL,evidence['row_text']);action.do_action.assert_not_called()

    def test_foreign_wrong_row_hidden_disabled_and_duplicate_refused(self):
        cases=[[node(children=[row()],pid=99)], [node(children=[row(label='Start the obey daemon')])],
               [node(children=[row(enabled=False)])], [node(children=[row(buttons=2)])],
               [node(children=[row(),row()])]]
        for roots in cases:
            with self.subTest(roots=roots),self.assertRaises(RuntimeError):ui.select_retry(roots,42,API)


if __name__=='__main__':unittest.main()
