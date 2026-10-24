"""Real WebKit HTML accessibility/action contract, never a packaged App substitute."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('WebKit accessibility fixture requires disposable Docker')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from linux_accessibility import ToolkitSetting
from linux_git_retry import birth, require_owner
from linux_receipt_ui import visible_text
import linux_setup_retry as retry
import gi

if len(sys.argv)==4 and sys.argv[1]=='--fixture':
    gi.require_version('Gtk','3.0');gi.require_version('WebKit2','4.1')
    from gi.repository import Gtk, WebKit2
    marker=Path(sys.argv[2]);unstyled=sys.argv[3]=='unstyled'
    manager=WebKit2.UserContentManager()
    manager.register_script_message_handler('fixture')
    manager.connect('script-message-received::fixture',lambda *_:marker.write_text('actual WebKit Retry action\n'))
    view=WebKit2.WebView.new_with_user_content_manager(manager)
    reset='ul {list-style:none;margin:0;padding:0}' if unstyled else ''
    # Ordinary semantic HTML with the App's adjacent heading/status spans and
    # list-style reset, not injected App JS or a fake Installer response.
    html='''<!doctype html><html><head><style>'''+reset+'''
    body {font:16px sans-serif} li {border:1px solid #888;padding:10px;margin:10px}
    .heading {display:flex;justify-content:space-between}</style></head><body>
    <h1>Owned setup fixture</h1><ul>
    <li><div class="heading"><span>Read what this machine has</span><span>Done</span></div></li>
    <li><div class="heading"><span>Install selected app packages</span><span>Failed</span></div>
    <p>E_ARTIFACT_DO: owned fixture transport fault</p><p>E_ARTIFACT_DO</p>
    <button onclick="window.webkit.messageHandlers.fixture.postMessage('clicked');
      this.parentElement.appendChild(document.createElement('button')).textContent='Retry'">Retry</button></li>
    <li><div class="heading"><span>Update anything older than this app needs</span><span>Waiting</span></div></li>
    </ul></body></html>'''
    view.load_html(html,'http://127.0.0.1/')
    window=Gtk.Window(title='Owned WebKit setup fixture');window.set_default_size(1000,700)
    window.add(view);window.connect('destroy',Gtk.main_quit);window.show_all();Gtk.main()
    raise SystemExit(0)

gi.require_version('Atspi','2.0')
from gi.repository import Atspi
Atspi.set_timeout(1000,5000)


def tree(root):
    queue=[(root,None)];rows=[]
    while queue:
        node,parent=queue.pop();index=len(rows)
        if index>=4000:raise RuntimeError('fixture tree exceeds bound')
        rows.append({'index':index,'parent':parent,'role':node.get_role_name(),'name':node.get_name()})
        count=node.get_child_count()
        if not 0<=count<=4000:raise RuntimeError('fixture child count exceeds bound')
        queue.extend((node.get_child_at_index(i),index) for i in range(count))
    return rows


with tempfile.TemporaryDirectory() as temporary:
    setting=ToolkitSetting(dict(os.environ));child=None
    try:
        setting.enable()
        for mode in ['unstyled','normal']:
            marker=Path(temporary)/mode
            child=subprocess.Popen([sys.executable,__file__,'--fixture',str(marker),mode],start_new_session=True)
            started=birth(child.pid);deadline=time.monotonic()+45
            while time.monotonic()<deadline:
                if child.poll() is not None:raise RuntimeError('WebKit fixture exited before accessibility readiness')
                desktop=Atspi.get_desktop(0)
                roots=[desktop.get_child_at_index(i) for i in range(desktop.get_child_count())]
                owned=[root for root in roots if root.get_process_id()==child.pid]
                if len(owned)==1:
                    text,_=visible_text(roots,child.pid,Atspi)
                    if any(retry.CODE in value for value in text):break
                time.sleep(.1)
            else:raise RuntimeError('WebKit HTML never became accessible')
            print(json.dumps({'mode':mode,'tree':tree(owned[0]),'visible_text':text}),flush=True)
            require_owner(child.pid,started,Path(sys.executable))
            action,record=retry.select_retry(roots,child.pid,Atspi)
            require_owner(child.pid,started,Path(sys.executable))
            assert action.do_action(0) is True
            deadline=time.monotonic()+5
            while not marker.exists() and time.monotonic()<deadline:time.sleep(.05)
            assert marker.read_text()=='actual WebKit Retry action\n'
            time.sleep(.1)
            try:retry.select_retry(roots,child.pid,Atspi)
            except RuntimeError:pass
            else:raise AssertionError('actual duplicate WebKit Retry controls accepted')
            print(json.dumps({'mode':mode,'actual_callback':True,'duplicate_refused':True,'selection':record}),flush=True)
            child.terminate();child.wait(timeout=20);child=None
    finally:
        if child is not None and child.poll() is None:child.terminate();child.wait(timeout=20)
        setting.restore()
        assert setting.read()==setting.original
