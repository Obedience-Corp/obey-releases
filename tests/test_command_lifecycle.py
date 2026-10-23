"""Owned process and filesystem cases require the disposable Linux container."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists():
    raise RuntimeError("command lifecycle tests require Docker")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_app_candidate as app
from verify_candidate import command


class CommandLifecycle(unittest.TestCase):
    def test_timeout_retains_partial_output_and_remains_failure(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(subprocess.TimeoutExpired):
            command([sys.executable, "-c", "import sys,time; print('progress',flush=True); print('diagnostic',file=sys.stderr,flush=True); time.sleep(30)"], os.environ, timeout=0.2)
        report = json.loads(output.getvalue())
        self.assertEqual(report["stdout"], "progress\n")
        self.assertEqual(report["stderr"], "diagnostic\n")
        self.assertEqual(report["timeout_seconds"], 0.2)

    def test_owned_timeout_kills_descendants_but_not_unrelated_process(self):
        # Both owned processes ignore TERM, forcing the same GNU timeout group
        # KILL path used for privileged apt. No sudo or host process is touched.
        outsider = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        output = io.StringIO()
        child = "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('child',os.getpid(),flush=True); time.sleep(30)"
        parent = "import os,signal,subprocess,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('parent',os.getpid(),flush=True); subprocess.Popen([sys.executable,'-c',sys.argv[1]]); time.sleep(30)"
        try:
            with patch.object(app, "APT_KILL_GRACE_SECONDS", 1), contextlib.redirect_stdout(output), self.assertRaises(RuntimeError):
                command(app.owned_timeout([sys.executable, "-c", parent, child], 1), os.environ, timeout=5)
            report = json.loads(output.getvalue())
            identities = {name: int(pid) for name, pid in (line.split() for line in report["stdout"].splitlines())}
            self.assertEqual(set(identities), {"parent", "child"})
            for pid in identities.values():
                status = Path(f"/proc/{pid}/stat")
                # An exited orphan may remain a zombie until container init
                # reaps it. Zombies cannot execute or retain apt locks.
                self.assertTrue(not status.exists() or status.read_text().split(") ", 1)[1].startswith("Z "))
            self.assertIsNone(outsider.poll())
            self.assertNotEqual(report["exit"], 0)
        finally:
            outsider.terminate()
            outsider.wait(timeout=5)

    def test_apt_separates_network_from_no_download_install(self):
        with tempfile.TemporaryDirectory() as root, patch.object(app, "command") as invoked:
            deb = Path(root) / "candidate.deb"
            app.install_deb(deb, {})
            calls = invoked.call_args_list
            self.assertEqual(calls[0].args[0], ["apt-get", "--assume-no", "install", deb.resolve()])
            self.assertFalse(calls[0].kwargs["check"])
            self.assertIn("--download-only", calls[1].args[0])
            self.assertIn("1800s", calls[1].args[0])
            self.assertIn("--no-download", calls[2].args[0])
            self.assertIn("300s", calls[2].args[0])
            for call in calls[1:]:
                self.assertEqual(call.args[0][:2], ["sudo", "timeout"])
                self.assertIn("--kill-after=15s", call.args[0])
        with patch.object(app, "command", side_effect=["plan", RuntimeError("download failed")]) as invoked:
            with self.assertRaisesRegex(RuntimeError, "download failed"):
                app.install_deb(Path("candidate.deb"), {})
            self.assertEqual(invoked.call_count, 2)
