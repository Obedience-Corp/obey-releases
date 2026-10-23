"""Receipt, identity and bootstrap failures in the existing Docker harness."""
import copy
from contextlib import chdir, closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists():
    raise RuntimeError("selected filesystem tests require the Docker harness")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_selected_components import PACKAGES, checked_bootstrap, checked_receipts, checked_status, require_clean_host, native_selected


class SelectedContracts(unittest.TestCase):
    def test_failure_preserves_partial_report_and_still_raises(self):
        with tempfile.TemporaryDirectory() as temporary, chdir(temporary):
            data = b"fixture bootstrap"
            checksums = hashlib.sha256(data).hexdigest().encode() + b"  festival-linux-amd64\n"
            def fetch(url):
                return checksums if url.endswith("checksums.txt") else data
            def run(arguments, *args, **kwargs):
                return "v0.3.7" if arguments[1] == "version" else {"ok": True}
            with patch("verify_selected_components.require_clean_host"), patch("verify_selected_components.fetch", side_effect=fetch), patch("verify_selected_components.command", side_effect=run), patch.dict(os.environ, {"RUNNER_TEMP": temporary}):
                with self.assertRaises(sqlite3.OperationalError):
                    native_selected("linux-x86_64")
            report = json.loads(Path("proof-selected-linux-x86_64.json").read_text())
            self.assertIn("failure", report)
            self.assertFalse(report["native_component_execution"])
            self.assertFalse(report["trust_complete"])
            self.assertEqual(set(report["install"]), {"festival", "obedience-corp/camp-app", "obey"})

    def test_bootstrap_rejects_corruption_and_duplicate_checksums(self):
        data = b"actual public binary bytes"
        digest = hashlib.sha256(data).hexdigest()
        row = f"{digest}  festival-linux-amd64\n".encode()
        self.assertEqual(checked_bootstrap(data, row, "festival-linux-amd64"), digest)
        for content, rows in ((data + b"corrupt", row), (data, row * 2), (data, b"bad digest\n")):
            with self.assertRaises(ValueError):
                checked_bootstrap(content, rows, "festival-linux-amd64")

    def test_native_guard_refuses_operator_machine_and_credentials(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
            require_clean_host("linux-x86_64")
        with patch.dict(os.environ, {"CANDIDATE_NATIVE_DISPOSABLE": "1", "CANDIDATE_RUNNER_KIND": "github-hosted", "GH_TOKEN": "not-a-real-secret"}, clear=True), patch("verify_selected_components.native_platform", return_value="linux/amd64"), self.assertRaisesRegex(RuntimeError, "credentials"):
            require_clean_host("linux-x86_64")

    def fixture(self, root):
        home = root / "managed"
        (home / "bin").mkdir(parents=True)
        database = sqlite3.connect(home / "state.db")
        database.execute("create table receipts(package_id text,version text,source text,channel text)")
        database.execute("create table receipt_files(receipt_pkg_id text,path text,hash text,mode integer)")
        for package, version in PACKAGES.items():
            database.execute("insert into receipts values(?,?,?,?)", (package, version, "official-obey", "stable"))
        for name, package in (("camp", "festival"), ("fest", "festival"), ("obey", "obey"), ("ob", "obey"), ("camp-app", "camp-app")):
            path = home / "bin" / name
            path.write_bytes(name.encode())
            database.execute("insert into receipt_files values(?,?,?,?)", ("obedience-corp/" + package, str(path), hashlib.sha256(path.read_bytes()).hexdigest(), 493))
        database.commit()
        database.close()
        return home

    def test_actual_persisted_inventory_rejects_optional_or_changed_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = self.fixture(Path(temporary))
            self.assertEqual(len(checked_receipts(home)["files"]), 5)
            (home / "bin/ob").write_bytes(b"foreign replacement")
            with self.assertRaises(ValueError):
                checked_receipts(home)
            (home / "bin/ob").write_bytes(b"ob")
            with closing(sqlite3.connect(home / "state.db")) as db:
                db.execute("insert into receipts values(?,?,?,?)", ("obedience-corp/camp-buzz", "1.0.0", "official-obey", "stable"))
                db.commit()
            with self.assertRaisesRegex(ValueError, "selection/version"):
                checked_receipts(home)

    def test_receipt_cannot_escape_through_parent_segments(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = self.fixture(root)
            (root / "external").mkdir()
            outside = root / "external/ob"
            outside.write_bytes(b"ob")
            with closing(sqlite3.connect(home / "state.db")) as db:
                db.execute("update receipt_files set path=? where path=?", (str(home / "bin/../../external/ob"), str(home / "bin/ob")))
                db.commit()
            with self.assertRaisesRegex(ValueError, "outside"):
                checked_receipts(home)

    def test_live_status_requires_selected_paths_and_companion_protocol(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = self.fixture(Path(temporary))
            tools = [{"tool": name, "version": version, "path": str(home / "bin" / name), "present": True} for name, version in (("camp", "0.16.2"), ("fest", "0.9.8"), ("obey", "0.2.3"), ("camp-app", "0.1.0"))]
            tools[-1].update(protocol_major=1, capabilities=["status", "open"])
            tools.append({"tool": "ob", "version": "0.1.0", "present": True, "receipt_version": "0.2.3"})
            document = {"ok": True, "data": {"tools": tools}}
            checked_status(document, home)
            for field, value in (("version", "0.0.0"), ("path", str(home.parent / "outside")), ("capabilities", ["status"]), ("protocol_major", 0)):
                wrong = copy.deepcopy(document)
                wrong["data"]["tools"][3][field] = value
                with self.assertRaises(ValueError):
                    checked_status(wrong, home)

    def test_old_obey_runtime_and_receipt_do_not_qualify_corrected_windows_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = self.fixture(Path(temporary))
            tools = [{'tool': name, 'version': version, 'path': str(home / 'bin' / name), 'present': True} for name, version in [('camp','0.16.2'), ('fest','0.9.8'), ('obey','0.2.3'), ('camp-app','0.1.0')]]
            tools[-1].update(protocol_major=1, capabilities=['status','open'])
            tools.append({'tool':'ob','version':'0.1.0','present':True,'path':str(home / 'bin/ob'),'receipt_version':'0.2.3'})
            document = {'ok':True,'data':{'tools':tools}}
            checked_status(document, home)
            wrong = copy.deepcopy(document)
            wrong['data']['tools'][2]['version'] = '0.2.2'
            with self.assertRaises(ValueError):
                checked_status(wrong, home)
            with closing(sqlite3.connect(home / 'state.db')) as database:
                database.execute("update receipts set version='0.2.2' where package_id='obedience-corp/obey'")
                database.commit()
            with self.assertRaises(ValueError):
                checked_receipts(home)

    def test_actual_windows_runtime_log_requires_observability_and_quiet_discovery(self):
        from verify_selected_components import checked_windows_discovery_log
        good = b'time=now level=INFO msg="daemon ready"\ntime=now level=WARN msg="optional provider not configured"\n'
        result = checked_windows_discovery_log(good)
        self.assertEqual(result['required_obey_version'], '0.2.3')
        self.assertEqual(result['sha256'], hashlib.sha256(good).hexdigest())
        for bad in [b'', b'   ', b'exec: "lsof": executable file not found in %PATH%', b'exec: \"ps\": executable file not found', b'msg="bridge startup provider discovery failed" error="list Codex processes failed"']:
            with self.assertRaises(ValueError):
                checked_windows_discovery_log(bad)

    def test_log_snapshot_retains_exact_checked_bytes_when_live_log_grows_or_fails(self):
        from verify_selected_components import record_windows_discovery_snapshot
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'live.log'; output = root / 'proof'; output.mkdir()
            original = b'level=INFO msg="daemon ready"\n'; source.write_bytes(original)
            report = {}; record_windows_discovery_snapshot(source, output, report)
            source.write_bytes(original + b'level=INFO msg="later append"\n')
            snapshot = output / report['windows_default_discovery_log']['snapshot']
            self.assertEqual(snapshot.read_bytes(), original)
            self.assertEqual(report['windows_default_discovery_log']['sha256'], hashlib.sha256(snapshot.read_bytes()).hexdigest())
            self.assertNotEqual(report['windows_default_discovery_log']['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            bad = b'exec: "lsof": executable file not found'; source.write_bytes(bad)
            rejected = {}
            with self.assertRaises(ValueError):
                record_windows_discovery_snapshot(source, output, rejected)
            self.assertEqual(snapshot.read_bytes(), bad)
            self.assertFalse(rejected['windows_default_discovery_log']['verified'])
            self.assertEqual(rejected['windows_default_discovery_log']['sha256'], hashlib.sha256(bad).hexdigest())
