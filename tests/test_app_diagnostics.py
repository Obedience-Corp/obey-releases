"""Diagnostic boundaries and delayed snapshots run in filesystem isolation."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists():
    raise RuntimeError("diagnostic filesystem tests require Docker")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import mac_candidate_diagnostics as mac
import verify_app_candidate as app
from test_app_candidate import manifest


class DiagnosticBoundaries(unittest.TestCase):
    def test_only_two_managed_claims_are_removed_and_input_is_unchanged(self):
        original = {key: True for key in mac.MANAGED_BROWSER_ENTITLEMENTS}
        original.update({"com.apple.security.cs.allow-jit": True, "unchanged": ["original"]})
        filtered, removed = mac.without_managed_browser_entitlements(original)
        self.assertEqual(set(removed), mac.MANAGED_BROWSER_ENTITLEMENTS)
        self.assertEqual(filtered, {"com.apple.security.cs.allow-jit": True, "unchanged": ["original"]})
        self.assertTrue(all(original[key] for key in removed))
        with self.assertRaises(ValueError):
            mac.without_managed_browser_entitlements([])

    def test_macos_xattr_fallback_hashes_origin_without_dumping_it(self):
        responses = [
            {"exit": 0, "stdout": "com.apple.metadata:kMDItemWhereFroms\ncom.apple.quarantine\n"},
            {"exit": 0, "stdout": b"private origin URL".hex()},
            {"exit": 0, "stdout": b"0081;owned".hex()},
        ]
        with patch.object(mac, "os", wraps=os) as native_os, patch.object(mac, "capture", side_effect=responses):
            del native_os.listxattr
            result = mac.xattrs(Path("/owned/candidate"))
        origin = result["com.apple.metadata:kMDItemWhereFroms"]
        self.assertEqual(origin["sha256"], hashlib.sha256(b"private origin URL").hexdigest())
        self.assertNotIn("value", origin)
        self.assertEqual(result["com.apple.quarantine"]["value"], "0081;owned")

    def diagnostic_fixture(self, root):
        application = root / "installed/Festival App.app"
        binary = application / "Contents/MacOS/festival"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"original signed bytes")
        output = root / "output"
        output.mkdir()
        entitlements = {key: True for key in mac.MANAGED_BROWSER_ENTITLEMENTS}
        entitlements["preserved"] = True
        calls = []
        def capture(arguments, environment, timeout=30):
            calls.append(arguments)
            if arguments[0] == "ditto":
                shutil.copyfile(arguments[1], arguments[2])
            if arguments[0] == "codesign" and "--force" in arguments:
                Path(arguments[-1]).write_bytes(b"diagnostic modified signature")
            data = {"command": list(map(str, arguments)), "exit": 0, "stdout": "", "stderr": ""}
            if arguments[0] == "codesign" and "-dvv" in arguments:
                values = entitlements
                if Path(arguments[-1]).name == "modified-copy":
                    values, _ = mac.without_managed_browser_entitlements(values)
                data["stdout"] = plistlib.dumps(values).decode()
                data["stderr"] = "Identifier=original.festival\n"
            elif arguments[-1] == "version":
                data.update(exit=0 if Path(arguments[0]).name == "modified-copy" else -9,
                            stdout="v0.3.7" if Path(arguments[0]).name == "modified-copy" else "")
            return data
        return application, binary, output, capture, calls

    def test_modified_copy_diagnostic_never_changes_original_or_claims_acceptance(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            application, binary, output, capture, calls = self.diagnostic_fixture(root)
            with patch.object(mac, "capture", side_effect=capture), patch.object(mac, "crash_reports", return_value=[]):
                report = mac.diagnose(application, root, output, {}, True)
            self.assertEqual(binary.read_bytes(), b"original signed bytes")
            self.assertTrue(report["original_cli_bytes_unchanged"])
            self.assertFalse(report["original_candidate_accepted"])
            probe = report["modified_copy_probe"]
            self.assertEqual(probe["unchanged_copy_execution"]["exit"], -9)
            self.assertEqual(probe["same_entitlement_copy_execution"]["exit"], -9)
            self.assertEqual(probe["modified_copy_execution"]["exit"], 0)
            signed = [call for call in calls if "--force" in call]
            self.assertEqual(len(signed), 2)
            for call in signed:
                self.assertEqual(call[call.index("--identifier") + 1], "original.festival")
                self.assertEqual(call[call.index("--options") + 1], "runtime")
            self.assertEqual(probe["signing_identifier"], "original.festival")
            self.assertTrue(probe["diagnostic_only"])
            self.assertNotEqual(probe["original_sha256"], probe["modified_sha256"])
            self.assertEqual(set(probe["removed_entitlements"]), mac.MANAGED_BROWSER_ENTITLEMENTS)
            self.assertNotIn("diagnostic_error", report)

    def test_resigned_control_identifier_drift_stops_comparison(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            application, binary, output, capture, calls = self.diagnostic_fixture(root)
            def wrong_identifier(arguments, environment, timeout=30):
                record = capture(arguments, environment, timeout)
                if arguments[0] == "codesign" and "-dvv" in arguments and Path(arguments[-1]).name == "same-entitlement-copy":
                    record["stderr"] = "Identifier=unexpected\n"
                return record
            with patch.object(mac, "capture", side_effect=wrong_identifier), patch.object(mac, "crash_reports", return_value=[]):
                report = mac.diagnose(application, root, output, {}, True)
            self.assertIn("identifier", report["diagnostic_error"])
            self.assertNotIn("modified_copy_execution", report["modified_copy_probe"])
            self.assertTrue(report["original_cli_bytes_unchanged"])
            self.assertFalse(report["original_candidate_accepted"])

    def test_default_failure_diagnostics_do_not_sign_or_copy_payloads(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            application, binary, output, capture, calls = self.diagnostic_fixture(root)
            with patch.object(mac, "capture", side_effect=capture), patch.object(mac, "crash_reports", return_value=[]):
                report = mac.diagnose(application, root, output, {})
            self.assertFalse(any(arguments[0] == "ditto" or "--force" in arguments for arguments in calls))
            self.assertFalse(report["modified_copy_requested"])
            self.assertEqual(binary.read_bytes(), b"original signed bytes")

    def test_successful_diagnostic_cannot_clear_native_original_failure(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with patch.object(app, "require_clean_host"), patch.object(app, "native_platform", return_value="darwin/arm64"), patch.object(app, "verify_signature"), patch.object(app, "mac_install", side_effect=RuntimeError("original SIGKILL")), patch.object(app, "diagnose_mac_failure", return_value={"diagnostic_only": True, "modified_copy_execution": {"exit": 0}}), patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                with self.assertRaisesRegex(RuntimeError, "original SIGKILL"):
                    app.native(root, manifest(), "aarch64-apple-darwin", root / "report")
            report = json.loads((root / "report/proof.json").read_text())
            self.assertFalse(report["native_packaging_launch_verified"])
            self.assertEqual(report["failure"], "original SIGKILL")

    def test_windows_nonzero_taskkill_requires_owned_identity_readback(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        identities = [{"pid": 123, "started": "10001"}, {"pid": 124, "started": "10002"}]
        killed = Mock(returncode=255, stdout="root terminated", stderr="child unsupported")
        with patch.object(app, "windows_owned_birth", return_value="10001"), patch.object(app.os, "name", "nt"), patch.object(app, "Path", return_value=Mock(with_name=Mock(return_value="query.ps1"))), patch.object(app, "command", side_effect=[json.dumps(identities), '{"owned_processes_exited":true}']) as query, patch.object(app.subprocess, "run", return_value=killed):
            app.stop_owned(process, {})
        self.assertEqual(json.loads(query.call_args_list[1].args[1]["APP_PROOF_PROCESS_IDENTITIES"]), identities)
        process.wait.assert_called_once_with(timeout=20)

    def test_windows_cleanup_survivor_readback_still_fails(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        killed = Mock(returncode=0, stdout="", stderr="")
        with patch.object(app, "windows_owned_birth", return_value="10001"), patch.object(app.os, "name", "nt"), patch.object(app, "Path", return_value=Mock(with_name=Mock(return_value="query.ps1"))), patch.object(app, "command", side_effect=['[{"pid":123,"started":"10001"}]', RuntimeError("owned survivor")]), patch.object(app.subprocess, "run", return_value=killed):
            with self.assertRaisesRegex(RuntimeError, "owned survivor"):
                app.stop_owned(process, {})
        process.wait.assert_not_called()

    def test_wrong_root_birth_refuses_taskkill(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        with patch.object(app, "windows_owned_birth", return_value="10001"), patch.object(app.os, "name", "nt"), patch.object(app, "Path", return_value=Mock(with_name=Mock(return_value="query.ps1"))), patch.object(app, "command", return_value='[{"pid":123,"started":"9999"}]'), patch.object(app.subprocess, "run") as kill:
            with self.assertRaisesRegex(RuntimeError, "lost the known root identity"):
                app.stop_owned(process, {})
        kill.assert_not_called()
        process.wait.assert_not_called()

    def test_observed_windows_root_keeps_known_birth_and_rejects_wrong_pid(self):
        process = Mock(pid=123, identity={"pid":123,"started":"10001"})
        self.assertEqual(app.windows_owned_birth(process), "10001")
        process.identity["pid"] = 124
        with self.assertRaisesRegex(RuntimeError, "invalid observed Windows root"):
            app.windows_owned_birth(process)

    def test_delayed_captures_keep_all_frames_and_late_primary(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            process = Mock()
            process.poll.return_value = None
            clock = {"now": 0}
            sleeps = []
            def sleep(seconds):
                sleeps.append(seconds)
                clock["now"] += seconds
            def capture(process, target, path, environment):
                path.write_bytes(path.name.encode())
                return {"screenshot": path.name, "window_id": "owned"}
            records = []
            with patch.object(app.time, "monotonic", side_effect=lambda: clock["now"]), patch.object(app.time, "sleep", side_effect=sleep), patch.object(app, "window_capture", side_effect=capture):
                result = app.capture_startup(process, "windows", root, {}, records)
            self.assertEqual(sleeps, [5, 10])
            self.assertEqual([item["requested_seconds"] for item in records], [0, 5, 15])
            self.assertEqual((root / "app.png").read_bytes(), (root / "app-15s.png").read_bytes())
            self.assertEqual(result["screenshot"], "app.png")

    def test_slow_first_capture_does_not_collapse_later_delays(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            process = Mock()
            process.poll.return_value = None
            clock = {"now": 0}
            sleeps = []
            def sleep(seconds):
                sleeps.append(seconds)
                clock["now"] += seconds
            def capture(process, target, path, environment):
                if path.name == "app-initial.png":
                    clock["now"] += 31
                path.write_bytes(b"actual frame")
                return {"screenshot": path.name}
            records = []
            with patch.object(app.time, "monotonic", side_effect=lambda: clock["now"]), patch.object(app.time, "sleep", side_effect=sleep), patch.object(app, "window_capture", side_effect=capture):
                app.capture_startup(process, "linux", root, {}, records)
            self.assertEqual(sleeps, [5, 10])
            self.assertEqual([item["elapsed_seconds"] for item in records], [0, 5, 15])
            self.assertEqual([item["elapsed_since_launch_seconds"] for item in records], [31, 36, 46])

    def test_exit_between_frames_keeps_prior_evidence_and_fails(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            process = Mock()
            process.poll.side_effect = [None, None, 1]
            def capture(process, target, path, environment):
                path.write_bytes(b"initial")
                return {"screenshot": path.name}
            records = []
            with patch.object(app.time, "sleep"), patch.object(app, "window_capture", side_effect=capture):
                with self.assertRaisesRegex(RuntimeError, "exited"):
                    app.capture_startup(process, "windows", root, {}, records)
            self.assertEqual(len(records), 1)
            self.assertTrue((root / "app-initial.png").is_file())
            self.assertFalse((root / "app.png").exists())


if __name__ == "__main__":
    unittest.main()
