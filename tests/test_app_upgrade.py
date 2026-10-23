"""Upgrade input/state failure paths; filesystem mutations require Docker."""
import copy
import hashlib
import json
import os
import sqlite3
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists():
    raise RuntimeError("upgrade filesystem tests require Docker")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import app_upgrade_contract as contract
import verify_app_upgrade as upgrade
from test_app_candidate import manifest, SOURCE, VERSION


def public_fixture(root):
    assets = root / "assets"
    assets.mkdir()
    document = manifest()
    for entries in document["targets"].values():
        for entry in entries:
            entry["name"] = entry["name"].replace(" ", ".")
    linux = document["targets"]["x86_64-unknown-linux-gnu"]
    linux.append(dict(next(item for item in linux if item["name"].endswith(".deb"))))
    linux[-1]["name"] += ".sig"
    for entries in document["targets"].values():
        for entry in entries:
            (assets / entry["name"]).write_bytes(b"payload")
    (assets / "app-candidate.json").write_text(json.dumps(document))
    files = [item for entries in document["targets"].values() for item in entries]
    (assets / "checksums.txt").write_text("".join(f"{item['sha256']}  {item['name']}\n" for item in files))
    (root / "SHA256SUMS").write_text("".join(f"{item['sha256']}  {item['name']}\n" for item in files if not item["name"].endswith(".sig")))
    platforms = {}
    tag = contract.release_identity(SOURCE, VERSION)
    for key, (target, suffix) in contract.PLATFORMS.items():
        item = next(item for item in document["targets"][target] if item["name"].endswith(suffix))
        platforms[key] = {"url": f"https://github.com/{contract.REPOSITORY}/releases/download/{tag}/{item['name']}", "signature": "payload"}
    (root / "latest.json").write_text(json.dumps({"version": VERSION, "platforms": platforms}))
    metadata = {"draft": False, "prerelease": True, "tag_name": tag, "assets": []}
    for path in [*assets.iterdir(), root / "latest.json", root / "SHA256SUMS"]:
        metadata["assets"].append({"name": path.name, "size": path.stat().st_size, "digest": "sha256:" + contract.sha256(path),
                                   "browser_download_url": f"https://github.com/{contract.REPOSITORY}/releases/download/{tag}/{path.name}"})
    (root / "release.json").write_text(json.dumps(metadata))
    return document


def refresh_metadata(root, filename):
    metadata = json.loads((root / "release.json").read_text())
    path = root / filename if filename in ("SHA256SUMS", "latest.json") else root / "assets" / filename
    row = next(item for item in metadata["assets"] if item["name"] == filename)
    row.update(size=path.stat().st_size, digest="sha256:" + contract.sha256(path))
    (root / "release.json").write_text(json.dumps(metadata))


class UpgradeContracts(unittest.TestCase):
    def test_fresh_readback_requires_live_service_without_starting_it(self):
        import verify_app_candidate as app
        managed = Path("/home/.obey/installer")
        active = {"installed": True, "loaded": True, "socket_reachable": True, "daemon_pid": 123}
        with patch.object(upgrade, "default_home_readback", return_value={}), patch("verify_selected_components.checked_receipts", return_value={"files": []}), patch.object(app, "command", return_value=active) as run:
            self.assertEqual(app.fresh_setup_readback(Path("/app/festival.exe"), managed, {})["service"], active)
            self.assertEqual(run.call_args.args[0], [managed / "bin" / ("obey.exe" if os.name == "nt" else "obey"), "service", "status", "--json"])
            for key in active:
                run.return_value = dict(active, **{key: False})
                with self.assertRaisesRegex(RuntimeError, "responsive"):
                    app.fresh_setup_readback(Path("/app/festival.exe"), managed, {})

    def test_fresh_nonwindows_waits_for_real_readback_and_retains_ui_boundary(self):
        import verify_app_candidate as app
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            report = {}
            process = Mock()
            process.poll.return_value = None
            def poll(description, predicate, seconds):
                self.assertEqual(seconds, 600)
                self.assertIsNone(predicate())
                self.assertIsNone(predicate())
                return predicate()
            with patch.object(app, "fresh_setup_readback", side_effect=[sqlite3.OperationalError("not created"), ValueError("not installed"), {"service": "live"}]), patch.object(app, "wait_until", side_effect=poll), patch.object(app, "capture_startup", return_value={"window": "retained"}) as capture:
                result = app.wait_fresh_setup(process, Path("/app/festival"), Path("/home/managed"), "x86_64-unknown-linux-gnu", output, {}, report, "fresh")
                self.assertEqual(result, {"service": "live"})
                self.assertTrue(report["rendered_setup_requires_image_review"])
                self.assertEqual(capture.call_args.args[2], output / "fresh")
                self.assertEqual(report["fresh_last_provisioning_error"], "not installed")
            process.poll.return_value = 1
            with patch.object(app, "wait_until", side_effect=lambda description, predicate, seconds: predicate()):
                with self.assertRaisesRegex(RuntimeError, "App exited"):
                    app.wait_fresh_setup(process, Path("/app/festival"), Path("/home/managed"), "x86_64-unknown-linux-gnu", output, {}, {}, "dead")

    def test_default_home_refuses_existing_state_or_environment_override(self):
        with tempfile.TemporaryDirectory() as name:
            home = Path(name)
            env = {"PATH": "/system/bin"}
            self.assertEqual(upgrade.default_home_layout(home, env), home / ".obey/installer")
            self.assertEqual(env, {"PATH": "/system/bin"})
            for key in ("FESTIVAL_HOME", "OBEY_INSTALLER_HOME", "OBEY_CONFIG", "OBEY_SOCKET", "OBEY_GRPC_SOCKET", "CAMP_HOME", "CAMP_REGISTRY_PATH", "CAMP_APP_CONTROL_ROOT", "XDG_CONFIG_HOME"):
                with self.assertRaisesRegex(RuntimeError, "overrides"):
                    upgrade.default_home_layout(home, dict(env, **{key: "/foreign"}))
            for suffix in (".obey", ".local/share/obey", ".config/camp"):
                existing = home / suffix
                existing.mkdir(parents=True)
                with self.assertRaisesRegex(RuntimeError, "preexisting"):
                    upgrade.default_home_layout(home, env)
                existing.rmdir()
            (home / ".obey").symlink_to(home / "absent")
            with self.assertRaisesRegex(RuntimeError, "preexisting"):
                upgrade.default_home_layout(home, env)

    def test_setup_window_must_leave_installation_screen(self):
        setup = {"visible_names": ["Getting this machine ready", "not found"]}
        update_dialog = {"visible_names": ["Update ready", "Restart now"]}
        license_window = {"visible_names": ["Licenses", "License key"]}
        report = {}
        def poll(description, predicate, seconds):
            self.assertEqual(seconds, 600)
            self.assertIsNone(predicate())
            self.assertIsNone(predicate())
            return predicate()
        with patch.object(upgrade.app, "window_capture", side_effect=[setup, update_dialog, license_window]), patch.object(upgrade, "wait_until", side_effect=poll):
            self.assertEqual(upgrade.wait_windows_setup(Mock(), "windows", Path("/output"), {}, report, "auto_restarted_b"), license_window)
        self.assertEqual(report["auto_restarted_b_setup_window"], license_window)

    def test_default_home_readback_rejects_missing_or_external_selected_tools(self):
        with patch.object(upgrade, "command", return_value={"ok": False}), patch.object(upgrade, "checked_receipts") as receipts:
            with self.assertRaisesRegex(ValueError, "status failed"):
                upgrade.default_home_readback(Path("/app/festival-app.exe"), Path("/home/.obey/installer"), {})
            receipts.assert_not_called()

    def test_public_inputs_require_five_formats_and_both_checksum_contracts(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            document = public_fixture(root)
            self.assertEqual(contract.checked_public(root, SOURCE, VERSION), document)
            original = (root / "latest.json").read_text()
            value = json.loads(original)
            value["platforms"].pop("linux-x86_64-deb")
            (root / "latest.json").write_text(json.dumps(value))
            refresh_metadata(root, "latest.json")
            with self.assertRaisesRegex(ValueError, "five platforms"):
                contract.checked_public(root, SOURCE, VERSION)
            (root / "latest.json").write_text(original)
            refresh_metadata(root, "latest.json")
            lines = (root / "SHA256SUMS").read_text().splitlines()
            (root / "SHA256SUMS").write_text("\n".join(lines[:-1]) + "\n")
            refresh_metadata(root, "SHA256SUMS")
            with self.assertRaisesRegex(ValueError, "original producer payloads"):
                contract.checked_public(root, SOURCE, VERSION)

    def test_renamed_identical_payloads_cannot_prove_an_upgrade(self):
        a = manifest()
        linux = a["targets"]["x86_64-unknown-linux-gnu"]
        linux.append(dict(next(item for item in linux if item["name"].endswith(".deb"))))
        linux[-1]["name"] += ".sig"
        b = copy.deepcopy(a)
        b.update(source_revision="b" * 40, version="0.1.1")
        for entries in b["targets"].values():
            for item in entries:
                item["name"] = item["name"].replace("0.1.0", "0.1.1")
        with self.assertRaisesRegex(ValueError, "distinct updater payload"):
            contract.checked_upgrade_pair(a, b)
        for entries in b["targets"].values():
            for item in entries:
                item["sha256"] = hashlib.sha256(b"new B bytes").hexdigest()
        contract.checked_upgrade_pair(a, b)
        b["version"] = a["version"]
        with self.assertRaisesRegex(ValueError, "increasing versions"):
            contract.checked_upgrade_pair(a, b)

    def test_public_source_draft_url_and_server_digest_fail_closed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            public_fixture(root)
            original = json.loads((root / "release.json").read_text())
            mutations = [lambda m: m.update(draft=True), lambda m: m.update(tag_name="app-stable"),
                         lambda m: m["assets"][0].update(browser_download_url="https://example.org/untrusted"),
                         lambda m: m["assets"][0].update(digest="sha256:" + "0" * 64),
                         lambda m: m["assets"].pop()]
            for mutate in mutations:
                metadata = copy.deepcopy(original)
                mutate(metadata)
                (root / "release.json").write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):
                    contract.checked_public(root, SOURCE, VERSION)

    def test_persisted_foreign_files_and_settings_must_survive(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            settings, foreign = root / "settings.json", root / "foreign.txt"
            settings.write_text('{"fontSize":17,"wordWrap":true}')
            foreign.write_text("preserved")
            snapshot = contract.persisted_snapshot([foreign])
            expected = {"fontSize": 17, "wordWrap": True}
            contract.verify_persisted(snapshot, settings, expected)
            settings.write_text('{"fontSize":13,"wordWrap":true}')
            with self.assertRaisesRegex(ValueError, "settings"):
                contract.verify_persisted(snapshot, settings, expected)
            foreign.write_text("changed")
            with self.assertRaisesRegex(ValueError, "foreign file"):
                contract.verify_persisted(snapshot, settings, expected)

    def test_selected_receipt_timestamp_is_ignored_but_identity_and_bytes_are_not(self):
        document = {"receipts": [{"package_id": "package", "version": "1", "source": "official-obey", "channel": "stable", "updated": 1}],
                    "files": [{"receipt_pkg_id": "package", "path": "/owned/tool", "hash": "a" * 64}]}
        other = copy.deepcopy(document)
        other["receipts"][0]["updated"] = 2
        self.assertEqual(upgrade.component_identity(document), upgrade.component_identity(other))
        other["files"][0]["hash"] = "b" * 64
        self.assertNotEqual(upgrade.component_identity(document), upgrade.component_identity(other))
        with patch.object(upgrade, "checked_receipts", return_value=other), patch.object(upgrade, "verify_persisted") as readback:
            with self.assertRaisesRegex(ValueError, "selected package"):
                upgrade.retained_state({"managed_home": Path("/owned"), "receipts": document}, {})
            readback.assert_not_called()

    def test_windows_post_update_process_rejects_pid_reuse(self):
        identity = {"pid": 100, "started": "10001", "path": "owned.exe"}
        process = upgrade.ObservedWindowsProcess(identity, {})
        with patch.object(upgrade, "windows_query", return_value=identity):
            self.assertIsNone(process.poll())
        with patch.object(upgrade, "windows_query", return_value=dict(identity, started="10002")):
            self.assertEqual(process.poll(), 0)

    def test_payload_replacement_and_nsis_escape_fail(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            expected, actual = root / "expected", root / "actual"
            expected.mkdir(); actual.mkdir()
            for directory in (expected, actual):
                (directory / "festival-app.exe").write_text("B")
                (directory / "festival-activity-engine.exe").write_text("engine")
                (directory / "festival.exe").write_text("installer")
            upgrade.check_nsis_payload(actual, expected)
            (actual / "festival-app.exe").write_text("A")
            with self.assertRaisesRegex(ValueError, "authenticated B"):
                upgrade.check_nsis_payload(actual, expected)
            with patch.object(upgrade, "command", return_value="header\n----------\nPath = ../escape\n") as command:
                with self.assertRaisesRegex(ValueError, "unsafe NSIS"):
                    upgrade.nsis_reference(root / "B.exe", root / "extract", {})
                self.assertEqual(command.call_count, 1)

    def test_native_resolves_relative_inputs_before_debian_package_lookup(self):
        with patch.object(upgrade, "require_clean_host"), patch.object(upgrade, "native_platform", return_value="linux/amd64"), patch.object(upgrade, "checked_public", side_effect=RuntimeError("stop after input lookup")) as checked:
            with self.assertRaisesRegex(RuntimeError, "stop after input lookup"):
                upgrade.native(Path("relative-input"), "x86_64-unknown-linux-gnu", "deb", SOURCE, VERSION, "b" * 40, "0.1.1", Path("relative-report"))
            self.assertEqual(checked.call_args.args[0], Path("relative-input/a").resolve())
            self.assertTrue(checked.call_args.args[0].is_absolute())

    def test_native_operator_guard_precedes_fixture_or_installer(self):
        with patch.object(upgrade, "require_clean_host", side_effect=RuntimeError("operator forbidden")), patch.object(upgrade, "bootstrap_fixture") as seed:
            with self.assertRaisesRegex(RuntimeError, "operator forbidden"):
                upgrade.native(Path("unused"), "x86_64-unknown-linux-gnu", "deb", SOURCE, VERSION, "b" * 40, "0.1.1", Path("unused-output"))
            seed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
