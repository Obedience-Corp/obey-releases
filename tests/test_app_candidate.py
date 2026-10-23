"""App candidate mutations run only in the existing disposable Docker harness."""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists():
    raise RuntimeError("App filesystem tests require Docker")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_app_candidate as app
from assemble_app_candidate import assemble

VERSION, SOURCE = "0.1.0", "a" * 40


def manifest():
    targets = {}
    for target, (_, suffixes) in app.TARGETS.items():
        arch = "aarch64" if target.startswith("aarch64") else "x64" if target.endswith(("apple-darwin", "windows-msvc")) else "amd64"
        targets[target] = [{"name": f"Festival App_{VERSION}_{arch}{suffix}", "sha256": hashlib.sha256(b"payload").hexdigest(), "bytes": 7} for suffix in suffixes]
    return {"schema": "festival-app-candidate/v1", "version": VERSION, "source_revision": SOURCE, "targets": targets}


class AppContracts(unittest.TestCase):
    def test_inventory_identity_missing_architecture_and_duplicate_fail_closed(self):
        self.assertEqual(len(app.checked_manifest(manifest(), VERSION, SOURCE)), 11)
        mutations = [lambda m: m.update(source_revision="b" * 40),
                     lambda m: m["targets"].pop("aarch64-apple-darwin"),
                     lambda m: m["targets"]["x86_64-pc-windows-msvc"].pop(),
                     lambda m: m["targets"]["x86_64-pc-windows-msvc"][0].update(name="../../outside.exe"),
                     lambda m: m["targets"]["x86_64-pc-windows-msvc"][0].update(name="Festival App_0.1.0_arm64-setup.exe"),
                     lambda m: m["targets"]["x86_64-unknown-linux-gnu"][0].update(sha256="invalid")]
        for mutation in mutations:
            document = manifest()
            mutation(document)
            with self.assertRaises(ValueError):
                app.checked_manifest(document, VERSION, SOURCE)
        with self.assertRaises(ValueError):
            app.identity("app-stable", VERSION, SOURCE)
        app.identity("candidate-app-v0.1.0-aaaaaaaa", VERSION, SOURCE)

    def test_optional_deb_signature_retains_exact_declared_inventory(self):
        document = manifest()
        entries = document["targets"]["x86_64-unknown-linux-gnu"]
        deb = next(item for item in entries if item["name"].endswith(".deb"))
        entries.append(dict(deb, name=deb["name"] + ".sig"))
        self.assertEqual(len(app.checked_manifest(document, VERSION, SOURCE)), 12)
        entries.append(copy.deepcopy(deb))
        with self.assertRaises(ValueError):
            app.checked_manifest(document, VERSION, SOURCE)

    def test_downloaded_bytes_checksums_and_symlinks_are_checked_again(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            document = manifest()
            files = app.checked_manifest(document, VERSION, SOURCE)
            (root / "app-candidate.json").write_text(json.dumps(document))
            (root / "checksums.txt").write_text("".join(f"{item['sha256']}  {filename}\n" for filename, item in files.items()))
            for filename in files:
                (root / filename).write_bytes(b"payload")
            app.checked_downloads(root, VERSION, SOURCE)
            selected = root / next(iter(files))
            selected.write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                app.checked_downloads(root, VERSION, SOURCE)
            selected.unlink()
            selected.symlink_to("checksums.txt")
            with self.assertRaises(ValueError):
                app.checked_downloads(root, VERSION, SOURCE)

    def test_safe_archive_refuses_escape_link_and_duplicate(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for unsafe in ("../outside", "Festival App.app/../../outside", "Festival App.app/link"):
                archive = root / "bundle.tar.gz"
                with tarfile.open(archive, "w:gz") as stream:
                    item = tarfile.TarInfo(unsafe)
                    if unsafe.endswith("link"):
                        item.type, item.linkname = tarfile.SYMTYPE, "/outside"
                        stream.addfile(item)
                    else:
                        item.size = 1
                        stream.addfile(item, io.BytesIO(b"x"))
                destination = root / ("extract" + str(len(unsafe)))
                destination.mkdir(exist_ok=True)
                with self.assertRaises((ValueError, tarfile.FilterError)):
                    app.extract_app(archive, destination)
            self.assertFalse((root / "outside").exists())

    def test_signature_uses_pinned_production_trust_not_manifest_input(self):
        self.assertEqual(app.PUBLIC_KEY, "RWTlKfGG4A6IoCRsFpbcpf2yJ7v0D5CFRb17f8gK/n3LWdd9x1NKA+ms")
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            signature = root / "bundle.sig"
            signature.write_bytes(base64.b64encode(b"actual minisign content") + b"\n")
            with patch.object(app, "command") as command:
                app.verify_signature(root / "bundle", signature, root, {})
            arguments = command.call_args.args[0]
            self.assertEqual(arguments[arguments.index("-P") + 1], app.PUBLIC_KEY)
            signature.write_bytes(b"invalid!")
            with self.assertRaises(ValueError):
                app.verify_signature(root / "bundle", signature, root, {})

    def test_optional_deb_signature_is_checked_when_present_and_bad_fails(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            deb = root / "app.deb"
            with patch.object(app, "verify_signature") as verify:
                self.assertFalse(app.verify_optional_signature(deb, root, {}))
                verify.assert_not_called()
            signature = root / "app.deb.sig"
            signature.write_bytes(b"present")
            with patch.object(app, "verify_signature") as verify:
                self.assertTrue(app.verify_optional_signature(deb, root, {}))
                verify.assert_called_once_with(deb, signature, root, {})
            with patch.object(app, "verify_signature", side_effect=RuntimeError("bad deb signature")):
                with self.assertRaisesRegex(RuntimeError, "bad deb signature"):
                    app.verify_optional_signature(deb, root, {})

    def test_native_guard_runs_before_any_mutation_or_binary(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(app, "verify_signature") as signature:
            with self.assertRaises(RuntimeError):
                app.native(Path("unused"), manifest(), "x86_64-unknown-linux-gnu", Path("must-not-exist"))
            signature.assert_not_called()
            self.assertFalse(Path("must-not-exist").exists())

    def test_signature_failure_retains_partial_report_and_false_acceptance(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with patch.object(app, "require_clean_host"), patch.object(app, "native_platform", return_value="linux/amd64"), patch.object(app, "verify_signature", side_effect=ValueError("foreign key")), patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                with self.assertRaisesRegex(ValueError, "foreign key"):
                    app.native(root, manifest(), "x86_64-unknown-linux-gnu", root / "report")
            report = json.loads((root / "report/proof.json").read_text())
            self.assertEqual(report["failure"], "foreign key")
            self.assertFalse(report["first_use_complete"])
            self.assertFalse(report["native_packaging_launch_verified"])
            self.assertEqual(list(root.glob("app-proof-*")), [])

    def test_preexisting_windows_install_is_never_uninstalled(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            existing = root / "Festival App"
            existing.mkdir()
            (existing / "uninstall.exe").write_bytes(b"user installation")
            with patch.object(app, "require_clean_host"), patch.object(app, "native_platform", return_value="windows/amd64"), patch.object(app, "verify_signature"), patch.object(app, "windows_silent") as install, patch.dict(os.environ, {"RUNNER_TEMP": str(root), "LOCALAPPDATA": str(root)}):
                with self.assertRaisesRegex(RuntimeError, "preexisting App"):
                    app.native(root, manifest(), "x86_64-pc-windows-msvc", root / "report")
                install.assert_not_called()
            self.assertEqual((existing / "uninstall.exe").read_bytes(), b"user installation")

    def test_assembler_preserves_bytes_and_rejects_mixed_source_or_reuse(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            directories = []
            for target, entries in manifest()["targets"].items():
                directory = root / target
                directory.mkdir()
                directories.append(directory)
                for item in entries:
                    (directory / item["name"]).write_bytes(b"payload")
                (directory / f"candidate-{target}.json").write_text(json.dumps({"source": SOURCE, "target": target, "version": VERSION, "files": entries}))
            result = assemble(directories, root / "staged")
            self.assertEqual(result["source_revision"], SOURCE)
            for entries in result["targets"].values():
                for item in entries:
                    self.assertNotIn(" ", item["name"])
                    self.assertIn("original_name", item)
                    self.assertEqual((root / "staged" / item["name"]).read_bytes(), b"payload")
            with self.assertRaises(FileExistsError):
                assemble(directories, root / "staged")
            inventory = next(directories[-1].glob("candidate-*.json"))
            document = json.loads(inventory.read_text())
            document["source"] = "b" * 40
            inventory.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "different source"):
                assemble(directories, root / "mixed")
            self.assertFalse((root / "mixed").exists())

    def test_extracted_success_cannot_replace_failed_default_appimage(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            default, extracted = Mock(), Mock()
            default.poll.return_value = 1
            report = {}
            with patch.object(app.subprocess, "Popen", side_effect=[default, extracted]), patch.object(app, "window_capture", side_effect=[RuntimeError("libfuse missing"), {"window_id": "owned"}]), patch.object(app, "stop_owned") as cleanup:
                with self.assertRaisesRegex(RuntimeError, "diagnostic only"):
                    app.appimage_proof(root / "download.AppImage", root / "AppRun", "x86_64-unknown-linux-gnu", root, {}, report)
            self.assertFalse(report["appimage_default_launch_verified"])
            self.assertEqual(report["appimage_default_failure"], "libfuse missing")
            self.assertTrue(report["appimage_extracted_diagnostic_only"])
            self.assertEqual(cleanup.call_count, 2)

    def test_cleanup_never_signals_already_exited_process(self):
        process = Mock()
        process.poll.return_value = 0
        with patch.object(app.os, "killpg") as signal_group, patch.object(app, "command") as command:
            app.stop_owned(process, {})
        signal_group.assert_not_called()
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
