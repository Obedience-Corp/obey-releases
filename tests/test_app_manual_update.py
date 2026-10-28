"""Manual package replacement and failure preservation, in disposable storage."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists():
    raise RuntimeError("manual update filesystem tests require Docker")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import app_manual_update as manual
import verify_app_upgrade as upgrade


class ManualUpdate(unittest.TestCase):
    def test_appimage_replaces_owned_app_but_preserves_source_and_neighbors(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            assets = root / "assets"; assets.mkdir()
            source = assets / "B.AppImage"; source.write_bytes(b"B payload")
            binary = root / "App.AppImage"; binary.write_bytes(b"A payload")
            keep = root / "settings.json"; keep.write_bytes(b"user settings")
            doc = {"targets": {"linux": [{"name": source.name}]}}
            manual.install("appimage", binary, None, root, doc, "linux", root, {})
            self.assertEqual(binary.read_bytes(), source.read_bytes())
            self.assertEqual(source.read_bytes(), b"B payload")
            self.assertEqual(keep.read_bytes(), b"user settings")
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
            binary.unlink(); binary.symlink_to(keep)
            with self.assertRaisesRegex(ValueError, "regular App"):
                manual.install("appimage", binary, None, root, doc, "linux", root, {})
            self.assertEqual(keep.read_bytes(), b"user settings")

    def test_failed_mac_placement_restores_the_original_bundle(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = root / "installed/Festival App.app"
            binary = bundle / "Contents/MacOS/festival-app"
            binary.parent.mkdir(parents=True); binary.write_bytes(b"A")
            replacement = root / "staged/Festival App.app/Contents/MacOS/festival-app"
            replacement.parent.mkdir(parents=True); replacement.write_bytes(b"B")
            doc = {"version": "0.1.3", "installer_basename": "festival-app-installer",
                   "targets": {"mac": [{"name": "B.dmg"}]}}
            original_rename = Path.rename
            def fail_placement(path, target):
                if path == replacement.parent.parent.parent:
                    raise OSError("placement failed")
                return original_rename(path, target)
            with patch.object(manual.app, "mac_install", return_value=(replacement, None, None)), patch.object(Path, "rename", autospec=True, side_effect=fail_placement):
                with self.assertRaisesRegex(OSError, "placement failed"):
                    manual.install("dmg", binary, bundle, root, doc, "mac", root, {})
            self.assertEqual(binary.read_bytes(), b"A")
            self.assertEqual(replacement.read_bytes(), b"B")

    def test_installer_failure_propagates_for_deb_and_nsis(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); binary = root / "festival-app"; binary.write_bytes(b"A")
            for package_format, filename, function in (("deb", "B.deb", "install_deb"), ("nsis", "B-setup.exe", "windows_silent")):
                doc = {"targets": {"target": [{"name": filename}]}}
                with patch.object(manual.app, function, side_effect=RuntimeError("installer failed")) as run:
                    with self.assertRaisesRegex(RuntimeError, "installer failed"):
                        manual.install(package_format, binary, None, root, doc, "target", root, {})
                    self.assertEqual(run.call_args.args[0], root / "assets" / filename)

    def test_manual_mode_refuses_updater_failure_claim_before_reading_inputs(self):
        with patch.object(upgrade, "require_clean_host"), patch.object(upgrade, "checked_public") as read:
            with self.assertRaisesRegex(ValueError, "cannot claim updater"):
                upgrade.native(Path("unused"), "x86_64-pc-windows-msvc", "nsis", "a" * 40, "0.1.2", "b" * 40, "0.1.3", Path("output"), failure_mode="offline-check", mechanism="manual")
            read.assert_not_called()
