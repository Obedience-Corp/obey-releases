"""Published stable App release contracts; filesystem mutations require Docker."""
import copy
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import Mock, patch

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists():
    raise RuntimeError("stable release filesystem tests require Docker")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import app_upgrade_contract as contract
import verify_app_candidate as app
import verify_app_upgrade as upgrade
from test_app_candidate import manifest, SOURCE, VERSION
from test_app_upgrade import refresh_metadata

BASE = "https://github.com/" + contract.REPOSITORY + "/releases/download/"


def stable_names(version):
    document = manifest()
    linux = document["targets"]["x86_64-unknown-linux-gnu"]
    linux.append(dict(next(item for item in linux if item["name"].endswith(".deb"))))
    linux[-1]["name"] += ".sig"
    names = [entry["name"].replace(" ", ".").replace(VERSION, version) for entries in document["targets"].values() for entry in entries]
    return names


def stable_fixture(root, version=VERSION, payload=b"payload"):
    assets = root / "assets"
    assets.mkdir()
    tag = "app-v" + version
    names = stable_names(version)
    for name in names:
        (assets / name).write_bytes(payload)
    (root / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(payload).hexdigest()}  {name}\n" for name in names if not name.endswith(".sig")))
    platforms = {}
    for key, (target, suffix) in contract.PLATFORMS.items():
        name = next(n for n in names if n.endswith(suffix) and contract.stable_target(n) == target)
        platforms[key] = {"url": BASE + f"{tag}/{name}", "signature": payload.decode()}
    (root / "latest.json").write_text(json.dumps({"version": version, "platforms": platforms}))
    metadata = {"draft": False, "prerelease": False, "tag_name": tag, "assets": []}
    for path in [*assets.iterdir(), root / "latest.json", root / "SHA256SUMS"]:
        metadata["assets"].append({"name": path.name, "size": path.stat().st_size, "digest": "sha256:" + contract.sha256(path),
                                   "browser_download_url": BASE + f"{tag}/{path.name}"})
    (root / "release.json").write_text(json.dumps(metadata))


def edit_metadata(root, change):
    metadata = json.loads((root / "release.json").read_text())
    change(metadata)
    (root / "release.json").write_text(json.dumps(metadata))


class StableRelease(unittest.TestCase):
    def fixture(self, version=VERSION):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        stable_fixture(root, version)
        return root

    def test_stable_release_checks_without_candidate_inventory(self):
        root = self.fixture()
        document = contract.checked_public(root, "stable", VERSION)
        self.assertEqual((document["source_revision"], document["release_tag"], document["installer_basename"]),
                         ("stable", "app-v0.1.0", "festival-app-installer"))
        self.assertEqual(set(document["targets"]), set(app.TARGETS))
        names = {item["name"] for entries in document["targets"].values() for item in entries}
        self.assertIn("Festival.App_0.1.0_aarch64.dmg", names)
        self.assertIn("Festival.App_0.1.0_x64.dmg", names)
        self.assertFalse(any(name.endswith(".dmg.sig") for name in names))
        digest = hashlib.sha256(b"payload").hexdigest()
        for entries in document["targets"].values():
            for item in entries:
                self.assertEqual((item["sha256"], item["bytes"]), (digest, 7))
        app.checked_manifest(document, VERSION, "stable")
        self.assertEqual(app.installer_basename(document), "festival-app-installer")

    def test_stable_release_refusals(self):
        def remove(name):
            def change(root):
                (root / "assets" / name).unlink()
                edit_metadata(root, lambda m: m.update(assets=[a for a in m["assets"] if a["name"] != name]))
            return change

        def extra(root):
            (root / "assets" / "notes.txt").write_text("notes")
            edit_metadata(root, lambda m: m["assets"].append({
                "name": "notes.txt", "size": 5, "digest": "sha256:" + contract.sha256(root / "assets" / "notes.txt"),
                "browser_download_url": BASE + "app-v0.1.0/notes.txt"}))

        def bad_signature(root):
            latest = json.loads((root / "latest.json").read_text())
            latest["platforms"]["linux-x86_64"]["signature"] = "other"
            (root / "latest.json").write_text(json.dumps(latest))
            refresh_metadata(root, "latest.json")

        def bad_version(root):
            latest = json.loads((root / "latest.json").read_text())
            latest["version"] = "0.1.1"
            (root / "latest.json").write_text(json.dumps(latest))
            refresh_metadata(root, "latest.json")

        def bad_sum(root):
            lines = (root / "SHA256SUMS").read_text().splitlines()
            lines[0] = "0" * 64 + lines[0][64:]
            (root / "SHA256SUMS").write_text("\n".join(lines) + "\n")
            refresh_metadata(root, "SHA256SUMS")

        sig = next(n for n in stable_names(VERSION) if n.endswith(".app.tar.gz.sig"))
        cases = [
            ("prerelease", lambda r: edit_metadata(r, lambda m: m.update(prerelease=True)), "exact published immutable stable release"),
            ("draft", lambda r: edit_metadata(r, lambda m: m.update(draft=True)), "exact published immutable stable release"),
            ("test tag", lambda r: edit_metadata(r, lambda m: m.update(tag_name="app-test-" + SOURCE)), "exact published immutable stable release"),
            ("latest version", bad_version, "exact version and all five platforms"),
            ("extra asset", extra, "unexpected or missing assets"),
            ("missing signature", remove(sig), "unexpected or missing assets"),
            ("manifest signature", bad_signature, "manifest URL/signature"),
            ("sums digest", bad_sum, "differs from published payload bytes"),
        ]
        for label, mutate, message in cases:
            with self.subTest(label):
                root = self.fixture()
                mutate(root)
                with self.assertRaisesRegex(ValueError, message):
                    contract.checked_public(root, "stable", VERSION)
        with self.assertRaisesRegex(ValueError, "invalid stable App version"):
            contract.checked_public(self.fixture(), "stable", "0.1")

    def test_fetch_public_stable_downloads_into_checked_layout(self):
        src = self.fixture()
        target = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, target, True)
        urls = []

        def fake(url, destination, limit, **kwargs):
            urls.append(url)
            name = url.rsplit("/", 1)[1]
            if url.startswith("https://api.github.com/"):
                source = src / "release.json"
            elif name in ("latest.json", "SHA256SUMS"):
                source = src / name
            else:
                source = src / "assets" / name
            with destination.open("xb") as stream:
                stream.write(source.read_bytes())

        with patch.object(contract, "anonymous_download", fake):
            document = contract.fetch_public(target / "public", "stable", VERSION)
            self.assertEqual(document["source_revision"], "stable")
            self.assertEqual(urls[0], "https://api.github.com/repos/Obedience-Corp/obey-releases/releases/tags/app-v0.1.0")
            self.assertFalse(any("app-test-" in url for url in urls))
            count = len(urls)
            with self.assertRaises(ValueError):
                contract.fetch_public(target / "bad", "stable", "0.1")
            self.assertEqual(len(urls), count)

    def stable_document(self, version, payload):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        stable_fixture(root, version, payload)
        return contract.checked_public(root, "stable", version)

    def test_upgrade_pair_accepts_test_a_and_stable_b(self):
        a = manifest()
        linux = a["targets"]["x86_64-unknown-linux-gnu"]
        linux.append(dict(next(item for item in linux if item["name"].endswith(".deb"))))
        linux[-1]["name"] += ".sig"
        b = self.stable_document("0.1.1", b"other!!")
        contract.checked_upgrade_pair(a, b)
        old = self.stable_document("0.1.0", b"payload")
        with self.assertRaisesRegex(ValueError, "increasing versions"):
            contract.checked_upgrade_pair(a, old)
        contract.checked_upgrade_pair(old, b)
        with self.assertRaisesRegex(ValueError, "distinct sources and increasing versions"):
            contract.checked_upgrade_pair(b, copy.deepcopy(b))

    def test_release_tag_keeps_test_identity(self):
        self.assertEqual(contract.release_tag(SOURCE, VERSION), "app-test-" + SOURCE)
        self.assertEqual(contract.release_tag("stable", VERSION), "app-v0.1.0")
        for args in (("A" * 40, VERSION), ("stable", "1.0"), ("main", VERSION)):
            with self.assertRaises(ValueError):
                contract.release_tag(*args)

    def test_published_stable_uses_fresh_chooser_readiness(self):
        with patch.object(app, "wait_windows_fresh_chooser", return_value={}) as chooser, \
                patch.object(upgrade, "wait_windows_setup") as historical, patch.object(app, "fresh_setup_readback", return_value={}):
            app.wait_fresh_setup(Mock(), Path("/installer"), Path("/managed"), "x86_64-pc-windows-msvc", Path("/proof"), {},
                                 {"input_kind": "published-stable"}, "fresh")
            chooser.assert_called_once()
            historical.assert_not_called()

    def test_stable_retained_inputs_skip_candidate_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public"
            (public / "assets").mkdir(parents=True)
            for name in ("release.json", "SHA256SUMS", "latest.json"):
                (public / name).write_text(name)
            app.retain_public_inputs(public, root / "stable-out", {"source_revision": "stable"})
            self.assertEqual({p.name for p in (root / "stable-out").iterdir()}, {"release.json", "SHA256SUMS", "latest.json"})
            with self.assertRaises(FileNotFoundError):
                app.retain_public_inputs(public, root / "test-out", {"source_revision": SOURCE})
            for name in ("app-candidate.json", "checksums.txt"):
                (public / "assets" / name).write_text(name)
            app.retain_public_inputs(public, root / "test-out2", {"source_revision": SOURCE})
            self.assertEqual(len(list((root / "test-out2").iterdir())), 5)

    def test_stable_fresh_setup_refuses_seeded_modes(self):
        document = {"source_revision": "stable", "version": VERSION, "targets": {}}
        with patch.object(app, "require_clean_host"), patch.object(app, "native_platform", return_value="linux/amd64"), \
                patch.dict(os.environ, {}, clear=True):
            for options in ({"existing_user": "current"}, {"login_shell_proof": True}):
                with self.subTest(options):
                    with self.assertRaisesRegex(ValueError, "stable fresh setup requires unseeded default-home mode"):
                        app.native(Path("/x"), document, "x86_64-unknown-linux-gnu", Path("/out"),
                                   fresh_setup=True, public_root=Path("/p"), **{"existing_user": "none", **options})

    def test_stable_b_allows_updater_free_workspace(self):
        contract.checked_upgrade_selection("updater", "none", None, "free-workspace", "stable")

    def test_draft_still_requires_manual(self):
        with self.assertRaisesRegex(ValueError, "requires manual replacement"):
            contract.checked_upgrade_selection("updater", "none", "candidate-tag", "free-workspace", "stable")

    def test_test_b_free_workspace_updater_still_refused(self):
        with self.assertRaisesRegex(ValueError, "requires manual replacement"):
            contract.checked_upgrade_selection("updater", "none", None, "free-workspace", SOURCE)


if __name__ == "__main__":
    unittest.main()
