"""Malformed candidate tests run only in the disposable container harness."""
import copy
import contextlib
import json
import shutil
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists():
    raise RuntimeError("filesystem candidate tests require the Docker harness")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_candidate
from verify_candidate import TARGETS, checked_build_info, checked_manifest, checked_payloads, checked_request, require_disposable

SOURCE = "a" * 40
VERSION = "0.2.2"


class CandidateContracts(unittest.TestCase):
    def test_embedded_build_source_must_match_even_when_cli_stamp_would_match(self):
        values = {"vcs": "git", "vcs.revision": SOURCE, "vcs.modified": "false",
                  "CGO_ENABLED": "1", "GOOS": "windows", "GOARCH": "arm64"}
        def document(settings):
            return {"Settings": [{"Key": key, "Value": value} for key, value in settings.items()]}
        checked_build_info(document(values), SOURCE, "windows-arm64")
        for key, wrong in (("vcs.revision", "c" * 40), ("vcs.modified", "true"),
                           ("CGO_ENABLED", "0"), ("GOOS", "linux"),
                           ("GOARCH", "amd64"), ("vcs", "hg")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                checked_build_info(document(dict(values, **{key: wrong})), SOURCE, "windows-arm64")
            missing = dict(values)
            missing.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                checked_build_info(document(missing), SOURCE, "windows-arm64")
        duplicate = document(values)
        duplicate["Settings"].append({"Key": "vcs.revision", "Value": SOURCE})
        with self.assertRaises(ValueError):
            checked_build_info(duplicate, SOURCE, "windows-arm64")

    def manifest(self):
        return {"schema": "obey-candidate/v1", "version": VERSION, "source_revision": SOURCE,
                "artifacts": [{"filename": f"obey-{VERSION}-{target}.tar.gz", "sha256": "b" * 64} for target in TARGETS]}

    def test_exact_identity_and_all_targets_required(self):
        self.assertEqual(checked_request("candidate-obey-v0.2.2-aaaaaaaa", VERSION, SOURCE, "windows-arm64"), "obey-0.2.2-windows-arm64.tar.gz")
        for tag, version, source, target in [("v0.2.2", VERSION, SOURCE, "windows-arm64"), ("candidate-obey-v0.2.2-aaaaaaaa", "../../v", SOURCE, "windows-arm64"), ("candidate-obey-v0.2.2-aaaaaaaa", VERSION, "a" * 8, "windows-arm64"), ("candidate-obey-v0.2.2-aaaaaaaa", VERSION, SOURCE, "windows-unknown")]:
            with self.subTest(target=target, tag=tag), self.assertRaises(ValueError):
                checked_request(tag, version, source, target)
        self.assertEqual(len(checked_manifest(self.manifest(), VERSION, SOURCE)), 6)
        for mutate in (lambda m: m["artifacts"].pop(), lambda m: m["artifacts"].append(m["artifacts"][0]), lambda m: m.update(source_revision="c" * 40), lambda m: m["artifacts"][0].update(sha256="not-a-hash")):
            document = copy.deepcopy(self.manifest())
            mutate(document)
            with self.assertRaises(ValueError):
                checked_manifest(document, VERSION, SOURCE)

    def archive(self, directory, names=("obey", "ob", "LICENSE"), link=False, executable=True):
        archive = directory / "candidate.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for index, name in enumerate(names):
                member = tarfile.TarInfo(name)
                member.mode = 0o755 if executable else 0o644
                data = b"candidate bytes"
                if link and index == 0:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/outside-owned-fixture"
                    output.addfile(member)
                else:
                    member.size = len(data)
                    output.addfile(member, io.BytesIO(data))
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def test_payload_inventory_and_digest_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, digest = self.archive(root)
            self.assertEqual(set(checked_payloads(archive, digest, False)), {"obey", "ob", "LICENSE"})
            with self.assertRaises(ValueError):
                checked_payloads(archive, "0" * 64, False)
            for names in [("../obey", "ob", "LICENSE"), ("obey", "ob", "ob", "LICENSE"), ("obey", "LICENSE"), ("obey", "ob", "LICENSE", "unreviewed")]:
                archive, digest = self.archive(root, names)
                with self.assertRaises(ValueError):
                    checked_payloads(archive, digest, False)
            for option in ({"link": True}, {"executable": False}):
                archive, digest = self.archive(root, **option)
                with self.assertRaises(ValueError):
                    checked_payloads(archive, digest, False)
            archive, digest = self.archive(root, ("obey.exe", "ob.exe", "LICENSE"), executable=False)
            self.assertEqual(set(checked_payloads(archive, digest, True)), {"obey.exe", "ob.exe", "LICENSE"})

    def bundle(self, directory):
        artifacts = []
        for target in TARGETS:
            suffix = ".exe" if target.startswith("windows-") else ""
            archive, digest = self.archive(directory, ("obey" + suffix, "ob" + suffix, "LICENSE"))
            filename = f"obey-{VERSION}-{target}.tar.gz"
            archive.rename(directory / filename)
            artifacts.append({"filename": filename, "sha256": digest})
        (directory / "candidate.json").write_text(json.dumps({"schema": "obey-candidate/v1", "version": VERSION, "source_revision": SOURCE, "artifacts": artifacts}))
        (directory / "checksums.txt").write_text("".join(item["sha256"] + "  " + item["filename"] + "\n" for item in artifacts))

    def test_privileged_fetch_validates_data_without_native_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixtures = root / "fixtures"
            fixtures.mkdir()
            self.bundle(fixtures)
            expected = {path.name for path in fixtures.iterdir()}
            metadata = {"isDraft": True, "assets": [{"name": name} for name in expected]}
            def inspect(arguments, **kwargs):
                self.assertEqual(arguments[:3], ["gh", "release", "view"])
                return json.dumps(metadata)
            def download(arguments, **kwargs):
                self.assertEqual(arguments[:3], ["gh", "release", "download"])
                wanted = {arguments[index + 1] for index, value in enumerate(arguments) if value == "--pattern"}
                self.assertEqual(wanted, expected)
                destination = Path(arguments[arguments.index("--dir") + 1])
                for filename in wanted:
                    shutil.copy2(fixtures / filename, destination / filename)
            environment = {"CANDIDATE_RUNNER_KIND": "github-hosted", "GITHUB_REPOSITORY": verify_candidate.REPOSITORY, "GH_TOKEN": "test-download-only-token"}
            arguments = ["verify_candidate.py", "--mode", "fetch", "--tag", "candidate-obey-v0.2.2-aaaaaaaa", "--version", VERSION, "--source", SOURCE, "--directory", str(root / "download")]
            with patch.dict(os.environ, environment, clear=True), patch.object(sys, "argv", arguments), patch("verify_candidate.subprocess.check_output", side_effect=inspect), patch("verify_candidate.subprocess.run", side_effect=download), patch("verify_candidate.native_proof", side_effect=AssertionError("fetch must not execute candidates")) as native:
                verify_candidate.main()
                native.assert_not_called()
            self.assertEqual({path.name for path in (root / "download").iterdir()}, expected)

    def test_native_mode_uses_artifacts_without_download_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "candidate"
            data.mkdir()
            self.bundle(data)
            environment = {"CANDIDATE_RUNNER_KIND": "github-hosted", "CANDIDATE_NATIVE_DISPOSABLE": "1", "GITHUB_REPOSITORY": verify_candidate.REPOSITORY}
            arguments = ["verify_candidate.py", "--mode", "verify", "--tag", "candidate-obey-v0.2.2-aaaaaaaa", "--version", VERSION, "--source", SOURCE, "--target", "windows-arm64", "--directory", str(data)]
            with contextlib.chdir(root), patch.dict(os.environ, environment, clear=True), patch.object(sys, "argv", arguments), patch("verify_candidate.subprocess.check_output", side_effect=AssertionError("native must not fetch draft")) as github, patch("verify_candidate.native_proof", return_value={"test_transport_only": True}) as native:
                verify_candidate.main()
                github.assert_not_called()
                native.assert_called_once()
            for token in ("GH_TOKEN", "GITHUB_TOKEN"):
                with patch.dict(os.environ, dict(environment, **{token: "test-download-only-token"}), clear=True), patch.object(sys, "argv", arguments), patch("verify_candidate.native_proof") as native, self.assertRaisesRegex(RuntimeError, "download credential"):
                    verify_candidate.main()
                native.assert_not_called()

    def test_no_native_mutation_on_an_unproven_runner(self):
        for environment in ({}, {"CANDIDATE_NATIVE_DISPOSABLE": "1", "CANDIDATE_RUNNER_KIND": "self-hosted"}):
            with patch.dict(os.environ, environment, clear=True), self.assertRaises(RuntimeError):
                require_disposable()
        with patch.dict(os.environ, {"CANDIDATE_NATIVE_DISPOSABLE": "1", "CANDIDATE_RUNNER_KIND": "github-hosted"}, clear=True):
            require_disposable()


if __name__ == "__main__":
    unittest.main()
