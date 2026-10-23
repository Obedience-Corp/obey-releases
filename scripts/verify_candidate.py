"""Verify unpublished binary candidates on disposable native GitHub runners.

This is distribution automation, not Obey implementation or private test source.
It accepts only the six declared targets and never publishes a release.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import subprocess
import tarfile
import tempfile
import time

TARGETS = {
    "macOS-arm64": "darwin/arm64", "macOS-x86_64": "darwin/amd64",
    "linux-arm64": "linux/arm64", "linux-x86_64": "linux/amd64",
    "windows-arm64": "windows/arm64", "windows-x86_64": "windows/amd64",
}
REPOSITORY = "Obedience-Corp/obey-releases"


def checked_request(tag, version, source, target):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("invalid candidate version")
    if not re.fullmatch(r"[0-9a-f]{40}", source) or target not in TARGETS:
        raise ValueError("invalid source revision or target")
    if tag != f"candidate-obey-v{version}-{source[:8]}":
        raise ValueError("candidate tag must match version and source")
    return f"obey-{version}-{target}.tar.gz"


def checked_manifest(document, version, source):
    if document.get("schema") != "obey-candidate/v1" or document.get("version") != version or document.get("source_revision") != source:
        raise ValueError("candidate identity mismatch")
    artifacts = document.get("artifacts", [])
    expected = {f"obey-{version}-{target}.tar.gz" for target in TARGETS}
    if len(artifacts) != 6 or {item.get("filename") for item in artifacts} != expected:
        raise ValueError("candidate requires exactly all six target archives")
    for item in artifacts:
        if not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")):
            raise ValueError("invalid artifact digest")
    return {item["filename"]: item["sha256"] for item in artifacts}


def checked_payloads(archive, expected_hash, windows):
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected_hash:
        raise ValueError("candidate archive checksum mismatch")
    suffix = ".exe" if windows else ""
    expected = {"obey" + suffix, "ob" + suffix, "LICENSE"}
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        if len(members) != 3 or {item.name for item in members} != expected:
            raise ValueError("unexpected, duplicate or unsafe archive paths")
        if any(not item.isfile() or item.size <= 0 or item.size > 512 * 1024 * 1024 for item in members):
            raise ValueError("archive contains a link, empty or oversized payload")
        if not windows and any(not stream.getmember(name).mode & 0o111 for name in expected - {"LICENSE"}):
            raise ValueError("archive command is not executable")
        return {item.name: stream.extractfile(item).read() for item in members}


def checked_build_info(document, source, target):
    settings = document.get("Settings", [])
    values = {item["Key"]: item["Value"] for item in settings}
    if len(values) != len(settings):
        raise ValueError("duplicate binary build settings")
    goos, goarch = TARGETS[target].split("/")
    required = {"vcs": "git", "vcs.revision": source, "vcs.modified": "false",
                "CGO_ENABLED": "1", "GOOS": goos, "GOARCH": goarch}
    if any(values.get(key) != value for key, value in required.items()):
        raise ValueError("binary build provenance does not match clean reviewed source and target")


def command(arguments, environment, timeout=60, json_output=False, check=True):
    completed = subprocess.run([str(value) for value in arguments], env=environment,
                               capture_output=True, text=True, timeout=timeout)
    print(json.dumps({"command": [str(value) for value in arguments], "exit": completed.returncode,
                      "stdout": completed.stdout, "stderr": completed.stderr}), flush=True)
    if completed.returncode and check:
        raise RuntimeError("candidate command failed")
    return json.loads(completed.stdout) if json_output else completed.stdout


def wait_until(description, predicate, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(1)
    raise RuntimeError("timed out: " + description)


def native_platform():
    architecture = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    return platform.system().lower() + "/" + str(architecture)


def require_disposable():
    if os.environ.get("CANDIDATE_NATIVE_DISPOSABLE") != "1" or os.environ.get("CANDIDATE_RUNNER_KIND") != "github-hosted":
        raise RuntimeError("native state/service proof requires a disposable GitHub-hosted runner")


def native_proof(directory, version, source, target, expected_hash):
    require_disposable()
    if native_platform() != TARGETS[target]:
        raise RuntimeError("runner does not match the actual target OS/architecture")
    archive = directory / f"obey-{version}-{target}.tar.gz"
    windows = target.startswith("windows-")
    payloads = checked_payloads(archive, expected_hash, windows)
    report = {"source_revision": source, "version": version, "target": target,
              "sha256": expected_hash, "runner_platform": native_platform()}
    with tempfile.TemporaryDirectory(prefix="obey-proof-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary)
        for name, data in payloads.items():
            path = root / name
            path.write_bytes(data)
            path.chmod(0o755 if name != "LICENSE" else 0o644)
        suffix = ".exe" if windows else ""
        obey, ob = root / ("obey" + suffix), root / ("ob" + suffix)
        home = root / "home"
        home.mkdir()
        config = home / "daemon.yaml"
        auto_data, auto_socket = root / "auto-data", root / "a.sock"
        config.write_text("data_dir: " + json.dumps(auto_data.as_posix()) + "\ngrpc:\n  socket: " + json.dumps(auto_socket.as_posix()) + "\nnetwork:\n  enabled: false\nwatcher:\n  enabled: false\n")
        environment = dict(os.environ, HOME=str(home), USERPROFILE=str(home), OBEY_CONFIG=str(config),
                           XDG_CONFIG_HOME=str(home / ".config"), XDG_DATA_HOME=str(home / ".local/share"),
                           XDG_STATE_HOME=str(home / ".local/state"), XDG_CACHE_HOME=str(home / ".cache"),
                           NO_COLOR="1", PATH=str(root) + os.pathsep + os.environ["PATH"])
        for credential in ("GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
            environment.pop(credential, None)
        # Inspect both files before executing either. CLI linker stamps alone
        # can claim the right revision while Go captured a different enclosing
        # repository; a nested worktree build exposed exactly that mismatch.
        for binary in (obey, ob):
            build_info = command(["go", "version", "-m", "-json", binary], environment, json_output=True)
            checked_build_info(build_info, source, target)
        report["embedded_source_verified"] = True
        info = command([obey, "version", "--json"], environment, json_output=True)
        abbreviated = info.get("commit", "")
        if info.get("version") != version or info.get("platform") != TARGETS[target] or not re.fullmatch(r"[0-9a-f]{7,40}", abbreviated) or not source.startswith(abbreviated):
            raise ValueError("binary version/source/platform mismatch")
        if target.startswith("macOS-"):
            for binary in (obey, ob):
                output = command(["otool", "-l", binary], environment)
                floors = re.findall(r"\bminos\s+([0-9.]+)", output)
                if not floors or any(value not in ("12.0", "12.0.0") for value in floors):
                    raise ValueError("binary does not retain the declared macOS12 floor")
        process = None
        log = root / "startup.log"
        try:
            with log.open("w") as output:
                process = subprocess.Popen([str(obey), "serve", "--foreground", "--data-dir", str(root / "data"),
                                            "--socket", str(root / "d.sock"), "--no-network", "--no-watcher", "--no-grpc"],
                                           env=environment, stdout=output, stderr=subprocess.STDOUT)
                def initialized():
                    if process.poll() is not None:
                        raise RuntimeError("daemon exited during initialization: " + log.read_text())
                    return "daemon starting" in log.read_text()
                wait_until("SQLite daemon initialization", initialized)
                database = root / "data/daemon.db"
                with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
                    if connection.execute("pragma integrity_check").fetchone() != ("ok",) or connection.execute("select count(*) from sqlite_master where type='table'").fetchone()[0] == 0:
                        raise RuntimeError("daemon did not create a valid initialized SQLite database")
                print(log.read_text(), flush=True)
                report["sqlite_initialized"] = True
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        # The sibling CLI must reach its own isolated daemon; never a user's socket.
        autostarted = False
        registered = False
        try:
            if windows:
                initial = command([obey, "service", "status", "--json"], environment, json_output=True)
                if initial.get("installed") or initial.get("loaded"):
                    raise RuntimeError("refusing to start or modify a preexisting service")
            autostarted = True
            status = command([ob, "status"], environment)
            if not re.search(r"daemon:\s+running", status):
                raise RuntimeError("sibling CLI did not start/reach the isolated daemon")
            command([obey, "stop"], environment)
            autostarted = False
            report["sibling_autostart"] = True
            if windows:
                registered = True  # Clean up even a partially successful install.
                command([obey, "service", "install"], environment)
                def ready():
                    data = command([obey, "service", "status", "--json"], environment, json_output=True)
                    return data if data.get("installed") and data.get("loaded") and data.get("socket_reachable") and data.get("daemon_pid", 0) > 0 else None
                active = wait_until("registered Windows service", ready)
                old_pid = int(active["daemon_pid"])
                # Establish ownership before deliberately crashing this fixture process.
                actual = command(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                  f"(Get-Process -Id {old_pid} -ErrorAction Stop).Path"], environment).strip()
                if not os.path.samefile(actual, obey):
                    raise RuntimeError("refusing to signal a process outside this candidate")
                command(["taskkill", "/PID", str(old_pid), "/F"], environment)
                def replaced():
                    data = ready()
                    return data if data and data["daemon_pid"] != old_pid else None
                active = wait_until("service recovery after owned process crash", replaced, 120)
                old_pid = active["daemon_pid"]
                command([obey, "service", "restart"], environment)
                wait_until("service restart replaces its process", replaced)
                command([obey, "stop"], environment)
                if not re.search(r"daemon:\s+running", command([ob, "status"], environment)):
                    raise RuntimeError("sibling CLI did not wake the registered service")
                command([obey, "service", "uninstall"], environment)
                registered = False
                final = command([obey, "service", "status", "--json"], environment, json_output=True)
                if final.get("installed") or final.get("loaded"):
                    raise RuntimeError("service remained installed after fixture cleanup")
                report["windows_service_lifecycle"] = True
        finally:
            if registered:
                command([obey, "service", "uninstall"], environment, check=False)
            elif autostarted:
                command([obey, "stop"], environment, check=False)
    return report


def checked_downloads(directory, version, source):
    hashes = checked_manifest(json.loads((directory / "candidate.json").read_text()), version, source)
    if {path.name for path in directory.iterdir()} != set(hashes) | {"candidate.json", "checksums.txt"}:
        raise ValueError("candidate directory has missing or unexpected files")
    rows = [line.split() for line in (directory / "checksums.txt").read_text().splitlines()]
    if len(rows) != 6 or any(len(row) != 2 for row in rows) or {name: digest for digest, name in rows} != hashes:
        raise ValueError("checksums do not match the complete candidate manifest")
    for target in TARGETS:
        filename = f"obey-{version}-{target}.tar.gz"
        checked_payloads(directory / filename, hashes[filename], target.startswith("windows-"))
    return hashes


def fetch_candidates(tag, version, source, directory):
    # Data-only boundary: this function never executes any candidate binary.
    checked_request(tag, version, source, next(iter(TARGETS)))
    metadata = json.loads(subprocess.check_output(["gh", "release", "view", tag, "--repo", REPOSITORY,
                                                   "--json", "isDraft,assets"], text=True))
    expected = {f"obey-{version}-{target}.tar.gz" for target in TARGETS} | {"candidate.json", "checksums.txt"}
    if not metadata["isDraft"] or len(metadata["assets"]) != len(expected) or {item["name"] for item in metadata["assets"]} != expected:
        raise ValueError("requires an unpublished draft with the complete candidate inventory")
    directory.mkdir()
    arguments = ["gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", str(directory)]
    for filename in sorted(expected):
        arguments.extend(["--pattern", filename])
    subprocess.run(arguments, check=True)
    checked_downloads(directory, version, source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fetch", "verify"), required=True)
    for name in ("tag", "version", "source"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--target")
    parser.add_argument("--directory", type=Path, default=Path("candidate"))
    args = parser.parse_args()
    if os.environ.get("CANDIDATE_RUNNER_KIND") != "github-hosted":
        raise RuntimeError("candidate staging requires a disposable hosted runner")
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise RuntimeError("candidate verification restricted to the binary repository")
    if args.mode == "fetch":
        if args.target is not None:
            raise ValueError("fetch must validate all targets, not one selected target")
        fetch_candidates(args.tag, args.version, args.source, args.directory)
        print("Validated complete eight-file draft inventory; no candidate executed", flush=True)
        return
    require_disposable()
    if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        raise RuntimeError("native execution must not receive a draft download credential")
    filename = checked_request(args.tag, args.version, args.source, args.target)
    hashes = checked_downloads(args.directory, args.version, args.source)
    report = native_proof(args.directory, args.version, args.source, args.target, hashes[filename])
    Path("proof-" + args.target + ".json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
