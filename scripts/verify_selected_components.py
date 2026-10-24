"""Anonymous selected-component acceptance on fresh disposable native runners."""
from contextlib import closing
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import urllib.request

from verify_candidate import command, native_platform, require_disposable

PACKAGES = {"obedience-corp/festival": "0.3.24", "obedience-corp/obey": "0.2.3",
            "obedience-corp/camp-app": "0.1.0"}
TARGETS = {"macOS-arm64": ("darwin/arm64", "darwin-arm64"),
           "macOS-x86_64": ("darwin/amd64", "darwin-amd64"),
           "linux-x86_64": ("linux/amd64", "linux-amd64"),
           "windows-x86_64": ("windows/amd64", "windows-amd64.exe")}


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "selected-component-native-proof"})
    with urllib.request.urlopen(request, timeout=120) as response:
        if response.status != 200:
            raise RuntimeError("public artifact is unavailable")
        data = response.read(128 * 1024 * 1024 + 1)
        if len(data) > 128 * 1024 * 1024:
            raise ValueError("oversized bootstrap artifact")
        return data


def checked_bootstrap(data, checksums, name):
    rows = [line.split() for line in checksums.decode().splitlines()]
    matches = [row for row in rows if len(row) == 2 and row[1] == name]
    digest = hashlib.sha256(data).hexdigest()
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{64}", matches[0][0]) or matches[0][0] != digest:
        raise ValueError("bootstrap checksum mismatch or duplicate entry")
    return digest


def checked_receipts(home, *, obey_version=None, immutable=False, external_suite=None):
    # Only an independently quiescent fixture may assert immutable storage.
    # This does not discover or lock out writers. Normal live readback stays ro.
    def no_sidecars():
        if any(os.path.lexists(str(home / 'state.db') + suffix) for suffix in ('-wal', '-shm', '-journal')):
            raise ValueError('immutable receipt read refuses SQLite sidecars')
    if immutable:
        no_sidecars()
    if external_suite not in (None, '0.3.9', '0.3.10', '0.3.24'):
        raise ValueError('unsupported external suite fixture')
    expected = dict(PACKAGES)
    if external_suite is not None:
        expected.pop('obedience-corp/festival')
    if obey_version is not None:
        if obey_version not in ("0.2.2", PACKAGES["obedience-corp/obey"]):
            raise ValueError("unsupported existing Obey fixture version")
        expected["obedience-corp/obey"] = obey_version
    with closing(sqlite3.connect((home / "state.db").as_uri() + ("?mode=ro&immutable=1" if immutable else "?mode=ro"), uri=True)) as database:
        database.row_factory = sqlite3.Row
        receipts = [dict(row) for row in database.execute("select * from receipts order by package_id")]
        files = [dict(row) for row in database.execute("select * from receipt_files order by path")]
    if immutable:
        no_sidecars()
    if {row["package_id"]: row["version"] for row in receipts} != expected:
        raise ValueError("receipt selection/version differs from the App's three selected packages")
    if any(row["source"] != "official-obey" or row["channel"] != "stable" for row in receipts):
        raise ValueError("selected package did not use the official stable source")
    for row in files:
        path = Path(row["path"])
        if row["receipt_pkg_id"] not in expected or not path.resolve().is_relative_to((home / "bin").resolve()) or path.is_symlink():
            raise ValueError("receipt file is outside the owned managed bin")
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row["hash"]:
            raise ValueError("installed file differs from its verified receipt")
    names = {Path(row["path"]).stem if os.name == "nt" else Path(row["path"]).name for row in files}
    required = {"camp-app", "obey", "ob"} if external_suite is not None else {"camp", "fest", "camp-app", "obey", "ob"}
    if not required <= names or names - required - (set() if external_suite is not None else {"festival"}) or len(files) != len(names):
        raise ValueError("selected executable inventory is incomplete")
    return {"receipts": receipts, "files": files}


def checked_windows_discovery_log(data):
    text = data.decode('utf-8-sig')
    if not text.strip():
        raise ValueError('Windows daemon runtime log is empty')
    if re.search(r'exec:.*\b(?:lsof|ps)\b.*(?:executable file not found|not recognized|cannot find)', text, re.IGNORECASE) or 'bridge startup provider discovery failed' in text.lower():
        raise ValueError('Windows daemon retained provider discovery failures or Unix utility dependency')
    return {'required_obey_version': PACKAGES['obedience-corp/obey'], 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'unix_utility_discovery_errors_absent': True,
            'provider_discovery_failure_messages_absent': True}


def record_windows_discovery_snapshot(source, output, report):
    data = source.read_bytes()
    snapshot = output / 'windows-discovery-after-reopen.log'
    snapshot.write_bytes(data)
    evidence = {'snapshot': snapshot.name, 'sha256': hashlib.sha256(data).hexdigest(),
                'bytes': len(data), 'verified': False}
    report['windows_default_discovery_log'] = evidence
    evidence.update(checked_windows_discovery_log(data))
    evidence['verified'] = True


def checked_status(document, home, *, obey_version=None, external_suite=None):
    if external_suite not in (None, '0.3.10', '0.3.24'):
        raise ValueError('unsupported compatible external suite fixture')
    required_obey = PACKAGES["obedience-corp/obey"] if obey_version is None else obey_version
    if required_obey not in ("0.2.2", PACKAGES["obedience-corp/obey"]):
        raise ValueError("unsupported existing Obey fixture version")
    if not document.get("ok"):
        raise ValueError("status failed")
    tools = document["data"]["tools"]
    suite_versions = {'camp': '0.10.1', 'fest': '0.8.0'} if external_suite == '0.3.10' else {'camp': '0.16.2', 'fest': '0.9.8'}
    for name, version in dict(suite_versions, obey=required_obey, **{'camp-app': '0.1.0'}).items():
        matches = [tool for tool in tools if tool.get("tool") == name]
        if len(matches) != 1 or not matches[0].get("present") or matches[0].get("version") != version:
            raise ValueError("selected native version is missing or unexpected")
        if external_suite is not None and name in suite_versions:
            row = matches[0]
            expected_path = Path('/usr/bin') / name
            if (Path(row['path']) != expected_path or row.get('origin') != 'package' or
                    row.get('bundle') not in (external_suite, 'v' + external_suite) or
                    row.get('receipt_version') or row.get('error') or
                    row.get('package') != 'obedience-corp/festival'):
                raise ValueError('external suite status differs from the exact package fixture')
        elif external_suite is not None:
            row = matches[0]
            package = 'obedience-corp/camp-app' if name == 'camp-app' else 'obedience-corp/obey'
            receipt_version = '0.1.0' if name == 'camp-app' else required_obey
            if (Path(row['path']) != home / 'bin' / name or row.get('origin') != 'managed' or
                    row.get('package') != package or row.get('receipt_version') != receipt_version or row.get('error')):
                raise ValueError('selected non-suite command is not the exact receipt-owned managed fixture')
        elif not Path(matches[0]["path"]).resolve().is_relative_to((home / "bin").resolve()):
            raise ValueError("selected status resolved an external executable")
    companion = next(tool for tool in tools if tool.get("tool") == "camp-app")
    if companion.get("protocol_major") != 1 or not {"status", "open"} <= set(companion.get("capabilities", [])):
        raise ValueError("companion lacks required control capabilities")
    siblings = [tool for tool in tools if tool.get("tool") == "ob"]
    if len(siblings) != 1 or not siblings[0].get("present") or siblings[0].get("receipt_version") != required_obey:
        raise ValueError("sibling CLI is not in the selected Obey package")


def require_clean_host(target):
    require_disposable()
    if target not in TARGETS or native_platform() != TARGETS[target][0]:
        raise RuntimeError("requires the actual advertised OS/architecture")
    if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        raise RuntimeError("anonymous native installation must not receive GitHub credentials")
    for name in ("camp", "fest", "camp-app", "obey", "ob"):
        if shutil.which(name):
            raise RuntimeError("refusing a host with preexisting ecosystem commands")
    home = Path.home()
    for directory in (home / "Library/LaunchAgents", home / ".config/systemd/user"):
        if directory.exists() and any("obey" in path.name.lower() for path in directory.iterdir()):
            raise RuntimeError("refusing preexisting Obey supervisor files")
    if os.name == "nt":
        tasks = subprocess.check_output(["pwsh", "-NoProfile", "-NonInteractive", "-Command",
                                         "$ErrorActionPreference='Stop'; @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -like '*Obey*' }).Count"], text=True).strip()
        if tasks != "0":
            raise RuntimeError("refusing preexisting Obey scheduled tasks")


def trust_state(binary, environment):
    if os.name == "nt":
        env = dict(environment, PROOF_EXECUTABLE=str(binary))
        return command(["pwsh", "-NoProfile", "-NonInteractive", "-Command",
                        "$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $env:PROOF_EXECUTABLE -ErrorAction Stop; "
                        "@{status=$s.Status.ToString();message=$s.StatusMessage} | ConvertTo-Json -Compress"], env, json_output=True)
    if native_platform().startswith("darwin/"):
        result = {}
        for name, arguments in (("codesign", ["codesign", "-dv", "--verbose=4", binary]),
                                ("spctl", ["spctl", "--assess", "--type", "execute", "--verbose=4", binary])):
            probe = subprocess.run([str(value) for value in arguments], env=environment, capture_output=True, text=True, timeout=60)
            result[name] = {"exit": probe.returncode, "stdout": probe.stdout, "stderr": probe.stderr}
        return result
    return {"native_signing": "not applicable to this Linux executable"}


def windows_policy(environment):
    if os.name != "nt":
        return None
    # Read only. An absent/inaccessible value is unknown, never interpreted as Off.
    return command(["pwsh", "-NoProfile", "-NonInteractive", "-Command",
                    "$o=Get-CimInstance Win32_OperatingSystem; $s=$null; $e=$null; "
                    "try { $s=(Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy' "
                    "-Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState } "
                    "catch { $e=$_.Exception.Message }; "
                    "@{os=$o.Caption;version=$o.Version;sac_raw=$s;sac_read_error=$e;"
                    "consumer_smartscreen_ui='not exercised'} | ConvertTo-Json -Compress"], environment, json_output=True)


def native_selected(target):
    require_clean_host(target)
    report = {"target": target, "platform": native_platform(), "anonymous": True,
              "native_component_execution": False, "trust_complete": False,
              "scope": "selected component execution/receipts; no App UI, reboot or consumer SmartScreen claim"}
    with tempfile.TemporaryDirectory(prefix="scp-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary)
        home = root / "managed"
        suffix = ".exe" if os.name == "nt" else ""
        bootstrap = root / ("festival" + suffix)
        name = "festival-" + TARGETS[target][1]
        base = "https://github.com/Obedience-Corp/festival-installer/releases/download/v0.3.7/"
        data = fetch(base + name)
        report["installer_sha256"] = checked_bootstrap(data, fetch(base + "checksums.txt"), name)
        bootstrap.write_bytes(data)
        bootstrap.chmod(0o755)
        config = root / "daemon.yaml"
        config.write_text("data_dir: " + json.dumps((root / "data").as_posix()) + "\ngrpc:\n  socket: " +
                          json.dumps((root / "a.sock").as_posix()) + "\nnetwork:\n  enabled: false\nwatcher:\n  enabled: false\n")
        environment = dict(os.environ, FESTIVAL_HOME=str(home), OBEY_CONFIG=str(config),
                           CAMP_APP_CONTROL_ROOT=str(root / "absent-app-control"),
                           PATH=str(root) + os.pathsep + str(home / "bin") + os.pathsep + os.environ["PATH"])
        for credential in ("GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
            environment.pop(credential, None)
        service_attempted = False
        try:
            report["bootstrap_version"] = command([bootstrap, "version"], environment)
            if "0.3.7" not in report["bootstrap_version"]:
                raise ValueError("wrong bootstrap version")
            report["install"] = {}
            for selected in ("festival", "obedience-corp/camp-app", "obey"):
                if selected == "obey":
                    service_attempted = True
                result = command([bootstrap, "--managed", "install", selected, "--no-shell-setup", "--no-restart", "--json"],
                                 environment, timeout=240, json_output=True)
                if not result.get("ok"):
                    raise RuntimeError("selected installation failed")
                report["install"][selected] = result
            report["persisted"] = checked_receipts(home)
            report["status"] = command([bootstrap, "--managed", "status", "--plugin", "obedience-corp/camp-app", "--json"],
                                       environment, json_output=True)
            checked_status(report["status"], home)
            report["versions"] = {}
            for name, arguments in (("camp", ["version", "--json"]), ("fest", ["version"]),
                                    ("camp-app", ["version", "--json"]), ("obey", ["version", "--json"]), ("ob", ["--help"])):
                binary = home / "bin" / (name + suffix)
                report["versions"][name] = command([binary, *arguments], environment)
            obey = json.loads(report["versions"]["obey"])
            companion = json.loads(report["versions"]["camp-app"])
            if obey.get("version") != PACKAGES["obedience-corp/obey"] or companion.get("data", {}).get("version") != PACKAGES["obedience-corp/camp-app"]:
                raise ValueError("live version differs from selected receipt")
            report["native_component_execution"] = True
            report["trust"] = {str(path.relative_to(root)): trust_state(path, environment)
                               for path in [bootstrap, *(home / "bin" / (name + suffix) for name in ("camp", "fest", "camp-app", "obey", "ob"))]}
            report["windows_policy"] = windows_policy(environment)
            report["trust_complete"] = True
        finally:
            failure = sys.exc_info()[1]
            if failure:
                report["failure"] = str(failure)
            try:
                if service_attempted and (home / "bin" / ("obey" + suffix)).exists():
                    executable = home / "bin" / ("obey" + suffix)
                    report["service_cleanup"] = command([executable, "service", "uninstall"], environment, timeout=120, check=False)
                    report["service_after_cleanup"] = command([executable, "service", "status", "--json"], environment, json_output=True)
                    state = report["service_after_cleanup"]
                    if state.get("loaded") or state.get("socket_reachable"):
                        raise RuntimeError("owned service remained live after cleanup")
            finally:
                # Keep successful earlier checks and the original error even
                # when a later query or cleanup fails. The job still fails.
                cleanup_failure = sys.exc_info()[1]
                if cleanup_failure is not None and cleanup_failure is not failure:
                    report["cleanup_failure"] = str(cleanup_failure)
                Path(f"proof-selected-{target}.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=TARGETS, required=True)
    arguments = parser.parse_args()
    result = native_selected(arguments.target)
    Path(f"proof-selected-{arguments.target}.json").write_text(json.dumps(result, indent=2) + "\n")
