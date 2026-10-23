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
import tempfile
import urllib.request

from verify_candidate import command, native_platform, require_disposable

PACKAGES = {"obedience-corp/festival": "0.3.24", "obedience-corp/obey": "0.2.2",
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


def checked_receipts(home):
    with closing(sqlite3.connect((home / "state.db").as_uri() + "?mode=ro", uri=True)) as database:
        database.row_factory = sqlite3.Row
        receipts = [dict(row) for row in database.execute("select * from receipts order by package_id")]
        files = [dict(row) for row in database.execute("select * from receipt_files order by path")]
    if {row["package_id"]: row["version"] for row in receipts} != PACKAGES:
        raise ValueError("receipt selection/version differs from the App's three selected packages")
    if any(row["source"] != "official-obey" or row["channel"] != "stable" for row in receipts):
        raise ValueError("selected package did not use the official stable source")
    for row in files:
        path = Path(row["path"])
        if row["receipt_pkg_id"] not in PACKAGES or not path.resolve().is_relative_to((home / "bin").resolve()) or path.is_symlink():
            raise ValueError("receipt file is outside the owned managed bin")
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row["hash"]:
            raise ValueError("installed file differs from its verified receipt")
    names = {Path(row["path"]).stem if os.name == "nt" else Path(row["path"]).name for row in files}
    required = {"camp", "fest", "camp-app", "obey", "ob"}
    if not required <= names or names - required - {"festival"} or len(files) != len(names):
        raise ValueError("selected executable inventory is incomplete")
    return {"receipts": receipts, "files": files}


def checked_status(document, home):
    if not document.get("ok"):
        raise ValueError("status failed")
    tools = document["data"]["tools"]
    for name, version in {"camp": "0.16.2", "fest": "0.9.8", "obey": "0.2.2", "camp-app": "0.1.0"}.items():
        matches = [tool for tool in tools if tool.get("tool") == name]
        if len(matches) != 1 or not matches[0].get("present") or matches[0].get("version") != version:
            raise ValueError("selected native version is missing or unexpected")
        if not Path(matches[0]["path"]).resolve().is_relative_to((home / "bin").resolve()):
            raise ValueError("selected status resolved an external executable")
    companion = next(tool for tool in tools if tool.get("tool") == "camp-app")
    if companion.get("protocol_major") != 1 or not {"status", "open"} <= set(companion.get("capabilities", [])):
        raise ValueError("companion lacks required control capabilities")
    siblings = [tool for tool in tools if tool.get("tool") == "ob"]
    if len(siblings) != 1 or not siblings[0].get("present") or siblings[0].get("receipt_version") != PACKAGES["obedience-corp/obey"]:
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
        tasks = subprocess.check_output(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                         "@(Get-ScheduledTask | Where-Object { $_.TaskName -like '*Obey*' }).Count"], text=True).strip()
        if tasks != "0":
            raise RuntimeError("refusing preexisting Obey scheduled tasks")


def trust_state(binary, environment):
    if os.name == "nt":
        env = dict(environment, PROOF_EXECUTABLE=str(binary))
        return command(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "$s=Get-AuthenticodeSignature -LiteralPath $env:PROOF_EXECUTABLE; "
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
    return command(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "$o=Get-CimInstance Win32_OperatingSystem; $s=$null; $e=$null; "
                    "try { $s=(Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy' "
                    "-Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState } "
                    "catch { $e=$_.Exception.Message }; "
                    "@{os=$o.Caption;version=$o.Version;sac_raw=$s;sac_read_error=$e;"
                    "consumer_smartscreen_ui='not exercised'} | ConvertTo-Json -Compress"], environment, json_output=True)


def native_selected(target):
    require_clean_host(target)
    report = {"target": target, "platform": native_platform(), "anonymous": True,
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
            report["bootstrap_version"] = command([bootstrap, "--version"], environment)
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
            report["trust"] = {str(path.relative_to(root)): trust_state(path, environment)
                               for path in [bootstrap, *(home / "bin" / (name + suffix) for name in ("camp", "fest", "camp-app", "obey", "ob"))]}
            report["windows_policy"] = windows_policy(environment)
            report["native_component_execution"] = True
        finally:
            if service_attempted and (home / "bin" / ("obey" + suffix)).exists():
                executable = home / "bin" / ("obey" + suffix)
                report["service_cleanup"] = command([executable, "service", "uninstall"], environment, timeout=120, check=False)
                report["service_after_cleanup"] = command([executable, "service", "status", "--json"], environment, json_output=True)
                state = report["service_after_cleanup"]
                if state.get("loaded") or state.get("socket_reachable"):
                    raise RuntimeError("owned service remained live after cleanup")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=TARGETS, required=True)
    arguments = parser.parse_args()
    result = native_selected(arguments.target)
    Path(f"proof-selected-{arguments.target}.json").write_text(json.dumps(result, indent=2) + "\n")
