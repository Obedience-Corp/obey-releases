"""Exercise the real App updater between anonymous immutable test releases.

No private checkout, replacement trust root, endpoint override or test backdoor.
Only fresh hosted accounts may execute; original package failures stay failures.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import time

import verify_app_candidate as app
from app_upgrade_contract import checked_upgrade_pair, checked_public, fetch_public, persisted_snapshot, sha256, verify_persisted
from verify_candidate import command, native_platform, wait_until
from owned_update_proxy import UpdateProxy
from verify_selected_components import TARGETS as COMPONENT_TARGETS, checked_bootstrap, checked_receipts, checked_status, fetch, require_clean_host

SCRIPT = Path(__file__).resolve().parent
MACHINES = {"aarch64-apple-darwin": "macOS-arm64", "x86_64-apple-darwin": "macOS-x86_64",
            "x86_64-unknown-linux-gnu": "linux-x86_64", "x86_64-pc-windows-msvc": "windows-x86_64"}
FORMATS = {"dmg": ".app.tar.gz", "deb": ".deb", "appimage": ".AppImage", "nsis": "-setup.exe"}


def artifact(directory, document, target, suffix):
    return directory / "assets" / next(item["name"] for item in document["targets"][target] if item["name"].endswith(suffix))


def tree(root):
    result = {}
    for path in root.rglob("*"):
        name = str(path.relative_to(root))
        if path.is_symlink():
            result[name] = ["link", os.readlink(path)]
        elif path.is_file():
            result[name] = ["file", sha256(path)]
        elif not path.is_dir():
            raise ValueError("unsupported package payload entry")
    return result


def check_tree(actual, expected):
    if tree(actual) != tree(expected):
        raise ValueError("installed App payload differs from authenticated B payload")
    return tree(actual)


def windows_query(mode, environment, **values):
    return command(["pwsh", "-NoProfile", "-NonInteractive", "-File", SCRIPT / "windows_app_upgrade.ps1"],
                   dict(environment, APP_UPGRADE_MODE=mode, **values), json_output=True)


class ObservedWindowsProcess:
    """A post-NSIS process is owned only with matching PID, creation time and path."""
    def __init__(self, identity, environment):
        self.pid = identity["pid"]
        self.identity = identity
        self.environment = environment

    def poll(self):
        current = windows_query("identity", self.environment, APP_UPGRADE_PID=str(self.pid))
        return None if current == self.identity else 0

    def wait(self, timeout=20):
        wait_until("owned Windows App exit", lambda: self.poll() is not None, seconds=timeout)
        return 0


def normal_quit(process, binary, bundle, target, environment, output, mac_tools=None):
    if process.poll() is not None:
        raise RuntimeError("App exited before normal quit request")
    if target.endswith("apple-darwin"):
        if mac_tools is None:
            raise RuntimeError('macOS normal-quit helper must be prepared before App launch')
        mac_tools.quit(process.pid, bundle, environment)
    elif target.endswith("windows-msvc"):
        started = app.windows_owned_birth(process)
        identities = command(["pwsh", "-NoProfile", "-File", SCRIPT / "windows_owned_processes.ps1"],
                             dict(environment, APP_PROOF_PROCESS_MODE="snapshot", APP_PROOF_PROCESS_PID=str(process.pid), APP_PROOF_PROCESS_STARTED=started), json_output=True)
        identity = windows_query("identity", environment, APP_UPGRADE_PID=str(process.pid))
        if identity.get("pid") != process.pid or identity.get("started") != started:
            raise RuntimeError("Windows App identity changed before normal quit")
        windows_query("quit", environment, APP_UPGRADE_PID=str(process.pid), APP_UPGRADE_EXE=str(binary), APP_UPGRADE_STARTED=identity["started"])
        command(["pwsh", "-NoProfile", "-File", SCRIPT / "windows_owned_processes.ps1"],
                dict(environment, APP_PROOF_PROCESS_MODE="verify", APP_PROOF_PROCESS_IDENTITIES=json.dumps(identities)), timeout=30)
    else:
        window = app.window_capture(process, target, output / "before-normal-quit.png", environment)
        # A window manager handles this normal _NET_CLOSE_WINDOW request.
        command(["wmctrl", "-ic", window["window_id"]], environment)
    process.wait(timeout=45)


def default_home_layout(home, environment):
    """Refuse existing state; never redirect the account or installer environment."""
    overrides = ("FESTIVAL_HOME", "OBEY_INSTALLER_HOME", "OBEY_CONFIG", "OBEY_SOCKET", "OBEY_GRPC_SOCKET",
                 "CAMP_HOME", "CAMP_CONFIG", "CAMP_REGISTRY_PATH", "CAMP_APP_CONTROL_ROOT")
    invalid = [name for name in overrides if environment.get(name)]
    # Hosted Ubuntu declares its ordinary desktop XDG default explicitly. This
    # is the same home, not permission to redirect configuration or seed tools.
    for name, suffix in (("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", ".local/share"), ("XDG_STATE_HOME", ".local/state")):
        value = environment.get(name)
        expected = home / suffix
        redirected = any(path.is_symlink() for path in (expected, *expected.parents) if path != home and path.is_relative_to(home))
        if value and (not Path(value).is_absolute() or Path(value) != expected or redirected):
            invalid.append(name)
    if invalid:
        raise RuntimeError("default-home proof refuses inherited tool/config overrides: " + ", ".join(invalid))
    for path in (home / ".obey", home / ".local/share/obey", home / ".config/camp"):
        if path.exists() or path.is_symlink():
            raise RuntimeError("default-home proof refuses preexisting ecosystem state: " + str(path))
    return home / ".obey/installer"


def default_home_readback(installer, managed, environment):
    """Read public sidecar resolution with the unchanged default environment."""
    status = command([installer, "--managed", "status", "--plugin", "obedience-corp/camp-app", "--json"], environment, json_output=True)
    checked_status(status, managed)
    return {"installer_status": status, "selected_mtime_ns": {
        row["path"]: Path(row["path"]).stat().st_mtime_ns for row in checked_receipts(managed)["files"]}}


def wait_windows_setup(process, target, output, environment, report, stage):
    """License UI proves setup settled, not license entitlement or useful work."""
    def capture():
        window = app.window_capture(process, target, output / (stage + "-setup.png"), environment)
        report[stage + "_setup_window"] = window
        names = window.get("visible_names", [])
        return window if "Licenses" in names and "License key" in names else None
    return wait_until("default-home setup reaches licensing after " + stage, capture, seconds=600)


def bootstrap_fixture(root, environment, machine, managed=None):
    managed = managed if managed is not None else root / "managed"
    suffix = ".exe" if os.name == "nt" else ""
    bootstrap = root / ("festival" + suffix)
    name = "festival-" + COMPONENT_TARGETS[machine][1]
    base = "https://github.com/Obedience-Corp/festival-installer/releases/download/v0.3.7/"
    data = fetch(base + name)
    digest = checked_bootstrap(data, fetch(base + "checksums.txt"), name)
    bootstrap.write_bytes(data)
    bootstrap.chmod(0o755)
    for selected in ("festival", "obedience-corp/camp-app", "obey"):
        result = command([bootstrap, "--managed", "install", selected, "--no-shell-setup", "--no-restart", "--json"], environment, timeout=240, json_output=True)
        if not result.get("ok"):
            raise RuntimeError("public selected-package fixture installation failed")
    receipts = checked_receipts(managed)
    camp = managed / "bin" / ("camp" + suffix)
    help_text = command([camp, "init", "--help"], environment)
    if any(flag not in help_text for flag in ("--no-git", "--no-skills", "--name", "--description", "--mission")):
        raise RuntimeError("released Camp lacks required fixture initialization contract")
    fixture = root / "fixture-camp"
    command([camp, "init", fixture, "--name", "FA0027 upgrade fixture", "--description", "Disposable published App upgrade fixture", "--mission", "Verify settings and selected tools survive the published App update", "--no-git", "--no-skills"], environment, timeout=120)
    entries = command([camp, "list", "--format", "json"], environment, json_output=True)
    matches = [item for item in entries if Path(item["path"]).resolve() == fixture.resolve()]
    if len(matches) != 1:
        raise ValueError("actual fixture Camp registration is missing or ambiguous")
    settings = Path.home() / ".obey/festival-app/settings.json"
    if settings.parent.exists():
        raise RuntimeError("refusing preexisting App settings/control data")
    settings.parent.mkdir(parents=True)
    seeded = {"wordWrap": True, "fontSize": 17, "navigationPanelWidth": 333,
              "defaultCampaignId": matches[0]["id"], "openCampaignIds": [matches[0]["id"]]}
    settings.write_text(json.dumps(seeded, indent=2) + "\n")
    foreign = [settings.parent / "upgrade-foreign-note.txt", fixture / "projects/unrelated/keep.txt", managed / "unselected-runtime/keep.txt"]
    for path in foreign:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("FA0027 foreign file: preserve exact bytes\n")
    return {"installer_sha256": digest, "receipts": receipts, "managed_home": managed, "camp": camp, "camp_id": matches[0]["id"], "fixture": fixture,
            "settings_path": settings, "settings": seeded, "snapshot": persisted_snapshot(foreign + [fixture / ".campaign/campaign.yaml"])}


def component_identity(document):
    return {
        "receipts": sorted((row["package_id"], row["version"], row["source"], row["channel"]) for row in document["receipts"]),
        "files": sorted((row["receipt_pkg_id"], row["path"], row["hash"]) for row in document["files"]),
    }


def retained_state(fixture, environment):
    selected = checked_receipts(fixture["managed_home"])
    if component_identity(selected) != component_identity(fixture["receipts"]):
        raise ValueError("upgrade changed selected package identities or file hashes")
    result = verify_persisted(fixture["snapshot"], fixture["settings_path"], fixture["settings"])
    entries = command([fixture["camp"], "list", "--format", "json"], environment, json_output=True)
    if not any(item["id"] == fixture["camp_id"] and Path(item["path"]).resolve() == fixture["fixture"].resolve() for item in entries):
        raise ValueError("upgrade lost the registered fixture Camp")
    return dict(result, selected_components=component_identity(selected), registered_camp_id=fixture["camp_id"], registered_camp_path=str(fixture["fixture"]))


def nsis_reference(installer, destination, environment):
    listing = command(["7z", "l", "-slt", installer], environment)
    # Only the archive-entry section is relevant, not the archive's absolute path.
    sections = listing.split("----------", 1)
    if len(sections) != 2:
        raise ValueError("cannot inspect signed NSIS payload inventory")
    names = [line[7:] for line in sections[1].splitlines() if line.startswith("Path = ")]
    if not names or len(names) > 100000 or len(names) != len(set(names)) or any(
            name.replace("\\", "/").startswith("/") or ":" in name or ".." in name.replace("\\", "/").split("/") for name in names):
        raise ValueError("unsafe NSIS reference extraction path")
    command(["7z", "x", "-y", "-o" + str(destination), installer], environment, timeout=120)
    binaries = list(destination.rglob("festival-app.exe"))
    if len(binaries) != 1:
        raise ValueError("signed B NSIS must contain exactly one App executable")
    return binaries[0].parent


def check_nsis_payload(installed, reference, installer_name='festival'):
    expected = tree(reference)
    # NSIS plugin machinery is not an installed App payload.
    expected = {name: value for name, value in expected.items() if name.split(os.sep)[0] != "$PLUGINSDIR"}
    if not {"festival-app.exe", installer_name + ".exe", "festival-activity-engine.exe"} <= expected.keys():
        raise ValueError("incomplete authenticated Windows reference payload")
    actual = tree(installed)
    if any(actual.get(name) != value for name, value in expected.items()):
        raise ValueError("installed Windows files differ from authenticated B NSIS payload")
    return expected


def check_installed_b(package_format, binary, bundle, reference, expected_image, version, environment, installer_name='festival'):
    if package_format == "dmg":
        if plistlib.loads((bundle / "Contents/Info.plist").read_bytes()).get("CFBundleShortVersionString") != version:
            raise ValueError("installed Mac version is not B")
        return check_tree(bundle, reference)
    if package_format == "nsis":
        actual_version = command(["pwsh", "-NoProfile", "-Command", "(Get-Item -LiteralPath $env:APP_PROOF_EXE).VersionInfo.ProductVersion"], dict(environment, APP_PROOF_EXE=str(binary))).strip()
        if actual_version not in (version, version + ".0"):
            raise ValueError("installed Windows version is not B")
        return check_nsis_payload(binary.parent, reference, installer_name)
    if package_format == "deb":
        if command(["dpkg-query", "-W", "-f=${Version}", "festival-app"], environment).strip() != version:
            raise ValueError("installed Debian version is not B")
        expected = tree(reference)
        for name, value in expected.items():
            path = Path("/") / name
            valid = path.is_file() and not path.is_symlink() and sha256(path) == value[1] if value[0] == "file" else path.is_symlink() and os.readlink(path) == value[1]
            if not valid:
                raise ValueError("installed Debian payload differs from authenticated B package")
        return expected
    if sha256(binary) != sha256(expected_image):
        raise ValueError("installed AppImage differs from authenticated B bytes")
    return {"appimage_sha256": sha256(binary)}


def menu_update_check(process, binary, environment, identity, output):
    return wait_until("actual owned App update menu", lambda: (
        value if (value := windows_query("check-updates", environment,
            APP_UPGRADE_PID=str(process.pid), APP_UPGRADE_EXE=str(binary),
            APP_UPGRADE_STARTED=identity["started"],
            APP_UPGRADE_MENU_DIAGNOSTICS=str(output / "native-menu.jsonl"))).get("invoked") else None), seconds=30)


def offline_check_then_retry(process, binary, fixture, proxy, target, output, environment, report, identity):
    before_payload = tree(binary.parent)
    before_state = retained_state(fixture, environment)
    blocked_before = sum(row["outcome"] == "blocked" for row in proxy.snapshot()["requests"])
    report["offline_menu_action"] = menu_update_check(process, binary, environment, identity, output)
    def failure_window():
        frame = app.window_capture(process, target, output / "offline-check.png", environment)
        report["offline_window"] = frame
        return frame if any("Update check failed:" in name for name in frame.get("visible_names", [])) else None
    wait_until("visible native update-check failure", failure_window, seconds=60)
    snapshot = proxy.snapshot()
    if sum(row["outcome"] == "blocked" for row in snapshot["requests"]) <= blocked_before:
        raise RuntimeError("offline injection did not observe the explicit update request")
    if windows_query("identity", environment, APP_UPGRADE_PID=str(process.pid)) != identity:
        raise RuntimeError("failed update changed the owned App process")
    if tree(binary.parent) != before_payload or retained_state(fixture, environment) != before_state:
        raise ValueError("failed update changed A payload or preserved user/component state")
    report["offline_original_payload"] = before_payload
    report["offline_preserved_state"] = before_state
    report["proxy_after_failure"] = snapshot
    proxy.allow_release_tunnels()
    report["same_pid_retry_action"] = menu_update_check(process, binary, environment, identity, output)
    report["same_pid_retry_identity"] = identity
    report["offline_check_preserved_a"] = True


def native(root, target, package_format, a_source, a_version, b_source, b_version, output, installation_context="redirected", failure_mode="none"):
    require_clean_host(MACHINES.get(target))
    if target not in MACHINES or native_platform() != app.TARGETS[target][0] or package_format not in FORMATS:
        raise ValueError("upgrade target/format does not match native machine")
    allowed = "dmg" if target.endswith("apple-darwin") else "nsis" if target.endswith("windows-msvc") else None
    if allowed and package_format != allowed or allowed is None and package_format not in ("deb", "appimage"):
        raise ValueError("unsupported native package format")
    if installation_context not in ("redirected", "default-home") or installation_context == "default-home" and package_format != "nsis":
        raise ValueError("default-home acceptance currently requires the native NSIS leg")
    if failure_mode not in ("none", "offline-check") or failure_mode == "offline-check" and (package_format != "nsis" or installation_context != "redirected"):
        raise ValueError("offline-check proof requires the Windows NSIS redirected fixture")
    if any(os.environ.get(key) for key in ("GH_TOKEN", "GITHUB_TOKEN")):
        raise RuntimeError("native upgrade must not receive GitHub credentials")
    if tuple(map(int, a_version.split("."))) >= tuple(map(int, b_version.split("."))):
        raise ValueError("B must be newer than A")
    root, output = root.resolve(), output.resolve()
    a = checked_public(root / "a", a_source, a_version)
    b = checked_public(root / "b", b_source, b_version)
    checked_upgrade_pair(a, b)
    a_installer, b_installer = app.installer_basename(a), app.installer_basename(b)
    suffix = '.exe' if target.endswith('windows-msvc') else ''
    output.mkdir()
    report = {"a_source": a_source, "a_version": a_version, "b_source": b_source, "b_version": b_version,
              "a_installer_basename": a_installer, "b_installer_basename": b_installer,
              "target": target, "package_format": package_format, "installation_context": installation_context, "failure_mode": failure_mode,
              "default_home_relaunch_verified": False, "two_version_update_verified": False,
              "license_access_verified": False, "useful_first_use_verified": False, "consumer_trust_verified": False, "reboot_verified": False, "native_failure_recovery_verified": False}
    environment = {key: value for key, value in os.environ.items() if not key.endswith(("_TOKEN", "_PASSWORD", "_PRIVATE_KEY"))}
    default_managed = default_home_layout(Path.home(), environment) if installation_context == "default-home" else None
    process = display = manager = proxy = None
    owned_deb = owned_nsis = False
    temporary = tempfile.TemporaryDirectory(prefix="app-upgrade-", dir=os.environ["RUNNER_TEMP"])
    work = Path(temporary.name)
    try:
        mac_options = {}
        managed = default_managed if default_managed is not None else work / "managed"
        if default_managed is None:
            config = work / "obey.yaml"
            config.write_text("data_dir: " + json.dumps((work / "data").as_posix()) + "\ngrpc:\n  socket: " + json.dumps((work / "a.sock").as_posix()) + "\nnetwork:\n  enabled: false\nwatcher:\n  enabled: false\n")
            environment.update(FESTIVAL_HOME=str(managed), OBEY_CONFIG=str(config), PATH=str(managed / "bin") + os.pathsep + environment["PATH"])
        report["managed_home"] = str(managed)
        for directory, document in ((root / "a", a), (root / "b", b)):
            for item in document["targets"][target]:
                if item["name"].endswith(tuple(FORMATS.values())):
                    payload = directory / "assets" / item["name"]
                    app.verify_signature(payload, payload.with_name(payload.name + ".sig"), work, environment)
        report["production_signatures_verified"] = True
        report["original_a_payload_sha256"] = sha256(artifact(root / "a", a, target, FORMATS[package_format]))
        fixture = bootstrap_fixture(work, environment, MACHINES[target], managed)
        report["before"] = retained_state(fixture, environment)
        bundle = reference = None
        if package_format == "dmg":
            report["a_native_package"] = {"version": a_version, "target": target}
            binary, _, _ = app.mac_install(root / "a/assets", a["targets"][target], work, environment, report["a_native_package"], a_installer)
            bundle = binary.parent.parent.parent
            expected = work / "reference-b"
            expected.mkdir()
            reference = app.extract_app(artifact(root / "b", b, target, ".app.tar.gz"), expected)
        elif package_format == "nsis":
            installed = Path(os.environ["LOCALAPPDATA"]) / "Festival App"
            if installed.exists():
                raise RuntimeError("refusing preexisting Windows App")
            owned_nsis = True
            app.windows_silent(artifact(root / "a", a, target, "-setup.exe"), environment)
            binary = installed / "festival-app.exe"
            initial_version = command(["pwsh", "-NoProfile", "-Command", "(Get-Item -LiteralPath $env:APP_PROOF_EXE).VersionInfo.ProductVersion"], dict(environment, APP_PROOF_EXE=str(binary))).strip()
            if initial_version not in (a_version, a_version + ".0"):
                raise ValueError("actual initial Windows version is not A")
            report["installed_a_version"] = initial_version
            reference = nsis_reference(artifact(root / "b", b, target, "-setup.exe"), work / "reference-b", environment)
        else:
            if shutil.which("festival-app"):
                raise RuntimeError("refusing preexisting Linux App")
            if Path("/tmp/.X11-unix/X99").exists():
                raise RuntimeError("refusing existing X display")
            display = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1280x900x24"], start_new_session=True, env=environment)
            environment["DISPLAY"] = ":99"
            wait_until("owned display", lambda: subprocess.run(["xdpyinfo"], env=environment, capture_output=True).returncode == 0)
            manager = subprocess.Popen(["openbox"], start_new_session=True, env=environment)
            if package_format == "deb":
                state = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", "festival-app"], capture_output=True, text=True, env=environment)
                if state.returncode == 0 and state.stdout.strip() != "not-installed":
                    raise RuntimeError("refusing preexisting App package state")
                deb_a = artifact(root / "a", a, target, ".deb")
                if command(["dpkg-deb", "-f", deb_a, "Package"], environment).strip() != "festival-app" or command(["dpkg-deb", "-f", deb_a, "Version"], environment).strip() != a_version:
                    raise ValueError("initial Debian package identity is not A")
                owned_deb = True
                app.install_deb(artifact(root / "a", a, target, ".deb"), environment)
                initial_version = command(["dpkg-query", "-W", "-f=${Version}", "festival-app"], environment).strip()
                if initial_version != a_version:
                    raise ValueError("actual initial Debian version is not A")
                report["installed_a_version"] = initial_version
                binary = Path("/usr/bin/festival-app")
                reference = work / "reference-b"
                command(["dpkg-deb", "-x", artifact(root / "b", b, target, ".deb"), reference], environment)
            else:
                binary = work / "Festival.App.AppImage"
                shutil.copyfile(artifact(root / "a", a, target, ".AppImage"), binary)
                binary.chmod(0o755)
        if failure_mode == "offline-check":
            proxy_names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
            if any(environment.get(name) for name in proxy_names):
                raise RuntimeError("owned transport proof refuses inherited proxy configuration")
            proxy = UpdateProxy()
            environment.update(HTTPS_PROXY=proxy.url, HTTP_PROXY=proxy.url, NO_PROXY="127.0.0.1,localhost")
            report["owned_proxy_url"] = proxy.url
        if target.endswith('apple-darwin'):
            import mac_window_tools
            tools = mac_window_tools.prepare(work, output, environment)
            report['mac_window_tools'] = tools.identity
            mac_options['mac_tools'] = tools
        log = (output / "app.log").open("w")
        try:
            if default_managed is not None:
                report["default_before"] = default_home_readback(binary.parent / (a_installer + suffix), managed, environment)
            process = subprocess.Popen([str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
            report["a_pid"] = process.pid
            report["a_window"] = app.window_capture(process, target, output / "a.png", environment, **mac_options)
            # A's real Update ready modal hides the underlying licensing screen
            # from UIA. Invoke its authenticated Restart now control below;
            # require unobscured setup completion in auto-restarted/reopened B.
            if package_format == "nsis":
                initial = windows_query("identity", environment, APP_UPGRADE_PID=str(process.pid))
                if proxy is not None:
                    offline_check_then_retry(process, binary, fixture, proxy, target, output, environment, report, initial)
                report["restart_control"] = wait_until("real Restart now control", lambda: (value if (value := windows_query("restart", environment, APP_UPGRADE_PID=str(process.pid), APP_UPGRADE_EXE=str(binary), APP_UPGRADE_STARTED=initial["started"], APP_UPGRADE_VERSION=b_version)).get("invoked") else None), seconds=600)
                process.wait(timeout=120)
                found = wait_until("NSIS installed and relaunched B", lambda: windows_query("find", environment, APP_UPGRADE_EXE=str(binary), APP_UPGRADE_OLD_PID=str(process.pid), APP_UPGRADE_AFTER=initial["started"]), seconds=300)
                process = ObservedWindowsProcess(found, environment)
            def installed_b():
                if process.poll() is not None:
                    raise RuntimeError("App exited before B installation could be verified")
                try:
                    value = check_installed_b(package_format, binary, bundle, reference,
                                              artifact(root / "b", b, target, ".AppImage") if package_format == "appimage" else None,
                                              b_version, environment, b_installer)
                except (ValueError, FileNotFoundError) as error:
                    report["pending_b_payload"] = str(error)
                    return None
                report.pop("pending_b_payload", None)
                return value
            report["b_payload"] = wait_until("real B installation and exact payload", installed_b, seconds=600)
            report["installed_b_version"] = b_version
            report["after_install"] = retained_state(fixture, environment)
            report["installed_payload_window"] = app.window_capture(process, target, output / "installed-before-quit.png", environment, **mac_options)
            if default_managed is not None:
                wait_windows_setup(process, target, output, environment, report, "auto_restarted_b")
                report["default_after_auto_restart"] = default_home_readback(binary.parent / (b_installer + suffix), managed, environment)
            report["running_version_before_quit"] = b_version if package_format == "nsis" else a_version
            normal_quit(process, binary, bundle, target, environment, output, **mac_options)
            process = None
            report["normal_quit_verified"] = True
            process = subprocess.Popen([str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
            report["reopened_pid"] = process.pid
            report["reopened_captures"] = []
            report["reopened_b_window"] = app.capture_startup(process, target, output, environment, report["reopened_captures"], "b-reopened", **mac_options)
            report["reopened_b_payload"] = check_installed_b(package_format, binary, bundle, reference, artifact(root / "b", b, target, ".AppImage") if package_format == "appimage" else None, b_version, environment, b_installer)
            report["after_reopen"] = retained_state(fixture, environment)
            if default_managed is not None:
                wait_windows_setup(process, target, output, environment, report, "reopened_b")
                report["default_after_reopen"] = default_home_readback(binary.parent / (b_installer + suffix), managed, environment)
                initial_mtimes = report["default_before"]["selected_mtime_ns"]
                if any(report[key]["selected_mtime_ns"] != initial_mtimes for key in ("default_after_auto_restart", "default_after_reopen")):
                    raise ValueError("current selected executables were needlessly rewritten")
                report["default_home_relaunch_verified"] = True
            if proxy is not None:
                report["proxy_after_recovery"] = proxy.snapshot()
                if not report.get("offline_check_preserved_a") or not any(row["outcome"] == "tunneled" for row in report["proxy_after_recovery"]["requests"]):
                    raise RuntimeError("same-process recovery did not use the owned original TLS tunnel")
                report["verified_failure_cases"] = ["offline-update-check"]
                report["native_failure_recovery_verified"] = True
            report["two_version_update_verified"] = True
        finally:
            log.close()
    except BaseException as error:
        report["two_version_update_verified"] = False
        report["native_failure_recovery_verified"] = False
        report["failure"] = str(error)
        raise
    finally:
        errors = []
        actions = []
        if process is not None:
            actions.append(lambda: app.stop_owned(process, environment))
        if default_managed is not None:
            daemon_log = Path.home() / ".local/share/obey/daemon.log"
            if daemon_log.is_file():
                try:
                    shutil.copyfile(daemon_log, output / "default-daemon.log")
                except OSError as error:
                    errors.append("cannot retain default daemon log: " + str(error))
        obey = managed / "bin" / ("obey.exe" if os.name == "nt" else "obey")
        if obey.exists():
            actions.append(lambda: command([obey, "service", "uninstall"], environment, timeout=120))
        if owned_nsis:
            actions.append(lambda: app.windows_silent(Path(os.environ["LOCALAPPDATA"]) / "Festival App/uninstall.exe", environment))
        if owned_deb:
            actions.append(lambda: app.apt_command(["remove", "--purge", "-y", "festival-app"], environment, 120))
        for child in (manager, display):
            if child is not None:
                def stop_child(child=child):
                    child.terminate()
                    child.wait(timeout=20)
                actions.append(stop_child)
        if proxy is not None:
            def close_proxy():
                report["proxy_before_cleanup"] = proxy.snapshot()
                proxy.close()
                report["proxy_after_cleanup"] = proxy.snapshot()
            actions.append(close_proxy)
        for action in actions:
            try:
                action()
            except Exception as error:
                errors.append(str(error))
        if not errors:
            try:
                temporary.cleanup()
            except Exception as error:
                errors.append(str(error))
        if errors:
            report["cleanup_failure"] = errors
            report["two_version_update_verified"] = False
            report["default_home_relaunch_verified"] = False
            report["native_failure_recovery_verified"] = False
        (output / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
        if errors:
            raise RuntimeError("owned upgrade cleanup failed: " + "; ".join(errors))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fetch", "verify"), required=True)
    for label in ("a", "b"):
        parser.add_argument("--" + label + "-source", required=True)
        parser.add_argument("--" + label + "-version", required=True)
    parser.add_argument("--failure-mode", choices=("none", "offline-check"), default="none")
    parser.add_argument("--target")
    parser.add_argument("--format", choices=tuple(FORMATS))
    parser.add_argument("--installation-context", choices=("redirected", "default-home"), default="redirected")
    args = parser.parse_args()
    root = Path("upgrade-candidates").resolve()
    if args.mode == "fetch":
        root.mkdir()
        a = fetch_public(root / "a", args.a_source, args.a_version)
        b = fetch_public(root / "b", args.b_source, args.b_version)
        checked_upgrade_pair(a, b)
    else:
        native(root, args.target, args.format, args.a_source, args.a_version, args.b_source, args.b_version, Path("upgrade-proof").resolve(), args.installation_context, args.failure_mode)
