"""Binary-only Festival App packaging/launch proof; never publishes or licenses.

Only the data-only fetch job may read authenticated drafts. Native execution is
restricted to fresh hosted machines and revalidates bytes without credentials.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import sqlite3
import subprocess
import tarfile
import tempfile
import time

from verify_candidate import REPOSITORY, command, native_platform, wait_until
from verify_selected_components import require_clean_host, record_windows_discovery_snapshot
from mac_candidate_diagnostics import diagnose as diagnose_mac_failure
from linux_window_diagnostics import capture_failure as capture_linux_failure

TARGETS = {
    "aarch64-apple-darwin": ("darwin/arm64", {".dmg", ".app.tar.gz", ".app.tar.gz.sig"}),
    "x86_64-apple-darwin": ("darwin/amd64", {".dmg", ".app.tar.gz", ".app.tar.gz.sig"}),
    "x86_64-unknown-linux-gnu": ("linux/amd64", {".deb", ".AppImage", ".AppImage.sig"}),
    "x86_64-pc-windows-msvc": ("windows/amd64", {"-setup.exe", "-setup.exe.sig"}),
}
# Public production trust anchor, identical to the reviewed App391 public key.
PUBLIC_KEY = "RWTlKfGG4A6IoCRsFpbcpf2yJ7v0D5CFRb17f8gK/n3LWdd9x1NKA+ms"


# Keep network transfer separate from the existing five-minute install budget.
# The failed hosted baseline fetched26.6MB in638s; an apt transaction is not an
# App startup timeout. GNU timeout owns the privileged process group, so killing
# only Python's sudo wrapper cannot leave apt holding the package database lock.
APT_DOWNLOAD_SECONDS = 30 * 60
APT_INSTALL_SECONDS = 300
APT_KILL_GRACE_SECONDS = 15


def owned_timeout(arguments, seconds):
    if type(seconds) is not int or seconds <= 0:
        raise ValueError("invalid owned command budget")
    return ["timeout", "--signal=TERM", f"--kill-after={APT_KILL_GRACE_SECONDS}s", f"{seconds}s", *arguments]


def apt_command(arguments, environment, seconds, check=True, authorization=None):
    if authorization is not None:
        return authorization.sudo(owned_timeout(["apt-get", *arguments], seconds), environment,
                                  seconds + APT_KILL_GRACE_SECONDS + 30, check=check)
    return command(["sudo", *owned_timeout(["apt-get", *arguments], seconds)], environment,
                   timeout=seconds + APT_KILL_GRACE_SECONDS + 30, check=check)


def install_cached_deb(deb, environment, authorization=None):
    # apt --no-download cannot install a renamed local Deb absent from its
    # canonical archive cache. Unpack those exact authenticated bytes first,
    # then configure using downloaded dependencies only. Never let fix-broken
    # remove the unpacked App and report apparent success.
    script = 'dpkg --unpack -- "$1" && apt-get --no-download --no-remove --fix-broken install -y'
    if authorization is not None:
        return authorization.sudo(owned_timeout(["bash", "-euc", script, "fa0027-owned-deb", Path(deb).resolve()], APT_INSTALL_SECONDS),
                                  environment, APT_INSTALL_SECONDS + APT_KILL_GRACE_SECONDS + 30)
    return command(["sudo", *owned_timeout(["bash", "-euc", script, "fa0027-owned-deb", Path(deb).resolve()], APT_INSTALL_SECONDS)],
                   environment, timeout=APT_INSTALL_SECONDS + APT_KILL_GRACE_SECONDS + 30)


def install_deb(deb, environment, authorization=None):
    deb = Path(deb).resolve()
    # Simulation cannot install even when the hosted apt configuration forces
    # Assume-Yes. The subsequent real download logs its exact transfer size.
    apt_command(["--simulate", "install", deb], environment, 60, authorization=authorization)
    apt_command(["install", "--download-only", "-y", deb], environment, APT_DOWNLOAD_SECONDS, authorization=authorization)
    install_cached_deb(deb, environment, authorization=authorization)


def identity(tag, version, source):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not re.fullmatch(r"[a-f0-9]{40}", source):
        raise ValueError("invalid App candidate version/source")
    if tag != f"candidate-app-v{version}-{source[:8]}":
        raise ValueError("App candidate tag must match version and source")


def installer_basename(document):
    """Select an explicit layout; field absence is the original v1 contract."""
    if 'installer_basename' not in document:
        return 'festival'
    if document['installer_basename'] != 'festival-app-installer':
        raise ValueError('unsupported App installer basename')
    return document['installer_basename']


def checked_manifest(document, version, source):
    if document.get("schema") != "festival-app-candidate/v1" or document.get("source_revision") != source or document.get("version") != version:
        raise ValueError("App candidate identity mismatch")
    installer_basename(document)
    targets = document.get("targets", {})
    if set(targets) != set(TARGETS):
        raise ValueError("App candidates require exactly four targets")
    files = {}
    for target, entries in targets.items():
        required = TARGETS[target][1]
        suffixes = required | ({".deb.sig"} if target.endswith("linux-gnu") else set())
        if not len(required) <= len(entries) <= len(suffixes):
            raise ValueError("incomplete App target inventory")
        seen = set()
        for item in entries:
            name = item.get("name", "")
            suffix = next((value for value in sorted(suffixes, key=len, reverse=True) if name.endswith(value)), None)
            if not re.fullmatch(r"[A-Za-z0-9_. -]+", name) or Path(name).name != name or "/" in name or "\\" in name or name in files or suffix is None or suffix in seen:
                raise ValueError("unsafe, duplicate or unsupported App artifact")
            if not re.search(r"_" + re.escape(version) + r"_", name) or not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")) or type(item.get("bytes")) is not int or not 0 < item["bytes"] < 2 * 1024**3:
                raise ValueError("invalid App file identity/digest/size")
            if target.endswith("apple-darwin"):
                arch = "aarch64" if target.startswith("aarch64") else "x64"
                if name not in (f"Festival.App_{version}_{arch}{suffix}", f"Festival App_{version}_{arch}{suffix}"):
                    raise ValueError("macOS artifact architecture mismatch")
            if target.endswith("linux-gnu") and not name.endswith("_amd64" + suffix):
                raise ValueError("Linux artifact architecture mismatch")
            if target.endswith("windows-msvc") and not name.endswith("_x64" + suffix):
                raise ValueError("Windows artifact architecture mismatch")
            seen.add(suffix)
            files[name] = item
        if not required <= seen:
            raise ValueError("incomplete App target suffixes")
    return files


def checked_downloads(directory, version, source):
    document = json.loads((directory / "app-candidate.json").read_text())
    files = checked_manifest(document, version, source)
    expected = set(files) | {"app-candidate.json", "checksums.txt"}
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError("unexpected or missing App draft files")
    checksums = {}
    for line in (directory / "checksums.txt").read_text().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
        if not match or match[2] in checksums:
            raise ValueError("invalid or duplicate checksum entry")
        checksums[match[2]] = match[1]
    if checksums != {name: item["sha256"] for name, item in files.items()}:
        raise ValueError("App checksum list disagrees with inventory")
    for name, item in files.items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("App artifact bytes disagree with inventory")
    return document


def fetch(tag, version, source, directory):
    identity(tag, version, source)
    metadata = json.loads(subprocess.check_output(["gh", "release", "view", tag, "--repo", REPOSITORY, "--json", "isDraft,assets"], text=True))
    if not metadata["isDraft"]:
        raise ValueError("App proof requires an unpublished candidate draft")
    names = [item["name"] for item in metadata["assets"]]
    if not 13 <= len(names) <= 14 or len(set(names)) != len(names) or any(Path(n).name != n or "/" in n or "\\" in n for n in names) or "app-candidate.json" not in names or "checksums.txt" not in names:
        raise ValueError("unexpected App draft inventory")
    directory.mkdir()
    subprocess.run(["gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", str(directory)], check=True)
    checked_downloads(directory, version, source)


def verify_signature(artifact, signature, temporary, environment):
    decoded = base64.b64decode(signature.read_bytes().strip(), validate=True)
    sig = temporary / (signature.name + ".minisig")
    sig.write_bytes(decoded)
    command(["minisign", "-Vm", artifact, "-P", PUBLIC_KEY, "-x", sig], environment)


def verify_optional_signature(artifact, temporary, environment):
    signature = artifact.with_name(artifact.name + ".sig")
    if not signature.exists():
        return False
    verify_signature(artifact, signature, temporary, environment)
    return True


def extract_app(archive, destination):
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        if not members or len(members) > 100000 or sum(m.size for m in members) > 2 * 1024**3 or len({m.name for m in members}) != len(members):
            raise ValueError("invalid App archive inventory")
        if any(not m.name.startswith("Festival App.app/") and m.name != "Festival App.app" for m in members):
            raise ValueError("unexpected App archive root")
        stream.extractall(destination, filter="data")
    return destination / "Festival App.app"


def mac_install(directory, entries, temporary, environment, report, installer_name='festival'):
    dmg = directory / next(item["name"] for item in entries if item["name"].endswith(".dmg"))
    archive = directory / next(item["name"] for item in entries if item["name"].endswith(".app.tar.gz"))
    authenticated = temporary / "authenticated"
    authenticated.mkdir()
    signed_app = extract_app(archive, authenticated)
    mount = temporary / "dmg"
    mount.mkdir()
    command(["hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", mount, dmg], environment)
    app = temporary / "installed/Festival App.app"
    try:
        command(["ditto", mount / "Festival App.app", app], environment)
    finally:
        command(["hdiutil", "detach", mount], environment)
    def tree(root):
        result = {}
        for path in root.rglob("*"):
            relative = str(path.relative_to(root))
            if path.is_symlink():
                if not path.resolve().is_relative_to(root.resolve()):
                    raise ValueError("App bundle link escapes its root")
                result[relative] = ["link", os.readlink(path)]
            elif path.is_file():
                result[relative] = ["file", hashlib.sha256(path.read_bytes()).hexdigest()]
            elif path.is_dir():
                result[relative] = ["directory"]
            else:
                raise ValueError("unsupported App bundle entry")
        return result
    if tree(app) != tree(signed_app):
        raise ValueError("DMG bundle differs from authenticated updater bundle")
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    if info.get("CFBundleShortVersionString") != report["version"] or info.get("LSMinimumSystemVersion") != "12.0":
        raise ValueError("App version or advertised macOS minimum mismatch")
    command(["codesign", "--verify", "--deep", "--strict", app], environment)
    report["macos_minimum"] = info["LSMinimumSystemVersion"]
    report["mach_o"] = {}
    expected_arch = "arm64" if report["target"].startswith("aarch64") else "x86_64"
    for name in ("festival-app", installer_name, "festival-activity-engine"):
        path = app / "Contents/MacOS" / name
        arches = command(["lipo", "-archs", path], environment).split()
        loads = command(["otool", "-l", path], environment)
        floors = re.findall(r"\bminos\s+([0-9.]+)", loads)
        if expected_arch not in arches or not floors or any(value not in ("12.0", "12.0.0") for value in floors):
            raise ValueError("bundled executable architecture or macOS12 floor mismatch")
        report["mach_o"][name] = {"architectures": arches, "minima": floors}
    report["structural_codesign_verified"] = True
    return app / "Contents/MacOS/festival-app", app / "Contents/MacOS", app / "Contents/Resources"


def window_capture(process, target, output, environment, mac_tools=None):
    def require_alive():
        if process.poll() is not None:
            raise RuntimeError("owned App process exited before its window appeared")
    if target.endswith("apple-darwin"):
        if mac_tools is None:
            raise RuntimeError('macOS window tools must be prepared before App launch')
        def window():
            require_alive()
            windows = mac_tools.query(process.pid, environment)
            return next((w for w in windows if w.get("kCGWindowLayer") == 0 and w.get("kCGWindowBounds", {}).get("Width", 0) > 100), None)
        found = wait_until("owned App window", window)
        command(["screencapture", "-x", "-l", str(found["kCGWindowNumber"]), output], environment)
        return {"window_id": found["kCGWindowNumber"], "title": found.get("kCGWindowName"), "screenshot": output.name}
    if target.endswith("windows-msvc"):
        query = f'$p=Get-Process -Id {process.pid} -ErrorAction Stop; if($p.MainWindowHandle -ne 0){{@{{handle=$p.MainWindowHandle.ToInt64();title=$p.MainWindowTitle;path=$p.Path;started=$p.StartTime.ToUniversalTime().Ticks.ToString()}}|ConvertTo-Json -Compress}}'
        def window():
            require_alive()
            return json.loads(command(["pwsh", "-NoProfile", "-Command", query], environment) or "null")
        found = wait_until("owned App window", window)
        capture = command(["pwsh", "-NoProfile", "-File", Path(__file__).with_name("capture_windows_app.ps1")],
                          dict(environment, APP_PROOF_SCREENSHOT=str(output), APP_PROOF_DIAGNOSTICS=str(output) + ".capture.jsonl", APP_PROOF_PID=str(process.pid),
                               APP_PROOF_HANDLE=str(found["handle"]), APP_PROOF_EXE=found["path"],
                               APP_PROOF_STARTED=found["started"]), json_output=True)
        return dict(capture, screenshot=output.name)
    def window():
        require_alive()
        result = subprocess.run(["xdotool", "search", "--onlyvisible", "--pid", str(process.pid)], env=environment, text=True, capture_output=True)
        return result.stdout.splitlines()[0] if result.returncode == 0 and result.stdout.strip() else None
    try:
        found = wait_until("owned App window", window)
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        try:
            capture_linux_failure(process, output, environment, error)
        except Exception as diagnostic_error:
            print(json.dumps({'linux_window_diagnostic_error': str(diagnostic_error)}), flush=True)
        raise
    title = command(["xdotool", "getwindowname", found], environment).strip()
    command(["import", "-window", found, output], environment)
    return {"window_id": found, "title": title, "screenshot": output.name}


def capture_startup(process, target, output, environment, captures, stem="app", mac_tools=None):
    launch_started = time.monotonic()
    first_capture = None
    latest = None
    for delay, label in ((0, "initial"), (5, "5s"), (15, "15s")):
        # A cold window or its first screenshot can take longer than all
        # requested delays. Anchor later samples after that first capture,
        # otherwise every supposed delayed frame is captured back-to-back.
        if first_capture is not None:
            remaining = delay - (time.monotonic() - first_capture)
            if remaining > 0:
                time.sleep(remaining)
        if process.poll() is not None:
            raise RuntimeError("owned App exited before delayed startup capture")
        screenshot = output / f"{stem}-{label}.png"
        latest = window_capture(process, target, screenshot, environment, **({"mac_tools": mac_tools} if mac_tools else {}))
        if process.poll() is not None or not screenshot.is_file() or screenshot.stat().st_size == 0:
            raise RuntimeError("owned App did not retain a live delayed screenshot")
        captured = time.monotonic()
        if first_capture is None:
            first_capture = captured
        captures.append({"requested_seconds": delay, "elapsed_seconds": round(captured - first_capture, 3),
                         "elapsed_since_launch_seconds": round(captured - launch_started, 3), "window": latest})
    # Keep the existing primary artifact name, now pointing at the late frame.
    primary = output / f"{stem}.png"
    shutil.copyfile(output / latest["screenshot"], primary)
    return dict(latest, screenshot=primary.name)


def appimage_proof(appimage, extracted, target, output, environment, report):
    process = None
    try:
        with (output / "appimage-default.log").open("w") as log:
            process = subprocess.Popen([str(appimage)], env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                report["appimage_default_window"] = capture_startup(process, target, output, environment, report.setdefault("appimage_default_captures", []), "appimage-default")
                if process.poll() is not None:
                    raise RuntimeError("default AppImage exited during launch")
                report["appimage_default_launch_verified"] = True
            except BaseException as error:
                report["appimage_default_launch_verified"] = False
                report["appimage_default_failure"] = str(error)
                report["appimage_default_exit"] = process.poll()
        stop_owned(process, environment)
        process = None
        if not report["appimage_default_launch_verified"]:
            # This diagnostic never replaces the original default launch result.
            with (output / "appimage-extracted-diagnostic.log").open("w") as log:
                process = subprocess.Popen([str(extracted)], env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                report["appimage_extracted_diagnostic_window"] = capture_startup(process, target, output, environment, report.setdefault("appimage_extracted_diagnostic_captures", []), "appimage-extracted-diagnostic")
                report["appimage_extracted_diagnostic_only"] = True
            raise RuntimeError("default AppImage launch failed; extracted startup is diagnostic only")
    finally:
        if process is not None:
            stop_owned(process, environment)


def windows_silent(executable, environment):
    script = '$ErrorActionPreference="Stop"; $p=Start-Process -FilePath $env:APP_PROOF_SETUP -ArgumentList "/S" -Wait -PassThru; if($p.ExitCode -ne 0){throw "NSIS failed: $($p.ExitCode)"}'
    command(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script], dict(environment, APP_PROOF_SETUP=str(executable)), timeout=120)


def windows_owned_birth(process):
    identity = getattr(process, "identity", None)
    if isinstance(identity, dict):
        if (type(identity.get("pid")) is not int or identity["pid"] <= 0 or identity["pid"] != process.pid
                or not re.fullmatch("[0-9]+", str(identity.get("started", ""))) or int(identity["started"]) <= 0):
            raise RuntimeError("invalid observed Windows root identity")
        return str(identity["started"])
    from windows_console import process_birth
    return process_birth(process)


def stop_owned(process, environment):
    if process.poll() is not None:
        return
    if os.name == "nt":
        query = Path(__file__).with_name("windows_owned_processes.ps1")
        started = windows_owned_birth(process)
        identities = json.loads(command(["pwsh", "-NoProfile", "-NonInteractive", "-File", query],
                                       dict(environment, APP_PROOF_PROCESS_MODE="snapshot", APP_PROOF_PROCESS_PID=str(process.pid), APP_PROOF_PROCESS_STARTED=started)))
        if not isinstance(identities, list) or any(not isinstance(item, dict) or type(item.get("pid")) is not int or item["pid"] <= 0 or not re.fullmatch("[0-9]+", str(item.get("started", ""))) or int(item["started"]) <= 0 for item in identities):
            raise RuntimeError("invalid owned process identity snapshot")
        if {"pid": process.pid, "started": started} not in identities or len({item["pid"] for item in identities}) != len(identities):
            raise RuntimeError("owned process snapshot lost the known root identity")
        # taskkill can return nonzero for an already-exiting WebView descendant.
        # Retain that result, and accept cleanup only after identity-aware readback.
        killed = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], env=environment,
                                text=True, capture_output=True, timeout=30)
        print(json.dumps({"owned_process_cleanup": {"identities": identities, "taskkill_exit": killed.returncode,
                                                  "stdout": killed.stdout, "stderr": killed.stderr}}), flush=True)
        command(["pwsh", "-NoProfile", "-NonInteractive", "-File", query],
                dict(environment, APP_PROOF_PROCESS_MODE="verify", APP_PROOF_PROCESS_IDENTITIES=json.dumps(identities)), timeout=30)
    else:
        os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=20)


def fresh_setup_readback(installer, managed, environment, external_suite=None, active_session=None):
    import verify_app_upgrade as upgrade
    from verify_selected_components import checked_receipts
    if active_session is not None:
        status = active_session.readback()
    elif external_suite is None:
        status = upgrade.default_home_readback(installer, managed, environment)
        status["receipts"] = checked_receipts(managed)
    else:
        status = external_suite.readback()
    obey = managed / "bin" / ("obey.exe" if os.name == "nt" else "obey")
    service = command([obey, "service", "status", "--json"], environment, json_output=True)
    if not (service.get("installed") and service.get("loaded") and service.get("socket_reachable") and service.get("daemon_pid", 0) > 0):
        raise RuntimeError("App-provisioned default service is not installed, loaded and responsive")
    status["service"] = service
    return status


def wait_fresh_setup(process, installer, managed, target, output, environment, report, stage, mac_tools=None, external_suite=None, active_session=None):
    import verify_app_upgrade as upgrade
    if target.endswith("windows-msvc"):
        upgrade.wait_windows_setup(process, target, output, environment, report, stage)
        return fresh_setup_readback(installer, managed, environment, external_suite)
    def ready():
        if process.poll() is not None:
            raise RuntimeError("App exited during fresh default-home setup")
        try:
            return fresh_setup_readback(installer, managed, environment, external_suite, active_session)
        except (RuntimeError, ValueError, OSError, sqlite3.Error) as error:
            report[stage + "_last_provisioning_error"] = str(error)
            return None
    result = wait_until("App-driven default-home selected packages and live service", ready, seconds=600)
    # Component/service readiness cannot establish rendered UI. Retain delayed
    # original windows for explicit image review before accepting that boundary.
    capture_dir = output / stage
    capture_dir.mkdir()
    report[stage + "_capture_directory"] = stage
    report[stage + "_window"] = capture_startup(process, target, capture_dir, environment, report.setdefault(stage + "_captures", []), **({"mac_tools": mac_tools} if mac_tools else {}))
    report["rendered_setup_requires_image_review"] = True
    return result


def extract_appimage_observers(appimage, temporary, environment, installer_name='festival'):
    """Extract authenticated CLI observers; never launch the extracted App."""
    subprocess.run([str(appimage), "--appimage-extract"], cwd=temporary, env=environment,
                   check=True, stdout=subprocess.DEVNULL, timeout=60)
    root = temporary / 'squashfs-root'
    installers = [path for path in root.rglob(installer_name) if path.is_file() and os.access(path, os.X_OK)]
    if len(installers) != 1:
        raise ValueError('AppImage must bundle exactly one installer executable')
    return installers[0].parent, root


def native(directory, document, target, output, linux_package="both", fresh_setup=False, public_root=None, existing_user="none", login_shell_proof=False, missing_git_manual=False, login_shell_kind='default', guest_context=None):
    require_clean_host({"aarch64-apple-darwin": "macOS-arm64", "x86_64-apple-darwin": "macOS-x86_64", "x86_64-unknown-linux-gnu": "linux-x86_64", "x86_64-pc-windows-msvc": "windows-x86_64"}.get(target))
    if existing_user not in ("none", "older-idle", "older-active", "current", "missing-companion", "corrupt-integrations", "foreign-companion", "corrupt-receipts", "external-suite-old", "external-suite-minimum", "external-suite-current") or existing_user != "none" and not fresh_setup:
        raise ValueError("existing-user scenario requires public default-home proof")
    if existing_user in ("corrupt-integrations", "foreign-companion") and target != "x86_64-pc-windows-msvc":
        raise ValueError("manual existing-user diagnostic/recovery currently requires native Windows")
    if existing_user == 'corrupt-receipts' and not (target == 'x86_64-pc-windows-msvc' or
            target == 'x86_64-unknown-linux-gnu' and linux_package == 'both'):
        raise ValueError('receipt recovery requires native Windows or Linux Deb')
    if existing_user.startswith('external-suite-') and (target != 'x86_64-unknown-linux-gnu' or linux_package != 'both' or login_shell_proof or missing_git_manual or login_shell_kind != 'default' or guest_context is not None):
        raise ValueError('external suite proof requires isolated Linux Deb first-launch mode')
    if existing_user == 'older-active' and (target != 'x86_64-unknown-linux-gnu' or linux_package != 'both' or login_shell_proof or missing_git_manual or login_shell_kind != 'default' or guest_context is not None):
        raise ValueError('real active-session proof requires isolated Linux Deb mode')
    if login_shell_proof and (not fresh_setup or existing_user != "none"):
        raise ValueError("new login shell proof requires unseeded public fresh setup")
    if missing_git_manual and (not fresh_setup or existing_user != 'none' or login_shell_proof or target != 'x86_64-unknown-linux-gnu' or linux_package != 'both'):
        raise ValueError('missing Git recovery requires unseeded Linux Deb fresh setup only')
    checked_login_selection(login_shell_kind, login_shell_proof, fresh_setup, target, existing_user, missing_git_manual)
    if target not in TARGETS or native_platform() != TARGETS[target][0]:
        raise ValueError("App target does not match native machine")
    if linux_package not in ("both", "appimage") or linux_package == "appimage" and not target.endswith("linux-gnu"):
        raise ValueError("invalid fresh AppImage target/mode")
    if any(os.environ.get(name) for name in ("GH_TOKEN", "GITHUB_TOKEN")):
        raise RuntimeError("App native execution must not receive a draft credential")
    if guest_context is not None:
        if not fresh_setup or public_root is None or existing_user != 'none' or login_shell_proof or missing_git_manual or target != 'x86_64-unknown-linux-gnu':
            raise ValueError('local guest requires an unseeded public Linux journey')
        guest_context.validate()
    installer_name = installer_basename(document)
    report = {"source_revision": document["source_revision"], "version": document["version"], "target": target,
              "installer_basename": installer_name,
              "runner_platform": native_platform(), "first_use_complete": False, "useful_first_use_verified": False, "native_failure_recovery_verified": False, "license_access_verified": False,
              "reboot_verified": False, "consumer_trust_verified": False, "two_version_update_verified": False, "native_packaging_launch_verified": False, "linux_package_mode": linux_package}
    output.mkdir()
    process = xvfb = manager = window_events = None
    installed = None
    owned_deb = False
    appimage = extracted_appimage = None
    environment = dict(os.environ)
    for key in list(environment):
        if key.endswith(("_TOKEN", "_PASSWORD", "_PRIVATE_KEY")):
            environment.pop(key, None)
    default_managed = None
    packaging_root = None
    existing_fixture = None
    login_fixture = None
    account_fixture = None
    git_fixture = None
    integration_fixture = None
    foreign_fixture = None
    receipt_fixture = None
    receipt_accessibility = None
    external_fixture = None
    active_fixture = None
    report['active_session_update_verified'] = False
    report["corrupt_receipt_manual_recovery_verified"] = False
    report["foreign_companion_manual_recovery_verified"] = False
    report["corrupt_integration_manual_recovery_verified"] = False
    report['missing_git_manual_recovery_verified'] = False
    report['automatic_git_authorization_verified'] = False
    report["new_login_shell_verified"] = False
    report['requested_login_shell'] = login_shell_kind
    report["existing_user_scenario"] = existing_user
    report["existing_user_reconciliation_verified"] = False
    report["external_suite_compatibility_verified"] = False
    report['external_suite_preexisted_app_install'] = False
    report["missing_companion_repair_verified"] = False
    if fresh_setup:
        # Runtime import reuses the existing default-home/normal-quit contracts;
        # upgrade verification itself imports this packaging module.
        import verify_app_upgrade as upgrade
    report["fresh_default_setup_verified"] = False
    report["selected_packages_preseeded"] = False

    def uninstall_windows():
        windows_silent(installed / "uninstall.exe", environment)
        wait_until("owned App uninstall", lambda: not (installed / "festival-app.exe").exists())
        report["uninstalled"] = True

    def uninstall_deb():
        apt_command(["remove", "--purge", "-y", "festival-app"], environment, 120, authorization=guest_context)
        if Path("/usr/bin/festival-app").exists():
            raise RuntimeError("owned deb uninstall left App executable")
        report["deb_uninstalled"] = True

    temporary_context = tempfile.TemporaryDirectory(prefix="app-proof-", dir=os.environ["RUNNER_TEMP"])
    try:
        temporary = Path(temporary_context.name)
        mac_options = {}
        if fresh_setup:
            report["default_xdg_environment"] = {name: environment[name] for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME") if environment.get(name)}
            default_managed = upgrade.default_home_layout(Path.home(), environment)
            if login_shell_proof:
                import login_shell
                if login_shell_kind == 'zsh':
                    import mac_login_account
                    account_fixture = mac_login_account.prepare(environment, report)
                login_fixture = login_shell.prepare(environment, report, login_shell_kind)
        if not fresh_setup:
            environment.update(FESTIVAL_HOME=str(temporary / "managed"), OBEY_CONFIG=str(temporary / "obey.yaml"))
            if os.name == 'nt':
                # Make this Windows packaging fixture's declared isolation real;
                # accepted Mac/Linux packaging contexts stay unchanged.
                (temporary / 'obey.yaml').write_text('data_dir: ' + json.dumps((temporary / 'data').as_posix()) + '\ngrpc:\n  socket: ' + json.dumps((temporary / 'daemon.sock').as_posix()) + '\nnetwork:\n  enabled: false\nwatcher:\n  enabled: false\n')
                import packaging_service
                report['packaging_service_baseline'] = packaging_service.baseline(temporary, environment)
                packaging_root = temporary
        # The machine/account itself is disposable. Native OS lookup retains
        # its real HOME, unlike redirected-home tests that miss supervisors.
        if public_root is not None:
            retained = output / "public-inputs"
            retained.mkdir()
            for name in ("release.json", "SHA256SUMS", "latest.json"):
                shutil.copyfile(public_root / name, retained / name)
            for name in ("app-candidate.json", "checksums.txt"):
                shutil.copyfile(public_root / "assets" / name, retained / name)
        entries = document["targets"][target]
        updater = next(item["name"] for item in entries if item["name"].endswith((".app.tar.gz", ".AppImage", "-setup.exe")))
        report["original_updater_payload"] = next(item for item in entries if item["name"] == updater)
        verify_signature(directory / updater, directory / (updater + ".sig"), temporary, environment)
        report["production_updater_signature_verified"] = True
        if target.endswith("apple-darwin"):
            binary, commands, resources = mac_install(directory, entries, temporary, environment, report, installer_name)
        elif target.endswith("windows-msvc"):
            install_path = Path(os.environ["LOCALAPPDATA"]) / "Festival App"
            if install_path.exists():
                raise RuntimeError("refusing preexisting App installation")
            installed = install_path
            windows_silent(directory / updater, environment)
            binary, commands, resources = installed / "festival-app.exe", installed, installed / "resources"
            binary_version = command(["pwsh", "-NoProfile", "-Command", "(Get-Item -LiteralPath $env:APP_PROOF_EXE).VersionInfo.ProductVersion"], dict(environment, APP_PROOF_EXE=str(binary))).strip()
            if binary_version not in (report["version"], report["version"] + ".0"):
                raise ValueError("installed Windows App version mismatch")
            report["installed_version"] = binary_version
        else:
            if shutil.which("festival-app"):
                raise RuntimeError("refusing a preexisting App command")
            if linux_package == "both":
                deb = directory / next(item["name"] for item in entries if item["name"].endswith(".deb"))
                report["deb_signature_verified"] = verify_optional_signature(deb, temporary, environment)
                package = command(["dpkg-deb", "-f", deb, "Package"], environment).strip()
                deb_version = command(["dpkg-deb", "-f", deb, "Version"], environment).strip()
                if package != "festival-app" or deb_version != report["version"]:
                    raise ValueError("deb package/version differs from candidate identity")
                state = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", package], capture_output=True, text=True, env=environment)
                if state.returncode == 0 and state.stdout.strip() != "not-installed":
                    raise RuntimeError("refusing preexisting App package state")
                if existing_user.startswith('external-suite-'):
                    import external_suite
                    external_fixture = external_suite.Fixture(temporary, Path('/usr/bin') / installer_name,
                        default_managed, environment, output, report.setdefault('external_suite_fixture', {}), existing_user)
                    external_fixture.install_package()
                owned_deb = True
                install_deb(deb, environment, authorization=guest_context)
                installed_version = command(["dpkg-query", "-W", "-f=${Version}", package], environment).strip()
                if installed_version != report["version"]:
                    raise ValueError("installed deb version mismatch")
                report["deb_installed_version"] = installed_version
                report["deb_install_with_dependency_resolution"] = True
                if external_fixture is not None:
                    external_fixture.report['after_app_package_install'] = external_fixture.unchanged()
                    report['external_suite_preexisted_app_install'] = True
            # The guest retains its original public download through reboot.
            # Ordinary hosted proofs still own a temporary copy.
            appimage = directory / updater if guest_context is not None and linux_package == 'appimage' else temporary / updater
            if appimage != directory / updater:
                shutil.copyfile(directory / updater, appimage)
            appimage.chmod(0o755)
            image_commands, extracted_root = extract_appimage_observers(appimage, temporary, environment, installer_name)
            extracted_appimage = temporary / "squashfs-root/AppRun"
            if linux_package == "appimage":
                # Extract only to inspect/probe the authenticated bundled CLI
                # resources; the App itself launches the original image below.
                binary, commands, resources = appimage, image_commands, extracted_root
                report["deb_install_exercised"] = False
            else:
                binary, commands, resources = Path("/usr/bin/festival-app"), Path("/usr/bin"), Path("/usr/lib")
            if guest_context is not None:
                report['local_guest_session'] = guest_context.validate()
            else:
                if Path("/tmp/.X11-unix/X99").exists():
                    raise RuntimeError("refusing a preexisting display")
                xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1280x900x24"], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                environment["DISPLAY"] = ":99"
                wait_until("owned Xvfb", lambda: subprocess.run(["xdpyinfo"], env=environment, capture_output=True).returncode == 0)
                if fresh_setup:
                    manager = subprocess.Popen(["openbox"], env=environment, start_new_session=True)
                    from linux_desktop import wait_for_openbox
                    report['linux_desktop_ready'] = wait_for_openbox(manager, environment)
            from linux_window_events import Recorder
            window_events = Recorder(output, environment, report)
        suffix = ".exe" if target.endswith("windows-msvc") else ""
        installer, activity = commands / (installer_name + suffix), commands / ("festival-activity-engine" + suffix)
        for path in (binary, installer, activity):
            if not path.is_file():
                raise ValueError("installed bundle is missing " + str(path))
        # Resource placement differs between packaging formats; retain the
        # actual discovered path, refusing absence rather than inventing one.
        runtime = list(resources.rglob("festival-activity.config.yaml"))
        if len(runtime) != 1:
            raise ValueError("bundle must contain exactly one Activity runtime config")
        report["installer_version"] = command([installer, "version"], environment).strip()
        report["activity_help"] = command([activity, "--help"], environment).strip()
        report["runtime_config"] = str(runtime[0])
        if existing_user not in ("none", "older-active") and not existing_user.startswith("external-suite-"):
            import existing_obey
            existing_fixture = existing_obey.seed(temporary, installer, default_managed, target, environment, output, report, "current" if existing_user in ("corrupt-integrations", "foreign-companion", "corrupt-receipts") else existing_user)
            if existing_user == "corrupt-integrations":
                import corrupt_integrations
                integration_fixture = corrupt_integrations.Fixture(default_managed, temporary / "integration-rollback", report.setdefault("integration_preferences_fixture", {}))
                integration_fixture.corrupt()
                report["corrupt_integration_installer_error"] = corrupt_integrations.installer_error(installer, environment, output)
            if existing_user == "foreign-companion":
                import foreign_companion
                foreign_fixture = foreign_companion.Fixture(default_managed, installer, temporary / "companion-rollback", report.setdefault("foreign_companion_fixture", {}))
                foreign_fixture.substitute()
                report["foreign_companion_probe"] = foreign_companion.probe(installer, foreign_fixture, environment, output)
        if existing_user == 'older-active':
            import active_session
            active_fixture = active_session.Fixture(temporary, installer, default_managed, target, environment,
                                                    output, report.setdefault('active_session_fixture', {}))
            active_fixture.seed()
            report['selected_packages_preseeded'] = True
            report['existing_seed_method'] = 'authenticated historical managed Obey fixture with real provider work'
        if external_fixture is not None:
            external_fixture.prepare_existing_cli()
            report['selected_packages_preseeded'] = True
            report['existing_seed_method'] = 'real external Debian suite and official managed CLI tools; no App settings'
        if existing_user == "corrupt-receipts":
            import corrupt_receipts
            if target.endswith('linux-gnu'):
                from linux_accessibility import ToolkitSetting
                receipt_accessibility = ToolkitSetting(environment)
                receipt_accessibility.enable()
            receipt_fixture = corrupt_receipts.Fixture(default_managed, temporary / "receipt-rollback", report.setdefault("corrupt_receipt_fixture", {}), environment)
            receipt_fixture.corrupt()
            report["corrupt_receipt_installer_status"] = corrupt_receipts.probe(installer, receipt_fixture, report["existing_before"], environment, output)
        if guest_context is not None:
            guest_context.before_launch(installer, environment, output, report)
        if missing_git_manual:
            import missing_git
            git_fixture = missing_git.Fixture(temporary/'git-restore-cache', output, environment)
            git_fixture.enable_accessibility()
            git_fixture.remove()
            report['git_missing_prerequisite'] = missing_git.git_status(installer, environment, False, output/'git-absent-status.json')
        if target.endswith('apple-darwin'):
            import mac_window_tools
            tools = mac_window_tools.prepare(temporary, output, environment)
            report['mac_window_tools'] = tools.identity
            mac_options['mac_tools'] = tools
        with (output / "app.log").open("w") as log:
            process = subprocess.Popen([str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
            report["pid"] = process.pid
            def alive_window():
                if process.poll() is not None:
                    raise RuntimeError("App exited before window capture: " + (output / "app.log").read_text())
                return True
            alive_window()
            report["window"] = capture_startup(process, target, output, environment, report.setdefault("startup_captures", []), **mac_options)
            if process.poll() is not None or not (output / "app.png").is_file() or (output / "app.png").stat().st_size == 0:
                raise RuntimeError("App did not retain a live captured window")
            if fresh_setup:
                if integration_fixture is not None:
                    def diagnosed():
                        if process.poll() is not None:
                            raise RuntimeError("App exited instead of presenting the corrupt-integration diagnostic")
                        frame = window_capture(process, target, output / "corrupt-integration.png", environment)
                        report["corrupt_integration_window"] = frame
                        return frame if corrupt_integrations.error_window(frame, report["corrupt_integration_installer_error"]) else None
                    wait_until("actual App displays the injected integration preferences error", diagnosed, seconds=180)
                    report["corrupt_integration_unchanged_preferences"] = integration_fixture.unchanged_corruption()
                    report["corrupt_integration_preserved_user"] = corrupt_integrations.unchanged_user(
                        existing_fixture, report["existing_before"], installer, environment)
                    # Restore only after the real owned App has quit normally.
                    upgrade.normal_quit(process, binary, None, target, environment, output)
                    integration_fixture.restore()
                    process = subprocess.Popen([str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT)
                    report["integration_recovery_pid"] = process.pid
                if foreign_fixture is not None:
                    def foreign_diagnosed():
                        if process.poll() is not None:
                            raise RuntimeError("App exited instead of preserving and reporting the foreign companion")
                        frame = window_capture(process, target, output / "foreign-companion.png", environment)
                        report["foreign_companion_window"] = frame
                        return frame if foreign_companion.error_window(frame, report["foreign_companion_probe"]) else None
                    wait_until("actual App reports the preserved foreign companion", foreign_diagnosed, seconds=180)
                    report["foreign_companion_preserved_user"] = foreign_companion.preserved_user(
                        existing_fixture, report["existing_before"], foreign_fixture, environment)
                    upgrade.normal_quit(process, binary, None, target, environment, output)
                    foreign_fixture.restore()
                    process = subprocess.Popen([str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT)
                    report["foreign_recovery_pid"] = process.pid
                if receipt_fixture is not None:
                    def receipt_diagnosed():
                        if process.poll() is not None:
                            raise RuntimeError("App exited instead of reporting unreadable receipt state")
                        frame = window_capture(process, target, output / "corrupt-receipt.png", environment)
                        if target.endswith('linux-gnu'):
                            frame['receipt_accessibility'] = corrupt_receipts.linux_observation(process, binary, environment)
                        report["corrupt_receipt_window"] = frame
                        return frame if corrupt_receipts.error_window(frame) else None
                    wait_until("actual App reports unreadable installer state", receipt_diagnosed, seconds=180)
                    report["corrupt_receipt_preserved_user"] = corrupt_receipts.preserved_user(existing_fixture, report["existing_before"], receipt_fixture, environment)
                    upgrade.normal_quit(process, binary, None, target, environment, output)
                    receipt_fixture.restore()
                    process = subprocess.Popen([str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=os.name != 'nt')
                    report["receipt_recovery_pid"] = process.pid
                if git_fixture is not None:
                    report['git_missing_ui'] = missing_git.interact(process, binary, environment, 'inspect')
                    missing_capture = output/'git-missing'; missing_capture.mkdir()
                    report['git_missing_window'] = capture_startup(process, target, missing_capture, environment, report.setdefault('git_missing_captures', []))
                    git_fixture.restore()
                    report['git_restored_prerequisite'] = missing_git.git_status(installer, environment, True, output/'git-restored-status.json')
                    report['git_retry_action'] = missing_git.interact(process, binary, environment, 'retry')
                if guest_context is not None:
                    guest_context.install_git(process, binary, installer, environment, output, report)
                report["default_after_setup"] = wait_fresh_setup(process, installer, default_managed, target, output, environment, report, "fresh", external_suite=external_fixture, active_session=active_fixture, **mac_options)
                if active_fixture is not None:
                    active_fixture.after_update()
                if receipt_fixture is not None:
                    report["receipt_database_after_setup"] = receipt_fixture.healthy()
                if foreign_fixture is not None:
                    report["companion_after_setup"] = foreign_fixture.healthy()
                if integration_fixture is not None:
                    report["integration_preferences_after_setup"] = integration_fixture.healthy()
                if login_fixture is not None:
                    report["login_after_setup"] = login_shell.verify(login_fixture, default_managed, installer, environment, output, "after-setup")
                if existing_fixture is not None:
                    report["existing_after_setup"] = existing_obey.ready_readback(existing_fixture, installer, environment, "0.2.3")
                    if report["existing_after_setup"] is None:
                        raise RuntimeError("updated existing-user service was not ready")
                    existing_obey.compare(report["existing_before"], report["existing_after_setup"], "current" if existing_user in ("corrupt-integrations", "foreign-companion", "corrupt-receipts") else existing_user)
                upgrade.normal_quit(process, binary, binary.parent.parent.parent if target.endswith("apple-darwin") else None, target, environment, output, **mac_options)
                if active_fixture is not None:
                    active_fixture.stop_for_idle()
                process = subprocess.Popen([str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
                report["reopened_pid"] = process.pid
                report["default_after_reopen"] = wait_fresh_setup(process, installer, default_managed, target, output, environment, report, "reopened", external_suite=external_fixture, active_session=active_fixture, **mac_options)
                if receipt_fixture is not None:
                    report["receipt_database_after_reopen"] = receipt_fixture.healthy()
                    report["corrupt_receipt_manual_recovery_verified"] = True
                if foreign_fixture is not None:
                    report["companion_after_reopen"] = foreign_fixture.healthy()
                if integration_fixture is not None:
                    report["integration_preferences_after_reopen"] = integration_fixture.healthy()
                if login_fixture is not None:
                    report["login_after_reopen"] = login_shell.verify(login_fixture, default_managed, installer, environment, output, "after-reopen")
                    if report["login_after_setup"] != report["login_after_reopen"]:
                        raise ValueError("App reopen changed ordinary shell commands or profile state")
                    report["new_login_shell_verified"] = True
                for field in ("receipts", "selected_mtime_ns"):
                    if report["default_after_setup"][field] != report["default_after_reopen"][field]:
                        raise ValueError("App relaunch changed selected package receipts/files")
                if target.endswith('windows-msvc') and existing_user != 'older-idle':
                    daemon_log = Path.home() / '.local/share/obey/daemon.log'
                    record_windows_discovery_snapshot(daemon_log, output, report)
                if existing_fixture is not None:
                    report["existing_after_reopen"] = existing_obey.ready_readback(existing_fixture, installer, environment, "0.2.3")
                    if report["existing_after_reopen"] is None:
                        raise RuntimeError("reopened existing-user service was not ready")
                    existing_obey.compare(report["existing_after_setup"], report["existing_after_reopen"], "current")
                    report["existing_user_reconciliation_verified"] = True
                    report["missing_companion_repair_verified"] = existing_user == "missing-companion"
                    report["corrupt_integration_manual_recovery_verified"] = integration_fixture is not None and integration_fixture.restored
                    report["foreign_companion_manual_recovery_verified"] = foreign_fixture is not None and foreign_fixture.restored
                elif active_fixture is not None:
                    active_fixture.finish()
                    report['active_session_update_verified'] = True
                elif external_fixture is not None:
                    if not report['external_suite_preexisted_app_install']:
                        raise ValueError('external suite must preexist the App package installation')
                    external_fixture.finish(report['default_after_setup'], report['default_after_reopen'])
                    report['external_suite_compatibility_verified'] = True
                else:
                    report["fresh_default_setup_verified"] = True
                    report['missing_git_manual_recovery_verified'] = git_fixture is not None and git_fixture.restored
            report["primary_packaged_app_launch_verified"] = True
            if linux_package == "appimage":
                report["appimage_default_launch_verified"] = True
                report["appimage_extracted_app_executed"] = False
        # Stop only the process created by this proof, before uninstall/temp cleanup.
        if guest_context is not None:
            upgrade.normal_quit(process, binary, None, target, environment, output)
            report['guest_retained_for_reboot'] = True
        else:
            stop_owned(process, environment)
        process = None
        if appimage is not None and linux_package == "both" and not fresh_setup:
            appimage_proof(appimage, extracted_appimage, target, output, environment, report)
        if installed is not None:
            uninstall_windows()
            installed = None
    except BaseException as error:
        report["failure"] = str(error)
        if target.endswith("apple-darwin") and (temporary / "installed/Festival App.app").exists():
            report["mac_diagnostics"] = diagnose_mac_failure(temporary / "installed/Festival App.app", temporary, output, environment, allow_modified_copy=os.environ.get("APP_PROOF_MAC_ENTITLEMENT_DIAGNOSTIC") == "true", installer_name=installer_name)
        raise
    finally:
        cleanup_errors = []
        actions = []
        if process is not None and process.poll() is None:
            actions.append(lambda: stop_owned(process, environment))
        if integration_fixture is not None:
            def restore_owned_preferences():
                if process is not None and process.poll() is None:
                    raise RuntimeError("refusing preference rollback while owned App remains live")
                integration_fixture.restore()
            actions.append(restore_owned_preferences)
        if foreign_fixture is not None:
            def restore_owned_companion():
                if process is not None and process.poll() is None:
                    raise RuntimeError("refusing companion rollback while owned App remains live")
                foreign_fixture.restore()
            actions.append(restore_owned_companion)
        if receipt_fixture is not None:
            def restore_owned_receipts():
                if process is not None and process.poll() is None:
                    raise RuntimeError("refusing receipt rollback while owned App remains live")
                receipt_fixture.restore()
            actions.append(restore_owned_receipts)
        if receipt_accessibility is not None:
            def restore_receipt_accessibility():
                receipt_accessibility.restore()
                report['receipt_accessibility_restored'] = {
                    'original': receipt_accessibility.original,
                    'after': receipt_accessibility.read(),
                }
            actions.append(restore_receipt_accessibility)
        if account_fixture is not None:
            actions.append(account_fixture.restore)
        if git_fixture is not None:
            actions.append(git_fixture.restore)
            actions.append(git_fixture.restore_accessibility)
        if packaging_root is not None:
            actions.append(lambda: packaging_service.cleanup(packaging_root, environment, report))
        if default_managed is not None:
            daemon_log = Path.home() / ".local/share/obey/daemon.log"
            if active_fixture is not None:
                report['daemon_log_omitted'] = 'Real provider text is excluded from exported evidence'
            elif daemon_log.is_file():
                try:
                    shutil.copyfile(daemon_log, output / "default-daemon.log")
                except OSError as error:
                    cleanup_errors.append("cannot retain default daemon log: " + str(error))
            elif report.get("fresh_default_setup_verified"):
                cleanup_errors.append("App setup did not retain a default daemon log")
            obey = default_managed / "bin" / ("obey.exe" if os.name == "nt" else "obey")
            if obey.is_file() and guest_context is None:
                def uninstall_owned_service():
                    command([obey, "service", "uninstall"], environment, timeout=120)
                    state = command([obey, "service", "status", "--json"], environment, json_output=True)
                    report["service_after_cleanup"] = state
                    if state.get("installed") or state.get("loaded") or state.get("socket_reachable"):
                        raise RuntimeError("owned default service remained after cleanup")
                actions.append(uninstall_owned_service)
        if installed is not None and (installed / "uninstall.exe").is_file():
            actions.append(uninstall_windows)
        if owned_deb and guest_context is None:
            actions.append(uninstall_deb)
        if external_fixture is not None:
            actions.append(external_fixture.cleanup)
        if active_fixture is not None:
            actions.append(active_fixture.cleanup)
        if manager is not None:
            def stop_manager():
                manager.terminate()
                manager.wait(timeout=10)
            actions.append(stop_manager)
        if window_events is not None:
            actions.append(window_events.stop)
        if xvfb is not None:
            def stop_display():
                xvfb.terminate()
                xvfb.wait(timeout=10)
            actions.append(stop_display)
        if guest_context is not None:
            actions.append(guest_context.close)
            report["guest_cleanup_owner"] = "outer disposable VM; installed App and service retained for actual reboot"
        actions.append(temporary_context.cleanup)
        for action in actions:
            try:
                action()
            except BaseException as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            report["cleanup_failure"] = cleanup_errors
        report["native_packaging_launch_verified"] = "failure" not in report and not cleanup_errors
        report["fresh_default_setup_verified"] = report["fresh_default_setup_verified"] and report["native_packaging_launch_verified"]
        report["external_suite_compatibility_verified"] = report["external_suite_compatibility_verified"] and report["native_packaging_launch_verified"]
        report['active_session_update_verified'] = report['active_session_update_verified'] and report['native_packaging_launch_verified']
        report["new_login_shell_verified"] = report["new_login_shell_verified"] and report["native_packaging_launch_verified"]
        report["automatic_git_authorization_verified"] = report["automatic_git_authorization_verified"] and report["native_packaging_launch_verified"]
        report["corrupt_integration_manual_recovery_verified"] = report["corrupt_integration_manual_recovery_verified"] and report["native_packaging_launch_verified"]
        report["corrupt_receipt_manual_recovery_verified"] = report["corrupt_receipt_manual_recovery_verified"] and report["native_packaging_launch_verified"]
        report["foreign_companion_manual_recovery_verified"] = report["foreign_companion_manual_recovery_verified"] and report["native_packaging_launch_verified"]
        report["existing_user_reconciliation_verified"] = report["existing_user_reconciliation_verified"] and report["native_packaging_launch_verified"]
        report["missing_companion_repair_verified"] = report["missing_companion_repair_verified"] and report["native_packaging_launch_verified"]
        report['missing_git_manual_recovery_verified'] = report['missing_git_manual_recovery_verified'] and report['native_packaging_launch_verified']
        (output / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
        if cleanup_errors:
            raise RuntimeError("owned App cleanup failed: " + "; ".join(cleanup_errors))


def checked_login_selection(kind, enabled, fresh, target, existing, missing_git):
    if kind not in ('default', 'windows-powershell', 'zsh'):
        raise ValueError('unsupported ordinary login shell selection')
    if kind == 'default':
        return
    if not enabled or not fresh or existing != 'none' or missing_git:
        raise ValueError('selected login shell requires unseeded fresh login proof')
    if kind == 'windows-powershell' and target != 'x86_64-pc-windows-msvc':
        raise ValueError('Windows PowerShell selection requires native Windows')
    if kind == 'zsh' and target not in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
        raise ValueError('Zsh account selection requires native macOS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fetch", "verify", "fetch-public", "verify-fresh"), required=True)
    parser.add_argument("--tag")
    parser.add_argument("--verify-login-shell", action="store_true")
    parser.add_argument('--login-shell', choices=('default', 'windows-powershell', 'zsh'), default='default')
    parser.add_argument('--verify-missing-git-manual', action='store_true')
    parser.add_argument("--existing-user", choices=("none", "older-idle", "older-active", "current", "missing-companion", "corrupt-integrations", "foreign-companion", "corrupt-receipts", "external-suite-old", "external-suite-minimum", "external-suite-current"), default="none")
    for name in ("version", "source"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--target")
    parser.add_argument("--linux-package", choices=("both", "appimage"), default="both")
    parser.add_argument("--directory", type=Path, default=Path("app-candidate"))
    parser.add_argument("--output", type=Path, default=Path("app-proof"))
    args = parser.parse_args()
    if args.verify_login_shell and (args.mode != "verify-fresh" or args.existing_user != "none"):
        raise ValueError("login shell proof requires unseeded verify-fresh")
    if args.existing_user != "none" and args.mode != "verify-fresh":
        raise ValueError("existing-user scenarios require verify-fresh public inputs")
    if args.verify_missing_git_manual and (args.mode != 'verify-fresh' or args.target != 'x86_64-unknown-linux-gnu' or args.linux_package != 'both' or args.existing_user != 'none' or args.verify_login_shell):
        raise ValueError('missing Git proof requires unseeded Linux Deb verify-fresh only')
    checked_login_selection(args.login_shell, args.verify_login_shell, args.mode == 'verify-fresh', args.target, args.existing_user, args.verify_missing_git_manual)
    if args.mode in ("fetch", "verify"):
        identity(args.tag, args.version, args.source)
    if os.environ.get("CANDIDATE_RUNNER_KIND") != "github-hosted" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise RuntimeError("App proof restricted to hosted binary-repository workflow")
    if args.mode in ("fetch-public", "verify-fresh"):
        from app_upgrade_contract import fetch_public, checked_public
        if args.mode == "fetch-public":
            fetch_public(args.directory, args.source, args.version)
        else:
            document = checked_public(args.directory, args.source, args.version)
            native((args.directory / "assets").resolve(), document, args.target, args.output.resolve(), args.linux_package, fresh_setup=True, public_root=args.directory.resolve(), existing_user=args.existing_user, login_shell_proof=args.verify_login_shell, missing_git_manual=args.verify_missing_git_manual, login_shell_kind=args.login_shell)
    elif args.mode == "fetch":
        fetch(args.tag, args.version, args.source, args.directory)
    else:
        document = checked_downloads(args.directory, args.version, args.source)
        native(args.directory.resolve(), document, args.target, args.output.resolve(), args.linux_package)


if __name__ == "__main__":
    main()
