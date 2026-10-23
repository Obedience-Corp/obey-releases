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
import subprocess
import tarfile
import tempfile
import time

from verify_candidate import REPOSITORY, command, native_platform, wait_until
from verify_selected_components import require_clean_host
from mac_candidate_diagnostics import diagnose as diagnose_mac_failure

TARGETS = {
    "aarch64-apple-darwin": ("darwin/arm64", {".dmg", ".app.tar.gz", ".app.tar.gz.sig"}),
    "x86_64-apple-darwin": ("darwin/amd64", {".dmg", ".app.tar.gz", ".app.tar.gz.sig"}),
    "x86_64-unknown-linux-gnu": ("linux/amd64", {".deb", ".AppImage", ".AppImage.sig"}),
    "x86_64-pc-windows-msvc": ("windows/amd64", {"-setup.exe", "-setup.exe.sig"}),
}
# Public production trust anchor, identical to the reviewed App391 public key.
PUBLIC_KEY = "RWTlKfGG4A6IoCRsFpbcpf2yJ7v0D5CFRb17f8gK/n3LWdd9x1NKA+ms"


def identity(tag, version, source):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not re.fullmatch(r"[a-f0-9]{40}", source):
        raise ValueError("invalid App candidate version/source")
    if tag != f"candidate-app-v{version}-{source[:8]}":
        raise ValueError("App candidate tag must match version and source")


def checked_manifest(document, version, source):
    if document.get("schema") != "festival-app-candidate/v1" or document.get("source_revision") != source or document.get("version") != version:
        raise ValueError("App candidate identity mismatch")
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


def mac_install(directory, entries, temporary, environment, report):
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
    for name in ("festival-app", "festival", "festival-activity-engine"):
        path = app / "Contents/MacOS" / name
        arches = command(["lipo", "-archs", path], environment).split()
        loads = command(["otool", "-l", path], environment)
        floors = re.findall(r"\bminos\s+([0-9.]+)", loads)
        if expected_arch not in arches or not floors or any(value not in ("12.0", "12.0.0") for value in floors):
            raise ValueError("bundled executable architecture or macOS12 floor mismatch")
        report["mach_o"][name] = {"architectures": arches, "minima": floors}
    report["structural_codesign_verified"] = True
    return app / "Contents/MacOS/festival-app", app / "Contents/MacOS", app / "Contents/Resources"


def window_capture(process, target, output, environment):
    def require_alive():
        if process.poll() is not None:
            raise RuntimeError("owned App process exited before its window appeared")
    if target.endswith("apple-darwin"):
        script = 'import CoreGraphics; import Foundation; let ws = CGWindowListCopyWindowInfo([.optionOnScreenOnly,.excludeDesktopElements], kCGNullWindowID) as! [[String:Any]]; print(String(data:try! JSONSerialization.data(withJSONObject:ws.filter { ($0["kCGWindowOwnerPID"] as? Int) == Int(CommandLine.arguments[1]) }),encoding:.utf8)!)'
        def window():
            require_alive()
            windows = json.loads(command(["swift", "-e", script, str(process.pid)], environment))
            return next((w for w in windows if w.get("kCGWindowLayer") == 0 and w.get("kCGWindowBounds", {}).get("Width", 0) > 100), None)
        found = wait_until("owned App window", window)
        command(["screencapture", "-x", "-l", str(found["kCGWindowNumber"]), output], environment)
        return {"window_id": found["kCGWindowNumber"], "title": found.get("kCGWindowName"), "screenshot": output.name}
    if target.endswith("windows-msvc"):
        query = f'$p=Get-Process -Id {process.pid} -ErrorAction Stop; if($p.MainWindowHandle -ne 0){{@{{handle=$p.MainWindowHandle.ToInt64();title=$p.MainWindowTitle}}|ConvertTo-Json -Compress}}'
        def window():
            require_alive()
            return json.loads(command(["pwsh", "-NoProfile", "-Command", query], environment) or "null")
        found = wait_until("owned App window", window)
        capture = 'Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $r=[Windows.Forms.SystemInformation]::VirtualScreen; $b=New-Object Drawing.Bitmap $r.Width,$r.Height; $g=[Drawing.Graphics]::FromImage($b); try {$g.CopyFromScreen($r.Left,$r.Top,0,0,$b.Size); $b.Save($env:APP_PROOF_SCREENSHOT)} finally {$g.Dispose();$b.Dispose()}'
        command(["pwsh", "-NoProfile", "-Command", capture], dict(environment, APP_PROOF_SCREENSHOT=str(output)))
        return dict(found, screenshot=output.name)
    def window():
        require_alive()
        result = subprocess.run(["xdotool", "search", "--onlyvisible", "--pid", str(process.pid)], env=environment, text=True, capture_output=True)
        return result.stdout.splitlines()[0] if result.returncode == 0 and result.stdout.strip() else None
    found = wait_until("owned App window", window)
    title = command(["xdotool", "getwindowname", found], environment).strip()
    command(["import", "-window", found, output], environment)
    return {"window_id": found, "title": title, "screenshot": output.name}


def capture_startup(process, target, output, environment, captures, stem="app"):
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
        latest = window_capture(process, target, screenshot, environment)
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


def stop_owned(process, environment):
    if process.poll() is not None:
        return
    if os.name == "nt":
        query = Path(__file__).with_name("windows_owned_processes.ps1")
        identities = json.loads(command(["pwsh", "-NoProfile", "-NonInteractive", "-File", query],
                                       dict(environment, APP_PROOF_PROCESS_MODE="snapshot", APP_PROOF_PROCESS_PID=str(process.pid))))
        if not isinstance(identities, list) or any(not isinstance(item.get("pid"), int) or not str(item.get("started", "")).isdigit() for item in identities):
            raise RuntimeError("invalid owned process identity snapshot")
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


def native(directory, document, target, output, linux_package="both"):
    require_clean_host({"aarch64-apple-darwin": "macOS-arm64", "x86_64-apple-darwin": "macOS-x86_64", "x86_64-unknown-linux-gnu": "linux-x86_64", "x86_64-pc-windows-msvc": "windows-x86_64"}.get(target))
    if target not in TARGETS or native_platform() != TARGETS[target][0]:
        raise ValueError("App target does not match native machine")
    if linux_package not in ("both", "appimage") or linux_package == "appimage" and not target.endswith("linux-gnu"):
        raise ValueError("invalid fresh AppImage target/mode")
    if any(os.environ.get(name) for name in ("GH_TOKEN", "GITHUB_TOKEN")):
        raise RuntimeError("App native execution must not receive a draft credential")
    report = {"source_revision": document["source_revision"], "version": document["version"], "target": target,
              "runner_platform": native_platform(), "first_use_complete": False, "license_access_verified": False,
              "reboot_verified": False, "consumer_trust_verified": False, "two_version_update_verified": False, "native_packaging_launch_verified": False, "linux_package_mode": linux_package}
    output.mkdir()
    process = xvfb = None
    installed = None
    owned_deb = False
    appimage = extracted_appimage = None
    environment = dict(os.environ)
    for key in list(environment):
        if key.endswith(("_TOKEN", "_PASSWORD", "_PRIVATE_KEY")):
            environment.pop(key, None)
    def uninstall_windows():
        windows_silent(installed / "uninstall.exe", environment)
        wait_until("owned App uninstall", lambda: not (installed / "festival-app.exe").exists())
        report["uninstalled"] = True

    def uninstall_deb():
        command(["sudo", "apt-get", "remove", "--purge", "-y", "festival-app"], environment, timeout=120)
        if Path("/usr/bin/festival-app").exists():
            raise RuntimeError("owned deb uninstall left App executable")
        report["deb_uninstalled"] = True

    temporary_context = tempfile.TemporaryDirectory(prefix="app-proof-", dir=os.environ["RUNNER_TEMP"])
    try:
        temporary = Path(temporary_context.name)
        environment.update(FESTIVAL_HOME=str(temporary / "managed"), OBEY_CONFIG=str(temporary / "obey.yaml"))
        # The machine/account itself is disposable. Native OS lookup retains
        # its real HOME, unlike redirected-home tests that miss supervisors.
        entries = document["targets"][target]
        updater = next(item["name"] for item in entries if item["name"].endswith((".app.tar.gz", ".AppImage", "-setup.exe")))
        verify_signature(directory / updater, directory / (updater + ".sig"), temporary, environment)
        report["production_updater_signature_verified"] = True
        if target.endswith("apple-darwin"):
            binary, commands, resources = mac_install(directory, entries, temporary, environment, report)
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
                owned_deb = True
                command(["sudo", "apt-get", "install", "-y", deb], environment, timeout=300)
                installed_version = command(["dpkg-query", "-W", "-f=${Version}", package], environment).strip()
                if installed_version != report["version"]:
                    raise ValueError("installed deb version mismatch")
                report["deb_installed_version"] = installed_version
                report["deb_install_with_dependency_resolution"] = True
            appimage = temporary / updater
            shutil.copyfile(directory / updater, appimage)
            appimage.chmod(0o755)
            subprocess.run([str(appimage), "--appimage-extract"], cwd=temporary, env=environment, check=True, stdout=subprocess.DEVNULL, timeout=60)
            extracted_appimage = temporary / "squashfs-root/AppRun"
            if linux_package == "appimage":
                # Extract only to inspect/probe the authenticated bundled CLI
                # resources; the App itself launches the original image below.
                extracted_root = temporary / "squashfs-root"
                installers = [path for path in extracted_root.rglob("festival") if path.is_file() and os.access(path, os.X_OK)]
                if len(installers) != 1:
                    raise ValueError("AppImage must bundle exactly one installer executable")
                binary, commands, resources = appimage, installers[0].parent, extracted_root
                report["deb_install_exercised"] = False
            else:
                binary, commands, resources = Path("/usr/bin/festival-app"), Path("/usr/bin"), Path("/usr/lib")
            if Path("/tmp/.X11-unix/X99").exists():
                raise RuntimeError("refusing a preexisting display")
            xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1280x900x24"], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            environment["DISPLAY"] = ":99"
            wait_until("owned Xvfb", lambda: subprocess.run(["xdpyinfo"], env=environment, capture_output=True).returncode == 0)
        suffix = ".exe" if target.endswith("windows-msvc") else ""
        installer, activity = commands / ("festival" + suffix), commands / ("festival-activity-engine" + suffix)
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
        with (output / "app.log").open("w") as log:
            process = subprocess.Popen([str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
            report["pid"] = process.pid
            def alive_window():
                if process.poll() is not None:
                    raise RuntimeError("App exited before window capture: " + (output / "app.log").read_text())
                return True
            alive_window()
            report["window"] = capture_startup(process, target, output, environment, report.setdefault("startup_captures", []))
            if process.poll() is not None or not (output / "app.png").is_file() or (output / "app.png").stat().st_size == 0:
                raise RuntimeError("App did not retain a live captured window")
            report["primary_packaged_app_launch_verified"] = True
            if linux_package == "appimage":
                report["appimage_default_launch_verified"] = True
                report["appimage_extracted_app_executed"] = False
        # Stop only the process created by this proof, before uninstall/temp cleanup.
        stop_owned(process, environment)
        process = None
        if appimage is not None and linux_package == "both":
            appimage_proof(appimage, extracted_appimage, target, output, environment, report)
        if installed is not None:
            uninstall_windows()
            installed = None
    except BaseException as error:
        report["failure"] = str(error)
        if target.endswith("apple-darwin"):
            report["mac_diagnostics"] = diagnose_mac_failure(temporary / "installed/Festival App.app", temporary, output, environment, allow_modified_copy=os.environ.get("APP_PROOF_MAC_ENTITLEMENT_DIAGNOSTIC") == "true")
        raise
    finally:
        cleanup_errors = []
        actions = []
        if process is not None and process.poll() is None:
            actions.append(lambda: stop_owned(process, environment))
        if installed is not None and (installed / "uninstall.exe").is_file():
            actions.append(uninstall_windows)
        if owned_deb:
            actions.append(uninstall_deb)
        if xvfb is not None:
            def stop_display():
                xvfb.terminate()
                xvfb.wait(timeout=10)
            actions.append(stop_display)
        actions.append(temporary_context.cleanup)
        for action in actions:
            try:
                action()
            except BaseException as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            report["cleanup_failure"] = cleanup_errors
        report["native_packaging_launch_verified"] = "failure" not in report and not cleanup_errors
        (output / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
        if cleanup_errors:
            raise RuntimeError("owned App cleanup failed: " + "; ".join(cleanup_errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fetch", "verify"), required=True)
    for name in ("tag", "version", "source"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--target")
    parser.add_argument("--linux-package", choices=("both", "appimage"), default="both")
    parser.add_argument("--directory", type=Path, default=Path("app-candidate"))
    parser.add_argument("--output", type=Path, default=Path("app-proof"))
    args = parser.parse_args()
    identity(args.tag, args.version, args.source)
    if os.environ.get("CANDIDATE_RUNNER_KIND") != "github-hosted" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise RuntimeError("App proof restricted to hosted binary-repository workflow")
    if args.mode == "fetch":
        fetch(args.tag, args.version, args.source, args.directory)
    else:
        document = checked_downloads(args.directory, args.version, args.source)
        native(args.directory.resolve(), document, args.target, args.output.resolve(), args.linux_package)


if __name__ == "__main__":
    main()
