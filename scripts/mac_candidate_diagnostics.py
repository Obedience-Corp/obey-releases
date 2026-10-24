"""Failure-only diagnostics; modified copies can never qualify original bytes."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess

MANAGED_BROWSER_ENTITLEMENTS = frozenset({
    "com.apple.developer.web-browser",
    "com.apple.developer.web-browser.public-key-credential",
})


def without_managed_browser_entitlements(document):
    if not isinstance(document, dict):
        raise ValueError("entitlements must be a dictionary")
    removed = sorted(MANAGED_BROWSER_ENTITLEMENTS & document.keys())
    return {key: value for key, value in document.items() if key not in MANAGED_BROWSER_ENTITLEMENTS}, removed


def capture(arguments, environment, timeout=30):
    record = {"command": [str(value) for value in arguments]}
    try:
        result = subprocess.run(record["command"], env=environment, text=True, errors="replace",
                                capture_output=True, timeout=timeout)
        record.update(exit=result.returncode, stdout=result.stdout[-524288:], stderr=result.stderr[-524288:])
        record["output_truncated"] = len(result.stdout) > 524288 or len(result.stderr) > 524288
    except Exception as error:
        record["error"] = str(error)
    return record


def xattrs(path):
    result = {}
    try:
        if hasattr(os, "listxattr"):
            attributes = [(name, os.getxattr(path, name)) for name in sorted(os.listxattr(path))]
        else:
            # Python exposes listxattr only on Linux; macOS supplies xattr(1).
            listing = capture(["xattr", path], os.environ.copy())
            if listing.get("exit") != 0:
                raise OSError("xattr name query failed")
            attributes = []
            for name in sorted(listing.get("stdout", "").splitlines()):
                value = capture(["xattr", "-px", name, path], os.environ.copy())
                if value.get("exit") != 0:
                    raise OSError("xattr value query failed: " + name)
                attributes.append((name, bytes.fromhex(value.get("stdout", ""))))
        for name, value in attributes:
            item = {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
            # Do not dump arbitrary origin metadata/URLs into public logs.
            if name == "com.apple.quarantine":
                item["value"] = value.decode("utf-8", errors="replace")
            result[name] = item
    except OSError as error:
        result["query_error"] = str(error)
    return result


def crash_reports(app, output):
    records = []
    for root in (Path.home() / "Library/Logs/DiagnosticReports", Path("/Library/Logs/DiagnosticReports")):
        try:
            candidates = list(root.iterdir()) if root.is_dir() else []
        except OSError as error:
            records.append({"directory": str(root), "error": str(error)})
            continue
        for path in candidates:
            if not path.name.lower().startswith("festival") or path.suffix not in (".ips", ".crash"):
                continue
            try:
                if path.stat().st_size > 2 * 1024**2:
                    continue
                data = path.read_bytes()
                if str(app).encode() not in data:
                    continue
                destination = output / ("mac-crash-" + path.name)
                with destination.open("xb") as target:
                    target.write(data)
                records.append({"source": str(path), "artifact": destination.name})
            except OSError as error:
                records.append({"source": str(path), "error": str(error)})
    return records


def diagnose(app, temporary, output, environment, allow_modified_copy=False, installer_name='festival'):
    report = {"diagnostic_only": True, "original_candidate_accepted": False, "binaries": {}}
    try:
        for name in ("festival-app", installer_name, "festival-activity-engine"):
            binary = app / "Contents/MacOS" / name
            if binary.is_file():
                report["binaries"][name] = {
                    "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "xattrs": xattrs(binary),
                    "codesign": capture(["codesign", "-dvv", "--entitlements", ":-", binary], environment),
                }
        report["app_xattrs"] = xattrs(app)
        report["spctl"] = capture(["spctl", "--assess", "--type", "execute", "--verbose=4", app], environment)
        predicate = '(eventMessage CONTAINS[c] "festival" OR eventMessage CONTAINS[c] "app-proof") AND (process == "amfid" OR process == "syspolicyd" OR process == "kernel" OR process == "taskgated-helper")'
        report["execution_policy"] = capture(["log", "show", "--style", "compact", "--last", "5m", "--predicate", predicate], environment)
        report["crash_reports"] = crash_reports(app, output)
        report["modified_copy_requested"] = allow_modified_copy
        original = app / "Contents/MacOS" / installer_name
        if allow_modified_copy and installer_name in report["binaries"]:
            signed = report["binaries"][installer_name]["codesign"]
            entitlements = plistlib.loads(signed.get("stdout", "").encode())
            filtered, removed = without_managed_browser_entitlements(entitlements)
            if not removed:
                report["modified_copy_skipped"] = "neither managed browser entitlement is present"
            else:
                directory = temporary / "mac-entitlement-diagnostic-only"
                directory.mkdir()
                baseline, control, modified = (directory / name for name in ("original-copy", "same-entitlement-copy", "modified-copy"))
                identifiers = re.findall(r"^Identifier=(.+)$", signed.get("stderr", ""), re.MULTILINE)
                if len(identifiers) != 1 or not identifiers[0].strip():
                    raise RuntimeError("original signing identifier is unavailable or ambiguous")
                identifier = identifiers[0]
                probe = {"diagnostic_only": True, "removed_entitlements": removed,
                         "original_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
                         "signing_identifier": identifier}
                report["modified_copy_probe"] = probe
                for destination in (baseline, control, modified):
                    copied = capture(["ditto", original, destination], environment)
                    if copied.get("exit") != 0 or hashlib.sha256(destination.read_bytes()).hexdigest() != probe["original_sha256"]:
                        raise RuntimeError("diagnostic copy did not retain original bytes")
                probe["unchanged_copy_xattrs"] = xattrs(baseline)
                probe["unchanged_copy_execution"] = capture([baseline, "version"], environment)
                for destination, values, label in ((control, entitlements, "same_entitlement"),
                                                    (modified, filtered, "modified")):
                    plist = directory / (label + "-entitlements.plist")
                    plist.write_bytes(plistlib.dumps(values))
                    signing = capture(["codesign", "--force", "--sign", "-", "--identifier", identifier,
                                       "--options", "runtime", "--entitlements", plist, destination], environment)
                    probe[label + "_signing"] = signing
                    if signing.get("exit") != 0:
                        raise RuntimeError("diagnostic signing failed for " + label)
                    display = capture(["codesign", "-dvv", "--entitlements", ":-", destination], environment)
                    probe[label + "_codesign"] = display
                    actual_identifiers = re.findall(r"^Identifier=(.+)$", display.get("stderr", ""), re.MULTILINE)
                    if (display.get("exit") != 0 or plistlib.loads(display.get("stdout", "").encode()) != values
                            or actual_identifiers != [identifier]):
                        raise RuntimeError("diagnostic signing changed unexpected entitlements or identifier")
                    probe[label + "_sha256"] = hashlib.sha256(destination.read_bytes()).hexdigest()
                    probe[label + "_copy_execution"] = capture([destination, "version"], environment)
                # Neither this successful diagnostic nor an unmodified copy can
                # replace the original failed installed-bundle probe.
    except Exception as error:
        report["diagnostic_error"] = str(error)
    finally:
        original = app / "Contents/MacOS" / installer_name
        if original.is_file() and installer_name in report["binaries"]:
            report["original_cli_bytes_unchanged"] = hashlib.sha256(original.read_bytes()).hexdigest() == report["binaries"][installer_name]["sha256"]
        (output / "mac-diagnostics.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
