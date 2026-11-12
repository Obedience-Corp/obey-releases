"""Anonymous immutable App release inputs and persisted-state proof contracts."""
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

from verify_app_candidate import TARGETS, checked_downloads, checked_manifest
from verify_candidate import REPOSITORY

PLATFORMS = {
    "darwin-aarch64": ("aarch64-apple-darwin", ".app.tar.gz"),
    "darwin-x86_64": ("x86_64-apple-darwin", ".app.tar.gz"),
    "linux-x86_64": ("x86_64-unknown-linux-gnu", ".AppImage"),
    "linux-x86_64-deb": ("x86_64-unknown-linux-gnu", ".deb"),
    "windows-x86_64": ("x86_64-pc-windows-msvc", "-setup.exe"),
}


def release_identity(source, version):
    if not re.fullmatch(r"[0-9a-f]{40}", source) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("invalid immutable App source/version")
    return "app-test-" + source


STABLE_SOURCE = "stable"
# Every App release since 0.1.7 bundles this sidecar (festival-app src-tauri/tauri.conf.json:42-43).
STABLE_INSTALLER_BASENAME = "festival-app-installer"


def stable_identity(version):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("invalid stable App version")
    return "app-v" + version


def release_tag(source, version):
    """Test releases are keyed by their 40-hex source; stable releases by version."""
    return stable_identity(version) if source == STABLE_SOURCE else release_identity(source, version)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rate_limit_delay(error, now):
    """Only explicit server rate-limit headers authorize another anonymous GET."""
    if error.code not in (403, 429):
        return None
    retry = error.headers.get('Retry-After')
    reset = error.headers.get('X-RateLimit-Reset')
    waits = []
    if retry is not None:
        if not retry.isdigit():
            return None
        waits.append(int(retry))
    if error.headers.get('X-RateLimit-Remaining') == '0':
        if reset is None or not reset.isdigit():
            return None
        waits.append(max(0, int(reset) - now) + 1)
    return max(1, *waits) if waits else None


def open_anonymous(request, retry_rate_limit):
    deadline = time.monotonic() + 3605
    for attempt in range(4):
        try:
            return urllib.request.urlopen(request, timeout=120)
        except urllib.error.HTTPError as error:
            delay = rate_limit_delay(error, time.time()) if retry_rate_limit else None
            error.close()
            if delay is None or attempt == 3:
                raise
            if delay > deadline - time.monotonic():
                raise RuntimeError('anonymous release API rate-limit reset exceeds bounded retry window') from error
            print(f'Anonymous release API rate limited; waiting {delay:.0f}s for server reset (retry {attempt + 1}/3)', flush=True)
            remaining = delay
            while remaining > 0:
                interval = min(60, remaining)
                time.sleep(interval)
                remaining -= interval
                if remaining > 0:
                    print(f'Anonymous release API reset wait: {remaining:.0f}s remaining', flush=True)
    raise AssertionError('unreachable anonymous retry state')


def anonymous_download(url, destination, limit, *, retry_rate_limit=False):
    request = urllib.request.Request(url, headers={"User-Agent": "festival-app-native-upgrade-proof"})
    count = 0
    with open_anonymous(request, retry_rate_limit) as response, destination.open("xb") as stream:
        if response.status != 200:
            raise RuntimeError("immutable public App bytes unavailable")
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            if count > limit:
                raise ValueError("oversized public App artifact")
            stream.write(chunk)


def release_assets(metadata, source, version):
    tag = release_tag(source, version)
    stable = source == STABLE_SOURCE
    if (metadata.get("draft") is not False or metadata.get("prerelease") is not (not stable)
            or metadata.get("tag_name") != tag):
        raise ValueError("requires the exact published immutable "
                         + ("stable" if stable else "test") + " release")
    assets = {}
    for item in metadata.get("assets", []):
        name = item.get("name", "")
        expected = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
        if (not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in assets
                or item.get("browser_download_url") != expected
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("digest", ""))
                or type(item.get("size")) is not int or not 0 < item["size"] < 2 * 1024**3):
            raise ValueError("invalid public release asset name/URL/digest/size")
        assets[name] = item
    required = {"latest.json", "SHA256SUMS"} | (set() if stable else {"app-candidate.json", "checksums.txt"})
    if not required <= assets.keys():
        raise ValueError("public release lacks inventory/checksums/updater manifest")
    return assets


def checked_bytes(directory, assets):
    for name, item in assets.items():
        path = directory / name if name in ("latest.json", "SHA256SUMS") else directory / "assets" / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item["size"] or "sha256:" + sha256(path) != item["digest"]:
            raise ValueError("public bytes disagree with server digest/size")


def installer_sums(directory):
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match[2] in sums:
            raise ValueError("invalid or duplicate installer SHA256SUMS row")
        sums[match[2]] = match[1]
    return sums


def checked_updater_manifest(directory, document, assets, version):
    manifest = json.loads((directory / "latest.json").read_text())
    if manifest.get("version") != version or set(manifest.get("platforms", {})) != set(PLATFORMS):
        raise ValueError("updater manifest must contain exact version and all five platforms")
    for key, (target, suffix) in PLATFORMS.items():
        artifact = next(item for item in document["targets"][target] if item["name"].endswith(suffix))
        entry = manifest["platforms"][key]
        signature = directory / "assets" / (artifact["name"] + ".sig")
        if entry.get("url") != assets[artifact["name"]]["browser_download_url"] or entry.get("signature") != signature.read_text().strip():
            raise ValueError("manifest URL/signature differs from declared producer bytes")


STABLE_TARGET_SUFFIXES = (
    ("_aarch64.dmg", "aarch64-apple-darwin"), ("_aarch64.app.tar.gz", "aarch64-apple-darwin"),
    ("_x64.dmg", "x86_64-apple-darwin"), ("_x64.app.tar.gz", "x86_64-apple-darwin"),
    ("_amd64.deb", "x86_64-unknown-linux-gnu"), ("_amd64.AppImage", "x86_64-unknown-linux-gnu"),
    ("_x64-setup.exe", "x86_64-pc-windows-msvc"),
)


def stable_target(name):
    base = name[:-len(".sig")] if name.endswith(".sig") else name
    matches = [target for suffix, target in STABLE_TARGET_SUFFIXES if base.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError("public release has unexpected or missing assets")
    return matches[0]


def checked_public_stable(directory, version):
    tag = stable_identity(version)
    metadata = json.loads((directory / "release.json").read_text())
    assets = release_assets(metadata, STABLE_SOURCE, version)
    sums = installer_sums(directory)
    updater_suffixes = tuple(suffix for _, suffix in PLATFORMS.values())
    signatures = {name + ".sig" for name in sums if name.endswith(updater_suffixes)}
    files = set(sums) | signatures
    if set(assets) != files | {"latest.json", "SHA256SUMS"}:
        raise ValueError("public release has unexpected or missing assets")
    checked_bytes(directory, assets)
    if any(assets[name]["digest"] != "sha256:" + digest for name, digest in sums.items()):
        raise ValueError("installer SHA256SUMS differs from published payload bytes")
    targets = {target: [] for target in TARGETS}
    for name in sorted(files):
        targets[stable_target(name)].append(
            {"name": name, "sha256": assets[name]["digest"][len("sha256:"):], "bytes": assets[name]["size"]})
    document = {"schema": "festival-app-candidate/v1", "source_revision": STABLE_SOURCE, "version": version,
                "release_tag": tag, "installer_basename": STABLE_INSTALLER_BASENAME, "targets": targets}
    checked_manifest(document, version, STABLE_SOURCE)
    checked_updater_manifest(directory, document, assets, version)
    return document


def checked_public(directory, source, version):
    if source == STABLE_SOURCE:
        return checked_public_stable(directory, version)
    metadata = json.loads((directory / "release.json").read_text())
    assets = release_assets(metadata, source, version)
    document = checked_downloads(directory / "assets", version, source)
    expected = {item["name"] for entries in document["targets"].values() for item in entries}
    expected |= {"app-candidate.json", "checksums.txt", "latest.json", "SHA256SUMS"}
    if set(assets) != expected:
        raise ValueError("public release has unexpected or missing assets")
    checked_bytes(directory, assets)
    sums = installer_sums(directory)
    payloads = {item["name"]: item["sha256"] for entries in document["targets"].values()
                for item in entries if not item["name"].endswith(".sig")}
    if sums != payloads:
        raise ValueError("installer SHA256SUMS differs from original producer payloads")
    checked_updater_manifest(directory, document, assets, version)
    return document


def checked_manual_candidate(directory, source, version, tag):
    """Validate the original qualification-draft inventory without claiming publication."""
    from verify_app_candidate import identity
    identity(tag, version, source)
    if directory.is_symlink() or {p.name for p in directory.iterdir()} != {"assets"}:
        raise ValueError("unexpected manual candidate input layout")
    if (directory / "assets").is_symlink():
        raise ValueError("manual candidate assets must not be a link")
    return checked_downloads(directory / "assets", version, source)


def checked_upgrade_selection(mechanism, failure_mode, candidate_tag, readiness, b_source=None):
    if mechanism not in ("manual", "updater") or readiness not in ("licensed", "free-workspace"):
        raise ValueError("unsupported upgrade mechanism/readiness")
    if mechanism == "manual" and failure_mode != "none":
        raise ValueError("manual replacement cannot claim updater failure/retry proof")
    stable_updater = mechanism == "updater" and b_source == STABLE_SOURCE and not candidate_tag
    if (candidate_tag or readiness == "free-workspace") and mechanism != "manual" and not stable_updater:
        raise ValueError("draft/free-workspace acceptance requires manual replacement")


def windows_setup_ready(names, readiness):
    """Require the selected visible surface; an empty/setup/error page is not ready."""
    if readiness not in ("licensed", "free-workspace"):
        raise ValueError("unsupported Windows startup readiness")
    names = set(names)
    if readiness == "licensed":
        return {"Licenses", "License key"} <= names
    return {"Projects", "Activity"} <= names and not ({"Licenses", "License key"} & names)


def fetch_public(directory, source, version):
    tag = release_tag(source, version)
    directory.mkdir()
    anonymous_download(f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}", directory / "release.json", 1024**2, retry_rate_limit=True)
    metadata = json.loads((directory / "release.json").read_text())
    assets = release_assets(metadata, source, version)
    (directory / "assets").mkdir()
    for name, item in assets.items():
        path = directory / name if name in ("latest.json", "SHA256SUMS") else directory / "assets" / name
        anonymous_download(item["browser_download_url"], path, item["size"])
    return checked_public(directory, source, version)


def checked_upgrade_pair(a, b):
    a_tag = release_tag(a["source_revision"], a["version"])
    b_tag = release_tag(b["source_revision"], b["version"])
    if a_tag == b_tag or tuple(map(int, a["version"].split("."))) >= tuple(map(int, b["version"].split("."))):
        raise ValueError("upgrade requires distinct sources and increasing versions")
    for target, suffix in PLATFORMS.values():
        old = next(item for item in a["targets"][target] if item["name"].endswith(suffix))
        new = next(item for item in b["targets"][target] if item["name"].endswith(suffix))
        if old["sha256"] == new["sha256"]:
            raise ValueError("A/B must contain distinct updater payload bytes for every format")


def persisted_snapshot(paths):
    result = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("persisted fixture must be a regular owned file")
        result[str(path)] = sha256(path)
    return result


def verify_persisted(snapshot, settings_path, expected_settings):
    if persisted_snapshot([Path(name) for name in snapshot]) != snapshot:
        raise ValueError("upgrade changed an owned fixture or foreign file")
    if settings_path.is_symlink() or not settings_path.is_file():
        raise ValueError("persisted settings must remain a regular file")
    actual = json.loads(settings_path.read_text())
    if any(actual.get(key) != value for key, value in expected_settings.items()):
        raise ValueError("upgrade lost persisted App settings")
    return {"preserved_files": snapshot, "settings": {key: actual[key] for key in expected_settings}}
