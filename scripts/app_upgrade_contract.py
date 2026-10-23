"""Anonymous immutable App release inputs and persisted-state proof contracts."""
import hashlib
import json
from pathlib import Path
import re
import urllib.request

from verify_app_candidate import checked_downloads
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


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def anonymous_download(url, destination, limit):
    request = urllib.request.Request(url, headers={"User-Agent": "festival-app-native-upgrade-proof"})
    count = 0
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("xb") as stream:
        if response.status != 200:
            raise RuntimeError("immutable public App bytes unavailable")
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            if count > limit:
                raise ValueError("oversized public App artifact")
            stream.write(chunk)


def release_assets(metadata, source, version):
    tag = release_identity(source, version)
    if metadata.get("draft") is not False or metadata.get("prerelease") is not True or metadata.get("tag_name") != tag:
        raise ValueError("requires the exact published immutable test release")
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
    if not {"app-candidate.json", "checksums.txt", "latest.json", "SHA256SUMS"} <= assets.keys():
        raise ValueError("public release lacks inventory/checksums/updater manifest")
    return assets


def checked_public(directory, source, version):
    metadata = json.loads((directory / "release.json").read_text())
    assets = release_assets(metadata, source, version)
    document = checked_downloads(directory / "assets", version, source)
    expected = {item["name"] for entries in document["targets"].values() for item in entries}
    expected |= {"app-candidate.json", "checksums.txt", "latest.json", "SHA256SUMS"}
    if set(assets) != expected:
        raise ValueError("public release has unexpected or missing assets")
    for name, item in assets.items():
        path = directory / name if name in ("latest.json", "SHA256SUMS") else directory / "assets" / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item["size"] or "sha256:" + sha256(path) != item["digest"]:
            raise ValueError("public bytes disagree with server digest/size")
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match[2] in sums:
            raise ValueError("invalid or duplicate installer SHA256SUMS row")
        sums[match[2]] = match[1]
    payloads = {item["name"]: item["sha256"] for entries in document["targets"].values()
                for item in entries if not item["name"].endswith(".sig")}
    if sums != payloads:
        raise ValueError("installer SHA256SUMS differs from original producer payloads")
    manifest = json.loads((directory / "latest.json").read_text())
    if manifest.get("version") != version or set(manifest.get("platforms", {})) != set(PLATFORMS):
        raise ValueError("updater manifest must contain exact version and all five platforms")
    for key, (target, suffix) in PLATFORMS.items():
        artifact = next(item for item in document["targets"][target] if item["name"].endswith(suffix))
        entry = manifest["platforms"][key]
        signature = directory / "assets" / (artifact["name"] + ".sig")
        if entry.get("url") != assets[artifact["name"]]["browser_download_url"] or entry.get("signature") != signature.read_text().strip():
            raise ValueError("manifest URL/signature differs from declared producer bytes")
    return document


def fetch_public(directory, source, version):
    tag = release_identity(source, version)
    directory.mkdir()
    anonymous_download(f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}", directory / "release.json", 1024**2)
    metadata = json.loads((directory / "release.json").read_text())
    assets = release_assets(metadata, source, version)
    (directory / "assets").mkdir()
    for name, item in assets.items():
        path = directory / name if name in ("latest.json", "SHA256SUMS") else directory / "assets" / name
        anonymous_download(item["browser_download_url"], path, item["size"])
    return checked_public(directory, source, version)


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
