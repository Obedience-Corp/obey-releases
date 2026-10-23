"""Stage unchanged candidate bytes from four original App build inventories.

This local data-only collector neither publishes nor creates release authority.
Use a new destination; original per-target builder inventories are preserved.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from verify_app_candidate import TARGETS, checked_manifest, checked_downloads, identity


def assemble(directories, destination):
    if len(directories) != 4:
        raise ValueError("requires four builder inventory directories")
    source = version = None
    targets = {}
    inputs = {}
    for root in directories:
        inventories = list(root.glob("candidate-*.json"))
        if len(inventories) != 1:
            raise ValueError("requires exactly one original builder inventory per directory")
        document = json.loads(inventories[0].read_text())
        target = document.get("target")
        if target not in TARGETS or target in targets:
            raise ValueError("unknown or duplicate builder target")
        if source is None:
            source, version = document.get("source"), document.get("version")
        if document.get("source") != source or document.get("version") != version:
            raise ValueError("cannot combine builds from different source/version identities")
        entries = []
        for item in document.get("files", []):
            original = item["name"]
            if Path(original).name != original or "/" in original or "\\" in original:
                raise ValueError("unsafe builder filename")
            path = root / original
            if path.is_symlink() or not path.is_file() or path.stat().st_size != item["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
                raise ValueError("builder file changed since inventory")
            # GitHub normalizes spaces in uploaded asset names to dots. Do it
            # explicitly without changing bytes or losing the original label.
            name = original.replace(" ", ".")
            if name in inputs:
                raise ValueError("canonical asset filename collision")
            inputs[name] = path
            entries.append(dict(item, name=name, original_name=original))
        targets[target] = entries
    document = {"schema": "festival-app-candidate/v1", "source_revision": source, "version": version, "targets": targets,
                "provenance": "Original reviewed builder inventories; App binaries do not embed Git revision"}
    identity(f"candidate-app-v{version}-{source[:8]}", version, source)
    files = checked_manifest(document, version, source)
    destination.mkdir()
    for name, path in inputs.items():
        with path.open("rb") as incoming, (destination / name).open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing)
    (destination / "app-candidate.json").write_text(json.dumps(document, indent=2) + "\n")
    (destination / "checksums.txt").write_text("".join(files[name]["sha256"] + "  " + name + "\n" for name in sorted(files)))
    checked_downloads(destination, version, source)
    return document


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("directories", type=Path, nargs=4)
    args = parser.parse_args()
    assemble(args.directories, args.destination)
