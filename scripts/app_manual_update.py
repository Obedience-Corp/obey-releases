"""Replace only the App owned by the disposable upgrade journey, after normal quit."""
import shutil

import verify_app_candidate as app


def install(package_format, binary, bundle, candidate, document, target, work, environment):
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("manual update requires the owned regular App executable")
    suffixes = {"dmg": ".dmg", "nsis": "-setup.exe", "deb": ".deb", "appimage": ".AppImage"}
    if package_format not in suffixes:
        raise ValueError("unsupported manual update format")
    entries = document["targets"][target]
    payload = candidate / "assets" / next(row["name"] for row in entries if row["name"].endswith(suffixes[package_format]))
    if package_format == "dmg":
        if bundle.is_symlink() or not bundle.resolve().is_relative_to(work.resolve()):
            raise ValueError("manual Mac replacement must stay inside the owned fixture")
        stage = work / "manual-b"
        stage.mkdir()
        details = {"version": document["version"], "target": target}
        replacement, _, _ = app.mac_install(candidate / "assets", entries, stage, environment, details, app.installer_basename(document))
        backup = work / "previous-app-bundle"
        if backup.exists():
            raise ValueError("refusing an existing App backup")
        bundle.rename(backup)
        try:
            replacement.parent.parent.parent.rename(bundle)
        except BaseException:
            backup.rename(bundle)
            raise
        return details
    if package_format == "nsis":
        app.windows_silent(payload, environment)
    elif package_format == "deb":
        app.install_deb(payload, environment)
    else:
        if not binary.resolve().is_relative_to(work.resolve()):
            raise ValueError("manual AppImage replacement must stay inside the owned fixture")
        staged = work / "manual-b.AppImage"
        with staged.open("xb") as output, payload.open("rb") as source:
            shutil.copyfileobj(source, output)
        staged.chmod(0o755)
        staged.replace(binary)
    return {"package": payload.name}
