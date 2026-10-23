"""Real local Debian dependency transactions, only inside a disposable root container."""
from contextlib import ExitStack
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import threading
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists() or os.geteuid() != 0:
    raise RuntimeError("Debian integration requires disposable root Docker")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_app_candidate as app
from verify_candidate import command


def build(root, package, dependency=None):
    control = root / package / "DEBIAN"
    control.mkdir(parents=True)
    text = f"Package: {package}\nVersion: 1.0\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: Disposable local package proof\n"
    if dependency:
        text += f"Depends: {dependency} (= 1.0)\n"
    (control / "control").write_text(text)
    archive = root / (package + ".deb")
    subprocess.run(["dpkg-deb", "--build", "--root-owner-group", control.parent, archive], check=True)
    return archive, text


def status(package):
    result = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", package], text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "absent"


with tempfile.TemporaryDirectory(prefix="fa0027-deb-integration-") as directory, ExitStack() as cleanup:
    root = Path(directory)
    root.chmod(0o755)
    dep, control = build(root, "fa0027-dependency")
    candidate, _ = build(root, "fa0027-local-app", "fa0027-dependency")
    data = dep.read_bytes()
    (root / "Packages").write_text(control + f"Filename: ./{dep.name}\nSize: {len(data)}\nSHA256: {hashlib.sha256(data).hexdigest()}\n\n")
    # A file: repository bypasses apt's archive cache. Loopback HTTP exercises
    # the real download/cache path, with Docker blocking all external network.
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cleanup.callback(thread.join)
    cleanup.callback(server.server_close)
    cleanup.callback(server.shutdown)
    source = Path("/etc/apt/sources.list.d/fa0027-local-proof.list")
    source.write_text(f"deb [trusted=yes] http://127.0.0.1:{server.server_port} ./\n")
    # Resolve only the local fixture repository, with network disabled by Docker.
    subprocess.run(["apt-get", "-o", "Dir::Etc::sourcelist=" + str(source), "-o", "Dir::Etc::sourceparts=-", "update"], check=True)
    original = command
    phase = {"expect_cached": True}
    def already_root(arguments, environment, **kwargs):
        if arguments[0] != "sudo":
            raise AssertionError("expected privileged owned command")
        if "bash" in arguments and phase["expect_cached"]:
            cached = Path("/var/cache/apt/archives/fa0027-dependency_1.0_all.deb")
            assert cached.is_file() and cached.read_bytes() == data
            print("download cache authenticated before unpack: " + hashlib.sha256(data).hexdigest(), flush=True)
        # Root container lacks sudo. Everything after that launcher, including
        # GNU timeout/process group, dpkg and apt, executes unchanged for real.
        return original(arguments[1:], environment, **kwargs)
    with patch.object(app, "command", side_effect=already_root):
        app.install_deb(candidate, os.environ)
        assert status("fa0027-local-app") == "installed"
        assert status("fa0027-dependency") == "installed"
        print("positive: exact local Deb and cached dependency configured", flush=True)
        app.apt_command(["remove", "--purge", "-y", "fa0027-local-app", "fa0027-dependency"], os.environ, 120)
        assert status("fa0027-local-app") == status("fa0027-dependency") == "absent"
        for cached in Path("/var/cache/apt/archives").glob("fa0027-dependency_*.deb"):
            cached.unlink()
        phase["expect_cached"] = False
        try:
            app.install_cached_deb(candidate, os.environ)
        except RuntimeError:
            pass
        else:
            raise AssertionError("missing dependency cache must fail installation")
        assert status("fa0027-local-app") == "unpacked", status("fa0027-local-app")
        assert status("fa0027-dependency") in ("absent", "not-installed")
        print("negative: missing cache failed; App remains unpacked, never silently removed", flush=True)
        app.apt_command(["remove", "--purge", "-y", "fa0027-local-app"], os.environ, 120)
        assert status("fa0027-local-app") == "absent"
        print("cleanup: owned partial App purged and absent", flush=True)
