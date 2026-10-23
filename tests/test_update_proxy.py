"""Real opaque loopback transport and refusal/owned cleanup, Docker only."""
import os
from pathlib import Path
import socket
import socketserver
import sys
import threading
import time
import unittest

if os.environ.get("CANDIDATE_TEST_CONTAINER") != "1" or not Path("/.dockerenv").exists():
    raise RuntimeError("transport fixtures require Docker")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from owned_update_proxy import UpdateProxy, PUBLIC_RELEASE_TARGETS


def connect(proxy, target):
    client = socket.create_connection(("127.0.0.1", int(proxy.url.rsplit(":", 1)[1])), timeout=3)
    client.sendall(f"CONNECT {target[0]}:{target[1]} HTTP/1.1\r\nHost: {target[0]}:{target[1]}\r\n\r\n".encode())
    header = b""
    while not header.endswith(b"\r\n\r\n"):
        header += client.recv(1)
    return client, header


class ProxyContracts(unittest.TestCase):
    def test_block_then_opaque_passthrough_and_cleanup_never_reaches_other_target(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                data = self.request.recv(100)
                self.request.sendall(data)
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = server.server_address
        proxy = UpdateProxy({target})
        try:
            client, header = connect(proxy, target)
            with client:
                self.assertIn(b"502", header)
            client, header = connect(proxy, ("unselected.invalid", 443))
            with client:
                self.assertIn(b"403", header)
            proxy.allow_release_tunnels()
            client, header = connect(proxy, target)
            with client:
                self.assertIn(b"200", header)
                payload = b"\x16\x03\x03opaque-original-TLS-bytes"
                client.sendall(payload)
                self.assertEqual(client.recv(100), payload)
            self.assertEqual([row["outcome"] for row in proxy.snapshot()["requests"]], ["blocked", "denied", "tunneled"])
            proxy.close()
            self.assertTrue(proxy.snapshot()["closed"])
            self.assertEqual(proxy.snapshot()["active_connections"], 0)
            # Closing the owned proxy never stops this separate fixture server.
            with socket.create_connection(target, timeout=3) as unrelated:
                unrelated.sendall(b"still-live")
                self.assertEqual(unrelated.recv(100), b"still-live")
        finally:
            proxy.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_close_releases_a_client_that_never_sends_http_headers(self):
        proxy = UpdateProxy()
        client = socket.create_connection(("127.0.0.1", int(proxy.url.rsplit(":", 1)[1])), timeout=3)
        try:
            deadline = time.monotonic() + 3
            while proxy.snapshot()["active_connections"] != 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(proxy.snapshot()["active_connections"], 1)
            proxy.close()
            self.assertEqual(client.recv(1), b"")
            self.assertEqual(proxy.snapshot()["active_connections"], 0)
        finally:
            client.close()
            proxy.close()

    def test_close_releases_a_live_tunnel_and_allowlist_has_no_private_target(self):
        class Hold(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(1)
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Hold)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        proxy = UpdateProxy({server.server_address})
        try:
            self.assertEqual(PUBLIC_RELEASE_TARGETS, frozenset({("github.com", 443), ("release-assets.githubusercontent.com", 443), ("objects.githubusercontent.com", 443)}))
            proxy.allow_release_tunnels()
            client, header = connect(proxy, server.server_address)
            with client:
                self.assertIn(b"200", header)
                proxy.close()
                self.assertEqual(client.recv(1), b"")
            self.assertEqual(proxy.snapshot()["active_connections"], 0)
            with self.assertRaisesRegex(RuntimeError, "closed"):
                proxy.allow_release_tunnels()
        finally:
            proxy.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
