"""Owned loopback transport fault; tunnels original TLS without inspecting it."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import select
import socket
import threading
import time

PUBLIC_RELEASE_TARGETS = frozenset({("github.com", 443), ("release-assets.githubusercontent.com", 443),
                                   ("objects.githubusercontent.com", 443)})


class UpdateProxy:
    def __init__(self, targets=PUBLIC_RELEASE_TARGETS):
        self.targets = frozenset(targets)
        self._lock = threading.Condition()
        self._sockets = set()
        self._requests = []
        self._allowed = False
        self._closed = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass  # Never log request headers or credential-bearing data.

            def setup(self):
                super().setup()
                self.connection.settimeout(10)
                owner._track(self.connection)

            def finish(self):
                try:
                    super().finish()
                finally:
                    owner._untrack(self.connection)

            def do_CONNECT(self):
                upstream = None
                try:
                    try:
                        host, port = self.path.rsplit(":", 1)
                        target = (host.lower(), int(port))
                    except (ValueError, AttributeError):
                        self.send_error(400, "Invalid CONNECT target")
                        return
                    if target not in owner.targets:
                        owner._record(("<unselected>", 0), "denied")
                        self.send_error(403, "Target outside owned release allowlist")
                        return
                    allowed = owner._allow_request(target, self.client_address)
                    if not allowed:
                        owner._record(target, "blocked")
                        self.send_error(502, "Owned offline test fault")
                        return
                    upstream = socket.create_connection(target, timeout=10)
                    owner._track(upstream)
                    self.connection.settimeout(10)
                    owner._record(target, "tunneled")
                    self.send_response(200, "Connection established")
                    self.end_headers()
                    self.wfile.flush()
                    deadline = time.monotonic() + 900
                    while time.monotonic() < deadline:
                        with owner._lock:
                            if owner._closed:
                                return
                        readable, _, _ = select.select([self.connection, upstream], [], [], 0.2)
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is self.connection else self.connection).sendall(data)
                except OSError:
                    # A dropped peer remains visible to the client; never fake a
                    # successful response/body or substitute unauthenticated data.
                    return
                finally:
                    if upstream is not None:
                        upstream.close()
                        owner._untrack(upstream)
                    self.close_connection = True

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self._thread.start()

    @property
    def url(self):
        return "http://127.0.0.1:" + str(self._server.server_port)

    def allow_release_tunnels(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("owned update proxy is closed")
            self._allowed = True

    def _allow_request(self, target, peer):
        """Original policy; specialized fixtures may additionally authenticate peer ownership."""
        with self._lock:
            return self._allowed and not self._closed

    def _record(self, target, outcome):
        with self._lock:
            if len(self._requests) >= 100:
                raise RuntimeError("owned proxy request budget exceeded")
            self._requests.append({"host": target[0], "port": target[1], "outcome": outcome})

    def _track(self, connection):
        with self._lock:
            self._sockets.add(connection)

    def _untrack(self, connection):
        with self._lock:
            self._sockets.discard(connection)
            self._lock.notify_all()

    def snapshot(self):
        with self._lock:
            return {"requests": [dict(row) for row in self._requests], "active_connections": len(self._sockets),
                    "closed": self._closed, "pass_through_enabled": self._allowed}

    def close(self):
        with self._lock:
            self._closed = True
            connections = list(self._sockets)
        self._server.shutdown()
        self._server.server_close()
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self._thread.join(timeout=5)
        with self._lock:
            if not self._lock.wait_for(lambda: not self._sockets, timeout=12) or self._thread.is_alive():
                raise RuntimeError("owned update proxy did not release all connections/thread")


class SignatureFallbackProxy(UpdateProxy):
    """Original TLS to immutable feeds, then refuse only the defective feed host."""
    BAD_FEED_TARGET = ("raw.githubusercontent.com", 443)

    def __init__(self):
        self._bad_feed_blocked = False
        super().__init__(PUBLIC_RELEASE_TARGETS | {self.BAD_FEED_TARGET})
        self.allow_release_tunnels()

    def block_bad_feed(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("owned update proxy is closed")
            self._bad_feed_blocked = True
            # A fresh check must establish a new CONNECT; close prior keepalive
            # tunnels so the client cannot bypass the explicit phase transition.
            connections = list(self._sockets)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _allow_request(self, target, peer):
        with self._lock:
            return self._allowed and not self._closed and not (
                self._bad_feed_blocked and target == self.BAD_FEED_TARGET)
