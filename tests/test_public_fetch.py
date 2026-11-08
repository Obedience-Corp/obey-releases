"""Anonymous artifact transport retries preserve verification failures."""
import contextlib
import hashlib
import http.client
import http.server
import io
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_selected_components import checked_bootstrap, fetch


class PublicFetchContracts(unittest.TestCase):
    url = "https://example.invalid/pinned-artifact"

    def response(self, payload=b"verified bytes"):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = payload
        return response

    def http_error(self, status):
        return urllib.error.HTTPError(self.url, status, "fixture", {}, io.BytesIO(b"unavailable"))

    def test_real_http_gateway_failure_recovers_and_verifies_bytes(self):
        requests = []
        payload = b"complete pinned artifact"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.headers.get("Authorization"))
                self.send_response(504 if len(requests) < 3 else 200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch("verify_selected_components.time.sleep"), contextlib.redirect_stderr(io.StringIO()):
                downloaded = fetch(f"http://127.0.0.1:{server.server_port}/artifact")
            digest = hashlib.sha256(payload).hexdigest()
            self.assertEqual(checked_bootstrap(downloaded, f"{digest}  artifact\n".encode(), "artifact"), digest)
            self.assertEqual(requests, [None, None, None])
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_gateway_retries_return_only_complete_success_and_close_failures(self):
        failures = [self.http_error(status) for status in (504, 502, 503)]
        response = self.response()
        with patch("urllib.request.urlopen", side_effect=[*failures, response]) as opened, \
                patch("verify_selected_components.time.sleep") as sleep, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(fetch(self.url), b"verified bytes")
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2, 4])
        self.assertEqual(opened.call_count, 4)
        self.assertTrue(all(error.fp.closed for error in failures))
        for call in opened.call_args_list:
            self.assertEqual(call.args[0].full_url, self.url)
            self.assertNotIn("Authorization", call.args[0].headers)
            self.assertEqual(call.kwargs["timeout"], 120)
        response.read.assert_called_once_with(128 * 1024 * 1024 + 1)

    def test_persistent_gateway_failure_is_bounded_and_preserves_last_error(self):
        failures = [self.http_error(504) for _ in range(4)]
        with patch("urllib.request.urlopen", side_effect=failures) as opened, \
                patch("verify_selected_components.time.sleep") as sleep, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(urllib.error.HTTPError) as raised:
            fetch(self.url)
        self.assertIs(raised.exception, failures[-1])
        self.assertEqual(opened.call_count, 4)
        self.assertEqual(sleep.call_count, 3)

    def test_permanent_http_and_tls_errors_are_not_retried(self):
        import ssl
        for failure in (self.http_error(401), self.http_error(403), self.http_error(404),
                        urllib.error.URLError(ssl.SSLCertVerificationError("invalid certificate"))):
            with self.subTest(failure=failure), patch("urllib.request.urlopen", side_effect=failure) as opened, \
                    patch("verify_selected_components.time.sleep") as sleep, self.assertRaises(type(failure)):
                fetch(self.url)
            self.assertEqual(opened.call_count, 1)
            sleep.assert_not_called()

    def test_timeout_reset_and_truncated_read_restart_without_partial_bytes(self):
        for failure in (urllib.error.URLError(TimeoutError()), ConnectionResetError(),
                        http.client.IncompleteRead(b"partial", 100)):
            response = self.response()
            response.read.side_effect = failure
            with self.subTest(failure=failure), \
                    patch("urllib.request.urlopen", side_effect=[response, self.response(b"complete")]), \
                    patch("verify_selected_components.time.sleep"), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fetch(self.url), b"complete")
            response.__exit__.assert_called_once()

    def test_oversize_and_checksum_failures_are_not_retried(self):
        oversized = MagicMock()
        oversized.__len__.return_value = 128 * 1024 * 1024 + 1
        with patch("urllib.request.urlopen", return_value=self.response(oversized)) as opened, \
                patch("verify_selected_components.time.sleep") as sleep, self.assertRaisesRegex(ValueError, "oversized"):
            fetch(self.url)
        self.assertEqual(opened.call_count, 1)
        sleep.assert_not_called()
        checksums = hashlib.sha256(b"correct").hexdigest().encode() + b"  artifact\n"
        with patch("urllib.request.urlopen", return_value=self.response(b"corrupt")) as opened, \
                patch("verify_selected_components.time.sleep") as sleep, self.assertRaisesRegex(ValueError, "checksum"):
            checked_bootstrap(fetch(self.url), checksums, "artifact")
        self.assertEqual(opened.call_count, 1)
        sleep.assert_not_called()
