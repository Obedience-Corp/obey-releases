"""Anonymous API throttling must not become credentials or integrity retries."""
import io
import os
from email.message import Message
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('download tests require Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import app_upgrade_contract as contract


class AnonymousRateLimitContracts(unittest.TestCase):
    def error(self, code=403, **headers):
        values = Message()
        for key, value in headers.items(): values[key.replace('_', '-')] = value
        return HTTPError('https://api.github.com/test', code, 'rate limit exceeded', values, io.BytesIO(b'rate limited'))

    def test_only_explicit_rate_limit_headers_authorize_retry(self):
        for error in [self.error(), self.error(404, Retry_After='2'),
                      self.error(Retry_After='garbage'), self.error(X_RateLimit_Remaining='0'),
                      self.error(X_RateLimit_Remaining='0', X_RateLimit_Reset='invalid')]:
            self.assertIsNone(contract.rate_limit_delay(error, 100))
            error.close()
        self.assertEqual(contract.rate_limit_delay(self.error(X_RateLimit_Remaining='0', X_RateLimit_Reset='110'), 100), 11)
        self.assertEqual(contract.rate_limit_delay(self.error(429, Retry_After='12'), 100), 12)
        self.assertEqual(contract.rate_limit_delay(self.error(Retry_After='4', X_RateLimit_Remaining='0', X_RateLimit_Reset='110'), 100), 11)

    def test_anonymous_metadata_waits_then_creates_only_successful_bytes(self):
        error = self.error(X_RateLimit_Remaining='0', X_RateLimit_Reset='110')
        response = io.BytesIO(b'public metadata'); response.status = 200
        with tempfile.TemporaryDirectory() as directory, patch.object(contract.urllib.request, 'urlopen', side_effect=[error, response]) as opened, patch.object(contract.time, 'time', return_value=100), patch.object(contract.time, 'sleep') as sleep:
            path = Path(directory) / 'release.json'
            contract.anonymous_download('https://api.github.com/test', path, 100, retry_rate_limit=True)
            self.assertEqual(path.read_bytes(), b'public metadata')
            sleep.assert_called_once_with(11)
            self.assertEqual(opened.call_count, 2)
            self.assertNotIn('authorization', {key.lower(): value for key, value in opened.call_args.args[0].header_items()})

    def test_asset_failures_and_plain_forbidden_are_not_retried(self):
        for retry, error in [(False, self.error(Retry_After='1')), (True, self.error())]:
            with tempfile.TemporaryDirectory() as directory, patch.object(contract.urllib.request, 'urlopen', side_effect=error) as opened, patch.object(contract.time, 'sleep') as sleep:
                path = Path(directory) / 'asset'
                with self.assertRaises(HTTPError): contract.anonymous_download('https://github.com/asset', path, 100, retry_rate_limit=retry)
                self.assertFalse(path.exists()); self.assertEqual(opened.call_count, 1); sleep.assert_not_called()

    def test_retry_budget_and_attempts_are_bounded(self):
        with patch.object(contract.urllib.request, 'urlopen', side_effect=self.error(Retry_After='3606')) as opened, patch.object(contract.time, 'monotonic', return_value=0), patch.object(contract.time, 'sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError, 'bounded retry'): contract.open_anonymous(object(), True)
            sleep.assert_not_called(); self.assertEqual(opened.call_count, 1)
        with patch.object(contract.urllib.request, 'urlopen', side_effect=[self.error(Retry_After='1') for _ in range(4)]) as opened, patch.object(contract.time, 'sleep') as sleep:
            with self.assertRaises(HTTPError): contract.open_anonymous(object(), True)
            self.assertEqual(opened.call_count, 4); self.assertEqual(sleep.call_count, 3)

    def test_success_still_enforces_size_and_exclusive_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'asset'
            response = io.BytesIO(b'too long'); response.status = 200
            with patch.object(contract.urllib.request, 'urlopen', return_value=response) as opened:
                with self.assertRaisesRegex(ValueError, 'oversized'): contract.anonymous_download('https://github.com/asset', path, 2)
                self.assertEqual(opened.call_count, 1)
            path.write_bytes(b'preserve')
            response = io.BytesIO(b'new'); response.status = 200
            with patch.object(contract.urllib.request, 'urlopen', return_value=response):
                with self.assertRaises(FileExistsError): contract.anonymous_download('https://github.com/asset', path, 100)
            self.assertEqual(path.read_bytes(), b'preserve')
