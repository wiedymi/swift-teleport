#!/usr/bin/env python3
"""Tests for safe fixture failure diagnostics; no Docker engine is used."""
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import lab
import browser_mfa


class InitialAuthDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='teleport-lab-diagnostic-')
        self.addCleanup(self.directory.cleanup)
        self.lab = object.__new__(lab.Lab)
        self.lab.path = Path(self.directory.name)
        self.lab.env = {}
        for name in ('config', 'pki', 'admin-export'):
            (self.lab.path / name).mkdir(mode=0o700)
        for relative in ('config/auth-proxy.json', 'pki/proxy.key'):
            (self.lab.path / relative).write_bytes(b'not-a-credential')
            (self.lab.path / relative).chmod(0o600)

    def diagnostic(self, output):
        self.lab.compose = Mock(side_effect=[
            SimpleNamespace(stdout=b'a' * 64), SimpleNamespace(stdout=output),
        ])
        captured = io.StringIO()
        with patch.object(lab, 'execute', return_value=SimpleNamespace(stdout=b'exited 1 false\n')):
            with contextlib.redirect_stderr(captured):
                self.lab.diagnose_initial_auth_failure()
        self.lab.compose.assert_any_call('logs', '--no-color', '--tail', '20', 'auth-proxy', check=False, timeout=10)
        return captured.getvalue()

    def test_permission_failure_reports_only_known_paths_and_numeric_attributes(self):
        secret = b'UNTRUSTED_PRIVATE_VALUE_11b45e'
        output = self.diagnostic(b'permission denied: /etc/teleport/teleport.yaml ' + secret)
        self.assertIn('status=exited exit=1 oom=false user=root', output)
        self.assertIn('filesystem access denied: true', output)
        self.assertIn('access check named: /etc/teleport/teleport.yaml', output)
        self.assertIn('mode=0o600', output)
        self.assertNotIn(secret.decode(), output)

    def test_other_server_output_is_not_printed(self):
        secret = b'UNTRUSTED_PRIVATE_VALUE_11b45e'
        output = self.diagnostic(b'unknown error containing ' + secret)
        self.assertIn('filesystem access denied: false', output)
        self.assertNotIn(secret.decode(), output)

    def test_diagnostic_error_does_not_expose_its_message(self):
        secret = 'UNTRUSTED_PRIVATE_VALUE_11b45e'
        self.lab.compose = Mock(side_effect=lab.LabError(secret))
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            self.lab.diagnose_initial_auth_failure()
        self.assertIn('diagnostic is unavailable', captured.getvalue())
        self.assertNotIn(secret, captured.getvalue())


class BrowserMFARelayTests(unittest.TestCase):
    def test_callback_stays_on_exact_loopback_callback_target(self):
        value = 'http://127.0.0.1:12345/callback?response=authenticated-test-data'
        self.assertEqual(browser_mfa.callback_url(value), value)
        for invalid in (
                'http://localhost:12345/callback?response=x',
                'http://127.0.0.1/callback?response=x',
                'http://127.0.0.1:12345/other?response=x',
                'http://user@127.0.0.1:12345/callback?response=x',
                'http://127.0.0.1:12345/callback?response=x&response=y',
                'http://127.0.0.1:12345/callback?response=x&secret_key=y',
                'https://127.0.0.1:12345/callback?response=x',
                'http://127.0.0.1:12345/callback?response=x#fragment'):
            with self.subTest(value=invalid), self.assertRaises(lab.LabError):
                browser_mfa.callback_url(invalid)

    def test_callback_input_size_is_bounded(self):
        with self.assertRaises(lab.LabError):
            browser_mfa.callback_url('x' * 1_000_001)


if __name__ == '__main__':
    unittest.main()
