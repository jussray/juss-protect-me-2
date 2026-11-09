from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import medusa_fetch as f

class FakeResponse:
    def __init__(self, status=200, body=b"hello", headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {"Content-Type": "text/plain", "Content-Length": str(len(body))}
        self.read_count = 0
    def getheader(self, name):
        return self.headers.get(name)
    def read(self, count):
        self.read_count += 1
        result, self.body = self.body[:count], self.body[count:]
        return result

class FetchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = argparse.Namespace(url="https://example.org/info", out=str(self.root), name="info.txt", allow_http=False)

    def test_url_userinfo_and_sensitive_query_refused(self):
        for url in ["https://user:password@example.org/", "https://example.org/?access_token=abc", "https://example.org/?refresh-token=x", "https://example.org/?client_secret=x"]:
            with self.subTest(url=url), self.assertRaises(f.FetchError):
                f.parse_url(url)

    def test_sensitive_path_does_not_appear_in_manifest(self):
        p = f.parse_url("https://example.org/SECRET-PRIVATE/abc?q=visible")
        self.assertNotIn("SECRET-PRIVATE", f.safe_origin(p))
        self.assertNotIn("visible", f.safe_origin(p))

    def test_invalid_filename_blocked_before_any_network(self):
        for name in ("../escape", "/etc/passwd", ".hidden", "back\\slash"):
            self.args.name = name
            with self.subTest(name=name), patch.object(f, "read_url") as network:
                with self.assertRaises(f.FetchError):
                    f.fetch_one(self.args)
                network.assert_not_called()

    def test_preexisting_file_and_manifest_refused_before_network(self):
        path = self.root / "info.txt"
        path.write_text("untouched")
        with patch.object(f, "read_url") as network:
            with self.assertRaises(f.FetchError):
                f.fetch_one(self.args)
            network.assert_not_called()
        path.unlink()
        (self.root / "info.txt.manifest.json").write_text("protected")
        with patch.object(f, "read_url") as network:
            with self.assertRaises(f.FetchError):
                f.fetch_one(self.args)
            network.assert_not_called()

    def test_symlink_as_output_refused(self):
        (self.root / "info.txt").symlink_to(self.root / "other")
        with patch.object(f, "read_url") as network:
            with self.assertRaises(f.FetchError):
                f.fetch_one(self.args)
            network.assert_not_called()

    def test_loopback_and_metadata_addresses_refused(self):
        for ip in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"):
            with patch.object(f.socket, "getaddrinfo", return_value=[(2,1,6,"",(ip,0))]):
                with self.subTest(ip=ip), self.assertRaises(f.FetchError):
                    f.public_ip("example.org")

    def test_pins_selected_public_ip_and_preserves_tls_server_name(self):
        c = f.PinnedHTTPS("example.org", 443, "93.184.215.14")
        sock = Mock()
        c._context = Mock()
        with patch.object(f.socket, "create_connection", return_value=sock) as connect:
            c.connect()
        connect.assert_called_once_with(("93.184.215.14", 443), timeout=f.TIMEOUT)
        c._context.wrap_socket.assert_called_once_with(sock, server_hostname="example.org")

    def test_redirect_refused_before_second_request(self):
        conn = Mock()
        response = FakeResponse(status=302, headers={"Location": "https://evil.test/?token=leak"})
        conn.getresponse.return_value = response
        with patch.object(f, "public_ip", return_value="93.184.215.14"), patch.object(f, "PinnedHTTPS", return_value=conn):
            with self.assertRaisesRegex(f.FetchError, "redirect refused"):
                f.read_url("https://example.org/start")
        conn.request.assert_called_once()
        self.assertEqual(response.read_count, 0)

    def test_body_too_large_refused(self):
        response = FakeResponse(body=b"Z" * (f.MAX_BYTES + 2), headers={"Content-Type": "text/plain"})
        conn = Mock()
        conn.getresponse.return_value = response
        with patch.object(f, "public_ip", return_value="93.184.215.14"), patch.object(f, "PinnedHTTPS", return_value=conn):
            with self.assertRaisesRegex(f.FetchError, "exceeds limit"):
                f.read_url("https://example.org/start")

    def test_http_needs_explicit_opt_in(self):
        self.args.url = "http://example.org/"
        with patch.object(f, "read_url") as network:
            with self.assertRaises(f.FetchError):
                f.fetch_one(self.args)
            network.assert_not_called()

    def test_compression_refused(self):
        response = FakeResponse(headers={"Content-Type": "text/plain", "Content-Encoding": "gzip"})
        conn = Mock()
        conn.getresponse.return_value = response
        with patch.object(f, "public_ip", return_value="93.184.215.14"), patch.object(f, "PinnedHTTPS", return_value=conn):
            with self.assertRaisesRegex(f.FetchError, "compressed"):
                f.read_url("https://example.org/start")

    def test_manifest_file_never_overwritten(self):
        file = self.root / "page.html"
        manifest = Path(str(file) + ".manifest.json")
        manifest.write_text("critical old record")
        with self.assertRaises((FileExistsError, f.FetchError)):
            f.write_pair(file, b"new", {"sha256": "fake"})
        self.assertEqual(manifest.read_text(), "critical old record")
        self.assertFalse(file.exists())

    def test_fetch_writes_file_and_admit_checks_hash(self):
        p = f.parse_url(self.args.url)
        with patch.object(f, "read_url", return_value=(p, "93.184.215.14", "text/plain", b"hello")):
            self.assertEqual(f.fetch_one(self.args), 0)
        file = self.root / "info.txt"
        meta = json.loads(Path(str(file) + ".manifest.json").read_text())
        self.assertEqual(meta["sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(meta["can_authorize"], False)
        self.assertEqual(f.admit_one(argparse.Namespace(file=str(file))), 0)
        file.write_bytes(b"modified")
        with self.assertRaises(f.FetchError):
            f.admit_one(argparse.Namespace(file=str(file)))

    def test_manifest_symlink_refused_on_admit(self):
        p = self.root / "page.txt"
        p.write_text("hi")
        (self.root / "page.txt.manifest.json").symlink_to(p)
        with self.assertRaises(f.FetchError):
            f.admit_one(argparse.Namespace(file=str(p)))

if __name__ == "__main__":
    unittest.main()
