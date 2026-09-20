"""test_fetch_remote_image.py - Comprehensive unit tests for SEC-005 safe remote image fetch helper."""

import hashlib
import io
import ipaddress
import os
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.helpers.fetch_remote_image import (
    ImageFetchSecurityError,
    fetch_remote_image,
    get_private_cache_dir,
    normalize_and_validate_ip,
    parse_and_validate_image_format_and_dimensions,
)


def create_minimal_png(width: int, height: int) -> bytes:
    """Generate a minimal valid PNG byte sequence with specified dimensions."""
    def pngchunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack("!I", len(data)) + tag + data + struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw_scanlines = (b"\x00" + b"\x00\x00\x00" * width) * height
    idat = zlib.compress(raw_scanlines)
    return b"\x89PNG\r\n\x1a\n" + pngchunk(b"IHDR", ihdr) + pngchunk(b"IDAT", idat) + pngchunk(b"IEND", b"")


class TestFetchRemoteImage(unittest.TestCase):
    def test_ip_validation_public_addresses(self):
        """Public IPv4 and IPv6 addresses must be accepted."""
        ip4 = normalize_and_validate_ip("93.184.216.34")
        self.assertEqual(str(ip4), "93.184.216.34")

        ip6 = normalize_and_validate_ip("2606:2800:220:1:248:1893:25c8:1946")
        self.assertEqual(str(ip6), "2606:2800:220:1:248:1893:25c8:1946")

    def test_ip_validation_loopback_rejected(self):
        """Loopback IPv4 and IPv6 must be rejected."""
        with self.assertRaises(ImageFetchSecurityError):
            normalize_and_validate_ip("127.0.0.1")

        with self.assertRaises(ImageFetchSecurityError):
            normalize_and_validate_ip("::1")

    def test_ip_validation_private_rfc1918_rejected(self):
        """RFC 1918 private IPv4 addresses must be rejected."""
        for priv in ["10.0.0.1", "172.16.5.1", "192.168.1.1"]:
            with self.subTest(ip=priv):
                with self.assertRaises(ImageFetchSecurityError):
                    normalize_and_validate_ip(priv)

    def test_ip_validation_cgnat_and_site_local_rejected(self):
        """Carrier-Grade NAT (100.64.0.0/10) and site-local (fec0::/10) must be rejected."""
        with self.assertRaises(ImageFetchSecurityError):
            normalize_and_validate_ip("100.64.0.1")

        with self.assertRaises(ImageFetchSecurityError):
            normalize_and_validate_ip("::ffff:100.64.0.1")

        with self.assertRaises(ImageFetchSecurityError):
            normalize_and_validate_ip("fec0::1")

        with self.assertRaises(ImageFetchSecurityError):
            normalize_and_validate_ip("64:ff9b::a00:1")

    def test_insecure_scheme_rejected(self):
        """Non-HTTPS URLs must be rejected before any network resolution."""
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            fetch_remote_image("http://example.com/image.png")
        self.assertIn("only https:// is permitted", str(ctx.exception))

    def test_private_cache_dir_permissions_and_symlink_rejection(self):
        """Cache directory must have mode 0700 and reject symlinks."""
        with tempfile.TemporaryDirectory() as td:
            custom_cache = Path(td) / "test_cache"
            cache_dir = get_private_cache_dir(custom_cache)
            self.assertTrue(cache_dir.exists())
            mode = oct(cache_dir.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o700")

            # Symlink cache directory must be rejected
            symlink_cache = Path(td) / "symlink_cache"
            symlink_cache.symlink_to(cache_dir, target_is_directory=True)
            with self.assertRaises(ImageFetchSecurityError):
                get_private_cache_dir(symlink_cache)

            # Failed chmod must not fail-open
            with patch("os.chmod", side_effect=PermissionError("simulated permission error")):
                with self.assertRaises(ImageFetchSecurityError):
                    get_private_cache_dir(custom_cache)

    def test_dimension_bomb_rejected(self):
        """Image exceeding dimension bounds (e.g. 10000x1 PNG) must be rejected."""
        png_10k = create_minimal_png(10000, 1)
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            parse_and_validate_image_format_and_dimensions(png_10k)
        self.assertIn("exceed permitted limits", str(ctx.exception))

    def test_non_image_payload_rejected(self):
        """HTML or arbitrary non-image payload must be rejected."""
        html_data = b"<html><body>not an image</body></html>"
        with self.assertRaises(ImageFetchSecurityError):
            parse_and_validate_image_format_and_dimensions(html_data)

    def test_valid_image_dimensions_parsed(self):
        """Valid PNG within 4096x4096 bounds must be accepted."""
        png_valid = create_minimal_png(256, 128)
        ext, w, h = parse_and_validate_image_format_and_dimensions(png_valid)
        self.assertEqual(ext, ".png")
        self.assertEqual(w, 256)
        self.assertEqual(h, 128)

    def test_destination_symlink_hijacking_prevented(self):
        """If destination file in cache is a pre-existing symlink, it must be unlinked and replaced."""
        png_valid = create_minimal_png(64, 64)
        sha256 = hashlib.sha256(png_valid).hexdigest()

        with tempfile.TemporaryDirectory() as td:
            cache_dir = Path(td) / "cache"
            get_private_cache_dir(cache_dir)

            dest_file = cache_dir / f"{sha256}.png"
            sentinel = Path(td) / "victim_file"
            sentinel.write_bytes(b"original victim content")
            dest_file.symlink_to(sentinel)

            # Mock network fetch
            body = io.BytesIO(png_valid)
            resp = MagicMock(status=200)
            resp.getheader.side_effect = lambda k, default=None: "image/png" if k == "Content-Type" else default
            resp.read.side_effect = body.read
            conn = MagicMock()
            conn.getresponse.return_value = resp

            with patch("tools.helpers.fetch_remote_image.resolve_and_validate_host", return_value="93.184.216.34"), \
                 patch("tools.helpers.fetch_remote_image.socket.create_connection"), \
                 patch("tools.helpers.fetch_remote_image.ssl.create_default_context"), \
                 patch("tools.helpers.fetch_remote_image.http.client.HTTPSConnection", return_value=conn):
                result_path = fetch_remote_image("https://example.com/logo.png", cache_dir=cache_dir)

            self.assertEqual(result_path, dest_file)
            self.assertFalse(result_path.is_symlink(), "Destination file must NOT be a symlink")
            self.assertEqual(result_path.read_bytes(), png_valid)
            self.assertEqual(sentinel.read_bytes(), b"original victim content", "Victim file must NOT have been overwritten")


if __name__ == "__main__":
    unittest.main()
