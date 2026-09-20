"""test_fetch_remote_image.py - Unit tests for SEC-005 safe remote image fetch helper."""

import ipaddress
import tempfile
import unittest
from pathlib import Path
from tools.helpers.fetch_remote_image import (
    ImageFetchSecurityError,
    fetch_remote_image,
    get_private_cache_dir,
    normalize_and_validate_ip,
)


class TestFetchRemoteImage(unittest.TestCase):
    def test_ip_validation_public_ipv4(self):
        """Public IPv4 address must be accepted."""
        ip = normalize_and_validate_ip("93.184.216.34")
        self.assertEqual(str(ip), "93.184.216.34")

    def test_ip_validation_loopback_rejected(self):
        """Loopback IPv4 and IPv6 must be rejected."""
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            normalize_and_validate_ip("127.0.0.1")
        self.assertIn("Loopback", str(ctx.exception))

        with self.assertRaises(ImageFetchSecurityError) as ctx:
            normalize_and_validate_ip("::1")
        self.assertIn("Loopback", str(ctx.exception))

    def test_ip_validation_private_rfc1918_rejected(self):
        """RFC 1918 private IPv4 addresses must be rejected."""
        for priv in ["10.0.0.1", "172.16.5.1", "192.168.1.1"]:
            with self.subTest(ip=priv):
                with self.assertRaises(ImageFetchSecurityError) as ctx:
                    normalize_and_validate_ip(priv)
                self.assertIn("Private", str(ctx.exception))

    def test_ip_validation_ipv4_mapped_ipv6_normalized(self):
        """IPv4-mapped IPv6 addresses (::ffff:0:0/96) must be normalized and checked against private/loopback."""
        # Mapped loopback
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            normalize_and_validate_ip("::ffff:127.0.0.1")
        self.assertIn("Loopback", str(ctx.exception))

        # Mapped private
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            normalize_and_validate_ip("::ffff:192.168.0.1")
        self.assertIn("Private", str(ctx.exception))

        # Mapped public IPv4 should be accepted and normalized
        ip = normalize_and_validate_ip("::ffff:93.184.216.34")
        self.assertEqual(str(ip), "93.184.216.34")

    def test_insecure_scheme_rejected(self):
        """Non-HTTPS URLs must be rejected before any network resolution."""
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            fetch_remote_image("http://example.com/image.png")
        self.assertIn("only https:// is permitted", str(ctx.exception))

    def test_private_cache_dir_permissions(self):
        """Cache directory must be created with private mode 0700."""
        with tempfile.TemporaryDirectory() as td:
            custom_cache = Path(td) / "test_cache"
            cache_dir = get_private_cache_dir(custom_cache)
            self.assertTrue(cache_dir.exists())
            mode = oct(cache_dir.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o700")


if __name__ == "__main__":
    unittest.main()
