"""test_fetch_remote_image.py - Comprehensive unit tests for SEC-005 safe remote image fetch helper."""

import hashlib
import io
import ipaddress
import os
import socket
import struct
import tempfile
import threading
import time
import types
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


def create_minimal_png(width: int = 2, height: int = 2) -> bytes:
    """Generate a minimal valid PNG byte sequence with specified dimensions."""
    def pngchunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack("!I", len(data)) + tag + data + struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw_scanlines = (b"\x00" + b"\x00\x00\x00" * width) * height
    idat = zlib.compress(raw_scanlines)
    return b"\x89PNG\r\n\x1a\n" + pngchunk(b"IHDR", ihdr) + pngchunk(b"IDAT", idat) + pngchunk(b"IEND", b"")


def create_minimal_gif(logical_w: int, logical_h: int, frame_w: int, frame_h: int) -> bytes:
    """Generate a minimal valid GIF byte sequence with distinct logical and frame dimensions."""
    out = bytearray(b"GIF89a")
    out.extend(struct.pack("<HH", logical_w, logical_h))
    out.extend(b"\x80\x00\x00")  # Global Color Table flag, 2 colors
    out.extend(b"\x00\x00\x00\xff\xff\xff")  # Global Color Table
    out.append(0x2C)  # Image Descriptor
    out.extend(struct.pack("<HHHH", 0, 0, frame_w, frame_h))
    out.append(0x00)  # no local color table
    out.append(0x02)  # LZW min code size
    out.append(0x01)  # sub-block len
    out.append(0x00)
    out.append(0x00)  # block terminator
    out.append(0x3B)  # trailer
    return bytes(out)


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

    def test_cache_creation_mode_with_permissive_umask(self):
        """Cache directory must be created private immediately, even with permissive umask 000."""
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "permissive_cache"
            old_umask = os.umask(0o000)
            try:
                res = get_private_cache_dir(target)
            finally:
                os.umask(old_umask)
            mode = oct(res.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o700")

    def test_fake_or_truncated_png_headers_rejected(self):
        """Fake PNG headers, zero-size PNGs, and truncated headers must be rejected."""
        # 1. Fake 24-byte PNG with garbage chunk
        fake_png = b"\x89PNG\r\n\x1a\n" + b"garbage!" + struct.pack(">II", 1, 1)
        with self.assertRaises(ImageFetchSecurityError):
            parse_and_validate_image_format_and_dimensions(fake_png)

        # 2. Zero-size PNG
        zero_png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + struct.pack(">II", 0, 0) + b"\x08\x02\x00\x00\x00"
        with self.assertRaises(ImageFetchSecurityError):
            parse_and_validate_image_format_and_dimensions(zero_png)

        # 3. Truncated PNG header (only 24 bytes)
        valid = create_minimal_png(2, 2)
        with self.assertRaises(ImageFetchSecurityError):
            parse_and_validate_image_format_and_dimensions(valid[:24])

    def test_png_valid_crc_invalid_deflate_rejected(self):
        """PNG with valid chunk CRCs but invalid zlib compressed IDAT data must be rejected."""
        def chunk(kind, data):
            return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        ihdr = chunk(b"IHDR", struct.pack("!IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        corrupted_png = b"\x89PNG\r\n\x1a\n" + ihdr + chunk(b"IDAT", b"NOT A ZLIB STREAM") + chunk(b"IEND", b"")
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            parse_and_validate_image_format_and_dimensions(corrupted_png)
        self.assertIn("IDAT", str(ctx.exception))

    def test_dimension_bomb_rejected(self):
        """Image exceeding dimension bounds (e.g. 10000x1 PNG) must be rejected."""
        png_10k = create_minimal_png(10000, 1)
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            parse_and_validate_image_format_and_dimensions(png_10k)
        self.assertIn("exceed permitted limits", str(ctx.exception))

    def test_gif_frame_dimension_bomb_rejected(self):
        """GIF with logical screen (0,0) or (1,1) but frame (10000,1) must be rejected."""
        gif_bomb = create_minimal_gif(logical_w=0, logical_h=0, frame_w=10000, frame_h=1)
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            parse_and_validate_image_format_and_dimensions(gif_bomb)
        self.assertIn("exceed permitted limits", str(ctx.exception))

    def test_gif_without_frames_rejected(self):
        """GIF with logical screen but zero image frame descriptors must be rejected."""
        gif_no_frames = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x80\x00\x00\x00\x00\x00\xff\xff\xff" + b";"
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            parse_and_validate_image_format_and_dimensions(gif_no_frames)
        self.assertIn("no image frames", str(ctx.exception))

    def test_gif_truncated_descriptor_safe_rejection(self):
        """Truncated GIF image descriptor must raise ImageFetchSecurityError, not IndexError."""
        bad_gif = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00" + b"," + struct.pack("<HHHH", 0, 0, 1, 1)
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            parse_and_validate_image_format_and_dimensions(bad_gif)
        self.assertIn("Truncated", str(ctx.exception))

    def test_webp_canvas_without_bitstream_rejected(self):
        """WebP with VP8X extended header but no image bitstream chunk must be rejected."""
        webp_no_bitstream = b"RIFF" + struct.pack("<I", 22) + b"WEBPVP8X" + struct.pack("<I", 10) + b"\x00" * 10
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            parse_and_validate_image_format_and_dimensions(webp_no_bitstream)
        self.assertIn("missing image bitstream chunk", str(ctx.exception))

    def test_jpeg_sof_without_scan_rejected(self):
        """JPEG with SOF but no Start of Scan (SOS) marker must be rejected."""
        jpeg_no_sos = b"\xff\xd8\xff\xc0" + struct.pack(">H", 17) + b"\x08" + struct.pack(">HH", 1, 1) + b"\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00\xff\xd9"
        with self.assertRaises(ImageFetchSecurityError) as ctx:
            parse_and_validate_image_format_and_dimensions(jpeg_no_sos)
        self.assertIn("missing Start of Frame (SOF) or Start of Scan (SOS)", str(ctx.exception))

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

    def test_slow_dns_deadline_interrupted(self):
        """DNS resolution taking longer than total_timeout must be interrupted."""
        def slow_dns(*args, **kwargs):
            time.sleep(0.15)
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]

        with tempfile.TemporaryDirectory() as td:
            with patch("tools.helpers.fetch_remote_image.socket.getaddrinfo", side_effect=slow_dns):
                start = time.monotonic()
                with self.assertRaises(ImageFetchSecurityError) as ctx:
                    fetch_remote_image("https://example.com/img.png", cache_dir=Path(td), total_timeout=0.05)
                elapsed = time.monotonic() - start
                self.assertLess(elapsed, 0.12, "DNS wait must not exceed timeout budget")
                self.assertIn("timed out", str(ctx.exception))

    def test_eof_crossing_deadline_rejected(self):
        """If data transfer crosses the deadline, even if it returns EOF, it must be rejected."""
        valid_png = create_minimal_png(2, 2)
        clock = types.SimpleNamespace(value=0.0)
        reads = iter((valid_png, b""))

        def eof_crosses_deadline(size):
            val = next(reads)
            clock.value = 0.02 if val else 1.0
            return val

        with tempfile.TemporaryDirectory() as td:
            body = MagicMock()
            body.read.side_effect = eof_crosses_deadline
            resp = MagicMock(status=200)
            resp.getheader.side_effect = lambda k, default=None: "image/png" if k == "Content-Type" else default
            resp.read.side_effect = eof_crosses_deadline
            conn = MagicMock()
            conn.getresponse.return_value = resp

            with patch("tools.helpers.fetch_remote_image.resolve_and_validate_host", return_value="93.184.216.34"), \
                 patch("tools.helpers.fetch_remote_image.socket.create_connection"), \
                 patch("tools.helpers.fetch_remote_image.ssl.create_default_context"), \
                 patch("tools.helpers.fetch_remote_image.http.client.HTTPSConnection", return_value=conn), \
                 patch("tools.helpers.fetch_remote_image.time.monotonic", side_effect=lambda: clock.value):
                with self.assertRaises(ImageFetchSecurityError) as ctx:
                    fetch_remote_image("https://example.com/img.png", cache_dir=Path(td), total_timeout=0.05)
                self.assertIn("exceeded overall deadline", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
