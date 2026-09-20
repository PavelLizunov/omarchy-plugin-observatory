#!/usr/bin/env python3
"""fetch_remote_image.py - Reference implementation for SEC-005: Safe remote image retrieval.

Implements the complete 6-point SEC-005 hardening contract:
1. Destination Validation: HTTPS only. Resolves DNS and validates all resolved IPs against
   RFC 1918 private, loopback, link-local, multicast, site-local, carrier-grade NAT (100.64.0.0/10),
   and reserved/non-global ranges across both IPv4 and IPv6, including IPv4-mapped IPv6 (::ffff:0:0/96).
2. Redirect Revalidation: Re-validates scheme, hostname, and resolved IP at every redirect hop (<= 3 hops).
3. IP Pinning with SNI Preservation: Connects directly to the pre-validated IP while setting
   TLS Server Name Indication (SNI) and hostname verification to the original domain,
   preventing Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
4. Resource & Dimension Bounding: Enforces hard byte limit (default 5 MiB), decode dimension cap
   (<= 4096x4096 pixels, max 16 MP), and overall operation deadline (default 30s).
5. Private Cache Storage: Caches verified images in an owner-verified mode 0700 private user cache
   directory under $XDG_CACHE_HOME/omarchy-images/ with safe mkstemp file creation, symlink rejection,
   and content-addressed SHA-256 filenames.
6. Local file:// Output: Prints the verified local file path or URI for QML consumption.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import os
import socket
import ssl
import struct
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import List, Optional, Tuple

MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024  # 5 MiB
MAX_IMAGE_WIDTH = 4096
MAX_IMAGE_HEIGHT = 4096
MAX_IMAGE_PIXELS = 16 * 1024 * 1024   # 16 MP
MAX_REDIRECT_HOPS = 3
DEFAULT_SOCKET_TIMEOUT = 10.0
DEFAULT_TOTAL_TIMEOUT = 30.0

# Explicit non-public and special-purpose address ranges
DISALLOWED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),     # RFC 6598 Carrier-Grade NAT / Shared Address Space
    ipaddress.ip_network("198.18.0.0/15"),     # RFC 2544 Benchmarking
    ipaddress.ip_network("192.0.0.0/24"),      # RFC 6890 IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # RFC 5737 Documentation (TEST-NET-1)
    ipaddress.ip_network("198.51.100.0/24"),   # RFC 5737 Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),    # RFC 5737 Documentation (TEST-NET-3)
    ipaddress.ip_network("240.0.0.0/4"),       # RFC 1112 Reserved / Future use
    ipaddress.ip_network("fec0::/10"),         # RFC 3879 Deprecated Site-Local
    ipaddress.ip_network("2001:db8::/32"),     # RFC 3849 Documentation
    ipaddress.ip_network("64:ff9b:1::/48"),    # RFC 8215 Local-Use IPv4/IPv6 Translation
]


class ImageFetchSecurityError(Exception):
    """Raised when an image fetch violates network security or resource constraints."""


def normalize_and_validate_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse and validate an IP address against local, private, shared, and reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError as e:
        raise ImageFetchSecurityError(f"Invalid IP address format '{ip_str}': {e}") from e

    # Normalize IPv4-mapped IPv6 addresses (::ffff:192.0.2.1 -> 192.0.2.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        raise ImageFetchSecurityError(f"Loopback IP address rejected: {ip}")
    if ip.is_private:
        raise ImageFetchSecurityError(f"Private RFC 1918 / unique-local IP address rejected: {ip}")
    if ip.is_link_local:
        raise ImageFetchSecurityError(f"Link-local IP address rejected: {ip}")
    if ip.is_multicast:
        raise ImageFetchSecurityError(f"Multicast IP address rejected: {ip}")
    if ip.is_reserved:
        raise ImageFetchSecurityError(f"Reserved IP address rejected: {ip}")
    if ip.is_unspecified:
        raise ImageFetchSecurityError(f"Unspecified IP address rejected: {ip}")
    if getattr(ip, "is_site_local", False):
        raise ImageFetchSecurityError(f"Site-local IP address rejected: {ip}")
    if not ip.is_global:
        raise ImageFetchSecurityError(f"Non-global IP address rejected: {ip}")

    for net in DISALLOWED_NETWORKS:
        if ip in net:
            raise ImageFetchSecurityError(f"Prohibited non-public IP address range ({net}): {ip}")

    return ip


def resolve_and_validate_host(hostname: str, port: int) -> str:
    """Resolve hostname via DNS and validate all resolved IPs against prohibited ranges.
    
    Returns the first validated public IP address string.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ImageFetchSecurityError(f"DNS resolution failed for '{hostname}': {e}") from e

    if not addr_info:
        raise ImageFetchSecurityError(f"No IP addresses resolved for '{hostname}'")

    valid_ips: List[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        # Validate each resolved address
        normalize_and_validate_ip(ip_str)
        valid_ips.append(ip_str)

    return valid_ips[0]


def parse_and_validate_image_format_and_dimensions(data: bytes) -> Tuple[str, int, int]:
    """Inspect image magic bytes and header chunks to validate format and bounded dimensions.
    
    Returns (format_extension, width, height).
    Raises ImageFetchSecurityError if payload is not a valid recognized image or exceeds dimension caps.
    """
    if len(data) < 16:
        raise ImageFetchSecurityError("Downloaded payload is too small to be a valid image header")

    # 1. PNG: \x89PNG\r\n\x1a\n
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) < 24:
            raise ImageFetchSecurityError("Truncated PNG header")
        w, h = struct.unpack(">II", data[16:24])
        ext = ".png"

    # 2. GIF: GIF87a or GIF89a
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        if len(data) < 10:
            raise ImageFetchSecurityError("Truncated GIF header")
        w, h = struct.unpack("<HH", data[6:10])
        ext = ".gif"

    # 3. JPEG: \xff\xd8
    elif data.startswith(b"\xff\xd8"):
        idx = 2
        w, h = 0, 0
        while idx < len(data) - 8:
            if data[idx] != 0xff:
                idx += 1
                continue
            marker = data[idx + 1]
            if marker in (0xc0, 0xc1, 0xc2):  # SOF0, SOF1, SOF2
                h, w = struct.unpack(">HH", data[idx + 5:idx + 9])
                break
            elif marker in (0xd9, 0xda):  # EOI, SOS
                break
            else:
                length = struct.unpack(">H", data[idx + 2:idx + 4])[0]
                idx += 2 + length
        if w <= 0 or h <= 0:
            raise ImageFetchSecurityError("Could not determine JPEG image dimensions")
        ext = ".jpg"

    # 4. WebP: RIFF....WEBP
    elif len(data) >= 30 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        chunk_type = data[12:16]
        if chunk_type == b"VP8 ":
            w, h = struct.unpack("<HH", data[26:30])
            w, h = w & 0x3fff, h & 0x3fff
        elif chunk_type == b"VP8L":
            b0, b1, b2, b3 = data[21:25]
            w = 1 + (((b1 & 0x3f) << 8) | b0)
            h = 1 + (((b3 & 0xf) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6))
        elif chunk_type == b"VP8X":
            w = 1 + struct.unpack("<I", data[24:27] + b"\x00")[0]
            h = 1 + struct.unpack("<I", data[27:30] + b"\x00")[0]
        else:
            raise ImageFetchSecurityError("Unsupported WebP sub-format")
        ext = ".webp"

    else:
        raise ImageFetchSecurityError("Downloaded payload does not match a valid recognized image signature (PNG, JPEG, GIF, WebP)")

    if w > MAX_IMAGE_WIDTH or h > MAX_IMAGE_HEIGHT or (w * h) > MAX_IMAGE_PIXELS:
        raise ImageFetchSecurityError(
            f"Image dimensions ({w}x{h}, {w*h} pixels) exceed permitted limits (max {MAX_IMAGE_WIDTH}x{MAX_IMAGE_HEIGHT}, {MAX_IMAGE_PIXELS} pixels)"
        )

    return ext, w, h


def get_private_cache_dir(custom_dir: Optional[Path] = None) -> Path:
    """Initialize or verify a mode 0700 private user cache directory under XDG_CACHE_HOME.
    
    Enforces that the directory is not a symlink, is owned by current UID, and has mode 0700.
    """
    if custom_dir is not None:
        cache_dir = custom_dir
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        if xdg_cache:
            base = Path(xdg_cache)
        else:
            base = Path.home() / ".cache"
        cache_dir = base / "omarchy-images"

    # Reject if path exists and is a symlink
    if cache_dir.is_symlink():
        raise ImageFetchSecurityError(f"Insecure cache directory: path is a symbolic link: {cache_dir}")

    cache_dir.mkdir(parents=True, exist_ok=True)

    if cache_dir.is_symlink():
        raise ImageFetchSecurityError(f"Insecure cache directory: path is a symbolic link: {cache_dir}")

    try:
        st = cache_dir.stat()
    except OSError as e:
        raise ImageFetchSecurityError(f"Failed to inspect cache directory: {e}") from e

    if st.st_uid != os.getuid():
        raise ImageFetchSecurityError(f"Insecure cache directory ownership: UID {st.st_uid}, expected {os.getuid()}")

    # Enforce mode 0700 without swallowing errors
    try:
        os.chmod(cache_dir, 0o700)
    except OSError as e:
        raise ImageFetchSecurityError(f"Failed to enforce mode 0700 on cache directory: {e}") from e

    mode = cache_dir.stat().st_mode & 0o777
    if mode != 0o700:
        raise ImageFetchSecurityError(f"Insecure cache directory permissions: mode {oct(mode)}, expected 0o700")

    return cache_dir


def fetch_remote_image(
    url: str,
    cache_dir: Optional[Path] = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
    max_redirects: int = MAX_REDIRECT_HOPS,
    socket_timeout: float = DEFAULT_SOCKET_TIMEOUT,
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
) -> Path:
    """Safely fetch a remote image with destination validation, IP pinning, dimension bounding, and private caching.
    
    Returns the Path to the locally cached, verified image file.
    """
    deadline = time.monotonic() + total_timeout
    current_url = url
    hops = 0

    while hops <= max_redirects:
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            raise ImageFetchSecurityError(f"Operation exceeded overall deadline of {total_timeout}s")

        parsed = urllib.parse.urlsplit(current_url)
        if parsed.scheme.lower() != "https":
            raise ImageFetchSecurityError(f"Insecure scheme '{parsed.scheme}': only https:// is permitted")

        hostname = parsed.hostname
        if not hostname:
            raise ImageFetchSecurityError("Missing hostname in URL")

        port = parsed.port or 443

        # 1. Resolve and validate IP address
        pinned_ip = resolve_and_validate_host(hostname, port)

        step_timeout = min(socket_timeout, remaining_time)

        # 2. Establish TLS connection with IP pinning and SNI preservation
        ssl_ctx = ssl.create_default_context()
        raw_sock = socket.create_connection((pinned_ip, port), timeout=step_timeout)
        try:
            # Wrap socket with TLS; server_hostname pins SNI and certificate verification to original domain
            tls_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=hostname)
        except Exception:
            raw_sock.close()
            raise

        try:
            conn = http.client.HTTPSConnection(hostname, port=port, timeout=step_timeout)
            conn.sock = tls_sock

            path_and_query = parsed.path or "/"
            if parsed.query:
                path_and_query += f"?{parsed.query}"

            headers = {
                "User-Agent": "Omarchy-Image-Fetcher/1.0",
                "Accept": "image/png, image/jpeg, image/gif, image/webp",
                "Connection": "close",
            }
            conn.request("GET", path_and_query, headers=headers)
            resp = conn.getresponse()

            # Handle redirects safely
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location")
                if not location:
                    raise ImageFetchSecurityError(f"HTTP {resp.status} redirect without Location header")
                current_url = urllib.parse.urljoin(current_url, location)
                hops += 1
                conn.close()
                continue

            if resp.status != 200:
                raise ImageFetchSecurityError(f"Remote server returned HTTP {resp.status}: {resp.reason}")

            # Verify Content-Type: must be an explicit image MIME type
            ctype = resp.getheader("Content-Type", "")
            if not ctype or not ctype.lower().startswith("image/"):
                raise ImageFetchSecurityError(f"Rejected non-image Content-Type '{ctype}': expected image/*")

            # Read response with byte limit bounding
            data = bytearray()
            while True:
                if time.monotonic() > deadline:
                    raise ImageFetchSecurityError(f"Operation exceeded overall deadline of {total_timeout}s during transfer")

                chunk = resp.read(65536)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > max_bytes:
                    raise ImageFetchSecurityError(f"Response exceeded maximum size limit of {max_bytes} bytes")

            conn.close()
            break
        except Exception:
            tls_sock.close()
            raise
    else:
        raise ImageFetchSecurityError(f"Exceeded maximum redirect limit of {max_redirects} hops")

    # 3. Inspect image headers to validate format and bounded dimensions
    ext, width, height = parse_and_validate_image_format_and_dimensions(bytes(data))

    # 4. Cache into private directory with content-addressed SHA-256 hash using safe mkstemp
    target_cache_dir = get_private_cache_dir(cache_dir)
    sha256_hash = hashlib.sha256(data).hexdigest()
    dest_file = target_cache_dir / f"{sha256_hash}{ext}"

    # If destination exists and is a symlink, remove it to prevent destination symlink hijacking
    if dest_file.is_symlink():
        dest_file.unlink()

    # Create safe temporary file in the verified cache directory
    fd, tmp_path_str = tempfile.mkstemp(dir=target_cache_dir, prefix=".tmp_img_")
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, dest_file)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return dest_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely fetch and cache a remote image under SEC-005 contract.")
    parser.add_argument("url", help="HTTPS URL of the remote image")
    parser.add_argument("--cache-dir", type=Path, default=None, help="Custom cache directory")
    parser.add_argument("--max-bytes", type=int, default=MAX_DOWNLOAD_BYTES, help="Max byte limit (default: 5MB)")
    parser.add_argument("--file-uri", action="store_true", help="Print output as a file:// URI for QML")

    args = parser.parse_args()

    try:
        cached_path = fetch_remote_image(args.url, cache_dir=args.cache_dir, max_bytes=args.max_bytes)
        if args.file_uri:
            print(cached_path.as_uri())
        else:
            print(str(cached_path))
        return 0
    except Exception as e:
        print(f"Error fetching remote image: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
