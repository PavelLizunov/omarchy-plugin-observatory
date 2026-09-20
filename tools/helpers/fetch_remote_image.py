#!/usr/bin/env python3
"""fetch_remote_image.py - Reference implementation for SEC-005: Safe remote image retrieval.

Implements the complete 6-point SEC-005 hardening contract:
1. Destination Validation: HTTPS only. Resolves DNS and validates against RFC 1918 private,
   loopback, link-local, multicast, and unique-local ranges across both IPv4 and IPv6,
   including IPv4-mapped IPv6 address normalization (::ffff:0:0/96).
2. Redirect Revalidation: Re-validates scheme, hostname, and resolved IP at every redirect hop (<= 3 hops).
3. IP Pinning with SNI Preservation: Connects directly to the pre-validated IP while setting
   TLS Server Name Indication (SNI) and hostname verification to the original domain,
   preventing Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
4. Resource Bounding: Hard byte download limit (default 5 MiB) and connection/read timeouts.
5. Private Cache Storage: Caches verified images in a mode 0700 private user cache directory
   under $XDG_CACHE_HOME/omarchy-images/ with content-addressed SHA-256 filenames.
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
import sys
import urllib.parse
from pathlib import Path
from typing import List, Optional, Tuple

MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024  # 5 MiB
MAX_REDIRECT_HOPS = 3
DEFAULT_TIMEOUT_SECONDS = 10.0


class ImageFetchSecurityError(Exception):
    """Raised when an image fetch violates network security or resource constraints."""


def normalize_and_validate_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse and validate an IP address against local, private, and reserved ranges."""
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


def get_private_cache_dir(custom_dir: Optional[Path] = None) -> Path:
    """Initialize or verify a mode 0700 private user cache directory under XDG_CACHE_HOME."""
    if custom_dir is not None:
        cache_dir = custom_dir
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        if xdg_cache:
            base = Path(xdg_cache)
        else:
            base = Path.home() / ".cache"
        cache_dir = base / "omarchy-images"

    cache_dir.mkdir(parents=True, exist_ok=True)
    # Enforce mode 0700
    try:
        os.chmod(cache_dir, 0o700)
    except OSError:
        pass

    return cache_dir


def fetch_remote_image(
    url: str,
    cache_dir: Optional[Path] = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
    max_redirects: int = MAX_REDIRECT_HOPS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Path:
    """Safely fetch a remote image with destination validation, IP pinning, and size bounding.
    
    Returns the Path to the locally cached image file.
    """
    current_url = url
    hops = 0

    while hops <= max_redirects:
        parsed = urllib.parse.urlsplit(current_url)
        if parsed.scheme.lower() != "https":
            raise ImageFetchSecurityError(f"Insecure scheme '{parsed.scheme}': only https:// is permitted")

        hostname = parsed.hostname
        if not hostname:
            raise ImageFetchSecurityError("Missing hostname in URL")

        port = parsed.port or 443

        # 1. Resolve and validate IP address
        pinned_ip = resolve_and_validate_host(hostname, port)

        # 2. Establish TLS connection with IP pinning and SNI preservation
        ssl_ctx = ssl.create_default_context()
        raw_sock = socket.create_connection((pinned_ip, port), timeout=timeout)
        try:
            # Wrap socket with TLS; server_hostname pins SNI and certificate verification to original domain
            tls_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=hostname)
        except Exception:
            raw_sock.close()
            raise

        try:
            conn = http.client.HTTPSConnection(hostname, port=port, timeout=timeout)
            conn.sock = tls_sock

            path_and_query = parsed.path or "/"
            if parsed.query:
                path_and_query += f"?{parsed.query}"

            headers = {
                "User-Agent": "Omarchy-Image-Fetcher/1.0",
                "Accept": "image/*",
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

            # Verify Content-Type if present
            ctype = resp.getheader("Content-Type", "")
            if ctype and not any(ctype.lower().startswith(p) for p in ("image/", "application/octet-stream")):
                raise ImageFetchSecurityError(f"Unexpected Content-Type '{ctype}': expected image/*")

            # Read response with byte limit bounding
            data = bytearray()
            while True:
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

    # 3. Cache into private directory with content-addressed SHA-256 hash
    target_cache_dir = get_private_cache_dir(cache_dir)
    sha256_hash = hashlib.sha256(data).hexdigest()

    # Determine safe file extension
    ext = ".img"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        ext = ".png"
    elif data.startswith(b"\xff\xd8\xff"):
        ext = ".jpg"
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        ext = ".gif"
    elif len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        ext = ".webp"

    dest_file = target_cache_dir / f"{sha256_hash}{ext}"
    if not dest_file.exists():
        tmp_file = target_cache_dir / f".tmp_{os.getpid()}_{sha256_hash}{ext}"
        tmp_file.write_bytes(data)
        os.chmod(tmp_file, 0o600)
        os.replace(tmp_file, dest_file)

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
