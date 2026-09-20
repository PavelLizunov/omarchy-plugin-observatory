#!/usr/bin/env python3
"""fetch_remote_image.py - Reference implementation for SEC-005: Safe remote image retrieval.

Implements the complete 6-point SEC-005 hardening contract:
1. Destination Validation: HTTPS only. Resolves DNS with bounded timeout and validates all
   resolved IPs against RFC 1918 private, loopback, link-local, multicast, site-local (fec0::/10),
   carrier-grade NAT (100.64.0.0/10), benchmarking (198.18.0.0/15), and all non-global ranges
   across both IPv4 and IPv6, including IPv4-mapped IPv6 (::ffff:0:0/96).
2. Redirect Revalidation: Re-validates scheme, hostname, and resolved IP at every redirect hop (<= 3 hops).
3. IP Pinning with SNI Preservation: Connects directly to the pre-validated IP while setting
   TLS Server Name Indication (SNI) and hostname verification to the original domain,
   preventing Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
4. Structural & Dimension Bounding: Validates format structure and enforces decode dimension caps
   (width and height > 0, <= 4096x4096 pixels, max 16 MP):
   - PNG: Validates signature, IHDR (depth/color type legality, comp=0, filt=0, inter in 0..1), chunk CRCs,
     required IDAT and IEND, streaming zlib deflate verification without unbounded flush, exact expected
     scanline bytes calculation for both standard and Adam7 interlacing, and filter type validation (0..4).
   - GIF: Validates Logical Screen Descriptor, all frame descriptors (0x2C) with bounds checks,
     frame sub-block data, and requires at least one valid image frame with sub-blocks.
   - JPEG: Validates SOI, SOF marker dimensions, and requires Start of Scan (SOS, 0xDA) with entropy scan data.
   - WebP: Validates RIFF/WEBP structure, rejects ambiguous multi-raster containers, verifies VP8/VP8L headers
     and ANMF frame sub-chunks, ensuring verified dimensions match the actual rendered raster.
5. End-to-End Operation Deadline: Strict overall deadline (default 30s) bounding DNS wait, TCP connect,
   TLS handshake, HTTP headers, and data transfer via single-owner descriptor-duplicate watchdog shutdown
   (failing closed and immediately cleaning duplicate descriptors on error).
6. Private Cache Storage: Caches verified images in an owner-verified mode 0700 private user cache
   directory created with umask 077, symlink rejection, atomic mkstemp, and content-addressed SHA-256 filenames.
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
import threading
import time
import urllib.parse
import zlib
from pathlib import Path
from typing import List, Optional, Tuple

MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024  # 5 MiB
MAX_IMAGE_WIDTH = 4096
MAX_IMAGE_HEIGHT = 4096
MAX_IMAGE_PIXELS = 16 * 1024 * 1024   # 16 MP
MAX_REDIRECT_HOPS = 3
DEFAULT_SOCKET_TIMEOUT = 10.0
DEFAULT_TOTAL_TIMEOUT = 30.0

# Explicit non-public, shared, and special-purpose address ranges
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

# Legitimate PNG bit-depths per color-type (ISO/IEC 15948:2004 Table 1)
ALLOWED_PNG_DEPTHS = {
    0: (1, 2, 4, 8, 16),  # Grayscale
    2: (8, 16),          # Truecolor RGB
    3: (1, 2, 4, 8),      # Indexed color
    4: (8, 16),          # Grayscale with alpha
    6: (8, 16),          # Truecolor with alpha RGBA
}


class ImageFetchSecurityError(Exception):
    """Raised when an image fetch violates network security, format, or resource constraints."""


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


def resolve_and_validate_host(hostname: str, port: int, timeout: float = DEFAULT_SOCKET_TIMEOUT) -> str:
    """Resolve hostname via DNS with a bounded wait timeout and validate all resolved IPs.
    
    Note: The calling thread wait is bounded by timeout via daemon thread join.
    Returns the first validated public IP address string.
    """
    resolved_entries: List[Tuple] = []
    resolve_error: List[Exception] = []

    def _do_resolve():
        try:
            entries = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
            resolved_entries.extend(entries)
        except Exception as e:
            resolve_error.append(e)

    worker = threading.Thread(target=_do_resolve, daemon=True)
    worker.start()
    worker.join(timeout=max(0.001, timeout))

    if worker.is_alive():
        raise ImageFetchSecurityError(f"DNS resolution timed out after {timeout:.3f}s for '{hostname}'")

    if resolve_error:
        raise ImageFetchSecurityError(f"DNS resolution failed for '{hostname}': {resolve_error[0]}") from resolve_error[0]

    if not resolved_entries:
        raise ImageFetchSecurityError(f"No IP addresses resolved for '{hostname}'")

    valid_ips: List[str] = []
    for entry in resolved_entries:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        normalize_and_validate_ip(ip_str)
        valid_ips.append(ip_str)

    return valid_ips[0]


def calculate_adam7_expected_bytes(w: int, h: int, bits_per_pixel: int) -> Tuple[int, List[Tuple[int, int]]]:
    """Calculate total expected scanline bytes and pass dimensions for Adam7 interlaced PNG."""
    passes = [
        (0, 0, 8, 8),
        (4, 0, 8, 8),
        (0, 4, 4, 8),
        (2, 0, 4, 4),
        (0, 2, 2, 4),
        (1, 0, 2, 2),
        (0, 1, 1, 2),
    ]
    total_bytes = 0
    pass_specs = []
    for (xs, ys, xstep, ystep) in passes:
        pw = (w - xs + xstep - 1) // xstep if w > xs else 0
        ph = (h - ys + ystep - 1) // ystep if h > ys else 0
        if pw > 0 and ph > 0:
            row_bytes = (pw * bits_per_pixel + 7) // 8
            pass_bytes = ph * (1 + row_bytes)
            total_bytes += pass_bytes
            pass_specs.append((ph, 1 + row_bytes))
    return total_bytes, pass_specs


def parse_and_validate_image_format_and_dimensions(data: bytes) -> Tuple[str, int, int]:
    """Inspect image magic bytes, header chunks, and frame descriptors to validate format and bounded dimensions.
    
    Returns (format_extension, width, height).
    Raises ImageFetchSecurityError if payload is not a valid recognized image or exceeds dimension caps.
    """
    if len(data) < 16:
        raise ImageFetchSecurityError("Downloaded payload is too small to be a valid image header")

    # 1. PNG: \x89PNG\r\n\x1a\n
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) < 33:
            raise ImageFetchSecurityError("Truncated PNG header (must be at least 33 bytes for valid IHDR)")
        
        ihdr_len = struct.unpack(">I", data[8:12])[0]
        ihdr_type = data[12:16]
        if ihdr_len != 13 or ihdr_type != b"IHDR":
            raise ImageFetchSecurityError("Invalid PNG structure: first chunk must be IHDR with length 13")

        w, h, depth, color, comp, filt, inter = struct.unpack("!IIBBBBB", data[16:29])
        if w <= 0 or h <= 0:
            raise ImageFetchSecurityError(f"Invalid PNG dimensions ({w}x{h}): width and height must be positive")

        if comp != 0:
            raise ImageFetchSecurityError(f"Invalid PNG compression method {comp} (only 0 is permitted)")
        if filt != 0:
            raise ImageFetchSecurityError(f"Invalid PNG filter method {filt} (only 0 is permitted)")
        if inter not in (0, 1):
            raise ImageFetchSecurityError(f"Invalid PNG interlace method {inter} (only 0 or 1 is permitted)")

        allowed_depths = ALLOWED_PNG_DEPTHS.get(color)
        if not allowed_depths or depth not in allowed_depths:
            raise ImageFetchSecurityError(f"Invalid PNG bit depth {depth} for color type {color}")

        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]

        expected_crc = struct.unpack(">I", data[29:33])[0]
        actual_crc = zlib.crc32(data[12:29]) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ImageFetchSecurityError("Corrupted PNG IHDR chunk CRC")

        idx = 8
        has_idat = False
        has_iend = False
        idat_chunks = []
        while idx + 8 <= len(data):
            chunk_len = struct.unpack(">I", data[idx:idx + 4])[0]
            ctype = data[idx + 4:idx + 8]
            if idx + 8 + chunk_len + 4 > len(data):
                raise ImageFetchSecurityError("Truncated PNG chunk payload")
            chunk_crc = struct.unpack(">I", data[idx + 8 + chunk_len:idx + 12 + chunk_len])[0]
            if (zlib.crc32(data[idx + 4:idx + 8 + chunk_len]) & 0xFFFFFFFF) != chunk_crc:
                raise ImageFetchSecurityError("Corrupted PNG chunk CRC")
            if ctype == b"IDAT":
                has_idat = True
                idat_chunks.append(data[idx + 8:idx + 8 + chunk_len])
            elif ctype == b"IEND":
                has_iend = True
                break
            idx += 12 + chunk_len

        if not (has_idat and has_iend):
            raise ImageFetchSecurityError("Incomplete PNG: missing required IDAT or IEND chunk")

        # Streaming verification of IDAT chunks preserving unconsumed_tail and enforcing exact raster bounds
        max_scanline_bytes = min(MAX_IMAGE_PIXELS * 4 + 4096, 64 * 1024 * 1024)
        try:
            decompressor = zlib.decompressobj()
            decompressed_parts: List[bytes] = []
            decompressed_total = 0

            for chunk in idat_chunks:
                input_data = chunk
                while input_data:
                    budget_left = max_scanline_bytes - decompressed_total
                    if budget_left <= 0:
                        raise ImageFetchSecurityError("Decompressed PNG exceeds maximum permitted pixel capacity")

                    step_limit = min(65536, budget_left + 1)
                    out = decompressor.decompress(input_data, step_limit)
                    decompressed_total += len(out)
                    decompressed_parts.append(out)
                    if decompressed_total > max_scanline_bytes:
                        raise ImageFetchSecurityError("Decompressed PNG exceeds maximum permitted pixel capacity")

                    input_data = decompressor.unconsumed_tail
                    if not out and input_data == chunk:
                        break

            while not decompressor.eof and decompressor.unconsumed_tail:
                budget_left = max_scanline_bytes - decompressed_total
                if budget_left <= 0:
                    raise ImageFetchSecurityError("Decompressed PNG exceeds maximum permitted pixel capacity")
                step_limit = min(65536, budget_left + 1)
                out = decompressor.decompress(decompressor.unconsumed_tail, step_limit)
                if not out:
                    break
                decompressed_total += len(out)
                decompressed_parts.append(out)
                if decompressed_total > max_scanline_bytes:
                    raise ImageFetchSecurityError("Decompressed PNG exceeds maximum permitted pixel capacity")

            if not decompressor.eof:
                raise ImageFetchSecurityError("Incomplete or truncated PNG deflate stream in IDAT")

            decompressed_bytes = b"".join(decompressed_parts)

            # Exact scanline raster verification for standard and Adam7 interlaced PNGs
            bits_per_pixel = depth * channels
            if inter == 0:
                row_bytes = (w * bits_per_pixel + 7) // 8
                expected_bytes = h * (1 + row_bytes)
                if len(decompressed_bytes) != expected_bytes:
                    raise ImageFetchSecurityError(
                        f"Truncated PNG image data: decompressed {len(decompressed_bytes)} bytes, expected exactly {expected_bytes} for {w}x{h} depth={depth} color={color}"
                    )
                stride = 1 + row_bytes
                for row in range(h):
                    filter_type = decompressed_bytes[row * stride]
                    if filter_type > 4:
                        raise ImageFetchSecurityError(f"Invalid PNG filter type {filter_type} in row {row}")
            else:
                expected_bytes, pass_specs = calculate_adam7_expected_bytes(w, h, bits_per_pixel)
                if len(decompressed_bytes) != expected_bytes:
                    raise ImageFetchSecurityError(
                        f"Truncated Adam7 PNG image data: decompressed {len(decompressed_bytes)} bytes, expected exactly {expected_bytes} for {w}x{h}"
                    )
                offset = 0
                for ph, stride in pass_specs:
                    for row in range(ph):
                        filter_type = decompressed_bytes[offset + row * stride]
                        if filter_type > 4:
                            raise ImageFetchSecurityError(f"Invalid PNG filter type {filter_type} in Adam7 pass")
                    offset += ph * stride

        except zlib.error as e:
            raise ImageFetchSecurityError(f"Corrupted or invalid PNG compressed image stream (IDAT): {e}") from e

        ext = ".png"

    # 2. GIF: GIF87a or GIF89a
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        if len(data) < 13:
            raise ImageFetchSecurityError("Truncated GIF header")
        logical_w, logical_h = struct.unpack("<HH", data[6:10])

        max_w = logical_w
        max_h = logical_h

        flags = data[10]
        has_gct = bool(flags & 0x80)
        gct_size = 3 * (2 ** ((flags & 0x07) + 1)) if has_gct else 0
        idx = 13 + gct_size

        has_image_frame = False
        while idx < len(data):
            block_type = data[idx]
            if block_type == 0x3B:  # Trailer
                break
            elif block_type == 0x21:  # Extension
                if idx + 2 > len(data):
                    raise ImageFetchSecurityError("Truncated GIF extension header")
                idx += 2
                while idx < len(data):
                    sub_len = data[idx]
                    idx += 1
                    if sub_len == 0:
                        break
                    if idx + sub_len > len(data):
                        raise ImageFetchSecurityError("Truncated GIF extension sub-block")
                    idx += sub_len
            elif block_type == 0x2C:  # Image Descriptor
                if idx + 10 > len(data):
                    raise ImageFetchSecurityError("Truncated GIF Image Descriptor")
                left, top, iw, ih = struct.unpack("<HHHH", data[idx + 1:idx + 9])
                if iw <= 0 or ih <= 0:
                    raise ImageFetchSecurityError("Invalid GIF frame dimensions (must be > 0)")
                max_w = max(max_w, left + iw)
                max_h = max(max_h, top + ih)
                has_image_frame = True

                local_flags = data[idx + 9]
                has_lct = bool(local_flags & 0x80)
                lct_size = 3 * (2 ** ((local_flags & 0x07) + 1)) if has_lct else 0
                idx += 10 + lct_size
                if idx >= len(data):
                    raise ImageFetchSecurityError("Truncated GIF frame data")
                min_code_size = data[idx]
                idx += 1
                has_frame_subblocks = False
                while idx < len(data):
                    sub_len = data[idx]
                    idx += 1
                    if sub_len == 0:
                        break
                    if idx + sub_len > len(data):
                        raise ImageFetchSecurityError("Truncated GIF data sub-block")
                    idx += sub_len
                    has_frame_subblocks = True
                if not has_frame_subblocks:
                    raise ImageFetchSecurityError("Truncated GIF: image frame contains no data sub-blocks")
            else:
                idx += 1

        if not has_image_frame:
            raise ImageFetchSecurityError("Invalid GIF: no image frames found in stream")

        w, h = max_w, max_h
        ext = ".gif"

    # 3. JPEG: \xff\xd8
    elif data.startswith(b"\xff\xd8"):
        idx = 2
        w, h = 0, 0
        has_sof = False
        has_sos = False
        scan_data_present = False
        while idx < len(data) - 1:
            if data[idx] != 0xFF:
                idx += 1
                continue
            marker = data[idx + 1]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                if idx + 9 > len(data):
                    raise ImageFetchSecurityError("Truncated JPEG SOF marker")
                h, w = struct.unpack(">HH", data[idx + 5:idx + 9])
                has_sof = True
                length = struct.unpack(">H", data[idx + 2:idx + 4])[0]
                idx += 2 + length
            elif marker == 0xDA:  # SOS (Start of Scan)
                if idx + 4 > len(data):
                    raise ImageFetchSecurityError("Truncated JPEG SOS marker")
                sos_length = struct.unpack(">H", data[idx + 2:idx + 4])[0]
                has_sos = True
                idx += 2 + sos_length
                scan_start = idx
                while idx < len(data) - 1:
                    if data[idx] == 0xFF and data[idx + 1] not in (0x00, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
                        break
                    idx += 1
                if idx > scan_start:
                    scan_data_present = True
                break
            elif marker == 0xD9:  # EOI
                break
            elif marker in (0xD8, 0x00, 0x01) or (0xD0 <= marker <= 0xD7):
                idx += 2
            else:
                if idx + 4 > len(data):
                    raise ImageFetchSecurityError("Truncated JPEG segment")
                length = struct.unpack(">H", data[idx + 2:idx + 4])[0]
                idx += 2 + length

        if not (has_sof and has_sos and scan_data_present):
            raise ImageFetchSecurityError("Invalid JPEG: missing Start of Frame (SOF) or Start of Scan (SOS) data")
        ext = ".jpg"

    # 4. WebP: RIFF....WEBP
    elif len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        riff_file_size = struct.unpack("<I", data[4:8])[0] + 8
        if len(data) < riff_file_size:
            raise ImageFetchSecurityError(f"Truncated WebP file: received {len(data)} bytes, expected {riff_file_size} from RIFF header")

        idx = 12
        canvas_w, canvas_h = 0, 0
        is_extended = False
        is_animated = False
        raster_chunks_count = 0
        max_observed_w = 0
        max_observed_h = 0

        while idx + 8 <= len(data):
            chunk_type = data[idx:idx + 4]
            chunk_len = struct.unpack("<I", data[idx + 4:idx + 8])[0]
            if idx + 8 + chunk_len > len(data):
                tag_name = chunk_type.decode("latin1", "replace")
                raise ImageFetchSecurityError(f"Truncated WebP chunk '{tag_name}': declares {chunk_len} bytes, available {len(data) - idx - 8}")

            chunk_data = data[idx + 8:idx + 8 + chunk_len]

            if chunk_type == b"VP8X":
                is_extended = True
                if len(chunk_data) < 10:
                    raise ImageFetchSecurityError("Truncated VP8X header (must be at least 10 bytes)")
                flags = chunk_data[0]
                is_animated = bool(flags & 0x02)
                canvas_w = 1 + struct.unpack("<I", chunk_data[4:7] + b"\x00")[0]
                canvas_h = 1 + struct.unpack("<I", chunk_data[7:10] + b"\x00")[0]
                if canvas_w > MAX_IMAGE_WIDTH or canvas_h > MAX_IMAGE_HEIGHT or (canvas_w * canvas_h) > MAX_IMAGE_PIXELS:
                    raise ImageFetchSecurityError(f"WebP canvas dimensions ({canvas_w}x{canvas_h}) exceed permitted limits")
                max_observed_w = max(max_observed_w, canvas_w)
                max_observed_h = max(max_observed_h, canvas_h)

            elif chunk_type == b"VP8 ":
                raster_chunks_count += 1
                if len(chunk_data) < 10 or chunk_data[3:6] != b"\x9d\x01\x2a":
                    raise ImageFetchSecurityError("Invalid or truncated VP8 chunk header")
                raw_w, raw_h = struct.unpack("<HH", chunk_data[6:10])
                w, h = raw_w & 0x3FFF, raw_h & 0x3FFF
                if w <= 0 or h <= 0:
                    raise ImageFetchSecurityError(f"Invalid VP8 dimensions ({w}x{h}): must be positive")
                if w > MAX_IMAGE_WIDTH or h > MAX_IMAGE_HEIGHT or (w * h) > MAX_IMAGE_PIXELS:
                    raise ImageFetchSecurityError(f"WebP VP8 dimensions ({w}x{h}) exceed permitted limits")
                max_observed_w = max(max_observed_w, w)
                max_observed_h = max(max_observed_h, h)

            elif chunk_type == b"VP8L":
                raster_chunks_count += 1
                if len(chunk_data) < 5 or chunk_data[0] != 0x2F:
                    raise ImageFetchSecurityError("Invalid or truncated VP8L chunk header")
                b0, b1, b2, b3 = chunk_data[1:5]
                w = 1 + (((b1 & 0x3F) << 8) | b0)
                h = 1 + (((b3 & 0x0F) << 10) | (b2 << 2) | ((b1 & 0xC0) >> 6))
                if w <= 0 or h <= 0:
                    raise ImageFetchSecurityError(f"Invalid VP8L dimensions ({w}x{h}): must be positive")
                if w > MAX_IMAGE_WIDTH or h > MAX_IMAGE_HEIGHT or (w * h) > MAX_IMAGE_PIXELS:
                    raise ImageFetchSecurityError(f"WebP VP8L dimensions ({w}x{h}) exceed permitted limits")
                max_observed_w = max(max_observed_w, w)
                max_observed_h = max(max_observed_h, h)

            elif chunk_type == b"ANMF":
                if not is_animated:
                    raise ImageFetchSecurityError("ANMF frame chunk present in non-animated WebP")
                if len(chunk_data) < 16:
                    raise ImageFetchSecurityError("Truncated ANMF frame header (must be at least 16 bytes)")

                frame_x = 2 * struct.unpack("<I", chunk_data[0:3] + b"\x00")[0]
                frame_y = 2 * struct.unpack("<I", chunk_data[3:6] + b"\x00")[0]
                frame_w = 1 + struct.unpack("<I", chunk_data[6:9] + b"\x00")[0]
                frame_h = 1 + struct.unpack("<I", chunk_data[9:12] + b"\x00")[0]

                if frame_w > MAX_IMAGE_WIDTH or frame_h > MAX_IMAGE_HEIGHT or (frame_w * frame_h) > MAX_IMAGE_PIXELS:
                    raise ImageFetchSecurityError(f"WebP ANMF frame dimensions ({frame_w}x{frame_h}) exceed permitted limits")
                if canvas_w > 0 and (frame_x + frame_w > canvas_w or frame_y + frame_h > canvas_h):
                    raise ImageFetchSecurityError(f"WebP ANMF frame ({frame_x}+{frame_w}x{frame_y}+{frame_h}) exceeds canvas bounds ({canvas_w}x{canvas_h})")

                max_observed_w = max(max_observed_w, frame_x + frame_w)
                max_observed_h = max(max_observed_h, frame_y + frame_h)

                sub_idx = 16
                has_sub_raster = False
                while sub_idx + 8 <= len(chunk_data):
                    stag = chunk_data[sub_idx:sub_idx + 4]
                    slen = struct.unpack("<I", chunk_data[sub_idx + 4:sub_idx + 8])[0]
                    if sub_idx + 8 + slen > len(chunk_data):
                        sub_name = stag.decode("latin1", "replace")
                        raise ImageFetchSecurityError(f"Truncated sub-chunk '{sub_name}' in ANMF frame")
                    sdata = chunk_data[sub_idx + 8:sub_idx + 8 + slen]

                    if stag == b"VP8 ":
                        if len(sdata) < 10 or sdata[3:6] != b"\x9d\x01\x2a":
                            raise ImageFetchSecurityError("Invalid or truncated VP8 in ANMF frame")
                        raw_sw, raw_sh = struct.unpack("<HH", sdata[6:10])
                        sw, sh = raw_sw & 0x3FFF, raw_sh & 0x3FFF
                        if sw != frame_w or sh != frame_h:
                            raise ImageFetchSecurityError(f"WebP ANMF frame size ({frame_w}x{frame_h}) mismatches VP8 bitstream size ({sw}x{sh})")
                        has_sub_raster = True

                    elif stag == b"VP8L":
                        if len(sdata) < 5 or sdata[0] != 0x2F:
                            raise ImageFetchSecurityError("Invalid or truncated VP8L in ANMF frame")
                        sb0, sb1, sb2, sb3 = sdata[1:5]
                        sw = 1 + (((sb1 & 0x3F) << 8) | sb0)
                        sh = 1 + (((sb3 & 0x0F) << 10) | (sb2 << 2) | ((sb1 & 0xC0) >> 6))
                        if sw != frame_w or sh != frame_h:
                            raise ImageFetchSecurityError(f"WebP ANMF frame size ({frame_w}x{frame_h}) mismatches VP8L bitstream size ({sw}x{sh})")
                        has_sub_raster = True

                    sub_idx += 8 + slen + (slen & 1)

                if not has_sub_raster:
                    raise ImageFetchSecurityError("ANMF frame has no valid color bitstream sub-chunk (missing image bitstream chunk)")
                raster_chunks_count += 1

            idx += 8 + chunk_len + (chunk_len & 1)

        if raster_chunks_count == 0:
            raise ImageFetchSecurityError("WebP contains no image raster chunks (missing image bitstream chunk)")
        if not is_animated and raster_chunks_count > 1:
            raise ImageFetchSecurityError("Ambiguous WebP: multiple raster chunks in non-animated container")

        w, h = max_observed_w, max_observed_h
        ext = ".webp"

    else:
        raise ImageFetchSecurityError("Downloaded payload does not match a valid recognized image signature (PNG, JPEG, GIF, WebP)")

    if w <= 0 or h <= 0:
        raise ImageFetchSecurityError(f"Image dimensions ({w}x{h}) must be strictly positive")

    if w > MAX_IMAGE_WIDTH or h > MAX_IMAGE_HEIGHT or (w * h) > MAX_IMAGE_PIXELS:
        raise ImageFetchSecurityError(
            f"Image dimensions ({w}x{h}, {w * h} pixels) exceed permitted limits (max {MAX_IMAGE_WIDTH}x{MAX_IMAGE_HEIGHT}, {MAX_IMAGE_PIXELS} pixels)"
        )

    return ext, w, h


def get_private_cache_dir(custom_dir: Optional[Path] = None) -> Path:
    """Initialize or verify a mode 0700 private user cache directory under XDG_CACHE_HOME.
    
    Creates the directory with umask 077 so it is created private immediately without window of exposure.
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

    if cache_dir.is_symlink():
        raise ImageFetchSecurityError(f"Insecure cache directory: path is a symbolic link: {cache_dir}")

    old_umask = os.umask(0o077)
    try:
        cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    finally:
        os.umask(old_umask)

    if cache_dir.is_symlink():
        raise ImageFetchSecurityError(f"Insecure cache directory: path is a symbolic link: {cache_dir}")

    try:
        st = cache_dir.stat()
    except OSError as e:
        raise ImageFetchSecurityError(f"Failed to inspect cache directory: {e}") from e

    if st.st_uid != os.getuid():
        raise ImageFetchSecurityError(f"Insecure cache directory ownership: UID {st.st_uid}, expected {os.getuid()}")

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

        # 1. Resolve and validate IP address with bounded DNS timeout
        step_dns_timeout = min(socket_timeout, remaining_time)
        pinned_ip = resolve_and_validate_host(hostname, port, timeout=step_dns_timeout)

        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            raise ImageFetchSecurityError(f"Operation exceeded overall deadline of {total_timeout}s after DNS resolution")

        step_timeout = min(socket_timeout, remaining_time)

        # 2. Establish connection with timeout bounded by remaining deadline
        raw_sock = socket.create_connection((pinned_ip, port), timeout=step_timeout)
        tls_sock = None
        conn = None
        watchdog_sock = None
        watchdog = None

        try:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise ImageFetchSecurityError(f"Operation exceeded overall deadline of {total_timeout}s after TCP connect")

            # Duplicate file descriptor for single-owner watchdog shutdown; clean up dup_fd immediately if constructor fails
            raw_sock_fd = -1
            try:
                raw_sock_fd = raw_sock.fileno()
            except Exception:
                raw_sock_fd = -1

            if isinstance(raw_sock_fd, int) and raw_sock_fd >= 0:
                dup_fd = -1
                try:
                    dup_fd = os.dup(raw_sock_fd)
                    watchdog_sock = socket.socket(fileno=dup_fd)
                except (OSError, TypeError) as e:
                    if dup_fd >= 0:
                        try:
                            os.close(dup_fd)
                        except OSError:
                            pass
                    raw_sock.close()
                    raise ImageFetchSecurityError(f"Failed to create watchdog socket descriptor: {e}") from e
            else:
                watchdog_sock = None

            is_timeout_aborted = threading.Event()

            def _watchdog_abort():
                is_timeout_aborted.set()
                if watchdog_sock is not None:
                    try:
                        watchdog_sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass

            watchdog_interval = max(0.001, deadline - time.monotonic())
            watchdog = threading.Timer(watchdog_interval, _watchdog_abort)
            watchdog.daemon = True
            watchdog.start()

            try:
                # Update socket timeout for TLS handshake
                raw_sock.settimeout(min(socket_timeout, remaining_time))

                # TLS handshake with SNI preservation
                ssl_ctx = ssl.create_default_context()
                tls_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=hostname)

                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0 or is_timeout_aborted.is_set():
                    raise ImageFetchSecurityError(f"Operation exceeded overall deadline of {total_timeout}s during TLS handshake")

                conn = http.client.HTTPSConnection(hostname, port=port, timeout=min(socket_timeout, remaining_time))
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
                    continue

                if resp.status != 200:
                    raise ImageFetchSecurityError(f"Remote server returned HTTP {resp.status}: {resp.reason}")

                ctype = resp.getheader("Content-Type", "")
                if not ctype or not ctype.lower().startswith("image/"):
                    raise ImageFetchSecurityError(f"Rejected non-image Content-Type '{ctype}': expected image/*")

                # Read response with byte limit bounding
                data = bytearray()
                while True:
                    remaining_read_time = deadline - time.monotonic()
                    if remaining_read_time <= 0 or is_timeout_aborted.is_set():
                        raise ImageFetchSecurityError(f"Operation exceeded overall deadline of {total_timeout}s during transfer")

                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > max_bytes:
                        raise ImageFetchSecurityError(f"Response exceeded maximum size limit of {max_bytes} bytes")

                if is_timeout_aborted.is_set() or time.monotonic() > deadline:
                    raise ImageFetchSecurityError(f"Operation exceeded overall deadline of {total_timeout}s during transfer")

                break
            except Exception as e:
                if is_timeout_aborted.is_set() or time.monotonic() >= deadline:
                    raise ImageFetchSecurityError(f"Operation exceeded overall deadline of {total_timeout}s during transfer") from e
                raise
            finally:
                if watchdog is not None:
                    watchdog.cancel()
                    if hasattr(watchdog, "join"):
                        watchdog.join()
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            if tls_sock is not None:
                try:
                    tls_sock.close()
                except Exception:
                    pass
            try:
                raw_sock.close()
            except Exception:
                pass
            if watchdog_sock is not None:
                try:
                    watchdog_sock.close()
                except Exception:
                    pass
    else:
        raise ImageFetchSecurityError(f"Exceeded maximum redirect limit of {max_redirects} hops")

    # 4. Inspect image headers, chunks, and frame descriptors to validate format and bounded dimensions
    ext, width, height = parse_and_validate_image_format_and_dimensions(bytes(data))

    # 5. Cache into private directory with content-addressed SHA-256 hash using safe mkstemp
    target_cache_dir = get_private_cache_dir(cache_dir)
    sha256_hash = hashlib.sha256(data).hexdigest()
    dest_file = target_cache_dir / f"{sha256_hash}{ext}"

    if dest_file.is_symlink():
        dest_file.unlink()

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
