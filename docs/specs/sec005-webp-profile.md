# SEC-005 Safe WebP Profile Specification

**Specification Version:** 1.0.0  
**Target Platform:** Omarchy Quattro / Quickshell Plugin Ecosystem  
**Owning Rule:** `SEC-005` (`image-unvalidated-remote-uri`)  
**Implementation Reference:** `tools/helpers/fetch_remote_image.py`  

---

## 1. Scope & Dual-Level Acceptance Contract

This specification establishes the canonical structural and decoding profile for WebP images ingested by Omarchy Quattro plugins and helpers under rule **`SEC-005`**.

To eliminate decompression stalls, memory exhaustion bombs, and decoder-discrepancy exploits, a remote image is accepted and published into the private user cache **only** if it satisfies both levels of the dual-gate acceptance contract:

```text
ACCEPTED =
    destination_network_policy_ok
    AND encoded_byte_limit_ok (<= 5 MiB)
    AND structural_profile_ok (Level A)
    AND geometry_invariants_ok (Level A)
    AND complete_decode_ok (Level B)
    AND decoded_geometry_matches (Level B)
    AND resource_budgets_ok (Level B)
    AND private_cache_publish_ok
```

---

## 2. Level A: Structural & Container Profile

### 2.1 RIFF Container Invariants
1. **Container Header:** Must begin with literal ASCII FourCC `b"RIFF"`, followed by a 32-bit little-endian container payload length (`riff_size`), followed by literal FourCC `b"WEBP"`.
2. **Strict Size Integrity:** The total stream length must equal exactly `8 + riff_size`. Truncated streams and files with trailing unparsed data are rejected as ambiguous containers.
3. **Chunk Traversal Primitive:** Every RIFF chunk must be parsed via strict boundary-checked iteration within `[12, len(data))`:
   - Each chunk header declares FourCC and 32-bit little-endian length `chunk_len`.
   - The payload range `[offset + 8, offset + 8 + chunk_len)` must not exceed container boundary.
   - If `chunk_len` is odd, a 0x00 padding byte is accounted for at word boundaries.

### 2.2 Supported WebP Layouts
A WebP file must strictly conform to one of the following four canonical layouts:

| Layout Category | Top-Level Chunks | Layout Constraints & Rules |
| :--- | :--- | :--- |
| **Simple Lossy** | Exactly one `VP8 ` chunk | No `VP8X`, no `ANIM`, no `ANMF`. Canvas dimensions equal the uncompressed VP8 keyframe dimensions. |
| **Simple Lossless** | Exactly one `VP8L` chunk | No `VP8X`, no `ANIM`, no `ANMF`. Canvas dimensions equal the VP8L header dimensions (version must be 0). |
| **Extended Static** | Initial `VP8X`, followed by optional metadata, and exactly one `VP8 ` or `VP8L` raster | `VP8X` must be the first chunk at offset 12. Animation flag must be 0. Raster dimensions must match `VP8X` canvas dimensions. |
| **Extended Animated** | Initial `VP8X`, followed by `ANIM`, followed by one or more `ANMF` frame chunks | `VP8X` animation flag must be set. No top-level `VP8 ` or `VP8L` chunks permitted outside `ANMF` frames. |

*Rejection of Ambiguous Containers:* Non-animated containers with multiple top-level raster chunks (e.g. `VP8 ` followed by `VP8L`) are rejected.

### 2.3 Geometry & ANMF Frame Constraints
For extended and animated WebP containers:
1. **Canvas Caps:**
   - Canvas width $\le 4096$ pixels.
   - Canvas height $\le 4096$ pixels.
   - Total canvas area ($W \times H$) $\le 16,777,216$ pixels (16 MP).
2. **ANMF Frame Coordinates:**
   - From 16-byte ANMF header:
     * $X = 2 \times \text{uint24\_le}(\text{header}[0:3])$
     * $Y = 2 \times \text{uint24\_le}(\text{header}[3:6])$
     * $\text{Frame Width} = 1 + \text{uint24\_le}(\text{header}[6:9])$
     * $\text{Frame Height} = 1 + \text{uint24\_le}(\text{header}[9:12])$
   - Invariants:
     * $0 \le X < \text{Canvas Width}$
     * $0 \le Y < \text{Canvas Height}$
     * $X + \text{Frame Width} \le \text{Canvas Width}$
     * $Y + \text{Frame Height} \le \text{Canvas Height}$
     * $\text{Frame Width} \le 4096$, $\text{Frame Height} \le 4096$.
3. **Sub-chunk Integrity & Color Bitstream Matching:**
   - Sub-chunks inside an `ANMF` frame payload (offset 16 to frame end) must be iterated with strict boundary checks.
   - Every `ANMF` frame must contain **exactly one** color bitstream sub-chunk (`VP8 ` or `VP8L`).
   - Frames containing only `ALPH` (transparency) without a color bitstream are rejected.
   - The embedded `VP8 ` or `VP8L` bitstream must declare dimensions identical to the enclosing `ANMF` frame rectangle ($\text{Bitstream Width} == \text{Frame Width}$ and $\text{Bitstream Height} == \text{Frame Height}$).

---

## 3. Level B: Isolated Decode-Gate

Even if a payload satisfies Level A structural invariants, it must be verified by complete decoding before publication into the cache.

### 3.1 Decoder Backend Dependency
- **Canonical Engine:** `Pillow` (with verified `features.check("webp") == True`).
- **Dependency Contract:** Standalone CLI execution does not waive decoder dependencies. If the decoder backend is unavailable, the fetch helper fails closed with:
  ```text
  IMAGE_DECODER_UNAVAILABLE: Pillow with WebP codec support is required for decode-gate
  ```

### 3.2 Worker Process Isolation & Resource Ceilings
To protect the calling desktop shell process from native C library crashes, infinite decoding loops, or allocation spikes, decoding executes in an isolated child process (`fetch_remote_image.py --worker-decode`):
1. **CPU Limit:** Bounded by `resource.setrlimit(RLIMIT_CPU, (5, 5))` (max 5 seconds).
2. **Memory Limit:** Bounded by `resource.setrlimit(RLIMIT_AS, (512 * 1024 * 1024, ...))` (512 MiB virtual address space).
3. **Pixel Processing Ceiling:** Maximum cumulative decoded pixels across all animated frames $\le 67,108,864$ (64 MP).
4. **Frame Count Ceiling:** Maximum number of animated frames $\le 128$.
5. **Dimension Reconciliation:** The decoded image dimensions returned by the backend must match the Level A verified canvas dimensions exactly.
6. **Frame Count Reconciliation:** The decoded frame count returned by the backend must match the Level A verified structural frame count exactly. For static formats (PNG, JPEG, static WebP, 1-frame GIF), `expected_frames = 1`. For animated WebP, `expected_frames` equals the exact count of verified `ANMF` chunks. (Note: Multi-frame Animated PNG (APNG) files decode to multiple frames and are safely rejected under the current static PNG profile; plugins requiring animation must use WebP or GIF).

---

## 4. Error Semantics & Diagnostic Classification

Violations trigger typed `ImageFetchSecurityError` exceptions and terminate with exit code `1`:
- **`Truncated WebP file`**: File bytes less than declared in RIFF header.
- **`Ambiguous WebP file`**: Trailing unparsed bytes after RIFF container.
- **`Truncated WebP chunk`**: Declared chunk length exceeds container bounds.
- **`WebP canvas dimensions exceed permitted limits`**: Dimensions $> 4096\times 4096$ or $> 16\text{ MP}$.
- **`WebP ANMF frame exceeds canvas bounds`**: Sub-frame rectangle overflows canvas.
- **`WebP ANMF frame size mismatches bitstream size`**: Discrepancy between container frame header and raster bitstream.
- **`IMAGE_DECODER_UNAVAILABLE`**: Missing Pillow or WebP codec support in runtime environment.
