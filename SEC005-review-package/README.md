# SEC-005 WebP Profile & Decode-Gate Review Package

**Baseline Commit:** `8968782f574c9d235d8f67ceb41c665c46483cd7`  
**Current Head:** Worktree head  
**Date:** 2026-09-20  

---

## 1. Summary of Changes

This review package contains the complete, dual-level hardened implementation of `SEC-005` safe remote image retrieval:
1. **Safe RIFF Boundary Primitive (`_iter_riff_chunks`):** Unified boundary-checked chunk iteration for both outer WebP and nested `ANMF` frame sub-chunks. Strictly prevents buffer overflows, out-of-bounds indexing, and missing padding byte errors.
2. **WebP Geometry & Layout Validation (`_validate_webp`):** Enforces canonical WebP layouts (Simple Lossy, Simple Lossless, Extended Static, Extended Animated), rejects ambiguous multi-raster containers, validates `ANMF` frame coordinates against canvas, and strictly reconciles frame dimensions with embedded `VP8 `/`VP8L` bitstreams.
3. **Level B Isolated Decode-Gate (`_validate_image_with_decoder`):** Complete decoding verification in a dedicated resource-bounded subprocess (CPU 5s, virtual memory 512 MiB, pixel ceiling 64 MP) using Pillow. Reconciles decoded dimensions with structural dimensions and fails closed (`IMAGE_DECODER_UNAVAILABLE`) if the backend is absent.
4. **Single-Owner Watchdog Lifecycle:** Watchdog timer uses an independent `os.dup()` socket and only performs `shutdown()`. Immediate fail-closed cleanup of `dup_fd` on constructor errors prevents descriptor leakage. Main thread performs deterministic `cancel()`, `join()`, and cleanup.
5. **Canonical Specification:** Published `docs/specs/sec005-webp-profile.md` detailing the supported WebP profile and dual-level acceptance formula.

---

## 2. Test Verification

- `tests/test_fetch_remote_image.py`: **52 tests passed, 0 failures, 0 errors** (100% OK).
- Full repository test suite: **137 tests passed, 0 failures, 0 errors** (100% OK).
