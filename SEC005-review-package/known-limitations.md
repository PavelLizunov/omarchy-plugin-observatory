# Known Limitations & Explicit Boundary Scoping

1. **Decoder Dependency:** Level B decode verification requires `Pillow` with WebP support (`features.check("webp") == True`). In environments lacking Pillow, the helper fails closed with `IMAGE_DECODER_UNAVAILABLE`.
2. **Subprocess Overhead:** Level B verification executes in a separate Python process to isolate native C library allocations. While this adds ~30–50 ms per fresh image download, images are content-addressed and cached in mode `0700` private user storage, so each image is verified and decoded only once upon initial fetch.
3. **Strict WebP Profile:** WebP files with non-standard trailing bytes after the RIFF container or ambiguous combinations of multiple top-level rasters are deliberately rejected.
4. **DNS Cancellation Boundary:** DNS resolution wait is bounded by a daemon thread timeout. The calling thread aborts on time, while the OS `getaddrinfo` syscall completes asynchronously in the background.
5. **Multi-Frame APNG Safe Rejection:** Multi-frame Animated PNG (APNG) files are safely rejected under the current static PNG profile (`expected_frames = 1` vs `dec_frames > 1`). This is an intentional safe-fail compatibility boundary; plugins requiring multi-frame animations should use WebP or GIF.
