# Phala Testnet snapshot size verification — 2026-09-30

This is a local storage measurement for the unsigned, public-preview-only
snapshot selected in `deploy/phala/snapshot.lock.json`. It is not a guest boot,
chain-state validation, attestation result, or private-mode approval.

The selected lock has SHA-256
`a05312fe3fa447e33c48c94c512e7e6e3fcade103f9204a27516a1fdcdcc70ac`.
The dated archive URL in that lock returned HTTP 200 with the same effective URL.
The full download was exactly **11,137,971,554 bytes** and its independently
computed SHA-256 matched the locked value
`e1702bb220a337f94496e1f65b683b63f22334fdc500c5421dd118e593358636`.

In the managed Linux x86_64 container, CPython 3.13.5 loaded the lock's
`zstandard` 0.25.0 wheel after its SHA-256 matched
`8e735494da3db08694d26480f1493ad2cf86e99bdd53e8e9771b2752a5c0246a`.
The scanner passed the decompressed stream to Python `tarfile` in streaming
`r|` mode. It inspected every member and read each regular-file body in memory;
it did not extract the database. It then drained the decompressor to EOF.
The compressed archive checksum was computed separately in the managed native
Linux container.

| Measured item | Result |
| --- | ---: |
| Compressed archive | 11,137,971,554 bytes (10.373 GiB) |
| Declared regular-file bodies | 13,474,627,364 bytes (12.549 GiB) |
| Regular-file bytes actually read | 13,474,627,364 bytes |
| Members | 3,710 regular files; one directory |
| Unsafe/out-of-prefix paths, normalized duplicate paths, links, special files, sparse entries | Zero |
| Fresh-import archive plus extracted-file floor | **24,612,598,918 bytes (22.922 GiB)** |

The current importer keeps the compressed archive and staging tree together on
`zebra_public_testnet` until it atomically publishes the imported state, then
deletes the archive. Thus the sum above is the minimum simultaneous file-body
space needed for a successful first import. Directory and filesystem metadata,
allocation rounding, ext4 journal/reserved space, and Zebra catch-up or
compaction need additional capacity. The measured floor alone cannot establish
that a quoted 80 GB volume is sufficient throughout synchronization. The
selected snapshot is unsigned; its publisher's hash checks byte consistency,
not independent correctness of the Testnet state.

The downloaded archive was removed after measurement. No Phala resource was
created, no snapshot was extracted, and no real TDX boot was exercised.
