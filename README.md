# hmac-isal

SIMD-accelerated HMAC-SHA256 with key caching, built on Intel(R) ISA-L_crypto.

## Overview

This library provides high-performance HMAC-SHA256 computation using the
SIMD-optimised SHA256 implementations in the [Intel ISA-L_crypto][isa-l-crypto]
library.  Two SHA256 backends are used:

| Backend    | Description                                   | Used for                        |
|------------|-----------------------------------------------|---------------------------------|
| `sha256_ni` | Single-buffer SHA256 (SHA-NI instructions)   | Per-packet HMAC                 |
| `sha256_mb` | Multi-buffer SHA256 (up to 8 streams via SIMD) | Parallel multi-packet HMAC    |

## Key caching

HMAC-SHA256 expands the key into two 64-byte blocks before hashing the
message data:

    HMAC(K, m) = SHA256( (K' XOR opad) || SHA256( (K' XOR ipad) || m ) )

When the same key is used repeatedly, this library caches the two SHA256
intermediate states right after the ipad/opad blocks have been consumed.
Subsequent HMAC calls restore those states and skip two block compressions
per HMAC — a meaningful saving when processing many short messages with a
shared key.

## API

### Key cache

```c
hmac_isal_key_cache_t *hmac_isal_key_cache_create(const uint8_t *key,
                                                   size_t key_len);
void hmac_isal_key_cache_destroy(hmac_isal_key_cache_t *cache);
```

Create a cache object that stores the SHA256 context after processing the
ipad and opad blocks derived from `key`.  If `key_len > 64` the key is
hashed down first (per RFC 2104).

### Single-packet HMAC

```c
void hmac_isal_single(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t mac[32],
                      const hmac_isal_key_cache_t *cache);
```

Compute `HMAC(key, msg)`.  If `cache` is non-NULL, the cached ipad/opad
states are reused, saving two SHA256 block compressions.  The caller is
responsible for ensuring the cache matches the key.

### Multi-packet HMAC

```c
int hmac_isal_multi(const uint8_t *key, size_t key_len,
                    const uint8_t *msgs[], const size_t msg_lens[],
                    uint8_t *macs[], int num_packets,
                    const hmac_isal_key_cache_t *cache);
```

Compute HMAC for `num_packets` messages in a single call.  The inner
hashes are computed in parallel using the multi-buffer SHA256 engine; the
outer hashes are computed in parallel in a second pass.  Large batches
are internally split into groups of 8.

If `cache` is provided, the pre-computed ipad/opad bytes are used instead
of expanding the key on every call.

### Verification (constant-time)

```c
int hmac_isal_verify_single(const uint8_t *key, size_t key_len,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t mac[32],
                            const hmac_isal_key_cache_t *cache);
```

Returns 0 if `mac` matches, nonzero otherwise.  The comparison is
constant-time to resist timing side-channels.

## Building

### Prerequisites

- [Intel ISA-L_crypto][isa-l-crypto] (v2.x or later)
- A C99 compiler (gcc, clang)

### Build the library

```sh
make
```

If ISA-L_crypto is installed in a non-standard location:

```sh
make ISA_L_CRYPTO_PATH=/path/to/isa-l_crypto
```

### Run tests

```sh
make test
```

The test suite exercises every test vector through both the cached and
non-cached code paths and verifies constant-time comparison logic.

## Test vectors

The test suite covers:

- RFC 4231 Test Cases 2–7 (standard HMAC-SHA256 vectors)
- Key longer than the SHA256 block size (64 bytes)
- Empty message
- 1-byte key and exactly-64-byte key boundaries
- Multi-packet parallel HMAC (3 packets in one call)
- Verify-reject of a forged MAC

## License

MIT

[isa-l-crypto]: https://github.com/intel/isa-l_crypto
