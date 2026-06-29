# hmac-isal

SIMD-accelerated HMAC-SHA256 with key caching, built on Intel ISA-L crypto.
Falls back to OpenSSL EVP on non-x86 architectures (arm64, RISC-V, etc.) for
portable correctness across all platforms.

## Overview

HMAC-SHA256 expands the key into two 64-byte blocks before hashing the
message data:

    HMAC(K, m) = SHA256( (K' XOR opad) || SHA256( (K' XOR ipad) || m ) )

When the same key is used repeatedly, the **key cache** stores the
pre-computed ipad and opad byte arrays, saving the per-call key expansion.

### Backend dispatch

| Architecture | Backend                                            |
|-------------|----------------------------------------------------|
| x86_64      | Intel ISA-L multi-buffer SHA256 (SIMD accelerated) |
| arm64       | OpenSSL EVP SHA256 (portable fallback)             |
| other       | OpenSSL EVP SHA256 (portable fallback)             |

On x86_64, the ISA-L backend uses the multi-buffer context manager API
(`isal_sha256_ctx_mgr_*`) which auto-dispatches to the widest SIMD lane
width available:

| ISA        | Lanes | Typical hardware          |
|------------|-------|---------------------------|
| SSE4       | 4     | Older x86_64 CPUs         |
| AVX2       | 8     | Haswell and later         |
| AVX-512    | 16    | Skylake-SP and later      |

## API

### Key cache

```c
hmac_isal_key_cache_t *hmac_isal_key_cache_create(const uint8_t *key,
                                                   size_t key_len);
void hmac_isal_key_cache_destroy(hmac_isal_key_cache_t *cache);
```

If `key_len > 64` the key is hashed down first (per RFC 2104).

### Single-packet HMAC

```c
void hmac_isal_single(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t mac[32],
                      const hmac_isal_key_cache_t *cache);
```

Compute `HMAC(key, msg)`.  Pass `cache` to reuse pre-computed ipad/opad.

### Multi-packet HMAC

```c
int hmac_isal_multi(const uint8_t *key, size_t key_len,
                    const uint8_t *msgs[], const size_t msg_lens[],
                    uint8_t *macs[], int num_packets,
                    const hmac_isal_key_cache_t *cache);
```

Compute HMAC for `num_packets` messages in a single call.  Inner and outer
hashes are each processed in parallel through the multi-buffer engine.
Batches larger than 16 are split automatically.  Returns `num_packets` on
success.

### Verification (constant-time)

```c
int hmac_isal_verify_single(const uint8_t *key, size_t key_len,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t mac[32],
                            const hmac_isal_key_cache_t *cache);
```

Returns 0 if `mac` matches HMAC(key, msg), nonzero otherwise.

```c
uint64_t hmac_isal_verify_multi(const uint8_t *key, size_t key_len,
                                const uint8_t *msgs[], const size_t msg_lens[],
                                const uint8_t *macs[], int num_packets,
                                const hmac_isal_key_cache_t *cache);
```

Returns a **bitmask** where bit *i* (LSB = packet 0) is set when `macs[i]`
does **not** match `HMAC(key, msgs[i])`.  A return value of 0 means all
packets verified successfully.  The caller can inspect individual bits:

```c
uint64_t bad = hmac_isal_verify_multi(key, klen, msgs, lens, macs, n, NULL);
if (bad) {
    for (int i = 0; i < n; i++)
        if (bad & ((uint64_t)1 << i))
            handle_bad_packet(i);
}
```

All comparisons are constant-time.

## Building

### Prerequisites

- C99 compiler (gcc, clang)
- [Intel ISA-L_crypto][isa-l-crypto] — the Makefile defaults to `./isa-l_crypto_build/`,
  a local build of the ISA-L library.  Override with `ISA_L_CRYPTO_PATH`.
- OpenSSL (libcrypto) — for tests and non-x86 fallback.  Auto-detected
  via Homebrew on macOS.

### Build the library

```sh
make
```

Override ISA-L location if needed:

```sh
make ISA_L_CRYPTO_PATH=/path/to/isa-l_crypto
```

### Run tests

```sh
make test              # RFC 4231 vectors + multi-packet + large batch
make test-openssl      # above + OpenSSL cross-validation
```

The test suite covers:

- RFC 4231 Test Cases 2–7 (standard HMAC-SHA256 vectors)
- Keys longer than the block size (64 bytes), requiring hash-down
- Multi-packet HMAC (batches of 3, 17-packets spanning >1 internal batch)
- Key cache correctness on all paths
- `verify_single` — valid MAC accepted, forged MAC rejected
- `verify_multi` — valid MACs return 0, single forged MAC sets exactly the correct bit
- OpenSSL cross-validation — every RFC vector and multi-packet result
  compared against the reference `HMAC()` implementation

## License

MIT

[isa-l-crypto]: https://github.com/intel/isa-l_crypto
