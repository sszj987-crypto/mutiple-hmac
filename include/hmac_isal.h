#ifndef HMAC_ISAL_H
#define HMAC_ISAL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HMAC-SHA256 constants
 *
 * HMAC_ISAL_MAX_BATCH is set to 16 to match ISAL_SHA256_MAX_LANES,
 * supporting up to 16-wide SIMD on AVX-512 machines.
 * The ISA-L manager adapts automatically to the available ISA
 * (4 lanes on SSE4, 8 on AVX2, 16 on AVX-512).
 */
#define HMAC_ISAL_BLOCK_SIZE   64
#define HMAC_ISAL_DIGEST_SIZE  32
#define HMAC_ISAL_MAX_BATCH    16

/*
 * Opaque key cache that stores the pre-computed ipad and opad bytes.
 *
 * When the same key is used for multiple HMAC computations,
 * this avoids re-expanding the key on every call.
 */
typedef struct hmac_isal_key_cache hmac_isal_key_cache_t;

/*
 * Create a key cache from a key.
 *
 * If key_len > HMAC_ISAL_BLOCK_SIZE, the key is hashed down first
 * (per RFC 2104). The cache stores the resulting (K' XOR ipad) and
 * (K' XOR opad) byte arrays.
 *
 * Returns NULL on allocation failure.
 */
hmac_isal_key_cache_t *hmac_isal_key_cache_create(const uint8_t *key,
                                                   size_t key_len);

/* Destroy a key cache previously created by hmac_isal_key_cache_create. */
void hmac_isal_key_cache_destroy(hmac_isal_key_cache_t *cache);

/*
 * Single-packet HMAC-SHA256.
 *
 * Computes HMAC(key, msg) and writes the 32-byte result into mac.
 *
 * If cache is non-NULL, the pre-computed ipad/opad bytes are reused
 * to avoid re-expanding the key on every call.
 */
void hmac_isal_single(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t mac[HMAC_ISAL_DIGEST_SIZE],
                      const hmac_isal_key_cache_t *cache);

/*
 * Multi-packet HMAC-SHA256.
 *
 * Computes HMAC(key, msgs[i]) for i in [0, num_packets) using the
 * multi-buffer SHA256 engine, which processes up to 8 hashes in
 * parallel via SIMD.  Each macs[i] must point to a
 * HMAC_ISAL_DIGEST_SIZE-byte buffer.
 *
 * num_packets may be any positive integer; batches larger than 16 are
 * split automatically under the hood.
 *
 * Returns the number of packets processed (num_packets on success).
 *
 * If cache is non-NULL, the pre-computed ipad/opad bytes saved in the
 * cache are used; otherwise the key is expanded on every call.
 */
int hmac_isal_multi(const uint8_t *key, size_t key_len,
                    const uint8_t *msgs[], const size_t msg_lens[],
                    uint8_t *macs[], int num_packets,
                    const hmac_isal_key_cache_t *cache);

/*
 * Constant-time single-packet HMAC verification.
 *
 * Returns 0 if mac matches the computed HMAC(key, msg), nonzero otherwise.
 */
int hmac_isal_verify_single(const uint8_t *key, size_t key_len,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t mac[HMAC_ISAL_DIGEST_SIZE],
                            const hmac_isal_key_cache_t *cache);

/*
 * Constant-time multi-packet HMAC verification (bitmask result).
 *
 * Returns a bitmask where bit i (LSB = packet 0) is set when
 * macs[i] does NOT match HMAC(key, msgs[i]).  A return value of 0
 * means all packets verified successfully.
 *
 * The caller can inspect individual bits to decide how to handle
 * each packet, e.g.:
 *
 *   uint64_t bad = hmac_isal_verify_multi(key, klen, msgs, lens, macs, n, NULL);
 *   if (bad) {
 *       for (int i = 0; i < n; i++)
 *           if (bad & ((uint64_t)1 << i))
 *               handle_bad_packet(i);
 *   }
 *
 * num_packets may be any positive integer; batches larger than 16
 * are split automatically under the hood.  Only the bits corresponding
 * to actual packets are significant.
 */
uint64_t hmac_isal_verify_multi(const uint8_t *key, size_t key_len,
                                const uint8_t *msgs[], const size_t msg_lens[],
                                const uint8_t *macs[], int num_packets,
                                const hmac_isal_key_cache_t *cache);

#ifdef __cplusplus
}
#endif

#endif /* HMAC_ISAL_H */
