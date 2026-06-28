#ifndef HMAC_ISAL_H
#define HMAC_ISAL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HMAC-SHA256 constants */
#define HMAC_ISAL_BLOCK_SIZE   64
#define HMAC_ISAL_DIGEST_SIZE  32
#define HMAC_ISAL_MAX_BATCH    8

/*
 * Opaque key cache that stores the intermediate SHA256 states
 * after processing the ipad and opad blocks.
 *
 * When the same key is used for multiple HMAC computations,
 * this avoids recomputing the two SHA256 block compressions
 * for the key expansion each time.
 */
typedef struct hmac_isal_key_cache hmac_isal_key_cache_t;

/*
 * Create a key cache from a key.
 *
 * If key_len > HMAC_ISAL_BLOCK_SIZE, the key is hashed down first
 * (per RFC 2104). The cache stores the SHA256 contexts after
 * processing (K' XOR ipad) and (K' XOR opad).
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
 * If cache is non-NULL and corresponds to the same key, the cached
 * ipad/opad intermediate states are reused to save two SHA256 block
 * compressions.  The caller is responsible for ensuring cache matches key.
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
 * num_packets must be in [1, HMAC_ISAL_MAX_BATCH].
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
 * Constant-time HMAC verification.
 *
 * Returns 0 if mac matches the computed HMAC(key, msg), nonzero otherwise.
 * If cache is non-NULL, key is obtained from cache and key_len is ignored.
 */
int hmac_isal_verify_single(const uint8_t *key, size_t key_len,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t mac[HMAC_ISAL_DIGEST_SIZE],
                            const hmac_isal_key_cache_t *cache);

#ifdef __cplusplus
}
#endif

#endif /* HMAC_ISAL_H */
