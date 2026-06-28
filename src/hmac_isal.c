#include "hmac_isal.h"

#include <string.h>
#include <stdlib.h>

#include <sha256_ni.h>
#include <sha256_mb.h>

/* ---------- internal helpers ---------- */

/*
 * Pre-process a key for HMAC and XOR it with the given pad byte.
 *
 * If key_len <= 64, k' = key zero-padded to 64 bytes.
 * If key_len > 64,  k' = SHA256(key) zero-padded to 64 bytes.
 *
 * The result is k' XOR pad (where pad is 0x36 for ipad, 0x5C for opad).
 */
static void xor_key_pad(const uint8_t *key, size_t key_len,
                        uint8_t out[64], uint8_t pad)
{
    uint8_t k_prime[64];

    if (key_len > HMAC_ISAL_BLOCK_SIZE) {
        SHA256_CTX ctx;
        sha256_ni_init(&ctx);
        sha256_ni_update(&ctx, key, key_len);
        sha256_ni_final(k_prime, &ctx);
        memset(k_prime + HMAC_ISAL_DIGEST_SIZE, 0,
               HMAC_ISAL_BLOCK_SIZE - HMAC_ISAL_DIGEST_SIZE);
    } else {
        memcpy(k_prime, key, key_len);
        memset(k_prime + key_len, 0, HMAC_ISAL_BLOCK_SIZE - key_len);
    }

    for (int i = 0; i < HMAC_ISAL_BLOCK_SIZE; i++)
        out[i] = k_prime[i] ^ pad;
}

/*
 * Compute SHA256(data, len) and write 32-byte digest into out.
 */
static void sha256_compute(const uint8_t *data, size_t len,
                           uint8_t out[HMAC_ISAL_DIGEST_SIZE])
{
    SHA256_CTX ctx;
    sha256_ni_init(&ctx);
    sha256_ni_update(&ctx, data, len);
    sha256_ni_final(out, &ctx);
}

/* ---------- key cache ---------- */

struct hmac_isal_key_cache {
    /* SHA256 context saved right after processing the full ipad block */
    SHA256_CTX ipad_ctx;
    /* SHA256 context saved right after processing the full opad block */
    SHA256_CTX opad_ctx;
    /* Pre-computed ipad bytes (used as fallback in multi-buffer path) */
    uint8_t ipad[HMAC_ISAL_BLOCK_SIZE];
    /* Pre-computed opad bytes (used as fallback in multi-buffer path) */
    uint8_t opad[HMAC_ISAL_BLOCK_SIZE];
};

hmac_isal_key_cache_t *
hmac_isal_key_cache_create(const uint8_t *key, size_t key_len)
{
    hmac_isal_key_cache_t *cache = malloc(sizeof(*cache));
    if (!cache)
        return NULL;

    xor_key_pad(key, key_len, cache->ipad, 0x36);
    xor_key_pad(key, key_len, cache->opad, 0x5C);

    /* Save the SHA256 state right after processing the ipad block.
     * Subsequent HMAC calls can clone this context, feed the message,
     * and finalize — skipping the per-call ipad block compression. */
    sha256_ni_init(&cache->ipad_ctx);
    sha256_ni_update(&cache->ipad_ctx, cache->ipad, HMAC_ISAL_BLOCK_SIZE);

    sha256_ni_init(&cache->opad_ctx);
    sha256_ni_update(&cache->opad_ctx, cache->opad, HMAC_ISAL_BLOCK_SIZE);

    return cache;
}

void
hmac_isal_key_cache_destroy(hmac_isal_key_cache_t *cache)
{
    free(cache);
}

/* ---------- single-packet HMAC ---------- */

void
hmac_isal_single(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[HMAC_ISAL_DIGEST_SIZE],
                 const hmac_isal_key_cache_t *cache)
{
    uint8_t inner[HMAC_ISAL_DIGEST_SIZE];

    if (cache) {
        /* ----- fast path: reuse cached ipad/opad state ----- */
        SHA256_CTX ctx;

        /* inner = SHA256(ipad || msg) */
        memcpy(&ctx, &cache->ipad_ctx, sizeof(ctx));
        sha256_ni_update(&ctx, msg, msg_len);
        sha256_ni_final(inner, &ctx);

        /* mac = SHA256(opad || inner) */
        memcpy(&ctx, &cache->opad_ctx, sizeof(ctx));
        sha256_ni_update(&ctx, inner, sizeof(inner));
        sha256_ni_final(mac, &ctx);
    } else {
        /* ----- slow path: full key expansion every time ----- */
        uint8_t ipad[HMAC_ISAL_BLOCK_SIZE];
        uint8_t opad[HMAC_ISAL_BLOCK_SIZE];
        SHA256_CTX ctx;

        xor_key_pad(key, key_len, ipad, 0x36);
        xor_key_pad(key, key_len, opad, 0x5C);

        /* inner = SHA256(ipad || msg) */
        sha256_ni_init(&ctx);
        sha256_ni_update(&ctx, ipad, sizeof(ipad));
        sha256_ni_update(&ctx, msg, msg_len);
        sha256_ni_final(inner, &ctx);

        /* mac = SHA256(opad || inner) */
        sha256_ni_init(&ctx);
        sha256_ni_update(&ctx, opad, sizeof(opad));
        sha256_ni_update(&ctx, inner, sizeof(inner));
        sha256_ni_final(mac, &ctx);
    }
}

/* ---------- multi-packet HMAC (any number, batched internally in groups of 8) ---------- */

/*
 * Submit num_packets jobs to a multi-buffer SHA256 context.
 *
 * Two-phase submission:
 *   phase 0 – feed the first block (the padding block from HMAC key expansion)
 *   phase 1 – feed the remaining data    (message for inner, inner-hash for outer)
 *
 * This is a helper shared by the inner-hash and outer-hash phases of
 * multi-packet HMAC.
 */
static void mb_submit(SHA256_MB_CTX *mb,
                      const uint8_t *first_block,
                      const uint8_t *const *data, const size_t *lens,
                      int n)
{
    for (int i = 0; i < n; i++) {
        sha256_mb_update(mb, first_block, HMAC_ISAL_BLOCK_SIZE, i);
        if (lens[i] > 0)
            sha256_mb_update(mb, data[i], lens[i], i);
    }
}

int
hmac_isal_multi(const uint8_t *key, size_t key_len,
                const uint8_t *msgs[], const size_t msg_lens[],
                uint8_t *macs[], int num_packets,
                const hmac_isal_key_cache_t *cache)
{
    if (num_packets < 1)
        return 0;

    uint8_t ipad[HMAC_ISAL_BLOCK_SIZE];
    uint8_t opad[HMAC_ISAL_BLOCK_SIZE];
    const uint8_t *ipad_ptr;
    const uint8_t *opad_ptr;

    if (cache) {
        ipad_ptr = cache->ipad;
        opad_ptr = cache->opad;
    } else {
        xor_key_pad(key, key_len, ipad, 0x36);
        xor_key_pad(key, key_len, opad, 0x5C);
        ipad_ptr = ipad;
        opad_ptr = opad;
    }

    int processed = 0;
    while (processed < num_packets) {
        int batch = num_packets - processed;
        if (batch > HMAC_ISAL_MAX_BATCH)
            batch = HMAC_ISAL_MAX_BATCH;

        const uint8_t *batch_msgs[HMAC_ISAL_MAX_BATCH];
        size_t        batch_lens[HMAC_ISAL_MAX_BATCH];
        uint8_t      *batch_macs[HMAC_ISAL_MAX_BATCH];

        for (int i = 0; i < batch; i++) {
            batch_msgs[i] = msgs[processed + i];
            batch_lens[i] = msg_lens[processed + i];
            batch_macs[i] = macs[processed + i];
        }

        /* ---- phase 1: compute inner hashes in parallel ---- */
        uint8_t inner[HMAC_ISAL_MAX_BATCH][HMAC_ISAL_DIGEST_SIZE];

        {
            SHA256_MB_CTX mb;
            sha256_mb_init(&mb);
            mb_submit(&mb, ipad_ptr, batch_msgs, batch_lens, batch);
            for (int i = 0; i < batch; i++)
                sha256_mb_final(inner[i], &mb, i);
        }

        /* ---- phase 2: compute outer hashes in parallel ---- */
        {
            SHA256_MB_CTX mb;
            const uint8_t *inner_ptrs[HMAC_ISAL_MAX_BATCH];
            size_t        inner_lens[HMAC_ISAL_MAX_BATCH];

            sha256_mb_init(&mb);
            for (int i = 0; i < batch; i++) {
                inner_ptrs[i] = inner[i];
                inner_lens[i] = HMAC_ISAL_DIGEST_SIZE;
            }
            mb_submit(&mb, opad_ptr, inner_ptrs, inner_lens, batch);
            for (int i = 0; i < batch; i++)
                sha256_mb_final(batch_macs[i], &mb, i);
        }

        processed += batch;
    }

    return num_packets;
}

/* ---------- constant-time verification ---------- */

static int ct_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    int diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (int)a[i] ^ (int)b[i];
    return diff;
}

int
hmac_isal_verify_single(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t mac[HMAC_ISAL_DIGEST_SIZE],
                        const hmac_isal_key_cache_t *cache)
{
    uint8_t computed[HMAC_ISAL_DIGEST_SIZE];
    hmac_isal_single(key, key_len, msg, msg_len, computed, cache);
    return ct_compare(computed, mac, HMAC_ISAL_DIGEST_SIZE);
}
