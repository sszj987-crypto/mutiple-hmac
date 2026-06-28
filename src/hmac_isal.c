/*
 *  hmac_isal.c — SIMD-accelerated HMAC-SHA256 using Intel ISA-L crypto
 *
 *  Both single-packet and multi-packet HMAC are built on the ISA-L
 *  multi-buffer SHA256 context-manager API (isal_sha256_ctx_mgr_*),
 *  which auto-dispatches to SSE4 (4 lanes), AVX2 (8 lanes), or
 *  AVX-512 (16 lanes) depending on the CPU.
 *
 *  Key caching stores the pre-computed ipad/opad byte arrays so the
 *  key-expansion step (RFC 2104) is not repeated when the same key
 *  is used across many messages.
 *
 *  SPDX-License-Identifier: MIT
 */

#include "hmac_isal.h"

#include <string.h>
#include <stdlib.h>

#include <isa-l_crypto/sha256_mb.h>
#include <isa-l_crypto/multi_buffer.h>

/* Alignment required by ISAL_SHA256_HASH_CTX (16-byte minimum for SIMD). */
#define ALIGNED16 __attribute__((aligned(16)))

/* ---------- internal helpers ---------- */

/*
 * Pre-process a key for HMAC and XOR it with the given pad byte.
 *
 * If key_len <= 64, k' = key zero-padded to 64 bytes.
 * If key_len > 64,  k' = SHA256(key) zero-padded to 64 bytes.
 *
 * The result is k' XOR pad (where pad is 0x36 for ipad, 0x5C for opad).
 *
 * The hash path for over-long keys uses the same multi-buffer manager
 * so only one SHA256 implementation needs to be linked.
 */
static void xor_key_pad(const uint8_t *key, size_t key_len,
                        uint8_t out[HMAC_ISAL_BLOCK_SIZE], uint8_t pad)
{
    uint8_t k_prime[HMAC_ISAL_BLOCK_SIZE];

    if (key_len > HMAC_ISAL_BLOCK_SIZE) {
        /* RFC 2104: hash long keys down to HASH_SIZE bytes */
        ISAL_SHA256_HASH_CTX_MGR mgr;
        ISAL_SHA256_HASH_CTX     ctx ALIGNED16;
        ISAL_SHA256_HASH_CTX    *done = NULL;

        isal_sha256_ctx_mgr_init(&mgr);
        isal_hash_ctx_init(&ctx);
        isal_sha256_ctx_mgr_submit(&mgr, &ctx, &done,
                                   key, (uint32_t)key_len, ISAL_HASH_ENTIRE);
        while (!done)
            isal_sha256_ctx_mgr_flush(&mgr, &done);

        memcpy(k_prime, isal_hash_ctx_digest(&ctx), HMAC_ISAL_DIGEST_SIZE);
        memset(k_prime + HMAC_ISAL_DIGEST_SIZE, 0,
               HMAC_ISAL_BLOCK_SIZE - HMAC_ISAL_DIGEST_SIZE);
    } else {
        memcpy(k_prime, key, key_len);
        memset(k_prime + key_len, 0, HMAC_ISAL_BLOCK_SIZE - key_len);
    }

    for (int i = 0; i < HMAC_ISAL_BLOCK_SIZE; i++)
        out[i] = k_prime[i] ^ pad;
}

/* ---------- key cache ---------- */

struct hmac_isal_key_cache {
    uint8_t ipad[HMAC_ISAL_BLOCK_SIZE];
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

    return cache;
}

void
hmac_isal_key_cache_destroy(hmac_isal_key_cache_t *cache)
{
    free(cache);
}

/* ---------- single-packet HMAC ---------- */

/*
 * Compute a single SHA256 hash via the multi-buffer manager.
 *
 * The two-part message (first block, then remaining data) is submitted
 * as ISAL_HASH_FIRST + ISAL_HASH_LAST.  After the LAST submission the
 * job is flushed to completion.
 */
static void sha256_compute_two_part(const uint8_t *part1, size_t part1_len,
                                    const uint8_t *part2, size_t part2_len,
                                    uint8_t digest[HMAC_ISAL_DIGEST_SIZE])
{
    ISAL_SHA256_HASH_CTX_MGR mgr;
    ISAL_SHA256_HASH_CTX     ctx ALIGNED16;
    ISAL_SHA256_HASH_CTX    *done = NULL;

    isal_sha256_ctx_mgr_init(&mgr);
    isal_hash_ctx_init(&ctx);

    isal_sha256_ctx_mgr_submit(&mgr, &ctx, &done,
                               part1, (uint32_t)part1_len, ISAL_HASH_FIRST);
    isal_sha256_ctx_mgr_submit(&mgr, &ctx, &done,
                               part2, (uint32_t)part2_len, ISAL_HASH_LAST);

    while (!done)
        isal_sha256_ctx_mgr_flush(&mgr, &done);

    memcpy(digest, isal_hash_ctx_digest(&ctx), HMAC_ISAL_DIGEST_SIZE);
}

void
hmac_isal_single(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[HMAC_ISAL_DIGEST_SIZE],
                 const hmac_isal_key_cache_t *cache)
{
    uint8_t          ipad[HMAC_ISAL_BLOCK_SIZE];
    uint8_t          opad[HMAC_ISAL_BLOCK_SIZE];
    const uint8_t   *ipad_ptr;
    const uint8_t   *opad_ptr;
    uint8_t          inner[HMAC_ISAL_DIGEST_SIZE];

    if (cache) {
        ipad_ptr = cache->ipad;
        opad_ptr = cache->opad;
    } else {
        xor_key_pad(key, key_len, ipad, 0x36);
        xor_key_pad(key, key_len, opad, 0x5C);
        ipad_ptr = ipad;
        opad_ptr = opad;
    }

    /* inner = SHA256(ipad || msg) */
    sha256_compute_two_part(ipad_ptr, HMAC_ISAL_BLOCK_SIZE,
                            msg, msg_len, inner);

    /* mac = SHA256(opad || inner) */
    sha256_compute_two_part(opad_ptr, HMAC_ISAL_BLOCK_SIZE,
                            inner, HMAC_ISAL_DIGEST_SIZE, mac);
}

/* ---------- multi-packet HMAC ---------- */

/*
 * Process up to @n packets of a single HMAC phase (inner or outer)
 * in parallel through the ISA-L multi-buffer manager, collecting
 * the resulting digests into @digests.
 *
 * Each context goes through FIRST (the 64-byte ipad/opad block)
 * then LAST (the variable-length message or 32-byte inner hash).
 * Because the manager may return completed jobs out of order,
 * each context's user_data field holds the packet index.
 */
static void hmac_isal_multi_phase(
    ISAL_SHA256_HASH_CTX_MGR       *mgr,
    ISAL_SHA256_HASH_CTX            ctxs[],
    const uint8_t                  *first_block,
    const uint8_t *const           *data,
    const uint32_t                 *data_lens,
    uint8_t                         digests[][HMAC_ISAL_DIGEST_SIZE],
    int                             n)
{
    int              remaining = n;
    ISAL_SHA256_HASH_CTX *done = NULL;

    /* Initialise all contexts and tag each with its index. */
    for (int i = 0; i < n; i++) {
        isal_hash_ctx_init(&ctxs[i]);
        ctxs[i].user_data = (void *)(intptr_t)i;
    }

    /* Phase A: submit the first (padding) block for every packet. */
    for (int i = 0; i < n; i++)
        isal_sha256_ctx_mgr_submit(mgr, &ctxs[i], &done,
                                   first_block, HMAC_ISAL_BLOCK_SIZE,
                                   ISAL_HASH_FIRST);

    /* Phase B: submit the remaining data (LAST) for every packet.
     * The submit function may return a (possibly different) completed
     * job via @done; collect it immediately. */
    for (int i = 0; i < n && remaining > 0; i++) {
        isal_sha256_ctx_mgr_submit(mgr, &ctxs[i], &done,
                                   data[i], data_lens[i],
                                   ISAL_HASH_LAST);
        if (done) {
            int idx = (int)(intptr_t)done->user_data;
            memcpy(digests[idx], isal_hash_ctx_digest(done),
                   HMAC_ISAL_DIGEST_SIZE);
            remaining--;
            done = NULL;
        }
    }

    /* Phase C: flush any stragglers. */
    while (remaining > 0) {
        isal_sha256_ctx_mgr_flush(mgr, &done);
        if (done) {
            int idx = (int)(intptr_t)done->user_data;
            memcpy(digests[idx], isal_hash_ctx_digest(done),
                   HMAC_ISAL_DIGEST_SIZE);
            remaining--;
            done = NULL;
        }
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

    uint8_t         ipad[HMAC_ISAL_BLOCK_SIZE];
    uint8_t         opad[HMAC_ISAL_BLOCK_SIZE];
    const uint8_t  *ipad_ptr;
    const uint8_t  *opad_ptr;

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

        /* ---------- inner hashes ---------- */
        ISAL_SHA256_HASH_CTX inner_ctx[HMAC_ISAL_MAX_BATCH] ALIGNED16;
        uint8_t inner[HMAC_ISAL_MAX_BATCH][HMAC_ISAL_DIGEST_SIZE];
        ISAL_SHA256_HASH_CTX_MGR mgr;

        isal_sha256_ctx_mgr_init(&mgr);

        /* Build per-packet data arrays for the multi-buffer submit loop */
        const uint8_t *inner_data[HMAC_ISAL_MAX_BATCH];
        uint32_t       inner_lens[HMAC_ISAL_MAX_BATCH];
        for (int i = 0; i < batch; i++) {
            inner_data[i] = msgs[processed + i];
            inner_lens[i] = (uint32_t)msg_lens[processed + i];
        }

        hmac_isal_multi_phase(&mgr, inner_ctx,
                              ipad_ptr, inner_data, inner_lens,
                              inner, batch);

        /* ---------- outer hashes ---------- */
        ISAL_SHA256_HASH_CTX outer_ctx[HMAC_ISAL_MAX_BATCH] ALIGNED16;
        const uint8_t *outer_data[HMAC_ISAL_MAX_BATCH];
        uint32_t       outer_lens[HMAC_ISAL_MAX_BATCH];
        for (int i = 0; i < batch; i++) {
            outer_data[i] = inner[i];
            outer_lens[i] = HMAC_ISAL_DIGEST_SIZE;
        }

        hmac_isal_multi_phase(&mgr, outer_ctx,
                              opad_ptr, outer_data, outer_lens,
                              (uint8_t (*)[HMAC_ISAL_DIGEST_SIZE])macs + processed,
                              batch);

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

uint64_t
hmac_isal_verify_multi(const uint8_t *key, size_t key_len,
                       const uint8_t *msgs[], const size_t msg_lens[],
                       const uint8_t *macs[], int num_packets,
                       const hmac_isal_key_cache_t *cache)
{
    if (num_packets < 1)
        return 0;

    /* Allocate temporary buffers for the computed MACs. */
    uint8_t *computed = malloc((size_t)num_packets * HMAC_ISAL_DIGEST_SIZE);
    if (!computed)
        return UINT64_MAX;  /* allocation failure → every bit set */

    /* VLA sized to the actual packet count so hmac_isal_multi can
     * write back results in any internal batch size without overrun. */
    uint8_t *ptrs[num_packets];
    for (int i = 0; i < num_packets; i++)
        ptrs[i] = computed + (size_t)i * HMAC_ISAL_DIGEST_SIZE;

    hmac_isal_multi(key, key_len, msgs, msg_lens, ptrs, num_packets, cache);

    uint64_t mask = 0;
    for (int i = 0; i < num_packets; i++) {
        if (ct_compare(ptrs[i], macs[i], HMAC_ISAL_DIGEST_SIZE))
            mask |= (uint64_t)1 << i;
    }

    free(computed);
    return mask;
}
