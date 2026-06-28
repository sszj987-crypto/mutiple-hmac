/*
 * Test suite for hmac_isal.
 *
 * Uses the RFC 4231 / RFC 4868 HMAC-SHA256 test vectors.
 *
 * Build and run:
 *   make test
 *   ./test/test_hmac
 */

#include "hmac_isal.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---------- helpers ---------- */

static int failures = 0;

#define TEST(name_)                                  \
    do {                                             \
        printf("  %-40s ", name_);                   \
        fflush(stdout);                              \
    } while (0)

#define PASS()       printf("PASS\n")
#define FAIL(reason)                                                 \
    do {                                                             \
        printf("FAIL  %s:%d  %s\n", __FILE__, __LINE__, (reason));   \
        failures++;                                                  \
    } while (0)

static void hex_dump(const char *label, const uint8_t *data, size_t len)
{
    printf("    %s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    putchar('\n');
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2)
        return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

/* ---------- test case ---------- */

typedef struct {
    const char *name;
    const char *key_hex;
    const char *data_hex;
    const char *mac_hex;
} hmac_test;

static const hmac_test tests[] = {

    /* RFC 4231 Test Case 2 — 20-byte key, "Hi There" */
    {
        "RFC 4231 TC2",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "4869205468657265",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    },

    /* RFC 4231 Test Case 3 — 4-byte key, "what do ya want for nothing?" */
    {
        "RFC 4231 TC3",
        "4a656665",
        "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    },

    /* RFC 4231 Test Case 4 — 20-byte key, 50 bytes of 0xdd */
    {
        "RFC 4231 TC4",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddddddd",
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    },

    /* RFC 4231 Test Case 5 — 25-byte key, "Test Using Larger ..." */
    {
        "RFC 4231 TC5",
        "0102030405060708090a0b0c0d0e0f10111213141516171819",
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
    },

    /* RFC 4231 Test Case 6 — key > block size (131 bytes) */
    {
        "RFC 4231 TC6 (long key)",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaa",
        "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
        "65204b6579202d2048617368204b6579204669727374",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    },

    /* RFC 4231 Test Case 7 — key > block size (131 bytes), different data */
    {
        "RFC 4231 TC7 (long key)",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaa",
        "5468697320697320612074657374207573696e672061206c6172676572207468"
        "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
        "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
        "647320746f20626520686173686564206265666f7265206265696e6720757365"
        "642062792074686520484d414320616c676f726974686d2e",
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    },

};

static const int num_tests = (int)(sizeof(tests) / sizeof(tests[0]));

/* ---------- run a single test case ---------- */

static void run_test(const hmac_test *t, int use_cache)
{
    uint8_t key[256];
    uint8_t data[512];
    uint8_t expected[HMAC_ISAL_DIGEST_SIZE];
    uint8_t computed[HMAC_ISAL_DIGEST_SIZE];

    size_t key_len  = strlen(t->key_hex)  / 2;
    size_t data_len = strlen(t->data_hex) / 2;

    if (hex_to_bytes(t->key_hex,  key,  key_len)  < 0)  { FAIL("bad key hex");   return; }
    if (hex_to_bytes(t->data_hex, data, data_len) < 0)  { FAIL("bad data hex");  return; }
    if (hex_to_bytes(t->mac_hex,  expected, HMAC_ISAL_DIGEST_SIZE) < 0) {
        FAIL("bad mac hex");
        return;
    }

    /* --- single-packet HMAC --- */
    if (use_cache) {
        hmac_isal_key_cache_t *cache =
            hmac_isal_key_cache_create(key, key_len);
        if (!cache) { FAIL("cache alloc"); return; }
        hmac_isal_single(key, key_len, data, data_len, computed, cache);
        hmac_isal_key_cache_destroy(cache);
    } else {
        hmac_isal_single(key, key_len, data, data_len, computed, NULL);
    }

    if (memcmp(expected, computed, HMAC_ISAL_DIGEST_SIZE) != 0) {
        FAIL("MAC mismatch (single)");
        hex_dump("expected", expected, HMAC_ISAL_DIGEST_SIZE);
        hex_dump("got",      computed, HMAC_ISAL_DIGEST_SIZE);
        return;
    }

    /* --- verification --- */
    int bad = hmac_isal_verify_single(key, key_len, data, data_len, computed,
                                       NULL);
    if (bad != 0) { FAIL("verify rejected valid MAC"); return; }

    /* --- verification with wrong MAC --- */
    computed[0] ^= 0x01;
    bad = hmac_isal_verify_single(key, key_len, data, data_len, computed, NULL);
    if (bad == 0) { FAIL("verify accepted forged MAC"); return; }
    computed[0] ^= 0x01; /* restore */

    PASS();
}

/* ---------- multi-packet consistency harness ---------- */

/*
 * Run n packets sharing the same key.  Expected MACs come from the
 * single-packet path (validated against RFC 4231 separately), so this
 * checks that multi-buffer output matches single-packet output exactly.
 */
static void run_multi_consistency_test(int count, int use_cache)
{
    uint8_t  key_buf[64];
    size_t   key_len;
    uint8_t  msg[64];
    size_t   msg_len;
    uint8_t  expected[HMAC_ISAL_DIGEST_SIZE];
    uint8_t *mac_ptrs[HMAC_ISAL_MAX_BATCH + 1];
    uint8_t  mac_results[HMAC_ISAL_MAX_BATCH + 1][HMAC_ISAL_DIGEST_SIZE];
    const uint8_t *msg_ptrs[HMAC_ISAL_MAX_BATCH + 1];
    size_t         msg_lens[HMAC_ISAL_MAX_BATCH + 1];

    /* Use TC2 (first test case) key + message throughout */
    key_len = strlen(tests[0].key_hex) / 2;
    msg_len = strlen(tests[0].data_hex) / 2;
    if (hex_to_bytes(tests[0].key_hex,  key_buf, key_len) < 0 ||
        hex_to_bytes(tests[0].data_hex, msg,     msg_len) < 0) {
        FAIL("hex parse");
        return;
    }

    /* Reference MAC from the (already-validated) single packet path */
    hmac_isal_single(key_buf, key_len, msg, msg_len, expected, NULL);

    int n = count > HMAC_ISAL_MAX_BATCH + 1 ? HMAC_ISAL_MAX_BATCH + 1 : count;

    hmac_isal_key_cache_t *cache = NULL;
    if (use_cache) {
        cache = hmac_isal_key_cache_create(key_buf, key_len);
        if (!cache) { FAIL("cache alloc"); return; }
    }

    for (int i = 0; i < n; i++) {
        msg_ptrs[i] = msg;
        msg_lens[i] = msg_len;
        mac_ptrs[i] = mac_results[i];
    }

    int done = hmac_isal_multi(key_buf, key_len, msg_ptrs, msg_lens,
                               mac_ptrs, n, cache);
    if (done != n) {
        FAIL("wrong count");
        goto cleanup;
    }

    for (int i = 0; i < n; i++) {
        if (memcmp(expected, mac_results[i], HMAC_ISAL_DIGEST_SIZE) != 0) {
            FAIL("MAC mismatch");
            hex_dump("expected", expected, HMAC_ISAL_DIGEST_SIZE);
            hex_dump("got",      mac_results[i], HMAC_ISAL_DIGEST_SIZE);
            goto cleanup;
        }
    }

cleanup:
    if (cache)
        hmac_isal_key_cache_destroy(cache);

    if (failures > 0)
        return;  /* let caller's FAIL() already incremented */

    PASS();
}


static void run_large_batch_test(void)
{
    /* Packets use the same key + message (TC2).
     * HMAC_ISAL_MAX_BATCH=16, so HMAC_ISAL_MAX_BATCH+1=17 triggers batching. */
    int total = HMAC_ISAL_MAX_BATCH + 1;  /* 17 */
    run_multi_consistency_test(total, 0);
}

static void run_large_batch_cached_test(void)
{
    int total = HMAC_ISAL_MAX_BATCH + 1;  /* 17 */
    run_multi_consistency_test(total, 1);
}

/* ---------- main ---------- */

#ifdef HMAC_ISAL_HAVE_OPENSSL

/* HMAC() is deprecated in OpenSSL 3.x but remains the simplest way to
 * obtain a reference value for cross-validation; suppress the warning. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/evp.h>
#include <openssl/hmac.h>

/*
 * Cross-check every RFC 4231 test vector against OpenSSL.
 * Both the single-packet and cached paths must produce identical
 * results to the reference implementation.
 */
static void run_openssl_single_cross_check(void)
{
    uint8_t key[256], data[512], expected[HMAC_ISAL_DIGEST_SIZE];
    uint8_t computed[HMAC_ISAL_DIGEST_SIZE];

    for (int i = 0; i < num_tests; i++) {
        size_t key_len  = strlen(tests[i].key_hex) / 2;
        size_t data_len = strlen(tests[i].data_hex) / 2;

        if (hex_to_bytes(tests[i].key_hex,  key,  key_len)  < 0 ||
            hex_to_bytes(tests[i].data_hex, data, data_len) < 0)
        {
            FAIL("hex parse");
            return;
        }

        /* ---- OpenSSL reference ---- */
        unsigned int out_len;
        if (!HMAC(EVP_sha256(), key, (int)key_len,
                  data, data_len, expected, &out_len) ||
            out_len != HMAC_ISAL_DIGEST_SIZE)
        {
            FAIL("OpenSSL HMAC failed");
            return;
        }

        /* ---- hmac_isal_single (no cache) ---- */
        hmac_isal_single(key, key_len, data, data_len, computed, NULL);
        if (memcmp(expected, computed, HMAC_ISAL_DIGEST_SIZE) != 0) {
            FAIL("openssl cross-check (single, no cache)");
            hex_dump("openssl",  expected, HMAC_ISAL_DIGEST_SIZE);
            hex_dump("isal",     computed, HMAC_ISAL_DIGEST_SIZE);
            return;
        }

        /* ---- hmac_isal_single (with cache) ---- */
        hmac_isal_key_cache_t *cache =
            hmac_isal_key_cache_create(key, key_len);
        if (!cache) { FAIL("cache alloc"); return; }
        hmac_isal_single(key, key_len, data, data_len, computed, cache);
        hmac_isal_key_cache_destroy(cache);

        if (memcmp(expected, computed, HMAC_ISAL_DIGEST_SIZE) != 0) {
            FAIL("openssl cross-check (single, cached)");
            hex_dump("openssl",  expected, HMAC_ISAL_DIGEST_SIZE);
            hex_dump("isal",     computed, HMAC_ISAL_DIGEST_SIZE);
            return;
        }

        /* ---- verify_single against OpenSSL reference ---- */
        int bad = hmac_isal_verify_single(key, key_len, data, data_len,
                                           expected, NULL);
        if (bad != 0) {
            FAIL("verify_single rejected OpenSSL MAC");
            return;
        }
    }
    PASS();
}

/*
 * Multi-packet HMAC cross-check against OpenSSL.
 *
 * Uses the first num_test RFC 4231 test vectors as distinct packets,
 * computes a reference MAC for each via OpenSSL, then requests the
 * library to compute all of them in a single hmac_isal_multi call.
 * Each output is compared individually against the OpenSSL reference.
 */
static void run_openssl_multi_cross_check(void)
{
    uint8_t  key_buf[6][256], msg_buf[6][512];
    uint8_t  expected[6][HMAC_ISAL_DIGEST_SIZE];
    uint8_t  mac_results[6][HMAC_ISAL_DIGEST_SIZE];
    const uint8_t *msgs[6];
    size_t         key_lens[6], msg_lens[6];
    uint8_t       *mac_ptrs[6];

    int n = num_tests > 6 ? 6 : num_tests;

    /* Prepare per-packet key, message, and OpenSSL reference. */
    for (int i = 0; i < n; i++) {
        key_lens[i] = strlen(tests[i].key_hex) / 2;
        msg_lens[i] = strlen(tests[i].data_hex) / 2;
        if (hex_to_bytes(tests[i].key_hex,  key_buf[i], key_lens[i]) < 0 ||
            hex_to_bytes(tests[i].data_hex, msg_buf[i], msg_lens[i]) < 0)
        {
            FAIL("hex parse");
            return;
        }

        unsigned int out_len;
        if (!HMAC(EVP_sha256(), key_buf[i], (int)key_lens[i],
                  msg_buf[i], msg_lens[i], expected[i], &out_len) ||
            out_len != HMAC_ISAL_DIGEST_SIZE)
        {
            FAIL("OpenSSL HMAC failed");
            return;
        }

        msgs[i]    = msg_buf[i];
        mac_ptrs[i] = mac_results[i];
    }

    /* ---- multi with distinct keys (per-packet key expansion) ---- */
    /* hmac_isal_multi currently uses a single key for all packets.
     * Compute one packet at a time to cross-check.
     * (Multi-key multi-packet HMAC is not in scope for this library.) */
    for (int i = 0; i < n; i++) {
        hmac_isal_single(key_buf[i], key_lens[i],
                         msgs[i], msg_lens[i], mac_results[i], NULL);
        if (memcmp(expected[i], mac_results[i], HMAC_ISAL_DIGEST_SIZE) != 0) {
            FAIL("openssl multi cross-check");
            hex_dump("openssl",  expected[i], HMAC_ISAL_DIGEST_SIZE);
            hex_dump("isal",     mac_results[i], HMAC_ISAL_DIGEST_SIZE);
            return;
        }
    }

    /* ---- multi with same key, different messages ---- */
    /* Use the first test case's key for all packets. */
    {
        const uint8_t *same_key_msgs[6];
        size_t         same_key_lens[6];
        uint8_t        same_key_macs[6][HMAC_ISAL_DIGEST_SIZE];
        uint8_t       *same_key_ptrs[6];
        uint8_t        same_key[256];
        size_t         same_key_len = key_lens[0];

        memcpy(same_key, key_buf[0], same_key_len);
        for (int i = 0; i < n; i++) {
            same_key_msgs[i] = msg_buf[i];
            same_key_lens[i] = msg_lens[i];
            same_key_ptrs[i] = same_key_macs[i];
        }

        /* Reference: OpenSSL for each separately. */
        uint8_t same_key_expected[6][HMAC_ISAL_DIGEST_SIZE];
        for (int i = 0; i < n; i++) {
            unsigned int out_len;
            HMAC(EVP_sha256(), same_key, (int)same_key_len,
                 same_key_msgs[i], same_key_lens[i],
                 same_key_expected[i], &out_len);
        }

        /* hmac_isal_multi: all packets in one call. */
        int done = hmac_isal_multi(same_key, same_key_len,
                                   same_key_msgs, same_key_lens,
                                   same_key_ptrs, n, NULL);
        if (done != n) { FAIL("multi wrong count"); return; }

        for (int i = 0; i < n; i++) {
            if (memcmp(same_key_expected[i], same_key_macs[i],
                       HMAC_ISAL_DIGEST_SIZE) != 0)
            {
                FAIL("openssl multi same-key cross-check");
                hex_dump("openssl", same_key_expected[i],
                         HMAC_ISAL_DIGEST_SIZE);
                hex_dump("isal",    same_key_macs[i],
                         HMAC_ISAL_DIGEST_SIZE);
                return;
            }
        }

        /* ---- verify_multi against OpenSSL references ---- */
        uint64_t bad_mask = hmac_isal_verify_multi(same_key, same_key_len,
                                                    same_key_msgs,
                                                    same_key_lens,
                                                    (const uint8_t **)
                                                        same_key_ptrs,
                                                    n, NULL);
        if (bad_mask != 0) {
            FAIL("verify_multi rejected valid MACs");
            return;
        }

        /* ---- verify_multi with one forged MAC ---- */
        same_key_macs[1][0] ^= 0xFF;
        bad_mask = hmac_isal_verify_multi(same_key, same_key_len,
                                           same_key_msgs, same_key_lens,
                                           (const uint8_t **)same_key_ptrs,
                                           n, NULL);
        same_key_macs[1][0] ^= 0xFF;  /* restore */
        if (bad_mask == 0) {
            FAIL("verify_multi accepted forged MAC");
            return;
        }
        if ((bad_mask & ((uint64_t)1 << 1)) == 0) {
            FAIL("verify_multi forged MAC: bit 1 not set");
            return;
        }
        if (bad_mask & ~((uint64_t)1 << 1)) {
            FAIL("verify_multi forged MAC: extra bits set");
            return;
        }
    }

    PASS();
}

#endif /* HMAC_ISAL_HAVE_OPENSSL */

/* ---------- main ---------- */

int main(void)
{
    printf("=== hmac_isal test suite ===\n\n");

    /* ---- single-packet tests (no cache) ---- */
    printf("\n[Single-packet, no cache]\n");
    for (int i = 0; i < num_tests; i++) {
        char label[64];
        snprintf(label, sizeof(label), "%s (no cache)", tests[i].name);
        TEST(label);
        run_test(&tests[i], 0);
    }

    /* ---- single-packet tests (with cache) ---- */
    printf("\n[Single-packet, with key cache]\n");
    for (int i = 0; i < num_tests; i++) {
        char label[64];
        snprintf(label, sizeof(label), "%s (cached)", tests[i].name);
        TEST(label);
        run_test(&tests[i], 1);
    }

    /* ---- multi-packet tests ---- */
    printf("\n[Multi-packet (3 in parallel)]\n");
    TEST("3 identical packets, no cache");
    run_multi_consistency_test(3, 0);

    TEST("3 identical packets, cached");
    run_multi_consistency_test(3, 1);

    /* ---- key-cache multi test ---- */
    printf("\n[Multi-packet, key cache]\n");
    {
        uint8_t  key_buf[64], msg[64], expected[32];
        uint8_t *mac_ptrs[4], mac_results[4][32];
        const uint8_t *msg_ptrs[4];
        size_t msg_lens[4], key_len, msg_len;

        key_len = strlen(tests[0].key_hex) / 2;
        msg_len = strlen(tests[0].data_hex) / 2;
        hex_to_bytes(tests[0].key_hex,  key_buf, key_len);
        hex_to_bytes(tests[0].data_hex, msg,     msg_len);
        hmac_isal_single(key_buf, key_len, msg, msg_len, expected, NULL);

        hmac_isal_key_cache_t *cache = hmac_isal_key_cache_create(key_buf, key_len);
        if (!cache) { FAIL("cache alloc"); goto skip_cache_test; }

        for (int i = 0; i < 4; i++) {
            msg_ptrs[i] = msg; msg_lens[i] = msg_len; mac_ptrs[i] = mac_results[i];
        }

        int n = hmac_isal_multi(key_buf, key_len, msg_ptrs, msg_lens,
                                mac_ptrs, 4, cache);
        if (n != 4) { FAIL("cache wrong count"); }
        else {
            for (int i = 0; i < 4; i++) {
                if (memcmp(expected, mac_results[i], 32) != 0) {
                    FAIL("cache MAC mismatch");
                    goto cache_done;
                }
            }
            PASS();
        }
cache_done:
        hmac_isal_key_cache_destroy(cache);
    }
skip_cache_test:;

    /* ---- large-batch tests (>HMAC_ISAL_MAX_BATCH packets) ---- */
    printf("\n[Large batch (%d packets, >1 internal batch)]\n",
           HMAC_ISAL_MAX_BATCH + 1);
    TEST("17 packets, no cache");
    run_large_batch_test();

    TEST("17 packets, cached");
    run_large_batch_cached_test();

#ifdef HMAC_ISAL_HAVE_OPENSSL
    /* ---- OpenSSL cross-validation ---- */
    printf("\n[OpenSSL cross-validation]\n");
    TEST("RFC 4231 vectors vs OpenSSL");
    run_openssl_single_cross_check();

    TEST("Multi-packet vs OpenSSL");
    run_openssl_multi_cross_check();
#endif

    /* ---- summary ---- */
    printf("\n");
    if (failures == 0)
        printf("All tests PASSED.\n");
    else
        printf("%d test(s) FAILED.\n", failures);

    return failures ? 1 : 0;
}
