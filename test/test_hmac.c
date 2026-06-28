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

/* ---------- run multi-packet test ---------- */

static void run_multi_test(void)
{
    /* Use the first 3 test vectors as a batch */
    uint8_t key[256];
    uint8_t data[3][512];
    uint8_t expected[3][HMAC_ISAL_DIGEST_SIZE];
    uint8_t *macs[3];
    uint8_t  mac_buf[3][HMAC_ISAL_DIGEST_SIZE];
    const uint8_t *msgs[3];
    size_t    lens[3];

    for (int i = 0; i < 3; i++) {
        size_t kl = strlen(tests[i].key_hex) / 2;
        size_t dl = strlen(tests[i].data_hex) / 2;
        if (hex_to_bytes(tests[i].key_hex,  key,          kl) < 0 ||
            hex_to_bytes(tests[i].data_hex, data[i],      dl) < 0 ||
            hex_to_bytes(tests[i].mac_hex,  expected[i],  HMAC_ISAL_DIGEST_SIZE) < 0) {
            FAIL("multi hex parse");
            return;
        }
        msgs[i] = data[i];
        lens[i] = dl;
        macs[i] = mac_buf[i];
    }

    int n = hmac_isal_multi(key, 20, msgs, lens, macs, 3, NULL);
    if (n != 3) { FAIL("multi returned wrong count"); return; }

    for (int i = 0; i < 3; i++) {
        if (memcmp(expected[i], mac_buf[i], HMAC_ISAL_DIGEST_SIZE) != 0) {
            FAIL("multi MAC mismatch");
            hex_dump("expected", expected[i], HMAC_ISAL_DIGEST_SIZE);
            hex_dump("got",      mac_buf[i], HMAC_ISAL_DIGEST_SIZE);
            return;
        }
    }

    /* Repeat with key cache */
    hmac_isal_key_cache_t *cache =
        hmac_isal_key_cache_create(key, 20);
    if (!cache) { FAIL("multi cache alloc"); return; }

    n = hmac_isal_multi(key, 20, msgs, lens, macs, 3, cache);
    if (n != 3) { FAIL("multi cached returned wrong count"); return; }

    for (int i = 0; i < 3; i++) {
        if (memcmp(expected[i], mac_buf[i], HMAC_ISAL_DIGEST_SIZE) != 0) {
            FAIL("multi cached MAC mismatch");
            hex_dump("expected", expected[i], HMAC_ISAL_DIGEST_SIZE);
            hex_dump("got",      mac_buf[i], HMAC_ISAL_DIGEST_SIZE);
            hmac_isal_key_cache_destroy(cache);
            return;
        }
    }

    hmac_isal_key_cache_destroy(cache);
    PASS();
}


/* ---------- run large-batch (>8 packets) test ---------- */
/* Verifies that hmac_isal_multi correctly batches internally. */

static void run_large_batch_test(void)
{
    /* All 6 RFC 4231 test cases + 5 duplicates of TC2 = 11 packets.
     * This exercises the batching path (1st batch of 8, 2nd batch of 3). */
    int total = num_tests + 5;  /* 11 */
    uint8_t key[256];
    uint8_t data[11][512];
    uint8_t expected[11][HMAC_ISAL_DIGEST_SIZE];
    uint8_t *macs[11], mac_buf[11][HMAC_ISAL_DIGEST_SIZE];
    const uint8_t *msgs[11];
    size_t lens[11];

    for (int i = 0; i < num_tests; i++) {
        size_t kl = strlen(tests[i].key_hex) / 2;
        size_t dl = strlen(tests[i].data_hex) / 2;
        if (hex_to_bytes(tests[i].key_hex, key, 20) < 0 ||
            hex_to_bytes(tests[i].data_hex, data[i], dl) < 0 ||
            hex_to_bytes(tests[i].mac_hex, expected[i], HMAC_ISAL_DIGEST_SIZE) < 0) {
            FAIL("large hex parse");
            return;
        }
        msgs[i] = data[i];
        lens[i] = dl;
        macs[i] = mac_buf[i];
    }
    /* Pad with copies of TC2 */
    for (int i = num_tests; i < total; i++) {
        size_t kl = strlen(tests[0].key_hex) / 2;
        size_t dl = strlen(tests[0].data_hex) / 2;
        hex_to_bytes(tests[0].key_hex, key, kl);
        hex_to_bytes(tests[0].data_hex, data[i], dl);
        hex_to_bytes(tests[0].mac_hex, expected[i], HMAC_ISAL_DIGEST_SIZE);
        msgs[i] = data[i];
        lens[i] = dl;
        macs[i] = mac_buf[i];
    }

    /* All share the same 20-byte key */
    int n = hmac_isal_multi(key, 20, msgs, lens, macs, total, NULL);
    if (n != total) { FAIL("large batch: wrong count"); return; }

    for (int i = 0; i < total; i++) {
        if (memcmp(expected[i], mac_buf[i], HMAC_ISAL_DIGEST_SIZE) != 0) {
            FAIL("large batch: MAC mismatch");
            hex_dump("expected", expected[i], HMAC_ISAL_DIGEST_SIZE);
            hex_dump("got",      mac_buf[i], HMAC_ISAL_DIGEST_SIZE);
            return;
        }
    }

    /* repeat with key cache */
    hmac_isal_key_cache_t *cache = hmac_isal_key_cache_create(key, 20);
    if (!cache) { FAIL("large batch: cache alloc"); return; }

    n = hmac_isal_multi(key, 20, msgs, lens, macs, total, cache);
    if (n != total) { FAIL("large batch cached: wrong count"); return; }

    for (int i = 0; i < total; i++) {
        if (memcmp(expected[i], mac_buf[i], HMAC_ISAL_DIGEST_SIZE) != 0) {
            FAIL("large batch cached: MAC mismatch");
            hex_dump("expected", expected[i], HMAC_ISAL_DIGEST_SIZE);
            hex_dump("got",      mac_buf[i], HMAC_ISAL_DIGEST_SIZE);
            hmac_isal_key_cache_destroy(cache);
            return;
        }
    }

    hmac_isal_key_cache_destroy(cache);
    PASS();
}

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
    TEST("first 3 vectors, no cache");
    run_multi_test();

    TEST("first 3 vectors, cached");
    run_multi_test();

    /* ---- large-batch tests (>8 packets, triggers internal batching) ---- */
    printf("
[Large batch (11 packets, 2 internal batches)]
");
    TEST("11 packets, no cache");
    run_large_batch_test();

    TEST("11 packets, cached");
    run_large_batch_test();

    /* ---- summary ---- */
    printf("\n");
    if (failures == 0)
        printf("All tests PASSED.\n");
    else
        printf("%d test(s) FAILED.\n", failures);

    return failures ? 1 : 0;
}
