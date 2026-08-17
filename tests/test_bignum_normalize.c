/* ------------------------------------------------------------------ */
/**
 * @file    test_bignum_normalize.c
 * @brief   Детерминированные проверки контракта bignum_normalize.
 */
/* ------------------------------------------------------------------ */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bignum_normalize.h"

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", (message)); \
            assert(condition); \
        } \
    } while (0)

static void assert_zero_tail(const bignum_t *b, size_t start)
{
    for (size_t i = start; i < BIGNUM_CAPACITY; ++i) {
        ASSERT(b->words[i] == UINT64_C(0), "tail must be zero");
    }
}

static void test_null(void)
{
    ASSERT(bignum_normalize(NULL) == BIGNUM_NORMALIZE_ERROR_NULL_ARG,
           "normalize(NULL) status");
    puts("test_null: PASSED");
}

static void test_empty_len(void)
{
    bignum_t b;
    b.len = 0U;
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        b.words[i] = UINT64_C(0x1234567890abcdef);
    }
    ASSERT(bignum_normalize(&b) == BIGNUM_NORMALIZE_SUCCESS,
           "normalize(len=0) status");
    ASSERT(b.len == 0U, "normalize(len=0): len preserved");
    assert_zero_tail(&b, 0U);
    puts("test_empty_len: PASSED");
}

static void test_many_high_zero_words(void)
{
    bignum_t b;
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        b.words[i] = UINT64_C(0);
    }
    b.words[0] = UINT64_C(0x42);
    b.len = BIGNUM_CAPACITY;
    ASSERT(bignum_normalize(&b) == BIGNUM_NORMALIZE_SUCCESS,
           "normalize trailing zeros status");
    ASSERT(b.len == 1U && b.words[0] == UINT64_C(0x42),
           "normalize should trim to words[0]");
    assert_zero_tail(&b, 1U);
    puts("test_many_high_zero_words: PASSED");
}

static void test_len_invariant(void)
{
    bignum_t b;
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        b.words[i] = UINT64_C(0xdead);
    }
    b.words[10] = UINT64_C(0);
    b.len = 11U;
    ASSERT(bignum_normalize(&b) == BIGNUM_NORMALIZE_SUCCESS,
           "normalize invariant status");
    ASSERT(b.len == 10U, "normalize should trim len to 10");
    ASSERT(b.words[9] != UINT64_C(0), "highest word must be nonzero");
    assert_zero_tail(&b, 10U);
    puts("test_len_invariant: PASSED");
}

static void test_full_capacity(void)
{
    bignum_t b;
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        b.words[i] = UINT64_MAX;
    }
    b.len = BIGNUM_CAPACITY;
    ASSERT(bignum_normalize(&b) == BIGNUM_NORMALIZE_SUCCESS,
           "full capacity status");
    ASSERT(b.len == BIGNUM_CAPACITY, "full capacity len preserved");
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        ASSERT(b.words[i] == UINT64_MAX, "full capacity values preserved");
    }
    puts("test_full_capacity: PASSED");
}

static void test_idempotence(void)
{
    bignum_t b;
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        b.words[i] = UINT64_C(0xabcdef);
    }
    b.words[5] = UINT64_C(0);
    b.len = 6U;
    ASSERT(bignum_normalize(&b) == BIGNUM_NORMALIZE_SUCCESS,
           "first normalize status");
    size_t first_len = b.len;
    ASSERT(bignum_normalize(&b) == BIGNUM_NORMALIZE_SUCCESS,
           "second normalize status");
    ASSERT(b.len == first_len, "normalize must be idempotent");
    assert_zero_tail(&b, b.len);
    puts("test_idempotence: PASSED");
}

static void test_old_len_tail_cleanup(void)
{
    bignum_t b;
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        b.words[i] = UINT64_C(0xbadbadbadbadbadb);
    }
    b.len = 10U;
    b.words[5] = UINT64_C(0x12345678);
    for (size_t i = 6; i < 10U; ++i) {
        b.words[i] = UINT64_C(0);
    }
    ASSERT(bignum_normalize(&b) == BIGNUM_NORMALIZE_SUCCESS,
           "old len cleanup status");
    ASSERT(b.len == 6U, "len should become 6");
    assert_zero_tail(&b, 6U);
    puts("test_old_len_tail_cleanup: PASSED");
}

static void test_malformed_len(void)
{
    bignum_t b;
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        b.words[i] = UINT64_C(0);
    }
    b.words[0] = UINT64_C(0x42);
    b.len = BIGNUM_CAPACITY + 100U;
    ASSERT(bignum_normalize(&b) == BIGNUM_NORMALIZE_SUCCESS,
           "malformed len status");
    ASSERT(b.len == 1U, "malformed len should be clamped and normalized");
    ASSERT(b.words[0] == UINT64_C(0x42), "malformed len data preserved");
    assert_zero_tail(&b, 1U);
    puts("test_malformed_len: PASSED");
}

int main(void)
{
    puts("--- Starting deterministic bignum_normalize tests ---");
    test_null();
    test_empty_len();
    test_many_high_zero_words();
    test_len_invariant();
    test_full_capacity();
    test_idempotence();
    test_old_len_tail_cleanup();
    test_malformed_len();
    puts("--- All deterministic bignum_normalize tests passed ---");
    return 0;
}
