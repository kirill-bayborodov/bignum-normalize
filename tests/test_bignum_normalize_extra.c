/* ------------------------------------------------------------------ */
/**
 * @file    test_bignum_normalize_extra.c
 * @brief   Расширенные и fuzz/reference тесты bignum_normalize.
 */
/* ------------------------------------------------------------------ */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bignum_normalize.h"

typedef struct {
    uint64_t left;
    bignum_t value;
    uint64_t right;
} guarded_bignum_t;

static uint64_t next_value(uint64_t *state)
{
    *state ^= *state << 7;
    *state ^= *state >> 9;
    *state ^= *state << 8;
    return *state;
}

static size_t reference_len(const bignum_t *value)
{
    size_t len = value->len > BIGNUM_CAPACITY ? BIGNUM_CAPACITY : value->len;
    while (len > 0U && value->words[len - 1U] == UINT64_C(0)) {
        --len;
    }
    return len;
}

static void reference_normalize(bignum_t *value)
{
    size_t len = reference_len(value);
    value->len = len;
    for (size_t i = len; i < BIGNUM_CAPACITY; ++i) {
        value->words[i] = UINT64_C(0);
    }
}

static void test_guard_canaries(void)
{
    guarded_bignum_t guarded;
    guarded.left = UINT64_C(0x1122334455667788);
    guarded.right = UINT64_C(0x8877665544332211);
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        guarded.value.words[i] = i < 4U ? UINT64_C(0xdeadbeef) : UINT64_C(0);
    }
    guarded.value.words[3] = UINT64_C(0x42);
    guarded.value.len = 8U;
    assert(bignum_normalize(&guarded.value) == BIGNUM_NORMALIZE_SUCCESS);
    assert(guarded.left == UINT64_C(0x1122334455667788));
    assert(guarded.right == UINT64_C(0x8877665544332211));
    assert(guarded.value.len == 4U);
    for (size_t i = 4U; i < BIGNUM_CAPACITY; ++i) {
        assert(guarded.value.words[i] == UINT64_C(0));
    }
    puts("test_guard_canaries: PASSED");
}

static void test_fuzz_reference_equivalence(void)
{
    uint64_t state = UINT64_C(0x9E3779B97F4A7C15);
    for (size_t iteration = 0; iteration < 100000U; ++iteration) {
        bignum_t actual;
        bignum_t expected;
        actual.len = (size_t)(next_value(&state) % (BIGNUM_CAPACITY + 101U));
        for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
            actual.words[i] = next_value(&state);
        }
        expected = actual;
        assert(bignum_normalize(&actual) == BIGNUM_NORMALIZE_SUCCESS);
        reference_normalize(&expected);
        assert(actual.len == expected.len);
        for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
            assert(actual.words[i] == expected.words[i]);
        }
    }
    puts("test_fuzz_reference_equivalence: PASSED (100000 cases)");
}

static void test_adjacent_objects(void)
{
    struct {
        bignum_t first;
        bignum_t second;
    } objects;
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) {
        objects.first.words[i] = UINT64_C(0x11);
        objects.second.words[i] = UINT64_C(0x22);
    }
    objects.first.len = 1U;
    objects.second.len = BIGNUM_CAPACITY;
    objects.second.words[7] = UINT64_C(0x33);
    assert(bignum_normalize(&objects.first) == BIGNUM_NORMALIZE_SUCCESS);
    assert(bignum_normalize(&objects.second) == BIGNUM_NORMALIZE_SUCCESS);
    assert(objects.first.words[0] == UINT64_C(0x11));
    assert(objects.second.len == BIGNUM_CAPACITY);
    assert(objects.second.words[7] == UINT64_C(0x33));
    puts("test_adjacent_objects: PASSED");
}

int main(void)
{
    puts("--- Starting extended bignum_normalize tests ---");
    test_guard_canaries();
    test_fuzz_reference_equivalence();
    test_adjacent_objects();
    puts("--- All extended bignum_normalize tests passed ---");
    return 0;
}
