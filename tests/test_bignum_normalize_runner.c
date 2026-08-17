/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bignum_normalize.h"

int main(void)
{
    bignum_t value;
    for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) value.words[i] = i < 5U ? UINT64_C(0xaaaaaaaaaaaaaaaa) : UINT64_C(0);
    value.words[4] = UINT64_C(0x42);
    value.len = BIGNUM_CAPACITY;
    printf("Running test: test_bignum_normalize_runner... ");
    assert(bignum_normalize(&value) == BIGNUM_NORMALIZE_SUCCESS);
    assert(value.len == 5U);
    for (size_t i = 5U; i < BIGNUM_CAPACITY; ++i) assert(value.words[i] == 0U);
    assert(bignum_normalize(NULL) == BIGNUM_NORMALIZE_ERROR_NULL_ARG);
    puts("PASSED");
    return 0;
}
