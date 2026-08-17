/**
 * @file    bignum_normalize.c
 * @brief   Эталонная переносимая C-реализация bignum_normalize.
 */
/* ------------------------------------------------------------------ */
#include <stddef.h>
#include <stdint.h>

#include "bignum_normalize.h"

bignum_normalize_status_t bignum_normalize(bignum_t *x)
{
    size_t len;

    if (x == NULL) {
        return BIGNUM_NORMALIZE_ERROR_NULL_ARG;
    }

    len = x->len;
    if (len > BIGNUM_CAPACITY) {
        len = BIGNUM_CAPACITY;
    }

    while (len > 0U && x->words[len - 1U] == UINT64_C(0)) {
        --len;
    }

    x->len = len;
    for (size_t i = len; i < BIGNUM_CAPACITY; ++i) {
        x->words[i] = UINT64_C(0);
    }

    return BIGNUM_NORMALIZE_SUCCESS;
}
