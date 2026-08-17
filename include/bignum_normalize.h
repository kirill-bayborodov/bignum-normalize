/* bignum_normalize.h: нормализация bignum_t и очистка хвоста. */
/* ------------------------------------------------------------------ */
#pragma once
#ifndef BIGNUM_NORMALIZE_H
#define BIGNUM_NORMALIZE_H

#include <stddef.h>
#include <stdint.h>

#include "bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Результаты выполнения bignum_normalize. */
typedef enum {
    BIGNUM_NORMALIZE_SUCCESS        = 0,
    BIGNUM_NORMALIZE_ERROR_NULL_ARG = -1
} bignum_normalize_status_t;

/**
 * @brief Удаляет старшие нулевые слова и очищает неиспользуемый хвост.
 *
 * Функция предназначена для вызова после арифметических операций, чтобы
 * привести объект bignum_t к каноническому состоянию. Если `len` превышает
 * BIGNUM_CAPACITY, он сначала ограничивается вместимостью объекта. Затем
 * старшие нулевые слова удаляются из `len`, а все слова от нового `len` до
 * конца буфера записываются нулём. При `len == 0` очищается весь буфер.
 *
 * Функция не вызывает сторонних функций и не использует глобальное изменяемое
 * состояние. При NULL-аргументе память не читается и не изменяется.
 *
 * @param[in,out] x Объект bignum_t, который необходимо нормализовать.
 * @return `BIGNUM_NORMALIZE_SUCCESS` при успешной нормализации или
 *         `BIGNUM_NORMALIZE_ERROR_NULL_ARG`, если `x == NULL`.
 */
bignum_normalize_status_t bignum_normalize(bignum_t *x);

#ifdef __cplusplus
}
#endif

#endif /* BIGNUM_NORMALIZE_H */

/* SPDX-License-Identifier: MIT */
