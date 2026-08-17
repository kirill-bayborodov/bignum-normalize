/* ------------------------------------------------------------------ */
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bignum_normalize.h"

typedef struct { size_t id; int failed; } worker_data_t;

static void *worker(void *opaque)
{
    worker_data_t *data = (worker_data_t *)opaque;
    for (size_t iteration = 0; iteration < 10000U; ++iteration) {
        bignum_t value;
        for (size_t i = 0; i < BIGNUM_CAPACITY; ++i) value.words[i] = UINT64_C(0x1000) + data->id;
        value.words[iteration % 8U] = UINT64_C(0);
        value.len = 8U;
        if (bignum_normalize(&value) != BIGNUM_NORMALIZE_SUCCESS || value.len == 0U) {
            data->failed = 1;
            return NULL;
        }
        for (size_t i = value.len; i < BIGNUM_CAPACITY; ++i) {
            if (value.words[i] != 0U) data->failed = 1;
        }
    }
    return NULL;
}

int main(void)
{
    enum { THREADS = 8 };
    pthread_t threads[THREADS];
    worker_data_t data[THREADS] = { 0 };
    puts("--- Starting multithreaded bignum_normalize test ---");
    for (size_t i = 0; i < THREADS; ++i) { data[i].id = i; assert(pthread_create(&threads[i], NULL, worker, &data[i]) == 0); }
    for (size_t i = 0; i < THREADS; ++i) { assert(pthread_join(threads[i], NULL) == 0); assert(data[i].failed == 0); }
    puts("--- Multithreaded bignum_normalize test passed ---");
    return 0;
}
