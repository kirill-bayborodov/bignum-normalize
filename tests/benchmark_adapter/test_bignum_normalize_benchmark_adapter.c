/**
 * @file test_bignum_normalize_benchmark_adapter.c
 * @brief Deterministic lifecycle tests for the bignum_normalize benchmark adapter.
 */
#include "bignum_normalize_benchmark_adapter.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static benchmark_workload_t workload(void) {
    return (benchmark_workload_t){ .data_mode="custom", .input_kind="nonzero",
        .operation_kind="normalize", .measure_mode="kernel-only", .size_profile="one",
        .capacity_profile="normal", .seed=UINT64_C(11400714819323198485),
        .warmup=0U, .data_count=1U };
}
int main(void) {
    benchmark_adapter_t adapter;
    benchmark_workload_t w = workload();
    unsigned char *state;
    assert(bignum_normalize_benchmark_validate_workload(&w) == BIGNUM_NORMALIZE_BENCHMARK_STATUS_SUCCESS);
    assert(bignum_normalize_benchmark_validate_workload(NULL) == BIGNUM_NORMALIZE_BENCHMARK_STATUS_NULL_ARGUMENT);
    assert(bignum_normalize_benchmark_adapter_init(NULL) == BIGNUM_NORMALIZE_BENCHMARK_STATUS_NULL_ARGUMENT);
    assert(bignum_normalize_benchmark_adapter_init(&adapter) == BIGNUM_NORMALIZE_BENCHMARK_STATUS_SUCCESS);
    assert(adapter.initialize != NULL && adapter.operation != NULL && adapter.checksum != NULL);
    state = calloc(1U, adapter.state_size);
    assert(state != NULL);
    assert(adapter.initialize(state, 0U, &w, NULL) == BENCHMARK_ADAPTER_STATUS_SUCCESS);
    assert(adapter.operation(state, 0U, &w, NULL) == BENCHMARK_ADAPTER_STATUS_SUCCESS);
    assert(adapter.checksum(state, 0U, NULL) != 0U);
    free(state);
    puts("bignum_normalize benchmark adapter tests: OK");
    return EXIT_SUCCESS;
}
