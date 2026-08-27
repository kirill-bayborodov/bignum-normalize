/**
 * @file bench_bignum_normalize_mt.c
 * @brief Multi-thread benchmark-framework entrypoint for bignum_normalize.
 */
#include <benchmark_framework.h>
#include "bignum_normalize_benchmark_adapter.h"
int main(int argc, char **argv)
{
    benchmark_adapter_t adapter;
    if (bignum_normalize_benchmark_adapter_init(&adapter) != BIGNUM_NORMALIZE_BENCHMARK_STATUS_SUCCESS) return 2;
    benchmark_core_status_t status = benchmark_core_run_mt(argc, argv, &adapter);
    return status == BENCHMARK_CORE_STATUS_SUCCESS || status == BENCHMARK_CORE_STATUS_HELP ? 0 : 1;
}
