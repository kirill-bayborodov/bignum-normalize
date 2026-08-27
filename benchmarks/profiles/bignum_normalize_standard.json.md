# bignum_normalize standard benchmark profile

This companion document defines the `bignum_normalize_standard.json` matrix. The adapter accepts only `normalize` and `mixed` operation kinds, uses deterministic seed transport, and consumes framework tools from `libs/benchmark-framework/dist/tools`.

The matrix is a smoke/reproducibility contract, not a performance baseline. Run it with `make bench_matrix CONFIG=release BENCH_MATRIX_PROFILE=benchmarks/profiles/bignum_normalize_standard.json`.
