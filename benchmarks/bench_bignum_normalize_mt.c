/* ------------------------------------------------------------------ */
#define _POSIX_C_SOURCE 200809L
/**
 * @file    bench_bignum_normalize_mt.c
 * @brief   Multithread benchmark for bignum_normalize.
 */
/* ------------------------------------------------------------------ */
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bignum_normalize.h"

typedef enum { DATA_ALL_ZERO, DATA_ALL_NONZERO, DATA_MIXED } data_mode_t;

typedef struct {
    uint64_t iterations;
    uint64_t warmup;
    uint64_t total_iterations;
    size_t threads;
    size_t data_count;
    size_t src_len;
    uint64_t seed;
    data_mode_t mode;
} options_t;

typedef struct {
    const uint64_t (*data)[BIGNUM_CAPACITY];
    const options_t *options;
    size_t thread_id;
    uint64_t checksum;
    uint64_t successful;
    int failed;
} worker_arg_t;

static uint64_t next_value(uint64_t *state)
{
    *state ^= *state << 7;
    *state ^= *state >> 9;
    *state ^= *state << 8;
    return *state;
}

static const char *mode_name(data_mode_t mode)
{
    if (mode == DATA_ALL_ZERO) return "all_zero";
    if (mode == DATA_MIXED) return "mixed";
    return "all_nonzero";
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;
    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_mode(const char *text, data_mode_t *mode)
{
    if (strcmp(text, "all_zero") == 0) *mode = DATA_ALL_ZERO;
    else if (strcmp(text, "all_nonzero") == 0) *mode = DATA_ALL_NONZERO;
    else if (strcmp(text, "mixed") == 0) *mode = DATA_MIXED;
    else return -1;
    return 0;
}

static int parse_options(int argc, char **argv, options_t *options)
{
    *options = (options_t){
        .iterations = UINT64_C(1000000),
        .warmup = UINT64_C(10000),
        .total_iterations = 0,
        .threads = 2U,
        .data_count = 4096U,
        .src_len = BIGNUM_CAPACITY,
        .seed = UINT64_C(0x9E3779B97F4A7C15),
        .mode = DATA_ALL_NONZERO
    };

    for (int i = 1; i < argc; ++i) {
        uint64_t value;
        if (strcmp(argv[i], "--threads") == 0 ||
            strcmp(argv[i], "--iterations") == 0 ||
            strcmp(argv[i], "--total-iterations") == 0 ||
            strcmp(argv[i], "--warmup") == 0 ||
            strcmp(argv[i], "--data-count") == 0 ||
            strcmp(argv[i], "--src-len") == 0 ||
            strcmp(argv[i], "--seed") == 0) {
            const char *option = argv[i];
            if (i + 1 >= argc || parse_u64(argv[++i], &value) != 0) return -1;
            if (strcmp(option, "--threads") == 0) options->threads = (size_t)value;
            else if (strcmp(option, "--iterations") == 0) options->iterations = value;
            else if (strcmp(option, "--total-iterations") == 0) options->total_iterations = value;
            else if (strcmp(option, "--warmup") == 0) options->warmup = value;
            else if (strcmp(option, "--data-count") == 0) options->data_count = (size_t)value;
            else if (strcmp(option, "--src-len") == 0) options->src_len = (size_t)value;
            else options->seed = value;
        } else if (strcmp(argv[i], "--data-mode") == 0) {
            if (i + 1 >= argc || parse_mode(argv[++i], &options->mode) != 0) return -1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("usage: %s [--threads N] [--iterations N|--total-iterations N] [--warmup N] [--data-count N] [--src-len N] [--seed N] [--data-mode all_zero|all_nonzero|mixed]\n", argv[0]);
            exit(EXIT_SUCCESS);
        } else return -1;
    }

    if (options->threads == 0U || options->data_count == 0U ||
        options->src_len > BIGNUM_CAPACITY) return -1;
    if (options->total_iterations != 0U) {
        if (options->total_iterations % options->threads != 0U) return -1;
        options->iterations = options->total_iterations / options->threads;
    }
    return options->iterations != 0U ? 0 : -1;
}

static void fill_data(uint64_t (*data)[BIGNUM_CAPACITY], const options_t *options)
{
    uint64_t state = options->seed;
    for (size_t row = 0; row < options->data_count; ++row) {
        int zero = options->mode == DATA_ALL_ZERO ||
                   (options->mode == DATA_MIXED && (row % 2U) == 0U);
        for (size_t word = 0; word < options->src_len; ++word) {
            data[row][word] = zero ? UINT64_C(0) : next_value(&state);
        }
        if (!zero && options->src_len > 0U && data[row][options->src_len - 1U] == 0U) {
            data[row][options->src_len - 1U] = UINT64_C(1);
        }
    }
}

static uint64_t fingerprint(const uint64_t (*data)[BIGNUM_CAPACITY], const options_t *options)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t row = 0; row < options->data_count; ++row) {
        for (size_t word = 0; word < options->src_len; ++word) {
            hash ^= data[row][word];
            hash *= UINT64_C(1099511628211);
        }
    }
    return hash;
}

static void *worker(void *opaque)
{
    worker_arg_t *arg = opaque;
    bignum_t result;
    uint64_t total = arg->options->warmup + arg->options->iterations;

    for (uint64_t i = 0; i < total; ++i) {
        const uint64_t *source = arg->data[(i + arg->thread_id) % arg->options->data_count];
        result.len = arg->options->src_len;
        for (size_t j = 0; j < result.len; ++j) {
            result.words[j] = source[j];
        }
        if (bignum_normalize(&result) != BIGNUM_NORMALIZE_SUCCESS) {
            arg->failed = 1;
            return NULL;
        }
        if (i >= arg->options->warmup) {
            arg->checksum ^= result.words[0] + (uint64_t)result.len + i;
            ++arg->successful;
        }
    }
    return NULL;
}

static double seconds_between(struct timespec start, struct timespec end)
{
    return (double)(end.tv_sec - start.tv_sec) +
           (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

int main(int argc, char **argv)
{
    options_t options;
    uint64_t (*data)[BIGNUM_CAPACITY];
    pthread_t *threads;
    worker_arg_t *args;
    struct timespec start;
    struct timespec end;
    uint64_t checksum = 0;
    uint64_t successful = 0;
    uint64_t total_iterations;
    double elapsed;

    if (parse_options(argc, argv, &options) != 0) {
        fprintf(stderr, "invalid benchmark arguments; use --help\n");
        return EXIT_FAILURE;
    }
    data = calloc(options.data_count, sizeof(*data));
    threads = calloc(options.threads, sizeof(*threads));
    args = calloc(options.threads, sizeof(*args));
    if (data == NULL || threads == NULL || args == NULL) {
        perror("calloc");
        free(data);
        free(threads);
        free(args);
        return EXIT_FAILURE;
    }
    fill_data(data, &options);
    total_iterations = options.iterations * (uint64_t)options.threads;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t i = 0; i < options.threads; ++i) {
        args[i] = (worker_arg_t){
            .data = (const uint64_t (*)[BIGNUM_CAPACITY])data,
            .options = &options,
            .thread_id = i
        };
        if (pthread_create(&threads[i], NULL, worker, &args[i]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return EXIT_FAILURE;
        }
    }
    for (size_t i = 0; i < options.threads; ++i) {
        if (pthread_join(threads[i], NULL) != 0 || args[i].failed) {
            fprintf(stderr, "worker failed\n");
            return EXIT_FAILURE;
        }
        checksum ^= args[i].checksum;
        successful += args[i].successful;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = seconds_between(start, end);

    printf("benchmark=bignum_normalize_mt data_mode=%s seed=%" PRIu64
           " threads=%zu iterations_per_thread=%" PRIu64
           " total_iterations=%" PRIu64 " data_count=%zu src_len=%zu"
           " successful=%" PRIu64 " fingerprint=%" PRIu64
           " checksum=%" PRIu64 " elapsed_seconds=%.9f ns_per_call=%.3f\n",
           mode_name(options.mode), options.seed, options.threads,
           options.iterations, total_iterations, options.data_count,
           options.src_len, successful,
           fingerprint((const uint64_t (*)[BIGNUM_CAPACITY])data, &options),
           checksum, elapsed, elapsed * 1000000000.0 / (double)total_iterations);

    free(data);
    free(threads);
    free(args);
    return EXIT_SUCCESS;
}
