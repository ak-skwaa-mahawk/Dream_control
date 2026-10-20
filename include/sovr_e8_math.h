#ifndef SOVR_E8_MATH_H
#define SOVR_E8_MATH_H

#include <stdint.h>
#include <stdbool.h>

#define FIXED_SCALE             1000000LL
#define MAX_SHEAR_BOUND_FIXED   150000LL   /* 0.1500 in fixed-point */
#define E8_DIM                  8
#define E8_ROOT_COUNT           240

/* Deterministic integer square root via binary restoring method */
static inline int64_t isqrt64(int64_t val) {
    if (val <= 0) return 0;
    uint64_t rem = 0;
    uint64_t root = 0;
    uint64_t n = (uint64_t)val;

    for (int i = 0; i < 32; i++) {
        root <<= 1;
        rem = ((rem << 2) | (n >> 62));
        n <<= 2;
        if (root < rem) {
            rem -= (root + 1);
            root += 2;
        }
    }
    return (int64_t)(root >> 1);
}

/* Branchless scalar absolute difference */
static inline int64_t diff_abs(int64_t a, int64_t b) {
    int64_t d = a - b;
    int64_t mask = d >> 63;
    return (d ^ mask) - mask;
}

/*
 * Evaluates the C4 Shear Invariant between two 8D coordinates:
 * Delta_shear = sqrt( sum((cand[i] - prior[i])^2) )
 * Returns true if invariant holds (<= 0.1500), false on shear breach.
 */
static inline bool evaluate_shear_invariant(
    const int64_t prior[E8_DIM],
    const int64_t candidate[E8_DIM],
    int64_t *out_metric
) {
    int64_t sum_sq = 0;

    for (int i = 0; i < E8_DIM; i++) {
        int64_t delta = candidate[i] - prior[i];
        sum_sq += (delta * delta);
    }

    int64_t metric = isqrt64(sum_sq);
    *out_metric = metric;

    return (metric <= MAX_SHEAR_BOUND_FIXED);
}

/*
 * Strawman Deterministic Admission Filter
 * Validates unforgeable badge authority, monotonic sequence, and geometric limits.
 */
static inline int32_t strawman_admit_proposal(
    uint64_t badge,
    uint32_t expected_seq,
    uint32_t incoming_seq,
    const int64_t prior[E8_DIM],
    const int64_t candidate[E8_DIM]
) {
    if (incoming_seq != expected_seq) {
        return -1; /* ERR_SEQUENCE_MISMATCH */
    }

    if ((badge & 0x07) != 0x07) {
        return -2; /* ERR_CAPABILITY_PERM_DENIED */
    }

    int64_t metric = 0;
    if (!evaluate_shear_invariant(prior, candidate, &metric)) {
        return -3; /* ERR_SHEAR_BOUND_BREACH */
    }

    return 0; /* STATUS_ADMITTED */
}

#endif /* SOVR_E8_MATH_H */
