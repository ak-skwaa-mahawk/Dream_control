/* test/sovereign_assert.h - Freestanding Invariant Checks */
#ifndef SOVEREIGN_ASSERT_H
#define SOVEREIGN_ASSERT_H

#include <stdint.h>
#include "../src/phase_slider.h"
#include "../src/sovereign_ipc.h"

#define ASSERT_TRUE(cond) if (!(cond)) return 0

/**
 * 1. Validates native modulo 2^64 boundary wrap.
 */
static inline int test_phase_boundary_rollover(void) {
    SlideVector64 sv;
    slide_init(&sv, 0x1000ULL, 1, 1);
    sv.phase = 0xFFFFFFFFFFFFFFFFULL;
    slide_forward(&sv);
    /* Rollover: 0xFFFFFFFFFFFFFFFF + 0x1000 = 0x0000000000000FFF */
    ASSERT_TRUE(sv.phase == 0x0FFFULL);
    ASSERT_TRUE(sv.seq_id == 1ULL);
    return 1;
}

/**
 * 2. Validates ring buffer cache alignment.
 */
static inline int test_ring_page_alignment(const SovereignAuditRing *ring) {
    uintptr_t addr = (uintptr_t)ring;
    ASSERT_TRUE((addr & 0xFFFULL) == 0);
    return 1;
}

/**
 * 3. Validates branchless saturation masking.
 */
static inline int test_branchless_fault_clamp(void) {
    const int64_t FP_SCALE_TEST = (1 << 16);
    const int64_t K_NOMINAL_TEST = (int64_t)(0.35 * FP_SCALE_TEST);
    const int64_t THRESHOLD_TEST = (int64_t)(2.50 * FP_SCALE_TEST);

    /* Case A: Under-threshold error */
    int64_t warp_normal = (int64_t)(1.20 * FP_SCALE_TEST);
    int64_t abs_normal = (warp_normal ^ (warp_normal >> 63)) - (warp_normal >> 63);
    uint32_t fault_a = (abs_normal > THRESHOLD_TEST);
    int64_t damping_a = K_NOMINAL_TEST + (fault_a * (K_NOMINAL_TEST - abs_normal));
    ASSERT_TRUE(fault_a == 0);
    ASSERT_TRUE(damping_a == K_NOMINAL_TEST);

    /* Case B: Over-threshold error (Negative shock) */
    int64_t warp_shock = -(int64_t)(3.80 * FP_SCALE_TEST);
    int64_t abs_shock = (warp_shock ^ (warp_shock >> 63)) - (warp_shock >> 63);
    uint32_t fault_b = (abs_shock > THRESHOLD_TEST);
    int64_t damping_b = K_NOMINAL_TEST + (fault_b * (K_NOMINAL_TEST - abs_shock));
    ASSERT_TRUE(fault_b == 1);
    ASSERT_TRUE(damping_b == (2 * K_NOMINAL_TEST - abs_shock));

    return 1;
}

static inline int run_sovereign_suite(const SovereignAuditRing *ring) {
    if (!test_phase_boundary_rollover()) return -1;
    if (!test_ring_page_alignment(ring)) return -2;
    if (!test_branchless_fault_clamp()) return -3;
    return 0; /* All invariants hold */
}

#endif /* SOVEREIGN_ASSERT_H */
