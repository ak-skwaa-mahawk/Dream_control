/* src/phase_slider.h - 64-Bit Continuous Invariant Slider */
#ifndef PHASE_SLIDER_H
#define PHASE_SLIDER_H

#include <stdint.h>

typedef struct {
    uint64_t phase;       /* Current angle mapped over [0, 2^64 - 1] ≡ [0, 2π) */
    uint64_t phase_step;  /* Angular velocity per clock tick */
    uint64_t radius_num;  /* Fixed-point scale numerator */
    uint64_t radius_den;  /* Fixed-point scale denominator */
    uint64_t seq_id;      /* Monotonically advancing counter */
} SlideVector64;

typedef struct {
    uint64_t phase;
    uint64_t radius_num;
    uint64_t radius_den;
    uint64_t seq_id;
} SlideReceipt;

static inline void slide_init(SlideVector64 *sv, uint64_t step, uint64_t r_num, uint64_t r_den) {
    sv->phase = 0ULL;
    sv->phase_step = step;
    sv->radius_num = r_num;
    sv->radius_den = r_den;
    sv->seq_id = 0ULL;
}

static inline void slide_forward(SlideVector64 *sv) {
    /* Pure hardware ALU modulo 2^64: 0xFFFFFFFFFFFFFFFF + 1 wraps to 0x0 without branching */
    sv->phase += sv->phase_step;
    sv->seq_id++;
}

static inline void slide_emit_receipt(const SlideVector64 *sv, SlideReceipt *out) {
    out->phase = sv->phase;
    out->radius_num = sv->radius_num;
    out->radius_den = sv->radius_den;
    out->seq_id = sv->seq_id;
}

#endif /* PHASE_SLIDER_H */
