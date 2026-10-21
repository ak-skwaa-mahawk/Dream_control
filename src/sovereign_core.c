#include <stdint.h>
#include "phase_slider.h"
#include "sovereign_ipc.h"
#include "../test/sovereign_assert.h"

__attribute__((section(".ring_frame")))
SovereignAuditRing g_audit_ring;

void execute_sovereign_runtime(SlideVector64 *sv, SovereignKernelContext *ctx, uint64_t tick_stride, uint64_t runtime_cycles) {
    /* Execute bare-metal assertion harness */
    if (run_sovereign_suite(&g_audit_ring) != 0) {
        ctx->status = 0xDEADFA17ULL;
        return;
    }

    ctx->status = 0x1ULL; /* OPERATIONAL */

    for (uint64_t cycle = 0; cycle < runtime_cycles; cycle++) {
        slide_forward(sv);
        ctx->last_sync_tick += tick_stride;

        /* Non-blocking boundary yield */
        if (cycle == 0xFFFFFF) {
            break;
        }
    }
}
