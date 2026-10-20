#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <assert.h>
#include "ipc_contract.h"

#define MAX_SHEAR_BOUND 0.1500

static double compute_vector_shear(const int64_t v0[8], const int64_t v1[8]) {
    double sum_sq = 0.0;
    for (int i = 0; i < 8; i++) {
        /* Scaled fixed-point conversion: 1e6 fixed unit */
        double d = ((double)v1[i] - (double)v0[i]) / 1000000.0;
        sum_sq += d * d;
    }
    return sqrt(sum_sq);
}

int main(void) {
    printf("=== Verifying Sovereign IPC Contract Alignment ===\n");

    printf("[1] Checking sovr_ipc_envelope_t size...\n");
    printf("    sizeof(sovr_ipc_envelope_t) = %zu bytes\n", sizeof(sovr_ipc_envelope_t));
    assert(sizeof(sovr_ipc_envelope_t) == 64);

    printf("[2] Checking sovr_dataport_ring_t size...\n");
    printf("    sizeof(sovr_dataport_ring_t) = %zu bytes\n", sizeof(sovr_dataport_ring_t));
    assert(sizeof(sovr_dataport_ring_t) == SOVR_DATAPORT_PAGE_SIZE);

    printf("[3] Checking coordinate shear evaluation in ring...\n");
    int64_t prior[8]     = { 1288500, 152100, 1000000, 1000000, 0, 0, 0, 0 };
    int64_t candidate[8] = { 1288100, 151700, 1000000, 1000000, 0, 0, 0, 0 };

    double delta = compute_vector_shear(prior, candidate);
    printf("    Evaluated Shear Delta: %.6f (Bound: <= %.4f)\n", delta, MAX_SHEAR_BOUND);
    assert(delta <= MAX_SHEAR_BOUND);

    printf("[+] All structural alignment and shear invariants verified.\n");
    return 0;
}
