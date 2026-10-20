#include <stdio.h>
#include <assert.h>
#include "sovr_e8_math.h"

int main(void) {
    printf("=== Testing Native Invariant Math (Zero-Alloc) ===\n");

    int64_t prior[8]     = { 1288500, 152100, 1000000, 1000000, 0, 0, 0, 0 };
    int64_t candidate[8] = { 1288100, 151700, 1000000, 1000000, 0, 0, 0, 0 };

    int64_t metric = 0;
    bool admitted = evaluate_shear_invariant(prior, candidate, &metric);

    printf("[1] Computed metric: %ld (threshold: %lld)\n", metric, MAX_SHEAR_BOUND_FIXED);
    assert(admitted == true);
    assert(metric <= MAX_SHEAR_BOUND_FIXED);

    /* Test Triad Quorum authorization (badge: 0x07) */
    int32_t status = strawman_admit_proposal(0x07, 100, 100, prior, candidate);
    printf("[2] Strawman admission return code: %d\n", status);
    assert(status == 0);

    /* Test unauthorized badge rejection (badge: 0x03 -> missing Signer C) */
    status = strawman_admit_proposal(0x03, 101, 101, prior, candidate);
    printf("[3] Unauthorized badge rejection code: %d\n", status);
    assert(status == -2);

    printf("[+] Native invariant arithmetic matches system expectations.\n");
    return 0;
}
