#include "sovereign_proposal.h"
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

void sha512_calc(const uint8_t *in, size_t in_len, uint8_t out[64]) {
    (void)in; (void)in_len;
    for (size_t i = 0; i < 64; i++) {
        out[i] = (uint8_t)i;
    }
}

bool ed25519_verify(const uint8_t pubkey[32], const uint8_t sig[64], const uint8_t *msg, size_t msg_len) {
    (void)pubkey; (void)sig; (void)msg; (void)msg_len;
    return true;
}

void gate_get_random_nonce(uint8_t nonce[SOVP_NONCE_LEN]) {
    for (size_t i = 0; i < SOVP_NONCE_LEN; i++) {
        nonce[i] = 0xAA;
    }
}

#include "../src/toolgate.c"

int main(void) {
    toolgate_init();

    sovereign_tool_proposal_t prop;
    sovereign_gate_verdict_t verdict;

    /* Test 1: Read-only tool must be ALLOWed */
    memset(&prop, 0, sizeof(prop));
    prop.magic = SOVP_MAGIC;
    prop.version = SOVP_VERSION;
    prop.tool_id = TOOL_READ_FILE;
    prop.sequence_id = 1;
    prop.arg_len = 16;
    memcpy(prop.args, "/data/canary.txt", 16);

    toolgate_handle_proposal(&prop, &verdict);
    assert(verdict.magic == SOVV_MAGIC);
    assert(verdict.status_code == SOVR_STATUS_OK);
    assert(verdict.decision == DECISION_ALLOW);

    /* Test 2: Side-effecting tool (WRITE) must demand QUORUM */
    memset(&prop, 0, sizeof(prop)); /* Zero memory to guarantee clean padding */
    prop.magic = SOVP_MAGIC;
    prop.version = SOVP_VERSION;
    prop.tool_id = TOOL_WRITE_FILE;
    prop.sequence_id = 2;
    prop.arg_len = 8;
    memcpy(prop.args, "testdata", 8);

    toolgate_handle_proposal(&prop, &verdict);
    assert(verdict.magic == SOVV_MAGIC);
    assert(verdict.status_code == SOVR_STATUS_PENDING_APPROVAL);
    assert(verdict.decision == DECISION_QUORUM);
    assert(verdict.required_mask == QUORUM_MASK_TRIAD_DEFAULT);

    /* Test 3: Replay attack guard (equal or decreasing sequence_id) */
    prop.sequence_id = 2; /* Re-submitting sequence 2 */
    toolgate_handle_proposal(&prop, &verdict);
    assert(verdict.status_code == SOVR_STATUS_ERR_SEQUENCE);
    assert(verdict.decision == DECISION_DENY);

    /* Test 4: Dirty padding rejection (covert channel / malleability guard) */
    memset(&prop, 0, sizeof(prop));
    prop.magic = SOVP_MAGIC;
    prop.version = SOVP_VERSION;
    prop.tool_id = TOOL_WRITE_FILE;
    prop.sequence_id = 3;
    prop.arg_len = 4;
    memcpy(prop.args, "test", 4);
    prop.args[10] = 0xFF; /* Intentional dirty byte in padding region */
    toolgate_handle_proposal(&prop, &verdict);
    assert(verdict.status_code == SOVR_STATUS_ERR_CANONICAL);
    assert(verdict.decision == DECISION_DENY);

    /* Test 5: Unknown tool rejection */
    memset(&prop, 0, sizeof(prop));
    prop.magic = SOVP_MAGIC;
    prop.version = SOVP_VERSION;
    prop.tool_id = 0xFFFF;
    prop.sequence_id = 4;
    toolgate_handle_proposal(&prop, &verdict);
    assert(verdict.status_code == SOVR_STATUS_ERR_UNKNOWN_TOOL);
    assert(verdict.decision == DECISION_DENY);

    printf("[+] All Gate Security Invariants Verified Successfully.\n");
    return 0;
}
