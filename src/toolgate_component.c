/*
 * toolgate_component.c
 * Native seL4 CAmkES runtime component implementation for ToolGate.
 * Connects CAmkES dataport buffers and notification handlers to the verified
 * toolgate admission logic.
 */

#include <camkes.h>
#include <string.h>
#include "sovereign_proposal.h"

/* Declarations from src/toolgate.c */
void toolgate_init(void);
void toolgate_handle_proposal(const sovereign_tool_proposal_t *prop, sovereign_gate_verdict_t *verdict);
uint16_t toolgate_verify_approval(const sovereign_tool_approval_t *app);

/* CAmkES component lifecycle entry point */
void post_init(void) {
    toolgate_init();
}

/*
 * Doorbell handler triggered when Linux guest emits proposal_ready.
 * Evaluates the proposal staged at SOVP_OFFSET_PROPOSAL, coordinates
 * approvals, dispatches to executor over RPC if permitted, and writes
 * verdict / result back into guest_buf.
 */
void proposal_ready_handle(void) {
    /* Map typed pointers directly into fixed non-overlapping dataport offsets */
    volatile uint8_t *base = (volatile uint8_t *)guest_buf;
    const sovereign_tool_proposal_t *prop = (const sovereign_tool_proposal_t *)(base + SOVP_OFFSET_PROPOSAL);
    const sovereign_tool_approval_t *app  = (const sovereign_tool_approval_t *)(base + SOVP_OFFSET_APPROVAL);
    sovereign_gate_verdict_t *verdict     = (sovereign_gate_verdict_t *)(base + SOVP_OFFSET_VERDICT);
    sovereign_tool_result_t *res          = (sovereign_tool_result_t *)(base + SOVP_OFFSET_RESULT);

    /* If incoming frame is an approval relay (SOVQ) */
    if (app->magic == SOVQ_MAGIC) {
        uint16_t status = toolgate_verify_approval(app);
        if (status != SOVR_STATUS_OK) {
            verdict->magic = SOVV_MAGIC;
            verdict->status_code = status;
            verdict->decision = DECISION_DENY;
            verdict_ready_emit();
            return;
        }

        /* Quorum satisfied: dispatch privileged operation to ToolExecutor */
        uint16_t exec_status = exec_execute(
            prop->tool_id,
            prop->arg_len,
            (const uint8_t *)prop->args,
            (uint16_t *)&res->result_len,
            (uint8_t *)res->result
        );

        res->magic = SOVX_MAGIC;
        res->sequence_id = prop->sequence_id;
        res->status_code = exec_status;

        verdict->status_code = SOVR_STATUS_OK;
        verdict->decision = DECISION_ALLOW;
        verdict_ready_emit();
        return;
    }

    /* Otherwise, treat as new proposal evaluation (SOVP) */
    sovereign_gate_verdict_t local_verdict;
    toolgate_handle_proposal(prop, &local_verdict);

    /* Copy verdict out to shared dataport */
    memcpy(verdict, &local_verdict, sizeof(sovereign_gate_verdict_t));

    /* Immediate execution if ALLOWed without quorum requirement */
    if (local_verdict.decision == DECISION_ALLOW && local_verdict.status_code == SOVR_STATUS_OK) {
        uint16_t exec_status = exec_execute(
            prop->tool_id,
            prop->arg_len,
            (const uint8_t *)prop->args,
            (uint16_t *)&res->result_len,
            (uint8_t *)res->result
        );

        res->magic = SOVX_MAGIC;
        res->sequence_id = prop->sequence_id;
        res->status_code = exec_status;
    }

    /* Notify guest VM via GIC SPI notification */
    verdict_ready_emit();
}
