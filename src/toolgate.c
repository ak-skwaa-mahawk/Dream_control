#include "sovereign_proposal.h"
#include <string.h>

extern void sha512_calc(const uint8_t *in, size_t in_len, uint8_t out[64]);
extern bool ed25519_verify(const uint8_t pubkey[32], const uint8_t sig[64], const uint8_t *msg, size_t msg_len);
extern void gate_get_random_nonce(uint8_t nonce[SOVP_NONCE_LEN]);

typedef struct {
    uint64_t last_seen_sequence_id;
    bool has_active_challenge;
    uint64_t active_challenge_seq;
    uint8_t active_required_mask;
    uint8_t active_challenge[SOVP_CHALLENGE_LEN];
} gate_state_t;

static gate_state_t g_state;

static const sovereign_tool_policy_t *lookup_policy(uint16_t tool_id) {
    size_t count = sizeof(SOVP_POLICY) / sizeof(SOVP_POLICY[0]);
    for (size_t i = 0; i < count; i++) {
        if (SOVP_POLICY[i].tool_id == tool_id) {
            return &SOVP_POLICY[i];
        }
    }
    return NULL;
}

static uint8_t count_bits(uint8_t val) {
    uint8_t c = 0;
    while (val) {
        c += (uint8_t)(val & 1U);
        val >>= 1;
    }
    return c;
}

void toolgate_init(void) {
    memset(&g_state, 0, sizeof(g_state));
}

void toolgate_handle_proposal(const sovereign_tool_proposal_t *prop, sovereign_gate_verdict_t *verdict) {
    memset(verdict, 0, sizeof(*verdict));
    verdict->magic = SOVV_MAGIC;
    verdict->sequence_id = prop->sequence_id;

    if (prop->magic != SOVP_MAGIC) {
        verdict->status_code = SOVR_STATUS_ERR_MAGIC;
        verdict->decision = DECISION_DENY;
        return;
    }
    if (prop->version != SOVP_VERSION) {
        verdict->status_code = SOVR_STATUS_ERR_VERSION;
        verdict->decision = DECISION_DENY;
        return;
    }
    if (prop->sequence_id <= g_state.last_seen_sequence_id) {
        verdict->status_code = SOVR_STATUS_ERR_SEQUENCE;
        verdict->decision = DECISION_DENY;
        return;
    }
    if (prop->arg_len > SOVP_MAX_ARGS) {
        verdict->status_code = SOVR_STATUS_ERR_ARGS_LEN;
        verdict->decision = DECISION_DENY;
        return;
    }

    for (size_t i = prop->arg_len; i < SOVP_MAX_ARGS; i++) {
        if (prop->args[i] != 0U) {
            verdict->status_code = SOVR_STATUS_ERR_CANONICAL;
            verdict->decision = DECISION_DENY;
            return;
        }
    }

    const sovereign_tool_policy_t *policy = lookup_policy(prop->tool_id);
    if (!policy) {
        verdict->status_code = SOVR_STATUS_ERR_UNKNOWN_TOOL;
        verdict->decision = DECISION_DENY;
        return;
    }
    if (prop->arg_len < policy->min_arg_len || prop->arg_len > policy->max_arg_len) {
        verdict->status_code = SOVR_STATUS_ERR_ARGS_LEN;
        verdict->decision = DECISION_DENY;
        return;
    }

    g_state.last_seen_sequence_id = prop->sequence_id;

    if (policy->decision == DECISION_ALLOW) {
        verdict->status_code = SOVR_STATUS_OK;
        verdict->decision = DECISION_ALLOW;
        return;
    }

    if (policy->decision == DECISION_QUORUM) {
        verdict->status_code = SOVR_STATUS_PENDING_APPROVAL;
        verdict->decision = DECISION_QUORUM;
        verdict->required_mask = policy->required_mask;

        gate_get_random_nonce(verdict->gate_nonce);

        uint8_t pre_image[sizeof(SOVP_DOMAIN_SEP) - 1U + sizeof(sovereign_tool_proposal_t) + SOVP_NONCE_LEN];
        size_t off = 0;

        memcpy(&pre_image[off], SOVP_DOMAIN_SEP, sizeof(SOVP_DOMAIN_SEP) - 1U);
        off += sizeof(SOVP_DOMAIN_SEP) - 1U;

        memcpy(&pre_image[off], prop, sizeof(sovereign_tool_proposal_t));
        off += sizeof(sovereign_tool_proposal_t);

        memcpy(&pre_image[off], verdict->gate_nonce, SOVP_NONCE_LEN);
        off += SOVP_NONCE_LEN;

        sha512_calc(pre_image, off, verdict->challenge);

        g_state.has_active_challenge = true;
        g_state.active_challenge_seq = prop->sequence_id;
        g_state.active_required_mask = policy->required_mask;
        memcpy(g_state.active_challenge, verdict->challenge, SOVP_CHALLENGE_LEN);
        return;
    }

    verdict->status_code = SOVR_STATUS_OK;
    verdict->decision = DECISION_DENY;
}

uint16_t toolgate_verify_approval(const sovereign_tool_approval_t *app) {
    if (app->magic != SOVQ_MAGIC) return SOVR_STATUS_ERR_MAGIC;
    if (app->version != SOVP_VERSION) return SOVR_STATUS_ERR_VERSION;
    if (!g_state.has_active_challenge) return SOVR_STATUS_ERR_STALE;
    if (app->sequence_id != g_state.active_challenge_seq) return SOVR_STATUS_ERR_STALE;

    if (count_bits(app->signer_bitmap) != app->quorum_count) {
        return SOVR_STATUS_ERR_QUORUM_COUNT;
    }
    if ((app->signer_bitmap & g_state.active_required_mask) != g_state.active_required_mask) {
        return SOVR_STATUS_ERR_QUORUM_COUNT;
    }

    for (uint8_t i = 0; i < app->quorum_count && i < MAX_QUORUM_SIGNERS; i++) {
        const sovereign_witness_t *w = &app->witnesses[i];
        if (!ed25519_verify(w->public_key, w->signature, g_state.active_challenge, SOVP_CHALLENGE_LEN)) {
            return SOVR_STATUS_ERR_SIG_FAIL;
        }
    }

    g_state.has_active_challenge = false;
    return SOVR_STATUS_OK;
}
