#ifndef SOVEREIGN_PROPOSAL_H
#define SOVEREIGN_PROPOSAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SOVP_MAGIC   0x534F5650U  /* 'SOVP' guest -> gate: proposal */
#define SOVV_MAGIC   0x534F5656U  /* 'SOVV' gate -> guest: verdict  */
#define SOVQ_MAGIC   0x534F5651U  /* 'SOVQ' guest -> gate: approval */
#define SOVX_MAGIC   0x534F5658U  /* 'SOVX' gate -> guest: result   */

#define SOVP_VERSION             1U
#define SOVP_MAX_ARGS            992U
#define SOVP_MAX_RESULT          1008U
#define SOVP_NONCE_LEN           16U
#define SOVP_CHALLENGE_LEN       64U
#define SOVP_DOMAIN_SEP          "SOVP-APPROVE-v1"
#define MAX_QUORUM_SIGNERS       4U

/* 4KB Shared Dataport Offsets */
#define SOVP_OFFSET_PROPOSAL     0x0000U
#define SOVP_OFFSET_APPROVAL     0x0400U
#define SOVP_OFFSET_VERDICT      0x0600U
#define SOVP_OFFSET_RESULT       0x0800U

/* Tool IDs */
#define TOOL_READ_FILE           0x0001U
#define TOOL_HTTP_GET            0x0002U
#define TOOL_WRITE_FILE          0x0101U
#define TOOL_SEND_MESSAGE        0x0102U

/* Decisions */
#define DECISION_DENY            0U
#define DECISION_ALLOW           1U
#define DECISION_QUORUM          2U

/* Status Codes */
#define SOVR_STATUS_OK                0x0000U
#define SOVR_STATUS_ERR_MAGIC         0xE001U
#define SOVR_STATUS_ERR_VERSION       0xE002U
#define SOVR_STATUS_ERR_ARGS_LEN      0xE003U
#define SOVR_STATUS_ERR_CANONICAL     0xE004U
#define SOVR_STATUS_ERR_SEQUENCE      0xE005U
#define SOVR_STATUS_ERR_UNKNOWN_TOOL  0xE006U
#define SOVR_STATUS_PENDING_APPROVAL  0xE007U
#define SOVR_STATUS_ERR_STALE         0xE008U
#define SOVR_STATUS_ERR_QUORUM_COUNT  0xE00AU
#define SOVR_STATUS_ERR_SIG_FAIL      0xE00BU

#define SIGNER_MASK_A                 (1U << 0)
#define SIGNER_MASK_B                 (1U << 1)
#define SIGNER_MASK_C                 (1U << 2)
#define SIGNER_MASK_D                 (1U << 3)
#define QUORUM_MASK_TRIAD_DEFAULT     (SIGNER_MASK_A | SIGNER_MASK_B | SIGNER_MASK_C)

#pragma pack(push, 1)

typedef struct {
    uint8_t signer_index;
    uint8_t reserved[7];
    uint8_t signature[64];
    uint8_t public_key[32];
} sovereign_witness_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t tool_id;
    uint64_t sequence_id;
    uint64_t session_id;
    uint16_t arg_len;
    uint16_t reserved0;
    uint32_t reserved1;
    uint8_t  args[SOVP_MAX_ARGS];
} sovereign_tool_proposal_t;

typedef struct {
    uint32_t magic;
    uint16_t status_code;
    uint8_t  decision;
    uint8_t  required_mask;
    uint64_t sequence_id;
    uint8_t  gate_nonce[SOVP_NONCE_LEN];
    uint8_t  challenge[SOVP_CHALLENGE_LEN];
} sovereign_gate_verdict_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved0;
    uint64_t sequence_id;
    uint8_t  signer_bitmap;
    uint8_t  quorum_count;
    uint8_t  reserved_pad[6];
    sovereign_witness_t witnesses[MAX_QUORUM_SIGNERS];
} sovereign_tool_approval_t;

typedef struct {
    uint32_t magic;
    uint16_t status_code;
    uint16_t result_len;
    uint64_t sequence_id;
    uint8_t  result[SOVP_MAX_RESULT];
} sovereign_tool_result_t;

typedef struct {
    uint16_t tool_id;
    uint8_t  decision;
    uint8_t  required_mask;
    uint16_t min_arg_len;
    uint16_t max_arg_len;
} sovereign_tool_policy_t;

#pragma pack(pop)

_Static_assert(sizeof(sovereign_witness_t)       == 104,  "witness layout");
_Static_assert(sizeof(sovereign_tool_proposal_t) == 1024, "proposal must be 1024 bytes");
_Static_assert(sizeof(sovereign_gate_verdict_t)  == 96,   "verdict must be 96 bytes");
_Static_assert(sizeof(sovereign_tool_approval_t) == 440,  "approval size");
_Static_assert(sizeof(sovereign_tool_result_t)   == 1024, "result must be 1024 bytes");

_Static_assert(SOVP_OFFSET_PROPOSAL + sizeof(sovereign_tool_proposal_t) <= SOVP_OFFSET_APPROVAL, "buffer overlap 1");
_Static_assert(SOVP_OFFSET_APPROVAL + sizeof(sovereign_tool_approval_t) <= SOVP_OFFSET_VERDICT,  "buffer overlap 2");
_Static_assert(SOVP_OFFSET_VERDICT  + sizeof(sovereign_gate_verdict_t)  <= SOVP_OFFSET_RESULT,   "buffer overlap 3");
_Static_assert(SOVP_OFFSET_RESULT   + sizeof(sovereign_tool_result_t)   <= 4096,                 "buffer overflow");

static const sovereign_tool_policy_t SOVP_POLICY[] = {
    { TOOL_READ_FILE,    DECISION_ALLOW,  0,                         1, 256 },
    { TOOL_HTTP_GET,     DECISION_ALLOW,  0,                         1, 512 },
    { TOOL_WRITE_FILE,   DECISION_QUORUM, QUORUM_MASK_TRIAD_DEFAULT, 2, SOVP_MAX_ARGS },
    { TOOL_SEND_MESSAGE, DECISION_QUORUM, QUORUM_MASK_TRIAD_DEFAULT, 2, SOVP_MAX_ARGS },
};

#endif /* SOVEREIGN_PROPOSAL_H */
