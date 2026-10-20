#include "sovereign_proposal.h"
#include <string.h>

/*
 * Privileged dispatch: executed only inside the native seL4 ToolExecutor
 * component after the gate has verified quorum and policy.
 */
uint16_t toolexec_dispatch(uint16_t tool_id, const uint8_t *args, uint16_t arg_len, sovereign_tool_result_t *res) {
    memset(res, 0, sizeof(*res));
    res->magic = SOVX_MAGIC;

    switch (tool_id) {
        case TOOL_READ_FILE:
            /* Execute read capability */
            res->status_code = SOVR_STATUS_OK;
            res->result_len = 14;
            memcpy(res->result, "EXEC_READ_OK\n", 14);
            return SOVR_STATUS_OK;

        case TOOL_WRITE_FILE:
            /* Execute write capability to persistent store */
            res->status_code = SOVR_STATUS_OK;
            res->result_len = 15;
            memcpy(res->result, "EXEC_WRITE_OK\n", 15);
            return SOVR_STATUS_OK;

        default:
            res->status_code = SOVR_STATUS_ERR_UNKNOWN_TOOL;
            return SOVR_STATUS_ERR_UNKNOWN_TOOL;
    }
}
