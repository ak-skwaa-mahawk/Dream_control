#ifndef SOVR_IPC_CONTRACT_H
#define SOVR_IPC_CONTRACT_H

#include <stdint.h>

#define SOVR_IPC_MAX_PAYLOAD_WORDS 4
#define SOVR_DATAPORT_PAGE_SIZE    4096
#define SOVR_RING_VECTOR_CAPACITY  50

/* Protocol Identifiers (Passed in Message Tag) */
typedef enum {
    SOVR_PROTO_TOOL_GATE    = 0x01,
    SOVR_PROTO_E8_ROUTER    = 0x02,
    SOVR_PROTO_SLIDE_VECTOR = 0x03,
} sovr_proto_t;

/* Core IPC Register Envelope (Zero-Branch / Cache-Hot: 64 bytes) */
typedef struct {
    uint32_t tag;               /* Bits 0..3: Word count, 4..7: Cap count, 8..15: Proto */
    uint32_t sequence_id;       /* Anti-replay monotonic transaction index */
    uint64_t badge;             /* Hardware-injected sender identity badge */
    uint64_t msg_words[SOVR_IPC_MAX_PAYLOAD_WORDS];
} __attribute__((aligned(64))) sovr_ipc_envelope_t;

/* SlideVector64 Coordinate Element (80 bytes) */
typedef struct {
    int64_t  coordinates[8];    /* E8 dimension projection coordinates (64 bytes) */
    uint64_t energy_metric;     /* Shear energy scalar (8 bytes) */
    uint64_t flags;             /* Vector status flags (8 bytes) */
} sovr_slide_vector_t;

/* Memory-Mapped Shared Dataport (Exact 4096-byte Hardware Page) */
typedef struct {
    /* Cache-line 0: Control & Ownership Synchronization (64 bytes) */
    volatile uint32_t head;
    volatile uint32_t tail;
    uint32_t buffer_flags;
    uint32_t client_state;
    uint8_t  state_anchor[32];   /* Current cryptographic root / drift state */
    uint8_t  _reserved_hdr[16];  /* Pad control header to exact 64 bytes */

    /* Vectors: 50 * 80 bytes = 4000 bytes */
    sovr_slide_vector_t vectors[SOVR_RING_VECTOR_CAPACITY];

    /* Tail padding: 4096 - (64 + 4000) = 32 bytes */
    uint8_t  _page_pad[32];
} __attribute__((aligned(SOVR_DATAPORT_PAGE_SIZE))) sovr_dataport_ring_t;

#endif /* SOVR_IPC_CONTRACT_H */
