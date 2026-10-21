#ifndef SOVEREIGN_IPC_H
#define SOVEREIGN_IPC_H

#include <stdint.h>

#define RING_BUFFER_SIZE 256

typedef struct {
    uint64_t head;
    uint64_t tail;
    uint64_t entries[RING_BUFFER_SIZE];
} __attribute__((aligned(4096))) SovereignAuditRing;

typedef struct {
    uint64_t status;
    uint64_t fault_count;
    uint64_t last_sync_tick;
} SovereignKernelContext;

#endif /* SOVEREIGN_IPC_H */
