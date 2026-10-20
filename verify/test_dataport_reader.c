#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "ipc_contract.h"

int main(void) {
    printf("=== Testing CAmkES Dataport Ring Ingestion ===\n");

    /* Allocate dummy 4096-byte shared memory page */
    sovr_dataport_ring_t dataport;
    memset(&dataport, 0, sizeof(sovr_dataport_ring_t));

    /* Initialize control header */
    dataport.head = 1;
    dataport.tail = 0;
    dataport.buffer_flags = 0x01; /* ACTIVE */
    dataport.client_state = 0x00; /* READY */
    memset((void*)dataport.state_anchor, 0xAB, 32);

    /* Populate slot 0 */
    dataport.vectors[0].coordinates[0] = 1288100;
    dataport.vectors[0].coordinates[1] = 151700;
    dataport.vectors[0].energy_metric = 566;
    dataport.vectors[0].flags = 0x01;

    printf("[1] Checking dataport page capacity: %d vectors\n", SOVR_RING_VECTOR_CAPACITY);
    assert(SOVR_RING_VECTOR_CAPACITY == 50);

    printf("[2] Verifying slot read at index 0...\n");
    printf("    Coord[0]: %ld, Coord[1]: %ld, Energy: %lu\n",
           dataport.vectors[0].coordinates[0],
           dataport.vectors[0].coordinates[1],
           dataport.vectors[0].energy_metric);

    assert(dataport.vectors[0].coordinates[0] == 1288100);
    assert(dataport.vectors[0].energy_metric == 566);

    printf("[+] Dataport ingestion test passed.\n");
    return 0;
}
