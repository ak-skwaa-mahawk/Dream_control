#include <stdio.h>
#include <assert.h>
#include "../include/ipc_contract.h"

typedef struct {
    uint32_t syllable_word;
    uint32_t sequence_id;
    uint64_t timestamp_ns;
    uint8_t  hash_commitment[32];
    uint8_t  pad[16];
} __attribute__((packed)) sovr_phoneme_ipc_t;

int main(void) {
    assert(sizeof(sovr_phoneme_ipc_t) == 64);
    printf("[+] sovr_phoneme_ipc_t verified: exactly 64 bytes.\n");
    return 0;
}
