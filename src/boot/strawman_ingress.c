#include "sovr_phoneme_engine.h"
#include <stdint.h>
#include <stdbool.h>
#include "ipc_contract.h"
#include "sovr_e8_math.h"


/* Zero-alloc Athabaskan phonetic gatekeeper */
static inline bool sovr_validate_phoneme_word(uint32_t w) {
    sovr_phoneme_desc_t desc;
    sovr_phoneme_unpack(w, &desc);
    if (desc.onset_id > 51) return false;
    if (desc.nucleus_id > 7) return false;
    if (desc.tone_id > 3) return false;
    if (desc.coda_id > 31 && desc.coda_id != 63) return false;
    return true;
}


extern sovr_dataport_ring_t _sovr_shared_dataport;

/* Freestanding Strawman policy engine main ingress loop */
void strawman_ingress_entry(void) {
    uint32_t expected_seq = 1;
    volatile sovr_dataport_ring_t *ring = &_sovr_shared_dataport;

    while (1) {
        if (ring->head != ring->tail) {
            uint32_t idx = ring->tail % SOVR_RING_VECTOR_CAPACITY;
            int64_t candidate[8];

            for (int i = 0; i < 8; i++) {
                candidate[i] = ring->vectors[idx].coordinates[i];
            }

            /* Phonological register gatekeeper check (bits stored in coordinate channel 4) */
            uint32_t phoneme_word = (uint32_t)(candidate[4] & 0xFFFFFFFF);
            if (phoneme_word != 0 && !sovr_validate_phoneme_word(phoneme_word)) {
                ring->buffer_flags = 0xDEAD; /* Trap on phonotactic violation */
                continue;
            }

            int64_t prior[8] = { 1288500, 152100, 1000000, 1000000, 0, 0, 0, 0 };
            uint64_t client_badge = (uint64_t)ring->client_state;

            int32_t code = strawman_admit_proposal(
                client_badge,
                expected_seq,
                ring->head,
                prior,
                candidate
            );

            if (code == 0) {
                ring->tail = (ring->tail + 1) % SOVR_RING_VECTOR_CAPACITY;
                expected_seq++;
            } else {
                ring->buffer_flags = 0xDEAD; /* Trap on violation */
            }
        }
    }
}
