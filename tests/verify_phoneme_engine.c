#include <stdio.h>
#include <assert.h>
#include "../include/sovr_phoneme_engine.h"

int main(void) {
    /* 1. Invariant Envelope Size Check */
    assert(sizeof(sovr_phoneme_ipc_t) == 64);

    /* 2. Encode Minimal Pair: shih (/ʃɪh/, brown bear) vs shìh (/ʃɪ̀h/, food) */
    /* Onset: sh=34, Nucl: i=3, Coda: h=2 */
    sovr_phoneme_desc_t bear_desc = {
        .onset_id = 34,
        .nucleus_id = 3,
        .nasal = false,
        .is_long = false,
        .tone_id = GWICHIN_TONE_UNMARKED_HIGH, /* 0 */
        .coda_id = 2,
        .prefix_id = DENE_CLASSIFIER_NONE,
        .provenance = 0x1A4
    };

    sovr_phoneme_desc_t food_desc = bear_desc;
    food_desc.tone_id = GWICHIN_TONE_LOW_GRAVE; /* 1 */

    uint32_t w_bear = sovr_phoneme_pack(&bear_desc);
    uint32_t w_food = sovr_phoneme_pack(&food_desc);

    printf("[+] Bear Word (shih): 0x%08X\n", w_bear);
    printf("[+] Food Word (shìh): 0x%08X\n", w_food);

    /* Assert bit inversion is strictly at bit position 19 */
    uint32_t diff = w_bear ^ w_food;
    assert(diff == (1U << PHONEME_TONE_SHIFT));
    printf("[+] Minimal pair verified: exact bit flip at position %u (diff=0x%08X).\n", 
           PHONEME_TONE_SHIFT, diff);

    /* 3. Bidirectional Unpack Check */
    sovr_phoneme_desc_t unpacked;
    sovr_phoneme_unpack(w_food, &unpacked);

    assert(unpacked.onset_id == 34);
    assert(unpacked.nucleus_id == 3);
    assert(unpacked.tone_id == GWICHIN_TONE_LOW_GRAVE);
    assert(unpacked.coda_id == 2);
    assert(unpacked.provenance == 0x1A4);
    printf("[+] Round-trip unpack deterministic and exact.\n");

    return 0;
}
