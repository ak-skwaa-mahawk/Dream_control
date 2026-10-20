#include <stdio.h>
#include <assert.h>
#include "../include/sovr_phoneme_engine.h"

int main(void) {
    /* Galtee sirrii: shih (0x898041A4) -> onset=34, nucl=3, tone=0, coda=2 */
    uint32_t valid_word = 0x898041A4;
    sovr_phoneme_desc_t d1;
    sovr_phoneme_unpack(valid_word, &d1);
    assert(d1.onset_id <= 51);
    assert(d1.nucleus_id <= 7);
    assert(d1.tone_id <= 3);
    printf("[+] Galteen sirriin (%s) daangaa keessa jira.\n", "shih");

    /* Galtee dogoggoraa: Onset ID 60 (daangaa 51 ol) */
    uint32_t invalid_word = valid_word | (60U << PHONEME_ONSET_SHIFT);
    sovr_phoneme_desc_t d2;
    sovr_phoneme_unpack(invalid_word, &d2);
    assert(d2.onset_id > 51);
    printf("[+] Galteen dogoggoraa (Onset ID %u) qabamee kuffifamuuf qophiidha.\n", d2.onset_id);

    return 0;
}
