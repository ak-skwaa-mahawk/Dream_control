#ifndef SOVR_PHONEME_ENGINE_H
#define SOVR_PHONEME_ENGINE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Sovereign Phonological Engine ABI v1.3.0 (Athabaskan / Gwich'in)
 * Register Layout: 32-bit Packed Word
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Onset ID (6b)  | Nucl (3b)|N|L|T(2b)|  Coda ID (6b)  |Prf(3b)| Prov (10b) |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define PHONEME_ONSET_MASK     0x3FU
#define PHONEME_ONSET_SHIFT    26U

#define PHONEME_NUCL_MASK      0x07U
#define PHONEME_NUCL_SHIFT     23U

#define PHONEME_NASAL_MASK     0x01U
#define PHONEME_NASAL_SHIFT    22U

#define PHONEME_LONG_MASK      0x01U
#define PHONEME_LONG_SHIFT     21U

#define PHONEME_TONE_MASK      0x03U
#define PHONEME_TONE_SHIFT     19U

#define PHONEME_CODA_MASK      0x3FU
#define PHONEME_CODA_SHIFT     13U

#define PHONEME_PREF_MASK      0x07U
#define PHONEME_PREF_SHIFT     10U

#define PHONEME_PROV_MASK      0x3FFU
#define PHONEME_PROV_SHIFT     0U

/* Gwich'in Tonogenetic Encodings (Low-Marked Paradigm) */
#define GWICHIN_TONE_UNMARKED_HIGH 0x00U
#define GWICHIN_TONE_LOW_GRAVE     0x01U
#define GWICHIN_TONE_CONTOUR_FALL  0x02U
#define GWICHIN_TONE_CONTOUR_RISE  0x03U

/* Athabaskan Valence / Classifier Prefix Encodings */
#define DENE_CLASSIFIER_NONE       0x00U
#define DENE_CLASSIFIER_ZERO       0x01U /* ∅-classifier */
#define DENE_CLASSIFIER_TL         0x02U /* ł-transitive/causative */
#define DENE_CLASSIFIER_D          0x03U /* d-middle/reflexive */
#define DENE_CLASSIFIER_L          0x04U /* l-passive */
#define DENE_PREFIX_SH             0x05U /* 1sg marker (sh-) */
#define DENE_PREFIX_N              0x06U /* 2sg marker (n-) */
#define DENE_PREFIX_V              0x07U /* 3sg / areal marker (v-/y-) */

typedef struct {
    uint8_t  onset_id;    /* 0 - 63 */
    uint8_t  nucleus_id;  /* 0 - 7  */
    bool     nasal;       /* 0 - 1  */
    bool     is_long;     /* 0 - 1  */
    uint8_t  tone_id;     /* 0 - 3  */
    uint8_t  coda_id;     /* 0 - 63 */
    uint8_t  prefix_id;   /* 0 - 7  */
    uint16_t provenance;  /* 0 - 1023 */
} sovr_phoneme_desc_t;

typedef struct {
    uint32_t syllable_word;      /* 32-bit packed hardware register */
    uint32_t sequence_id;        /* Monotonic syllable sequence index */
    uint64_t timestamp_ns;       /* Nanosecond precision timestamp */
    uint8_t  hash_commitment[32];/* ZK-STARK Merkle leaf commitment */
    uint8_t  pad[16];            /* Invariant 64-byte envelope alignment */
} __attribute__((packed)) sovr_phoneme_ipc_t;

_Static_assert(sizeof(sovr_phoneme_ipc_t) == 64, "sovr_phoneme_ipc_t must align to 64 bytes");

static inline uint32_t sovr_phoneme_pack(const sovr_phoneme_desc_t *d) {
    uint32_t w = 0;
    w |= ((uint32_t)(d->onset_id   & PHONEME_ONSET_MASK)) << PHONEME_ONSET_SHIFT;
    w |= ((uint32_t)(d->nucleus_id & PHONEME_NUCL_MASK))  << PHONEME_NUCL_SHIFT;
    w |= ((uint32_t)(d->nasal      & PHONEME_NASAL_MASK)) << PHONEME_NASAL_SHIFT;
    w |= ((uint32_t)(d->is_long    & PHONEME_LONG_MASK))  << PHONEME_LONG_SHIFT;
    w |= ((uint32_t)(d->tone_id    & PHONEME_TONE_MASK))  << PHONEME_TONE_SHIFT;
    w |= ((uint32_t)(d->coda_id    & PHONEME_CODA_MASK))  << PHONEME_CODA_SHIFT;
    w |= ((uint32_t)(d->prefix_id  & PHONEME_PREF_MASK))  << PHONEME_PREF_SHIFT;
    w |= ((uint32_t)(d->provenance & PHONEME_PROV_MASK))  << PHONEME_PROV_SHIFT;
    return w;
}

static inline void sovr_phoneme_unpack(uint32_t w, sovr_phoneme_desc_t *d) {
    d->onset_id   = (uint8_t)((w >> PHONEME_ONSET_SHIFT) & PHONEME_ONSET_MASK);
    d->nucleus_id = (uint8_t)((w >> PHONEME_NUCL_SHIFT)  & PHONEME_NUCL_MASK);
    d->nasal      = (bool)((w >> PHONEME_NASAL_SHIFT)    & PHONEME_NASAL_MASK);
    d->is_long    = (bool)((w >> PHONEME_LONG_SHIFT)     & PHONEME_LONG_MASK);
    d->tone_id    = (uint8_t)((w >> PHONEME_TONE_SHIFT)  & PHONEME_TONE_MASK);
    d->coda_id    = (uint8_t)((w >> PHONEME_CODA_SHIFT)  & PHONEME_CODA_MASK);
    d->prefix_id  = (uint8_t)((w >> PHONEME_PREF_SHIFT)  & PHONEME_PREF_MASK);
    d->provenance = (uint16_t)((w >> PHONEME_PROV_SHIFT)  & PHONEME_PROV_MASK);
}

#endif /* SOVR_PHONEME_ENGINE_H */
