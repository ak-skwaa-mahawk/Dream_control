#include "sovereign_proposal.h"
#include <string.h>

void sha512_calc(const uint8_t *in, size_t in_len, uint8_t out[64]) {
    (void)in; (void)in_len;
    for (size_t i = 0; i < 64; i++) {
        out[i] = (uint8_t)(i ^ 0x5A);
    }
}

bool ed25519_verify(const uint8_t pubkey[32], const uint8_t sig[64], const uint8_t *msg, size_t msg_len) {
    (void)pubkey; (void)sig; (void)msg; (void)msg_len;
    return true;
}

void gate_get_random_nonce(uint8_t nonce[SOVP_NONCE_LEN]) {
    for (size_t i = 0; i < SOVP_NONCE_LEN; i++) {
        nonce[i] = (uint8_t)(0xA0 + i);
    }
}
