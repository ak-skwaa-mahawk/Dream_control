#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define DATAPORT_SIZE 4096
#define APPROVAL_OFFSET 0x400

struct __attribute__((__packed__)) gate_approval {
    uint32_t seq_id;              /* +0x00: Monotonic Proposal Sequence ID          */
    uint8_t  witness_mask;        /* +0x04: Bitmask of signers (0x07 = Triad 0,1,2) */
    uint8_t  reserved[3];         /* +0x05: Canonical zero-padding                  */
    uint8_t  challenge_nonce[32]; /* +0x08: 32-byte hash matching audit entry tip   */
    uint8_t  signatures[6][64];   /* +0x28: Up to 6 x 64-byte Ed25519 signatures    */
};

_Static_assert(sizeof(struct gate_approval) == 424, "gate_approval must be exactly 424 bytes");

static void dump_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static EVP_PKEY* load_public_key(const char *keys_dir, int signer_idx) {
    char path[256];
    snprintf(path, sizeof(path), "%s/notary_signer_%d.pub", keys_dir, signer_idx);

    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    uint8_t pub_bytes[32];
    size_t read_bytes = fread(pub_bytes, 1, sizeof(pub_bytes), f);
    fclose(f);

    if (read_bytes != 32) {
        return NULL;
    }

    return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub_bytes, 32);
}

static int verify_signature(EVP_PKEY *pkey, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return 0;

    int ret = 0;
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == 1) {
        if (EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len) == 1) {
            ret = 1;
        }
    }

    EVP_MD_CTX_free(md_ctx);
    return ret;
}

int main(int argc, char **argv) {
    const char *bin_path = (argc > 1) ? argv[1] : "./workspace/harness_approval.bin";
    const char *keys_dir = (argc > 2) ? argv[2] : "./workspace/notary_keys";

    FILE *f = fopen(bin_path, "rb");
    if (!f) {
        perror("[-] Failed to open approval binary");
        return 1;
    }

    struct gate_approval approval;
    size_t read_bytes = fread(&approval, 1, sizeof(approval), f);
    fclose(f);

    if (read_bytes != sizeof(struct gate_approval)) {
        fprintf(stderr, "[-] Incomplete read: got %zu bytes, expected %zu\n",
                read_bytes, sizeof(struct gate_approval));
        return 1;
    }

    printf("=== CAmkES Dataport Approval Inspection (Offset 0x%04X) ===\n", APPROVAL_OFFSET);
    printf("  Sequence ID  : %u\n", approval.seq_id);
    printf("  Witness Mask : 0x%02X\n", approval.witness_mask);

    if ((approval.witness_mask & 0x07) != 0x07) {
        fprintf(stderr, "[-] Quorum failure: Witness mask does not meet Triad threshold (0x07)\n");
        return 2;
    }
    printf("  Quorum Status: Verified (Triad quorum 0x07 satisfied)\n");

    printf("  Challenge Nonce (32B): ");
    dump_hex(approval.challenge_nonce, 32);

    /* Construct 36-byte sign_message: struct.pack('<I', seq_id) + challenge_nonce */
    uint8_t sign_message[36];
    uint32_t seq_le = approval.seq_id;
    sign_message[0] = (uint8_t)(seq_le & 0xFF);
    sign_message[1] = (uint8_t)((seq_le >> 8) & 0xFF);
    sign_message[2] = (uint8_t)((seq_le >> 16) & 0xFF);
    sign_message[3] = (uint8_t)((seq_le >> 24) & 0xFF);
    memcpy(sign_message + 4, approval.challenge_nonce, 32);

    int valid_sig_count = 0;
    for (int i = 0; i < 3; ++i) {
        EVP_PKEY *pkey = load_public_key(keys_dir, i);
        if (!pkey) {
            fprintf(stderr, "[-] Could not load public key: %s/notary_signer_%d.pub\n", keys_dir, i);
            continue;
        }

        if (verify_signature(pkey, sign_message, sizeof(sign_message), approval.signatures[i], 64)) {
            printf("  Signature [%d] : Cryptographically Verified (Ed25519 valid)\n", i);
            valid_sig_count++;
        } else {
            fprintf(stderr, "[-] Signature [%d] : INVALID signature over sign_message\n", i);
        }
        EVP_PKEY_free(pkey);
    }

    printf("  Total Cryptographically Valid Signatures: %d/3\n", valid_sig_count);
    if (valid_sig_count < 3) {
        fprintf(stderr, "[-] Quorum cryptographic verification failed: valid count < 3\n");
        return 3;
    }

    printf("[+] CAmkES dataport approval vector cryptographically confirmed.\n");
    return 0;
}
