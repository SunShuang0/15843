#include <memory.h>
#include "err.h"
#include "utils.h"
#include "gctr.h"
#include "ghash.h"

static uint8_t ZERO_BUFFER[BLOCK_SIZE] = {0};

void gcm_init(uint8_t* key,
              uint8_t* iv,
              int ivlen,
              GHashTable* ht,
              const CipherInfo* cipher,
              void* cctx,
              GCM_CTX* mctx) {

    cipher->init(key, cctx);
    mctx->gctx.cctx = cctx;
    mctx->gctx.cipher = cipher;

    uint8_t H[BLOCK_SIZE];
    cipher->encrypt(H, ZERO_BUFFER, cctx);
    ghash_init(H, ht, &mctx->hctx);

    gctr_init(iv, ivlen, H, ht, &mctx->gctx);

    mctx->alen = 0, mctx->clen = 0;
}

void gcm_reset(uint8_t* iv, int ivlen, GCM_CTX* mctx) {
    ghash_reset(&mctx->hctx);
    uint8_t* H = mctx->hctx.H;
    GHashTable* ht = mctx->hctx.ht;

    gctr_init(iv, ivlen, H, ht, &mctx->gctx);

    mctx->alen = 0, mctx->clen = 0;
}

void gcm_update_aad(uint8_t* aad, int alen, GCM_CTX* mctx) {
    mctx->alen = alen;
    int rem = (BLOCK_SIZE - alen % BLOCK_SIZE) % BLOCK_SIZE;
    ghash_update(aad, alen, &mctx->hctx);
    ghash_update(ZERO_BUFFER, rem, &mctx->hctx);
}


void gcm_encrypt_update(uint8_t* out,
                        int* outl,
                        uint8_t* in,
                        int inl,
                        GCM_CTX* mctx) {
    gctr_update(out, outl, in, inl, &mctx->gctx);
    mctx->clen += *outl;
    ghash_update(out, *outl, &mctx->hctx);
}


void gcm_encrypt_final(uint8_t* out,
                       int* outl,
                       uint8_t* tag,
                       int tlen,
                       GCM_CTX* mctx) {
    gctr_final(out, outl, &mctx->gctx);
    mctx->clen += *outl;
    int rem = (BLOCK_SIZE - mctx->clen % BLOCK_SIZE) % BLOCK_SIZE;
    ghash_update(out, *outl, &mctx->hctx);
    ghash_update(ZERO_BUFFER, rem, &mctx->hctx);
    // aclen
    uint8_t z1[BLOCK_SIZE], z2[BLOCK_SIZE];
    storeu64_be(z1, (uint64_t)(mctx->alen * 8));
    storeu64_be(z1 + 8, (uint64_t)(mctx->clen * 8));
    ghash_update(z1, BLOCK_SIZE, &mctx->hctx);

    CipherEncrypt encrypt = mctx->gctx.cipher->encrypt;
    encrypt(z2, mctx->gctx.j0, mctx->gctx.cctx);
    ghash_final(z1, &mctx->hctx);
    memxor(tag, z1, z2, tlen);
}


void gcm_decrypt_update(uint8_t* out,
                        int* outl,
                        uint8_t* in,
                        int inl,
                        GCM_CTX* mctx) {
    gctr_update(out, outl, in, inl, &mctx->gctx);
    mctx->clen += inl;
    ghash_update(in, inl, &mctx->hctx);
}


int gcm_decrypt_final(uint8_t* out,
                      int* outl,
                      uint8_t* tag,
                      int tlen,
                      GCM_CTX* mctx) {
    gctr_final(out, outl, &mctx->gctx);

    int rem = (BLOCK_SIZE - mctx->clen % BLOCK_SIZE) % BLOCK_SIZE;
    ghash_update(ZERO_BUFFER, rem, &mctx->hctx);
    // aclen
    uint8_t z1[BLOCK_SIZE], z2[BLOCK_SIZE];
    storeu64_be(z1, (uint64_t)(mctx->alen * 8));
    storeu64_be(z1 + 8, (uint64_t)(mctx->clen * 8));
    ghash_update(z1, BLOCK_SIZE, &mctx->hctx);

    CipherEncrypt encrypt = mctx->gctx.cipher->encrypt;
    encrypt(z2, mctx->gctx.j0, mctx->gctx.cctx);
    ghash_final(z1, &mctx->hctx);
    memxor(z1, z1, z2, tlen);
    if (memcmp(z1, tag, tlen) != 0) {
        ERR_LOG("GCM Tag verification failed");
        goto error;
    }

    return ERR_NOERROR;
error:
    return ERR_RUNTIME_ERROR;
}
