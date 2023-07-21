#include "gctr.h"
#include "utils.h"
#include <memory.h>
#include "ghash.h"

static void gctr_inc32(uint8_t* r, uint8_t* cnt) {
    uint32_t n = loadu32_be(cnt + 12);
    storeu32_be(r + 12, n + 1);
    memcpy(r, cnt, 12);
}

void gctr_init(uint8_t* iv,
               int ivlen,
               uint8_t* H,
               GHashTable* ht,
               GCTR_CTX* gctx) {
    if (ivlen == (96 / 8)) {
        memset(gctx->j0, 0, BLOCK_SIZE);
        memcpy(gctx->j0, iv, 96 / 8);
        gctx->j0[BLOCK_SIZE - 1] = 1;
    } else {
        // H(IV || 0(s+64) || ivlen(64) )
        int s = (BLOCK_SIZE - ivlen % BLOCK_SIZE) % BLOCK_SIZE;
        uint8_t tmp[BLOCK_SIZE] = {0};
        GHash_CTX ctx;
        ghash_init(H, ht, &ctx);
        ghash_update(iv, ivlen, &ctx);
        ghash_update(tmp, s, &ctx);
        storeu64_be(tmp + BLOCK_SIZE / 2, (uint64_t)(ivlen * 8));
        ghash_update(tmp, BLOCK_SIZE, &ctx);
        ghash_final(gctx->j0, &ctx);
    }
    gctr_inc32(gctx->j, gctx->j0);
    gctx->bsize = 0;
}

void gctr_update(uint8_t* out,
                 int* outl,
                 uint8_t* in,
                 int inl,
                 GCTR_CTX* gctx) {
    *outl = 0;
    CipherEncrypt encrypt = gctx->cipher->encrypt;
    while (inl > 0) {

        int size = BLOCK_SIZE - gctx->bsize;
        if (size > inl) {
            size = inl;
        }
        memcpy(gctx->buffer + gctx->bsize, in, size);
        gctx->bsize += size;
        in += size, inl -= size;

        if (gctx->bsize == BLOCK_SIZE) {

            memcpy(out, gctx->buffer, BLOCK_SIZE);
            memcpy(gctx->buffer, gctx->j, BLOCK_SIZE);

            gctr_inc32(gctx->j, gctx->j);
            encrypt(gctx->buffer, gctx->buffer, gctx->cctx);
            memxor(out, out, gctx->buffer, BLOCK_SIZE);

            gctx->bsize = 0;
            *outl += BLOCK_SIZE, out += BLOCK_SIZE;
        }
    }
}

void gctr_final(uint8_t* out, int* outl, GCTR_CTX* gctx) {
    CipherEncrypt encrypt = gctx->cipher->encrypt;
    if (gctx->bsize) {
        memcpy(out, gctx->buffer, gctx->bsize);
        // encrypt
        encrypt(gctx->buffer, gctx->j, gctx->cctx);
        memxor(out, out, gctx->buffer, gctx->bsize);
    }

    *outl = gctx->bsize;
}
