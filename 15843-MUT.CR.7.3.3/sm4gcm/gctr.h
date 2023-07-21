#ifndef GCTR_H
#define GCTR_H

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "mode.h"

void gctr_init(uint8_t* iv,
               int ivlen,
               uint8_t* H,
               GHashTable* ht,
               GCTR_CTX* gctx);

void gctr_update(uint8_t* out,
                 int* outl,
                 uint8_t* in,
                 int inl,
                 GCTR_CTX* gctx);

void gctr_final(uint8_t* out, int* outl, GCTR_CTX* gctx);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // GCTR_H
