#ifndef SM4_H
#define SM4_H

#include "types.h"

#define SM4_KEYLEN 16
#define SM4_BLOCK_SIZE 16

typedef struct SM4_CTX {
    uint32_t rk[32];
} SM4_CTX;

extern const CipherInfo SM4Info;

void sm4_init(uint8_t* key, SM4_CTX* ctx);

void sm4_encrypt(uint8_t* out, uint8_t* in, SM4_CTX* ctx);

void sm4_decrypt(uint8_t* out, uint8_t* in, SM4_CTX* ctx);

#endif  // SM4_H
