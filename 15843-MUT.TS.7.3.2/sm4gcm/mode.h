#ifndef MODE_H
#define MODE_H

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "types.h"

#define BLOCK_SIZE 16


typedef struct ECB_CTX {
    uint8_t buffer[BLOCK_SIZE];
    int bsize;
    const CipherInfo* cipher;
    void* cctx;
} ECB_CTX;


void ecb_init(uint8_t* key,
              const CipherInfo* cipher,
              void* cctx,
              ECB_CTX* mctx);


void ecb_reset(ECB_CTX* mctx);


void ecb_encrypt_update(uint8_t* out,
                        int* outl,
                        uint8_t* in,
                        int inl,
                        ECB_CTX* mctx);


void ecb_encrypt_final(uint8_t* out, int* outl, ECB_CTX* mctx);


void ecb_decrypt_update(uint8_t* out,
                        int* outl,
                        uint8_t* in,
                        int inl,
                        ECB_CTX* mctx);


int ecb_decrypt_final(uint8_t* out, int* outl, ECB_CTX* mctx);



typedef struct CBC_CTX {
    uint8_t iv[BLOCK_SIZE];
    uint8_t buffer[BLOCK_SIZE];
    int bsize;
    const CipherInfo* cipher;
    void* cctx;
} CBC_CTX;


void cbc_init(uint8_t* key,
              uint8_t* iv,
              const CipherInfo* cipher,
              void* cctx,
              CBC_CTX* mctx);


void cbc_reset(uint8_t* iv, CBC_CTX* mctx);


void cbc_encrypt_update(uint8_t* out,
                        int* outl,
                        uint8_t* in,
                        int inl,
                        CBC_CTX* mctx);


void cbc_encrypt_final(uint8_t* out, int* outl, CBC_CTX* mctx);


void cbc_decrypt_update(uint8_t* out,
                        int* outl,
                        uint8_t* in,
                        int inl,
                        CBC_CTX* mctx);


int cbc_decrypt_final(uint8_t* out, int* outl, CBC_CTX* mctx);


typedef uint64_t GHashTable[256][2];

typedef struct GHash_CTX {
    uint8_t buffer[BLOCK_SIZE];
    int bsize;
    uint8_t X[BLOCK_SIZE];
    uint8_t H[BLOCK_SIZE];
    GHashTable* ht;
} GHash_CTX;

typedef struct GCTR_CTX {
    uint8_t j0[BLOCK_SIZE];
    uint8_t j[BLOCK_SIZE];
    uint8_t buffer[BLOCK_SIZE];
    int bsize;
    const CipherInfo* cipher;
    void* cctx;
} GCTR_CTX;

typedef struct GCM_CTX {
    GHash_CTX hctx;
    GCTR_CTX gctx;
    int alen;
    int clen;
} GCM_CTX;


void gcm_init(uint8_t* key,
              uint8_t* iv,
              int ivlen,
              GHashTable* ht,
              const CipherInfo* cipher,
              void* cctx,
              GCM_CTX* mctx);

void gcm_reset(uint8_t* iv,
               int ivlen,
               GCM_CTX* mctx);


void gcm_update_aad(uint8_t* aad, int alen, GCM_CTX* mctx);


void gcm_encrypt_update(uint8_t* out,
                        int* outl,
                        uint8_t* in,
                        int inl,
                        GCM_CTX* mctx);

void gcm_encrypt_final(uint8_t* out,
                       int* outl,
                       uint8_t* tag,
                       int tlen,
                       GCM_CTX* mctx);


void gcm_decrypt_update(uint8_t* out,
                        int* outl,
                        uint8_t* in,
                        int inl,
                        GCM_CTX* mctx);


int gcm_decrypt_final(uint8_t* out,
                      int* outl,
                      uint8_t* tag,
                      int tlen,
                      GCM_CTX* mctx);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif // MODE_H
