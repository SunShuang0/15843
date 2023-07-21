#ifndef TYPES_H
#define TYPES_H

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>


typedef void (*CipherInit)(uint8_t* key, void* ctx);
typedef void (*CipherEncrypt)(uint8_t* out, uint8_t* in, void* ctx);
typedef void (*CipherDecrypt)(uint8_t* out, uint8_t* in, void* ctx);

typedef struct CipherInfo {
    CipherInit init;
    CipherEncrypt encrypt;
    CipherDecrypt decrypt;
} CipherInfo;



typedef void (*HashInit)(void* ctx);
typedef void (*HashUpdate)(uint8_t* in, int inl, void* ctx);
typedef void (*HashFinal)(uint8_t* out, void* ctx);

typedef struct HashInfo {
    HashInit init;
    HashUpdate update;
    HashFinal final;
    const int DIGEST_SIZE;
} HashInfo;

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif // TYPES_H
