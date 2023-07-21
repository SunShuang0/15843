//#include <memory.h>
//#include <stdlib.h>
//
//#include "sm4gcm/sm4.h"
//#include "sm4gcm/mode.h"
//#include "sm4gcm/err.h"
//#include "sm4gcm/utils.h"
//
//extern const CipherInfo SM4Info;
//
//static uint8_t gcm_key[SM4_KEYLEN] = {
//    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
//    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68
//};
//
//static uint8_t gcm_iv[] = {
//    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
//    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68
//};
//
//static uint8_t gcm_aad[] = {
//    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
//    0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde,
//};
//
//static uint8_t gcm_pt[] = {
//    0x31, 0x32, 0x33
//};
//
//
//static uint8_t en_out[SM4_BLOCK_SIZE * 4];
//static int en_outlen;
//static uint8_t en_tag[SM4_BLOCK_SIZE];
//static int en_taglen = SM4_BLOCK_SIZE;
//
//
//int sm4gcm_test_main() {
//    GCM_CTX en_ctx;
//    SM4_CTX sm4_en_ctx;
//    uint8_t* en_outptr;
//    const CipherInfo* cipher = &SM4Info;
//
//    // Encryt
//    // puts("[sm4 GCM]");
//    en_outptr = en_out;
//    gcm_init(gcm_key, gcm_iv, sizeof(gcm_iv), NULL, cipher, &sm4_en_ctx, &en_ctx);
//
//    gcm_encrypt_update(en_outptr, &en_outlen, gcm_pt, sizeof(gcm_pt), &en_ctx);
//    en_outptr += en_outlen;
//    gcm_encrypt_final(en_outptr, &en_outlen, en_tag, en_taglen, &en_ctx);
//    en_outptr += en_outlen;
//
//
//    puts("ciphertext:");
//    int size = (int)(en_outptr - en_out);
//    for (size_t i = 0; i < size; i++)
//    {
//        printf("%2x", en_out[i]);
//    }
//    printf("\n");
//
//    
//    // Decrypt
//    uint8_t de_out[SM4_BLOCK_SIZE * 4];
//    int de_outlen;
//    uint8_t de_tag[SM4_BLOCK_SIZE];
//    int de_taglen = SM4_BLOCK_SIZE;
//    GCM_CTX de_ctx;
//    SM4_CTX sm4_de_ctx;
//    uint8_t* de_outptr;
//    de_outptr = de_out;
//
//    gcm_init(gcm_key, gcm_iv, sizeof(gcm_iv), NULL, cipher, &sm4_de_ctx, &de_ctx);
//    gcm_decrypt_update(de_outptr, &de_outlen, en_out, size, &de_ctx);
//    de_outptr += de_outlen;
//    gcm_decrypt_final(de_outptr, &de_outlen, de_tag, de_taglen, &de_ctx);
//    de_outptr += de_outlen;
//    puts("plaintext:");
//    int size2 = (int)(de_outptr - de_out);
//    for (size_t i = 0; i < size2; i++)
//    {
//        printf("%2x", de_out[i]);
//    }
//    printf("\n");
//
//
//
//
//    return 0;
//error:
//    return -1;
//}