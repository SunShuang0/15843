#pragma once
#include <memory.h>
#include <stdlib.h>
#include "sm4gcm/sm4.h"
#include "sm4gcm/mode.h"
#include "sm4gcm/err.h"
#include "sm4gcm/utils.h"

/* SM4 Part Begin */
extern const CipherInfo SM4Info;
static uint8_t gcm_iv[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68
};
static uint8_t gcmad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
    0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde,
};

static uint8_t en_out[SM4_BLOCK_SIZE * 4];
static int en_outlen;
static uint8_t en_tag[SM4_BLOCK_SIZE];
static int en_taglen = SM4_BLOCK_SIZE;
/* SM4 Part End */


uint8_t TVPA[16] = { 0x2A, 0x2E, 0x90, 0xF3, 0x8D, 0x2F, 0x65, 0xE7, 0x1B, 0x5D, 0x72, 0x91, 0x4D, 0x8A, 0x42, 0x9D };
uint8_t KAP[16] = { 0xaa, 0xaa, 0x44, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x11 };
uint8_t KBP[16] = { 0xbb, 0xbb, 0x44, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x11 };
uint8_t KAB[16] = { 0xab, 0xab, 0x44, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x11 };
uint8_t SID1[8] = { 0xa7, 0x89, 0xee, 0x01, 0x00, 0x00, 0x00, 0x00 };
uint8_t SID2[8] = { 0xa7, 0x89, 0xee, 0x02, 0x00, 0x00, 0x00, 0x00 };
uint8_t TNP[8] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t IA[8] = { 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t IB[8] = { 0x5C, 0x69, 0x42, 0xDF, 0x71, 0x46, 0x19, 0x22 };

uint8_t Text2[8] = { 0xa2, 0x2a, 0xa2, 0x2a, 0xa2, 0x2a, 0xa2, 0x2a };
uint8_t Text3[8] = { 0xa3, 0x3a, 0xa3, 0x3a, 0xa3, 0x3a, 0xa3, 0x3a };
uint8_t Text4[8] = { 0xa4, 0x4a, 0xa4, 0x4a, 0xa4, 0x4a, 0xa4, 0x4a };


/**
 * @brief 拼接SID、TNA、IB、Text1（TNA使用前自加1）
 *
 * @param 拼接后的字符数组
 *
 */
void jointStringToA(uint8_t* jointedStringToA);
void jointStringToB(uint8_t* jointedStringToB);

/**
 * @brief 1.3 用KAB作密钥，用SM4对拼接字符串加密
 *
 * @param 加密结果
 *
 */
void encrypt(uint8_t* Key, uint8_t* EnInput, int plain_len, uint8_t* EnOutputWithTag);

/**
 * @brief 1.4 拼接Text2和加密结果，得到TokenAB，发送TokenAB给B
 *
 * @param TokenAB
 *
 */
void genTokenPA(uint8_t* TokenPA);

/**
 * @brief 3.2 使用KAB和SM4解密字符串，得到明文字符串
 *
 * @param 解密结果
 *
 */
// void decrypt(CipherInfo* cipher, int size, uint8_t* DeInput, uint8_t* DeOutput);