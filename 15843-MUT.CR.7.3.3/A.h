#pragma once
#include <memory.h>
#include <stdlib.h>
#include "sm4gcm/sm4.h"
#include "sm4gcm/mode.h"
#include "sm4gcm/err.h"
#include "sm4gcm/utils.h"
#include <windows.h>
#include <windef.h>
#include <wincrypt.h>
#include "math.h"

/* SM4 Part Begin */
extern const CipherInfo SM4Info;
static uint8_t gcm_iv_A[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68
};
static uint8_t gcm_aad_A[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
    0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde,
};

static uint8_t en_out_A[SM4_BLOCK_SIZE * 4];
static int en_outlen_A;
static uint8_t en_tag_A[SM4_BLOCK_SIZE];
static int en_taglen_A = SM4_BLOCK_SIZE;

/* SM4 Part End */


/*      2 A产生TokenAB        */
// 定义出KAB、SID、TNA、TNB、IA、IB、Text1、Text2
uint8_t KAB_A[16] = { 0x11, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x11 };
uint8_t SIDA[16] = { 0x28, 0xe7, 0x2c, 0xa2, 0xa0, 0x01, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t RA_A[16] = { 0x00 };
uint8_t RB_A[16] = { 0x00 };
uint8_t IA_A[8] = { 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t IB_A[8] = { 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t Text2[8] = { 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t Text3[8] = { 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


/**
 * @brief 2.1 A产生随机数RA
 *
 * @param 拼接后的字符数组
 *
 */
void genRA();

/**
 * @brief 2.2 拼接SIDA、RA_A、RB_A、IB_A、Text2
 *
 * @param 拼接后的字符数组
 *
 */
void jointStringA(uint8_t* jointedStringA, uint8_t* RB);

/**
 * @brief 2.3 用KAB作密钥，用SM4对拼接字符串加密
 *
 * @param 加密结果
 *
 */
void encryptA(uint8_t* EnInput, int plainSize, uint8_t* EnOutputWithTag);

/**
 * @brief 2.4 拼接Text2和加密结果，得到TokenAB，发送TokenAB给B
 *
 * @param TokenAB
 *
 */
void genTokenAB(uint8_t* TokenAB, uint8_t* RBfromB);

/*      5 A验证B   */
/**
 * @brief 5.1 接收到TokenBA，拆解后得到Text4和加密字符串
 *
 * @param 拆出Text4和密文
 *
 */
void parseTokenBA(uint8_t* TokenBA, uint8_t* cipherFromTokenBA, int neededLength);

/**
 * @brief 5.2 使用KAB和SM4解密字符串，得到明文字符串
 *
 * @param 解密结果
 *
 */
void decryptA(CipherInfo* cipher, int cipherSize, uint8_t* DeInput, uint8_t* DeOutput);

/**
 * @brief 5.3 拆解字符串，依次得到SIDB、TNA'、TNB'、IA'、Text3
 *	          检查SIDB是否不等于SIDA、TNA'是否等于TNA、TNB'是否大于TNB、IA'是否等于IA
 *            打印检查结果
 * @param
 *
 */
void AverifyB(uint8_t* TokenBA);