#pragma once
#include <memory.h>
#include <stdlib.h>
#include "sm4gcm/sm4.h"
#include "sm4gcm/mode.h"
#include "sm4gcm/err.h"
#include "sm4gcm/utils.h"
#include <windows.h>
#include <stdio.h>
#include <Wincrypt.h>
#include "math.h"

/* SM4 Part Begin */
extern const CipherInfo SM4Info;
static uint8_t gcm_iv_B[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
static uint8_t gcm_aad_B[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
    0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde,
};

static uint8_t en_out_B[SM4_BLOCK_SIZE * 4];
static int en_outlen_B;
static uint8_t en_tag_B[SM4_BLOCK_SIZE];
static int en_taglen_B = SM4_BLOCK_SIZE;

void encryptB(uint8_t* EnInput, uint8_t* EnOutput);
void decryptB(CipherInfo* cipher, int size, uint8_t* DeInput, uint8_t* DeOutput);

/* SM4 Part End */


/*      1 B产生RB        */
// 定义出KAB、SID、TNA、TNB、IA、IB、Text3、Text4
uint8_t KAB_B[16] = { 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
uint8_t SIDB[8] = { 0x28, 0xe7, 0x2c, 0xa2, 0xa0, 0x02, 0x00, 0x00 };
uint8_t RA_B[16] = { 0x49, 0x30, 0x10, 0x73, 0x81, 0x14, 0x10, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t RB_B[16] = { 0x96, 0x1d, 0x6a, 0x8a, 0xda, 0x73, 0xea, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t IA_B[8] = { 0x41, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t IB_B[8] = { 0x42, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t Text1[8] = { 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t Text4[8] = { 0xa4, 0x4a, 0xa4, 0x4a, 0x00, 0x00, 0x00, 0x00 };
uint8_t Text5[8] = { 0xa5, 0x5a, 0xa5, 0x5a, 0x00, 0x00, 0x00, 0x00 };

void intToHex(int num, uint8_t* RandomNumber, uint8_t* RBfromB);
void sendRB(uint8_t * RBfromB);


/*      3 B验证A        */
/**
 * @brief 3.1 接收到TokenAB，拆解TokenAB，得到Text2和加密字符串
 *
 * @param 拆出Text2和密文
 *
 */
void parseTokenAB(uint8_t* TokenAB, uint8_t* cipherFromTokenAB, int neededLength);

/**
 * @brief 3.2 使用KAB和SM4解密字符串
 *
 * @param 解密结果
 *
 */
void decryptB(CipherInfo* cipher, int cipherSize, uint8_t* DeInput, uint8_t* DeOutput);

/**
 * @brief 3.3 拆解字符串，得到SID'、TNA'、IB'
 *            检查SID'是否等于本地SID、TNA'是否大于本地TNA，如果大于，则更新本地TNA、IB'是否等于本地IB
 *
 * @param 检查结果
 *
 */
void BverifyA(uint8_t* TokenAB);


/*      4 B产生TokenBA        */
/**
 * @brief 4.1 拼接字符串SIDB、RA、IA、Text4
 *
 * @param 拼接后的字符数组
 *
 */
void jointStringB(uint8_t* jointedStringB);

/**
 * @brief 4.2 使用KAB和SM4加密字符串
 *
 * @param 加密结果
 *
 */
void encryptB(uint8_t* EnInput, int plainSize, uint8_t* EnOutputWithTag);

/**
 * @brief 4.3 拼接Text4和加密结果，得到TokenBA，发送TokenBA给A
 *
 * @param TokenBA
 *
 */
void genTokenBA(uint8_t* TokenAB);