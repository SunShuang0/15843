#pragma once
#include <memory.h>
#include <stdlib.h>
#include "sm4gcm/sm4.h"
#include "sm4gcm/mode.h"
#include "sm4gcm/err.h"
#include "sm4gcm/utils.h"

/* SM4 Part Begin */
extern const CipherInfo SM4Info;
static uint8_t gcm_iv_B[] = {
                            0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99,
                            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
};
static uint8_t gcm_aad_B[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
    0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde,
};

static uint8_t en_out_B[SM4_BLOCK_SIZE * 4];
static int en_outlen_B;
static uint8_t en_tag_B[SM4_BLOCK_SIZE];
static int en_taglen_B = SM4_BLOCK_SIZE;

/* SM4 Part End */


/*      2 B����TokenBA        */
// 2.1 �����KAB��SID��TNA��TNB��IA��IB��Text3��Text4
uint8_t KAB_B[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
// uint8_t KAB_B[16] = { 0x22, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
uint8_t SIDB[8] = { 0x28, 0xe7, 0x2c, 0xa2, 0x90, 0x02, 0x00, 0x00 };
uint8_t TNA_B[8] = { 0x31, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t TNB_B[8] = { 0x32, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t IA_B[8] = { 0x49, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t IB_B[8] = { 0x49, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t Text3[8] = { 0xa3, 0x3a, 0xa3, 0x3a, 0x00, 0x00, 0x00, 0x00 };
uint8_t Text4[8] = { 0xa4, 0x4a, 0xa4, 0x4a, 0x00, 0x00, 0x00, 0x00 };

/**
 * @brief 2.2 ���յ�TokenAB�����TokenAB���õ�Text2�ͼ����ַ���
 *
 * @param ���Text2������
 *
 */
void parseTokenAB(uint8_t* TokenAB, uint8_t* strWithTagFromTokenAB);

/**
 * @brief 2.3 ʹ��KAB��SM4�����ַ���
 *
 * @param ���ܽ��
 *
 */
void decryptB(CipherInfo* cipher, int cipherSize, uint8_t* DeInput, uint8_t* DeOutput);

/**
 * @brief 2.4 ����ַ������õ�SID'��TNA'��IB'
 *            ���SID'�Ƿ���ڱ���SID��TNA'�Ƿ���ڱ���TNA��������ڣ�����±���TNA��IB'�Ƿ���ڱ���IB
 *
 * @param �����
 *
 */
void BverifyA(uint8_t* TokenAB);

/**
 * @brief 2.5 ƴ���ַ���SID��TNA��TNB��IA��Text3��TNBʹ��ǰ�Լ�1��
 *
 * @param ƴ�Ӻ���ַ�����
 *
 */
void jointStringB(uint8_t* jointedStringA);

/**
 * @brief 2.6 ʹ��KAB��SM4�����ַ���
 *
 * @param ���ܽ��
 *
 */
void encryptB(uint8_t* EnInput, int plain_len, uint8_t* EnOutputWithTag);

/**
 * @brief 2.7 ƴ��Text4�ͼ��ܽ�����õ�TokenBA������TokenBA��A
 *
 * @param TokenBA
 *
 */
void genTokenBA(uint8_t* TokenAB);