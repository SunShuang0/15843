#pragma once
#include <memory.h>
#include <stdlib.h>
#include "sm4gcm/sm4.h"
#include "sm4gcm/mode.h"
#include "sm4gcm/err.h"
#include "sm4gcm/utils.h"

/* SM4 Part Begin */
extern const CipherInfo SM4Info;
static uint8_t gcm_iv_A[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
static uint8_t gcm_aad_A[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
    0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde,
};

static uint8_t en_out_A[SM4_BLOCK_SIZE * 4];
static int en_outlen_A;
static uint8_t en_tag_A[SM4_BLOCK_SIZE];
static int en_taglen_A = SM4_BLOCK_SIZE;

/* SM4 Part End */

/*      1 A ����Token     */

// 1.1 �����KAB��SID��TNA��TNB��IA��IB��Text1��Text2
uint8_t KAB_A[16] = { 0x49, 0x20, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x61, 0x68, 0x75, 0x61, 0x2c };
uint8_t SIDA[16] = { 0x28, 0xcc, 0x46, 0x02, 0x02, 0x01, 0x02, 0x01 ,0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t TNA_A[8] = { 0x01, 0x01, 0x01, 0x01, 0x10, 0x10, 0x10, 0x10 };
uint8_t TNB_A[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t IA_A[8] = { 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t IB_A[8] = { 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t Text1[8] = { 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t Text2[8] = { 0x54, 0x65, 0x78, 0x74, 0x32, 0x00, 0x00, 0x00 };

/**
 * @brief 1.2 ƴ��SID��TNA��IB��Text1��TNAʹ��ǰ�Լ�1��
 *
 * @param ƴ�Ӻ���ַ�����
 *
 */
void jointStringA(uint8_t* jointedStringA);

/**
 * @brief 1.3 ��KAB����Կ����SM4��ƴ���ַ�������
 *
 * @param ���ܽ��
 *
 */
void encryptA(uint8_t* EnInput, int plain_len, uint8_t* EnOutputWithTag);

/**
 * @brief 1.4 ƴ��Text2�ͼ��ܽ�����õ�TokenAB������TokenAB��B
 *
 * @param TokenAB
 *
 */
void genTokenAB(uint8_t* TokenAB);

/*      3 A��֤B   */
/**
 * @brief 3.1 ���յ�TokenBA������õ�Text4�ͼ����ַ���
 *
 * @param ���Text4������
 *
 */
void parseTokenBA(uint8_t* TokenBA, uint8_t* cipherFromTokenBA, int neededLength);

/**
 * @brief 3.2 ʹ��KAB��SM4�����ַ������õ������ַ���
 *
 * @param ���ܽ��
 *
 */
void decryptA(CipherInfo* cipher, int cipherSize, uint8_t* DeInput, uint8_t* DeOutput);

/**
 * @brief 3.3 ����ַ��������εõ�SIDB��TNA'��TNB'��IA'��Text3
 *	          ���SIDB�Ƿ񲻵���SIDA��TNA'�Ƿ����TNA��TNB'�Ƿ����TNB��IA'�Ƿ����IA
 *            ��ӡ�����
 * @param
 *
 */
void AverifyB(uint8_t* TokenBA);