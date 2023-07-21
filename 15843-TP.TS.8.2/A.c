//#include "A.h"
//void jointStringA(uint8_t* jointedStringA)
//{
//	int count = 0;
//	// joint SIDA
//	for (int i = 0; i < 8; i++)
//	{
//		jointedStringA[i] = SIDA[i];
//	}
//	count = 8;
//	
//	// joint TNA
//	TNA_A[0] += 1;
//	for (int i = 0; i < 8; i++)
//	{
//		jointedStringA[count + i] = TNA_A[i];
//	}
//	count += 8;
//
//	// joint IB
//	for (int i = 0; i < 8; i++)
//	{
//		jointedStringA[count + i] = IB_A[i];
//	}
//	count += 8;
//
//	// joint Text1
//	for (int i = 0; i < 8; i++)
//	{
//		jointedStringA[count + i] = Text1[i];
//	}
//
//}
//
//void encryptA(uint8_t* EnInput, int plain_len, uint8_t* EnOutput)
//{
//	GCM_CTX en_ctx;
//	SM4_CTX sm4_en_ctx;
//	uint8_t* en_outptr;
//	const CipherInfo* cipher = &SM4Info;
//
//	en_outptr = en_out_A;
//	gcm_init(KAB_A, gcm_iv_A, sizeof(gcm_iv_A), NULL, cipher, &sm4_en_ctx, &en_ctx);
//	gcm_encrypt_update(en_outptr, &en_outlen_A, EnInput, plain_len, &en_ctx);
//	en_outptr += en_outlen_A;
//	gcm_encrypt_final(en_outptr, &en_outlen_A, en_tag_A, en_taglen_A, &en_ctx);
//	en_outptr += en_outlen_A;
//
//
//	for (int i = 0; i < (int)(en_outptr - en_out_A); i++)
//	{
//		EnOutput[i] = en_out_A[i];
//	}
//}
//
//
///**
// * A Éú³É TokenAB
// */
//void genTokenAB(uint8_t * TokenAB)
//{
//	uint8_t jointedStringA[32] = { 0x00 };
//	jointStringA(jointedStringA);		// joints string for next encryption
//
//	for (int i = 0; i < 8; i++)
//	{
//		TokenAB[i] = Text2[i];
//	}
//
//	uint8_t EnOutput[32] = { 0x00 };
//	encryptA(jointedStringA, 32, EnOutput);
//
//	for (int i = 0; i < 32; i++)
//	{
//		TokenAB[8 + i] = EnOutput[i];
//	}
//
//}
//
//
//void parseTokenBA(uint8_t* TokenBA, uint8_t* cipherFromTokenBA)
//{
//	uint8_t Text4[8] = { 0x00 };
//	for (int i = 0; i < 8; i++)
//	{
//		Text4[i] = TokenBA[i];
//	}
//	for (int i = 0; i < 40; i++)
//	{
//		cipherFromTokenBA[i] = TokenBA[i + 8];
//	}
//}
//
//void decryptA(CipherInfo* cipher, int size, uint8_t* DeInput, uint8_t* DeOutput)
//{
//	uint8_t de_out[SM4_BLOCK_SIZE * 4];
//	int de_outlen;
//	uint8_t de_tag[SM4_BLOCK_SIZE];
//	int de_taglen = SM4_BLOCK_SIZE;
//	GCM_CTX de_ctx;
//	SM4_CTX sm4_de_ctx;
//	uint8_t* de_outptr;
//	de_outptr = de_out;
//
//	gcm_init(KAB_A, gcm_iv_A, sizeof(gcm_iv_A), NULL, cipher, &sm4_de_ctx, &de_ctx);
//	gcm_decrypt_update(de_outptr, &de_outlen, DeInput, size, &de_ctx);
//	de_outptr += de_outlen;
//	gcm_decrypt_final(de_outptr, &de_outlen, de_tag, de_taglen, &de_ctx);
//	de_outptr += de_outlen;
//	int size2 = (int)(de_outptr - de_out);
//	for (size_t i = 0; i < size; i++)
//	{
//		DeOutput[i] = de_out[i];
//	}
//}
//
//void AverifyB(uint8_t* TokenBA)
//{
//	uint8_t cipherFromTokenBA[40] = { 0x00 };
//	uint8_t plainFromTokenBA[40] = { 0x00 };
//	parseTokenBA(TokenBA, cipherFromTokenBA);
//
//	const CipherInfo* cipher = &SM4Info;
//
//	decryptA(cipher, 40, cipherFromTokenBA, plainFromTokenBA);
//
//	uint8_t SID[8] = { 0x00 };
//	uint8_t TNA[8] = { 0x00 };
//	uint8_t TNB[8] = { 0x00 };
//	uint8_t IA[8] = { 0x00 };
//	uint8_t Text3[8] = { 0x00 };
//	for (int i = 0; i < 8; i++)
//	{
//		SID[i] = plainFromTokenBA[i];
//		if (i < 5)
//		{
//			if (SID[i] != SIDA[i])
//			{
//				printf("ERROR! SID From B is Invalide!\n");
//				exit(EXIT_SUCCESS);
//			}
//		}
//		else if (i == 5)
//		{
//			if (SID[i] == SIDA[i])
//			{
//				printf("ERROR! SID From A is Invalide!\n");
//				exit(EXIT_SUCCESS);
//			}
//		}
//	}
//	for (int i = 0; i < 8; i++)
//	{
//		TNA[i] = plainFromTokenBA[i + 8];
//		if (TNA[i] != TNA_A[i])
//		{
//			printf("ERROR! TNA From B is Invalide!\n");
//			exit(EXIT_SUCCESS);
//		}
//	}
//	for (int i = 0; i < 8; i++)
//	{
//		TNB[i] = plainFromTokenBA[i + 8 + 8];
//	}
//	for (int i = 0; i < 8; i++)
//	{
//		IA[i] = plainFromTokenBA[i + 8 + 8 + 8];
//		if (IA[i] != IA_A[i])
//		{
//			printf("ERROR! IB From A is Invalide!\n");
//			exit(EXIT_SUCCESS);
//		}
//	}
//	for (int i = 0; i < 8; i++)
//	{
//		Text3[i] = plainFromTokenBA[i + 8 + 8 + 8 + 8];
//	}
//
//	if (TNB[0] <= TNB_A[0])
//	{
//		printf("ERROR! TNB From B is Invalide!\n");
//		exit(EXIT_SUCCESS);
//	}
//	else
//	{
//		for (int i = 0; i < 8; i++)
//		{
//			TNB_A[i] = TNB[i];
//		}
//	}
//
//}