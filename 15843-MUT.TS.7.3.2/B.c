#include "B.h"
void parseTokenAB(uint8_t* TokenAB, uint8_t* strWithTagFromTokenAB)
{
	uint8_t Text2[8] = { 0x00 };
	for (int i = 0; i < 8; i++)
	{
		Text2[i] = TokenAB[i];
	}
	for (int i = 0; i < 56; i++)
	{
		strWithTagFromTokenAB[i] = TokenAB[i + 8];
	}
}

void decryptB(CipherInfo* cipher, int cipherSize, uint8_t* DeInput, uint8_t* DeOutput)
{
	uint8_t de_out[SM4_BLOCK_SIZE * 4];
	int de_outlen;
	uint8_t de_tag[SM4_BLOCK_SIZE];
	int de_taglen = SM4_BLOCK_SIZE;
	GCM_CTX de_ctx;
	SM4_CTX sm4_de_ctx;
	uint8_t* de_outptr;
	de_outptr = de_out;

	gcm_init(KAB_B, gcm_iv_B, sizeof(gcm_iv_B), NULL, cipher, &sm4_de_ctx, &de_ctx);
	gcm_decrypt_update(de_outptr, &de_outlen, DeInput, cipherSize, &de_ctx);
	de_outptr += de_outlen;
	int err = gcm_decrypt_final(de_outptr, &de_outlen, DeInput+ cipherSize, de_taglen, &de_ctx);
	de_outptr += de_outlen;

	printf("plaintext:\n");
	for (size_t i = 0; i < cipherSize; i++)
	{
		DeOutput[i] = de_out[i];
		printf("%#04x ", de_out[i]);
	}
	printf("\n");
	printf("\n\nTag Err = %d\n\n", err);

}

void BverifyA(uint8_t* TokenAB)
{
	//printf("\nTokenAB In B:\n");
	//for (int i = 0; i < 64; i++)
	//{
	//	printf("%#04x ", TokenAB[i]);
	//}
	//printf("\n");
	uint8_t strWithTagFromTokenAB[48] = { 0x00 }; // include tag[16]
	uint8_t plainFromTokenAB[32] = { 0x00 };
	parseTokenAB(TokenAB, strWithTagFromTokenAB);

	const CipherInfo* cipher = &SM4Info;

	decryptB(cipher, 32, strWithTagFromTokenAB, plainFromTokenAB); // cipher = 48 - 16[tag] = 32

	uint8_t SID[8] = { 0x00 };
	uint8_t TNA[8] = { 0x00 };
	uint8_t IB[8] = { 0x00 };
	uint8_t Text1[8] = { 0x00 };

	for (int i = 0; i < 8; i++)
	{
		SID[i] = plainFromTokenAB[i];
		if (i < 5)
		{
			if (SID[i] != SIDB[i])
			{
				printf("ERROR! SID From A is Invalide!\n");
				exit(EXIT_SUCCESS);
			}
		}
		else if(i == 5)
		{
			if (SID[i] == SIDB[i])
			{
				printf("ERROR! SID From A is Invalide!\n");
				exit(EXIT_SUCCESS);
			}
		}
	}

	for (int i = 0; i < 8; i++)
	{
		TNA[i] = plainFromTokenAB[i + 8];
	}
	for (int i = 0; i < 8; i++)
	{
		IB[i] = plainFromTokenAB[i + 8 + 8];
		if (IB[i] != IB_B[i])
		{
			printf("ERROR! IB From A is Invalide!\n");
			exit(EXIT_SUCCESS);
		}
	}
	for (int i = 0; i < 8; i++)
	{
		Text1[i] = plainFromTokenAB[i + 8 + 8 + 8];
	}

	if (TNA[1] <= TNA_B[1])
	{
		printf("ERROR! TNA From A is Invalide!\n");
		exit(EXIT_SUCCESS);
	}
	else
	{
		for (int i = 0; i < 8; i++)
		{
			TNA_B[i] = TNA[i];
		}
	}

}

// 2.5 拼接字符串SIDB、TNA_B、TNB_B、IA_B、Text3（TNB使用前自加1）
void jointStringB(uint8_t* jointedStringB)
{
	int count = 0;
	// joint SIDB
	printf("\nSIDB:\n");
	for (int i = 0; i < 8; i++)
	{
		jointedStringB[i] = SIDB[i];
		printf("%#04x, ", jointedStringB[i]);
	}
	printf("\n");
	count = 8;

	// joint TNA_B
	printf("\nTNA:\n");
	for (int i = 0; i < 8; i++)
	{
		jointedStringB[count + i] = TNA_B[i];
		printf("%#04x, ", jointedStringB[count + i]);
	}
	count += 8;
	printf("\n");

	// joint TNB_B
	printf("\nTNB:\n");
	for (int i = 0; i < 8; i++)
	{
		jointedStringB[count + i] = TNB_B[i];
		printf("%#04x, ", jointedStringB[count + i]);
	}
	count += 8;
	printf("\n");

	// joint IA_B
	printf("\nIA:\n");
	for (int i = 0; i < 8; i++)
	{
		jointedStringB[count + i] = IA_B[i];
		printf("%#04x, ", jointedStringB[count + i]);
	}
	count += 8;
	printf("\n");

	// joint Text3
	printf("\nText3:\n");
	for (int i = 0; i < 8; i++)
	{
		jointedStringB[count + i] = Text3[i];
		printf("%#04x, ", jointedStringB[count + i]);
	}
	printf("\n");
}


// 2.6 使用KAB和SM4加密字符串
void encryptB(uint8_t* EnInput, int plain_len, uint8_t* EnOutputWithTag)
{
	GCM_CTX en_ctx;
	SM4_CTX sm4_en_ctx;
	uint8_t* en_outptr;
	const CipherInfo* cipher = &SM4Info;

	en_outptr = en_out_B;
	gcm_init(KAB_B, gcm_iv_B, sizeof(gcm_iv_B), NULL, cipher, &sm4_en_ctx, &en_ctx);
	gcm_encrypt_update(en_outptr, &en_outlen_B, EnInput, plain_len, &en_ctx);
	en_outptr += en_outlen_B;
	gcm_encrypt_final(en_outptr, &en_outlen_B, en_tag_B, en_taglen_B, &en_ctx);
	en_outptr += en_outlen_B;


	for (int i = 0; i < plain_len; i++)
	{
		EnOutputWithTag[i] = en_out_B[i];
	}

	printf("\nTag in B:");
	for (int i = 0; i < 16; i++)
	{
		EnOutputWithTag[plain_len + i] = en_tag_B[i];
		printf("%#04x, ", en_tag_B[i]);
	}
	printf("\n");
	

}


// 2.7 拼接Text4和加密结果，得到TokenBA，发送TokenBA给A
void genTokenBA(uint8_t* TokenBA)
{
	uint8_t jointedStringB[40] = { 0x00 };
	jointStringB(jointedStringB);		// joints string for next encryption

	for (int i = 0; i < 8; i++)
	{
		TokenBA[i] = Text4[i];
	}

	uint8_t EnOutput[56] = { 0x00 }; // cipher/plain length = 40, tag length = 16, entire output length = 40 + 16
	encryptB(jointedStringB, 40, EnOutput);
	for (int i = 0; i < 56; i++)
	{
		TokenBA[8 + i] = EnOutput[i];
	}

}