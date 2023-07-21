#include "A.h"
// 2.1 A产生随机数RA
void genRA()
{
	HCRYPTPROV   hCryptProv;
	int a = 0;
	LPCSTR UserName = "MyKeyContainer";
	if (CryptAcquireContext(&hCryptProv, UserName, NULL, PROV_RSA_FULL, 0))
	{
		// printf("A cryptographic context with the %s key container has been acquired.\n\n", UserName);
	}
	else
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (CryptAcquireContext(&hCryptProv, UserName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				// printf("A new key container has been created.\n");
			}
			else
			{
				printf("Could not create a new key container.\n");
				exit(1);
			}
		}
		else
		{
			printf("A cryptographic service handle could not be acquired.\n");
			exit(1);
		}
	}
	if (CryptGenRandom(hCryptProv, 4, (BYTE*)(&a)))
	{
		// printf("Random sequence generated. \n");
	}
	else
	{
		printf("Error during CryptGenRandom.\n");
		exit(1);
	}

	int temp[16];
	int i = 0;
	int m = 0;
	int yushu;
	uint8_t hex[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	if (a < 0)
	{
		a = -a;
	}
	while (a > 0)
	{
		yushu = a % 16;
		temp[i] = yushu;
		i++;
		a = a / 16;
	}
	int r = 0;
	for (i = i - 1; i >= 0; i--)
	{
		m = temp[i];
		RA_A[r] = hex[m];
		r++;
	}

}

// 2.2 拼接SIDA、RA_A、RB_A、IB_A、Text2
void jointStringA(uint8_t* jointedStringA, uint8_t* RB)
{
	int count = 0;
	// joint SIDA
	for (int i = 0; i < 16; i++)
	{
		jointedStringA[i] = SIDA[i];
	}
	count = 16;
	
	// joint RA
	for (int i = 0; i < 16; i++)
	{
		jointedStringA[count + i] = RA_A[i];
	}
	count += 16;

	// joint RB
	for (int i = 0; i < 16; i++)
	{
		jointedStringA[count + i] = RB[i];
	}
	count += 16;

	// joint IB
	for (int i = 0; i < 8; i++)
	{
		jointedStringA[count + i] = IB_A[i];
	}
	count += 8;

	// joint Text2
	for (int i = 0; i < 8; i++)
	{
		jointedStringA[count + i] = Text2[i];
	}

}

// 2.3 用KAB作密钥，用SM4对拼接字符串加密
void encryptA(uint8_t* EnInput, int plainSize, uint8_t* EnOutputWithTag)
{
	GCM_CTX en_ctx;
	SM4_CTX sm4_en_ctx;
	uint8_t* en_outptr;
	const CipherInfo* cipher = &SM4Info;

	en_outptr = en_out_A;
	gcm_init(KAB_A, gcm_iv_A, sizeof(gcm_iv_A), NULL, cipher, &sm4_en_ctx, &en_ctx);
	gcm_encrypt_update(en_outptr, &en_outlen_A, EnInput, plainSize, &en_ctx);
	en_outptr += en_outlen_A;
	gcm_encrypt_final(en_outptr, &en_outlen_A, en_tag_A, en_taglen_A, &en_ctx);
	en_outptr += en_outlen_A;

	for (int i = 0; i < plainSize; i++)
	{
		EnOutputWithTag[i] = en_out_A[i];
	}
	printf("\nTag in TokenAB:");
	for (int i = 0; i < 16; i++)
	{
		EnOutputWithTag[plainSize + i] = en_tag_A[i];
		printf("%#04x ", en_tag_A[i]);
	}
	printf("\n");
}


// 2.4 拼接Text2和加密结果，得到TokenAB，发送TokenAB给B
void genTokenAB(uint8_t * TokenAB, uint8_t* RBfromB)
{
	genRA();

	uint8_t jointedStringA[64] = { 0x00 };
	jointStringA(jointedStringA, RBfromB);		// joints string for next encryption

	for (int i = 0; i < 8; i++)
	{
		TokenAB[i] = Text3[i];
	}

	uint8_t EnOutputWithTag[80] = { 0x00 }; // plain is 64 bits long, tag is 16 bits long, total is 80
	encryptA(jointedStringA, 64, EnOutputWithTag);

	for (int i = 0; i < 80; i++)
	{
		TokenAB[8 + i] = EnOutputWithTag[i];
	}

}

// 5.1 接收到TokenBA，拆解后得到Text4和加密字符串
void parseTokenBA(uint8_t* TokenBA, uint8_t* cipherFromTokenBA, int neededLength)
{
	uint8_t Text[8] = { 0x00 };
	for (int i = 0; i < 8; i++)
	{
		Text[i] = TokenBA[i];
	}
	for (int i = 0; i < neededLength; i++)
	{
		cipherFromTokenBA[i] = TokenBA[i + 8];
	}
}

// 5.2 使用KAB和SM4解密字符串，得到明文字符串
void decryptA(CipherInfo* cipher, int cipherSize, uint8_t* DeInput, uint8_t* DeOutput)
{
	uint8_t de_out[SM4_BLOCK_SIZE * 4];
	int de_outlen;
	uint8_t de_tag[SM4_BLOCK_SIZE];
	int de_taglen = SM4_BLOCK_SIZE;
	GCM_CTX de_ctx;
	SM4_CTX sm4_de_ctx;
	uint8_t* de_outptr;
	de_outptr = de_out;

	gcm_init(KAB_A, gcm_iv_A, sizeof(gcm_iv_A), NULL, cipher, &sm4_de_ctx, &de_ctx);
	gcm_decrypt_update(de_outptr, &de_outlen, DeInput, cipherSize, &de_ctx);
	de_outptr += de_outlen;
	int err = gcm_decrypt_final(de_outptr, &de_outlen, DeInput+cipherSize, de_taglen, &de_ctx);
	de_outptr += de_outlen;

	for (size_t i = 0; i < cipherSize; i++)
	{
		DeOutput[i] = de_out[i];
	}
	printf("\n\nTag Err = %d\n\n", err);
}

// 5.3 拆解字符串，依次得到SIDB、TNA'、TNB'、IA'、Text3
void AverifyB(uint8_t* TokenBA)
{
	uint8_t strWithTagFromTokenAB[64] = { 0x00 }; // cipher/plain 48bits, tag 16bits, entire string from token 64bits
	uint8_t plainFromTokenBA[48] = { 0x00 };  // pure plain
	parseTokenBA(TokenBA, strWithTagFromTokenAB, 64);

	const CipherInfo* cipher = &SM4Info;
	decryptA(cipher, 48, strWithTagFromTokenAB, plainFromTokenBA); // pure cipher length 48

	uint8_t SID[16] = { 0x00 };
	uint8_t RA[16] = { 0x00 };
	uint8_t IA[8] = { 0x00 };
	uint8_t Text[8] = { 0x00 };

	// SIDB
	for (int i = 0; i < 16; i++)
	{
		SID[i] = plainFromTokenBA[i];
		if (i < 5)
		{
			if (SID[i] != SIDA[i])
			{
				printf("ERROR! SID From B is Invalide!\n");
				exit(EXIT_SUCCESS);
			}
		}
		else if (i == 5)
		{
			if (SID[i] == SIDA[i])
			{
				printf("ERROR! SID From A is Invalide!\n");
				exit(EXIT_SUCCESS);
			}
		}
	}

	// RA
	for (int i = 0; i < 16; i++)
	{
		RA[i] = plainFromTokenBA[i + 16];
		if (RA[i] != RA_A[i])
		{
			printf("ERROR! RA From B is Invalide!\n");
			exit(EXIT_SUCCESS);
		}
	}

	// IA
	for (int i = 0; i < 8; i++)
	{
		IA[i] = plainFromTokenBA[i + 16 + 16];
		if (IA[i] != IA_A[i])
		{
			printf("ERROR! IB From A is Invalide!\n");
			exit(EXIT_SUCCESS);
		}
	}
	for (int i = 0; i < 8; i++)
	{
		Text[i] = plainFromTokenBA[i + 16 + 16 + 8];
	}


}