#include "B.h"
void intToHex(int num, uint8_t * RandomNumber, uint8_t* RBfromB)
{
	int a[16];
	int i = 0;
	int m = 0;
	int yushu;
	uint8_t hex[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	if (num < 0)
	{
		num = -num;
	}
	while (num > 0)
	{
		yushu = num % 16;
		a[i] = yushu;
		i++;
		num = num / 16;
	}
	int r = 0;
	for(i = i - 1; i >= 0; i--)
	{
		m = a[i];
		RandomNumber[r] = hex[m];
		r++;
	}
	for (int i = 0; i < 16; i++)
	{
		RBfromB[i] = RandomNumber[i];
	}
}


void sendRB(uint8_t* RBfromB)
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
	intToHex(a, RB_B, RBfromB);

	for (int i = 0; i < 8; i++)
	{
		RBfromB[16 + i] = Text1[i];
	}
	printf("\nRBString:");
	for (int i = 0; i < 16; i++)
	{
		printf("%#04x, ", RBfromB[i]);
	}
	printf("\n");
}

void parseTokenAB(uint8_t* TokenAB, uint8_t* cipherFromTokenAB, int neededLength)
{
	uint8_t Text[8] = { 0x00 };
	for (int i = 0; i < 8; i++)
	{
		Text[i] = TokenAB[i];
	}
	printf("88:\n");
	for (int i = 0; i < neededLength; i++)
	{
		cipherFromTokenAB[i] = TokenAB[i + 8];
		printf("%#04x, ", cipherFromTokenAB[i]);
	}
	printf("\n");
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
	int err = gcm_decrypt_final(de_outptr, &de_outlen, DeInput + cipherSize, de_taglen, &de_ctx);
	de_outptr += de_outlen;
	printf("plaintext:\n");
	for (size_t i = 0; i < cipherSize; i++)
	{
		DeOutput[i] = de_out[i];
		printf("%#04x, ", de_out[i]);
	}
	printf("\n");

	printf("\n\nTag Err = %d\n\n", err);
}

void BverifyA(uint8_t* TokenAB)
{
	uint8_t strWithTagFromTokenAB[72] = { 0x00 }; // cipher is 64bits long, tag is 16bits long
	uint8_t plainFromTokenAB[56] = { 0x00 };  // pure cipher/plain's length
	parseTokenAB(TokenAB, strWithTagFromTokenAB, 72);
	
	const CipherInfo* cipher = &SM4Info;
	decryptB(cipher, 56, strWithTagFromTokenAB, plainFromTokenAB); // pure cipher's length is 64

	uint8_t SID[8] = { 0x00 };
	uint8_t RB[16] = { 0x00 };
	uint8_t IB[8] = { 0x00 };
	uint8_t Text[8] = { 0x00 };
	int count = 0;
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

	// RA
	for (int i = 0; i < 16; i++)
	{
		RA_B[i] = plainFromTokenAB[i + 8];
	}

	// RB
	for (int i = 0; i < 16; i++)
	{
		RB[i] = plainFromTokenAB[i + 8 + 16];
		if (RB[i] != RB_B[i])
		{
			printf("ERROR! RB From A is Invalide!\n");
			exit(EXIT_SUCCESS);
		}
	}

	// IB
	for (int i = 0; i < 8; i++)
	{
		IB[i] = plainFromTokenAB[i + 8 + 16 + 16];
		if (IB[i] != IB_B[i])
		{
			printf("ERROR! IB From A is Invalide!\n");
			exit(EXIT_SUCCESS);
		}
	}

	// Text
	for (int i = 0; i < 8; i++)
	{
		Text[i] = plainFromTokenAB[i + 8 + 16 + 16 + 8];
	}

}

// 4.1 拼接字符串SIDB、RA、IA、Text4
void jointStringB(uint8_t* jointedStringB)
{
	int count = 0;
	// joint SIDB
	for (int i = 0; i < 8; i++)
	{
		jointedStringB[i] = SIDB[i];
	}
	count = 8;

	// joint RA
	for (int i = 0; i < 16; i++)
	{
		jointedStringB[count + i] = RA_B[i];
	}
	count += 16;

	// joint IA_B
	for (int i = 0; i < 8; i++)
	{
		jointedStringB[count + i] = IA_B[i];
	}
	count += 8;

	// joint Text3
	for (int i = 0; i < 8; i++)
	{
		jointedStringB[count + i] = Text4[i];
	}
}


// 4.2 使用KAB和SM4加密字符串
void encryptB(uint8_t* EnInput, int plainSize, uint8_t* EnOutputWithTag)
{
	GCM_CTX en_ctx;
	SM4_CTX sm4_en_ctx;
	uint8_t* en_outptr;
	const CipherInfo* cipher = &SM4Info;

	en_outptr = en_out_B;
	gcm_init(KAB_B, gcm_iv_B, sizeof(gcm_iv_B), NULL, cipher, &sm4_en_ctx, &en_ctx);
	gcm_encrypt_update(en_outptr, &en_outlen_B, EnInput, plainSize, &en_ctx);
	en_outptr += en_outlen_B;
	gcm_encrypt_final(en_outptr, &en_outlen_B, en_tag_B, en_taglen_B, &en_ctx);
	en_outptr += en_outlen_B;

	for (int i = 0; i < plainSize; i++)
	{
		EnOutputWithTag[i] = en_out_B[i];
	}

	printf("\nTag in TokenBA:");
	for (int i = 0; i < 16; i++)
	{
		EnOutputWithTag[plainSize + i] = en_tag_B[i];
		printf("%#04x ", en_tag_B[i]);
	}
	printf("\n");

}


// 4.3 拼接Text4和加密结果，得到TokenBA，发送TokenBA给A
void genTokenBA(uint8_t* TokenBA)
{
	uint8_t jointedStringB[40] = { 0x00 };
	jointStringB(jointedStringB);		// joints string for next encryption
	printf("\njointstringinb:\n");
	for (int i = 0; i < 40; i++)
	{
		printf("%#04x ", jointedStringB[i]);
	}
	printf("\n");

	for (int i = 0; i < 8; i++)
	{
		TokenBA[i] = Text5[i];
	}

	uint8_t EnOutputWithTag[56] = { 0x00 }; // plain is 40 bits long, tag is 16 bits long, total is 56
	encryptB(jointedStringB, 40, EnOutputWithTag); // pure cipher/plain length
	for (int i = 0; i < 56; i++)
	{
		TokenBA[8 + i] = EnOutputWithTag[i];
	}

}