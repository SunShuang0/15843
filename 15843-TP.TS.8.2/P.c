#include "P.h"
void jointStringToA(uint8_t* jointedStringToA)
{
	int count = 0;
	// joint SIDA
	for (int i = 0; i < 8; i++)
	{
		jointedStringToA[i] = SID1[i];
	}
	count = 8;

	printf("\nSID1:");
	for (int i = 0; i < 8; i++)
	{
		printf("%#04x ", jointedStringToA[i]);
	}

	// TVPA
	for (int i = 0; i < 16; i++)
	{
		jointedStringToA[count + i] = TVPA[i];
	}
	
	printf("\nTVPA:");
	for (int i = 0; i < 16; i++)
	{
		printf("%#04x ", jointedStringToA[i + count]);
	}
	count += 16;

	// KAB
	for (int i = 0; i < 16; i++)
	{
		jointedStringToA[count + i] = KAB[i];
	}
	printf("\nKAB:");
	for (int i = 0; i < 16; i++)
	{
		printf("%#04x ", jointedStringToA[i + count]);
	}
	count += 16;

	// IB
	for (int i = 0; i < 8; i++)
	{
		jointedStringToA[count + i] = IB[i];
	}
	printf("\nIB:");
	for (int i = 0; i < 8; i++)
	{
		printf("%#04x ", jointedStringToA[i + count]);
	}
	count += 8;

	// Text3
	for (int i = 0; i < 8; i++)
	{
		jointedStringToA[count + i] = Text3[i];
	}
	printf("\nText3:");
	for (int i = 0; i < 8; i++)
	{
		printf("%#04x ", jointedStringToA[i + count]);
	}

}
void jointStringToB(uint8_t* jointedStringToB)
{
	int count = 0;
	// joint SID2
	for (int i = 0; i < 8; i++)
	{
		jointedStringToB[i] = SID2[i];
	}
	count = 8;

	printf("\nSID2:");
	for (int i = 0; i < 8; i++)
	{
		printf("%#04x ", jointedStringToB[i]);
	}

	// TNP
	for (int i = 0; i < 8; i++)
	{
		jointedStringToB[count + i] = TVPA[i];
	}

	printf("\nTNP:");
	for (int i = 0; i < 8; i++)
	{
		printf("%#04x ", jointedStringToB[i + count]);
	}
	printf("\n");
	count += 8;

	// KAB
	for (int i = 0; i < 16; i++)
	{
		jointedStringToB[count + i] = KAB[i];
	}
	printf("\nKAB:");
	for (int i = 0; i < 16; i++)
	{
		printf("%#04x ", jointedStringToB[i + count]);
	}
	printf("\n");
	count += 16;

	// IA
	for (int i = 0; i < 8; i++)
	{
		jointedStringToB[count + i] = IA[i];
	}
	printf("\nIA:");
	for (int i = 0; i < 8; i++)
	{
		printf("%#04x ", jointedStringToB[i + count]);
	}
	printf("\n");
	count += 8;

	// Text2
	for (int i = 0; i < 8; i++)
	{
		jointedStringToB[count + i] = Text2[i];
	}
	printf("\nText2:");
	for (int i = 0; i < 8; i++)
	{
		printf("%#04x ", jointedStringToB[i + count]);
	}
	printf("\n");

}


void encrypt(uint8_t* Key, uint8_t* EnInput, int plain_len, uint8_t* EnOutputWithTag)
{
	GCM_CTX en_ctx;
	SM4_CTX sm4_en_ctx;
	uint8_t* en_outptr;
	const CipherInfo* cipher = &SM4Info;

	en_outptr = en_out;
	gcm_init(Key, gcm_iv, sizeof(gcm_iv), NULL, cipher, &sm4_en_ctx, &en_ctx);
	gcm_encrypt_update(en_outptr, &en_outlen, EnInput, plain_len, &en_ctx);
	en_outptr += en_outlen;
	gcm_encrypt_final(en_outptr, &en_outlen, en_tag, en_taglen, &en_ctx);
	en_outptr += en_outlen;

	for (int i = 0; i < plain_len; i++)
	{
		EnOutputWithTag[i] = en_out[i];
	}

	printf("\nTag in A:");
	for (int i = 0; i < 16; i++)
	{
		EnOutputWithTag[plain_len + i] = en_tag[i];
		printf("%#04x, ", en_tag[i]);
	}
	printf("\n");
}


/**
 * A Éú³É TokenPA
 */
void genTokenPA(uint8_t* TokenPA)
{
	uint8_t jointedStringToA[56] = { 0x00 };
	jointStringToA(jointedStringToA);		// joints string for next encryption

	printf("\njointedStringToA:");
	for (int i = 0; i < 56; i++)
	{
		printf("%#04x ", jointedStringToA[i]);
	}
	printf("\n");

	for (int i = 0; i < 8; i++)
	{
		TokenPA[i] = Text4[i];
	}

	uint8_t EnOutput[72] = { 0x00 }; // 56 + 16
	encrypt(KAP, jointedStringToA, 56, EnOutput);

	for (int i = 0; i < 72; i++)
	{
		TokenPA[8 + i] = EnOutput[i];
	}
	printf("\nTokenPA1:\n");
	for (int i = 0; i < 144; i++)
	{
		printf("%#04x ", TokenPA[i]);
	}
	printf("\n");





	uint8_t jointedStringToB[48] = { 0x00 };
	jointStringToB(jointedStringToB);		// joints string for next encryption

	printf("\njointedStringToB:");
	for (int i = 0; i < 48; i++)
	{
		printf("%#04x ", jointedStringToB[i]);
	}
	printf("\n");

	uint8_t EnOutputB[64] = { 0x00 }; // 48 + 16
	encrypt(KBP, jointedStringToB, 48, EnOutputB);

	for (int i = 0; i < 64; i++)
	{
		TokenPA[80 + i] = EnOutputB[i];
	}
	printf("\nTokenPA2:\n");
	for (int i = 0; i < 144; i++)
	{
		printf("%#04x, ", TokenPA[i]);
	}
	printf("\n");




}


void decryptA(CipherInfo* cipher, int size, uint8_t* DeInput, uint8_t* DeOutput)
{
	//uint8_t de_out[SM4_BLOCK_SIZE * 4];
	//int de_outlen;
	//uint8_t de_tag[SM4_BLOCK_SIZE];
	//int de_taglen = SM4_BLOCK_SIZE;
	//GCM_CTX de_ctx;
	//SM4_CTX sm4_de_ctx;
	//uint8_t* de_outptr;
	//de_outptr = de_out;

	//gcm_init(KAB, gcm_iv, sizeof(gcm_iv), NULL, cipher, &sm4_de_ctx, &de_ctx);
	//gcm_decrypt_update(de_outptr, &de_outlen, DeInput, size, &de_ctx);
	//de_outptr += de_outlen;
	//gcm_decrypt_final(de_outptr, &de_outlen, de_tag, de_taglen, &de_ctx);
	//de_outptr += de_outlen;
	//int size2 = (int)(de_outptr - de_out);
	//for (size_t i = 0; i < size; i++)
	//{
	//	DeOutput[i] = de_out[i];
	//}
}
