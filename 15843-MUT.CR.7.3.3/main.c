#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "main.h"

int main()
{
	printf("\n----------  MUT.CR Begin  ----------\n");

	// uint8_t RBfromB[24] = { 0x00 };
	// sendRB(RBfromB);

	uint8_t TokenAB[80] = { 0x33, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00,
							0xf1, 0x1c, 0xef, 0x37, 0x51, 0xe1, 0x17, 0x3e,
							0x55, 0x16, 0x7d, 0x4e, 0x2c, 0xce, 0x4f, 0x8f,
							0x1e, 0x9a, 0xcd, 0x22, 0xa6, 0xf0, 0x9c, 0x25,
							0x8f, 0x8b, 0xb2, 0x8a, 0x4d, 0xa8, 0x6a, 0x2d,
							0x56, 0x59, 0x25, 0x5f, 0x95, 0x9e, 0xe7, 0x7e,
							0xf5, 0x92, 0x4d, 0x45, 0x5f, 0xf9, 0xeb, 0xa2,
							0x05, 0x66, 0xfc, 0x77, 0xe3, 0xcd, 0xdd, 0xfe,
							0xaf, 0x50, 0x88, 0xa9, 0x7b, 0x9f, 0x5a, 0xac,
							0xa3, 0x55, 0x7b, 0x55, 0xb4, 0x61, 0xe9, 0x18 }; // 72 + tag[16] = 88
	uint8_t TokenBA[64] = { 0x00 }; // 56 + tag[16] = 72

	// genTokenAB(TokenAB, RBfromB);

	printf("\nTokenAB: ");
	for (int i = 0; i < 80; i++)
	{
		printf("%#04x ", TokenAB[i]);
	}
	printf("\n");


	BverifyA(TokenAB);

	genTokenBA(TokenBA);

	printf("\nTokenBA: ");
	for (int i = 0; i < 64; i++)
	{
		printf("%#04x, ", TokenBA[i]);
	}
	printf("\n");

	// AverifyB(TokenBA);

	printf("\n----------  MUT.CR Success  ----------\n\n");

	system("pause");
}

