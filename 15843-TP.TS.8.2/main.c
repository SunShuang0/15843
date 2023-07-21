#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "main.h"

int main()
{
	printf("\n----------  MUT.TS Begin  ----------\n\n");
	uint8_t TokenPA[144] = { 0x00 };

	genTokenPA(TokenPA);
	printf("TokenPA:");
	for (int i = 0; i < 144; i++)
	{
		printf("%x", TokenPA[i]);
	}
	printf("\n");

	system("pause");
}

