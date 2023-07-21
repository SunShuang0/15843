#include <ctype.h>
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>


uint32_t loadu32_be(uint8_t* data) {
    uint32_t n = data[3];
    n |= data[2] << 8;
    n |= data[1] << 16;
    n |= data[0] << 24;
    return n;
}


uint64_t loadu64_be(uint8_t* data) {
    return ((uint64_t)loadu32_be(data) << 32) | loadu32_be(data + 4);
}


void storeu32_be(uint8_t* dst, uint32_t n) {
    dst[3] = n & 0xFF;
    dst[2] = (n >> 8) & 0xFF;
    dst[1] = (n >> 16) & 0xFF;
    dst[0] = (n >> 24) & 0xFF;
}


void storeu64_be(uint8_t* dst, uint64_t n) {
    storeu32_be(dst, n >> 32);
    storeu32_be(dst + 4, n & UINT32_MAX);
}


void dump_data(uint8_t* d, int size) {
    printf("dump data: size = %d\n", size);

    for (int i = 0; i < size; i += 16) {
        printf("%04x - ", i);

        for (int j = i; j < i + 16; j++) {
            if (j < size) {
                printf("%02x ", d[j]);
            } else {
                printf("   ");
            }
        }
        putchar(' ');

        for (int j = i; j < i + 16; j++) {
            if (j < size) {
                if (isprint(d[j])) {
                    putchar(d[j]);
                } else {
                    putchar('.');
                }
            } else {
                putchar(' ');
            }
        }
        puts("");
    }
    puts("");
}


void memxor(uint8_t* dst, uint8_t* a, uint8_t* b, int size) {
    for (int i = 0; i < size; i++) {
        dst[i] = a[i] ^ b[i];
    }
}

#include <time.h>

void rand_mem(uint8_t* mem, int size) {
    static int init = 0;
    if (init == 0) {

        srand((unsigned)time(NULL));
        init = 1;
    }
    for (int i = 0; i < size; i++) {
        mem[i] = rand() % 256;
    }
}
