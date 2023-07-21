#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

uint32_t loadu32_be(uint8_t* src);

void storeu32_be(uint8_t* dst, uint32_t n);

uint64_t loadu64_be(uint8_t* src);

void storeu64_be(uint8_t* dst, uint64_t n);

void dump_data(uint8_t* d, int len);

void memxor(uint8_t* dst, uint8_t* a, uint8_t* b, int size);

void rand_mem(uint8_t* mem, int size);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif // UTILS_H
