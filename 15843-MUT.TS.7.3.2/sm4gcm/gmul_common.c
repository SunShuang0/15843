#include "gmul.h"
#include "utils.h"

void gmul_common(uint8_t* r, uint8_t* X, uint8_t* H) {

    uint64_t Rh = (uint64_t)0xE1 << 56;
    uint64_t Zh = 0;
    uint64_t Zl = 0;

    uint64_t Vh = loadu64_be(H);
    uint64_t Vl = loadu64_be(H + 8);

    uint8_t x, t;

    for (int i = 0; i < 16; i++) {
        x = X[i];
        for (int j = 7; j >= 0; j--) {
            if ((x >> j) & 1) {
                Zh ^= Vh, Zl ^= Vl;
            }
            t = Vl & 1;
            Vl = (Vh << 63) | (Vl >> 1);
            Vh = Vh >> 1;
            if (t) {
                Vh ^= Rh;
            }
        }
    }

    storeu64_be(r, Zh);
    storeu64_be(r + 8, Zl);
}
