#ifndef CRYPTO_FIELD_H
#define CRYPTO_FIELD_H

#include "types.h"

extern const uint16_t crypto_P;
extern const uint16_t crypto_D_INV;
extern uint16_t crypto_G;

uint16_t crypto_modpow(uint16_t base, uint16_t exp, uint16_t mod);
uint16_t crypto_find_generator(void);
uint16_t crypto_inv3(void);

#endif
