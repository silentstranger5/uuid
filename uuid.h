#ifndef UUID

#define UUID

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void splitmix64_seed(uint64_t seed);
uint64_t splitmix64_next(void);

void xoroshiro_seed(uint64_t seed[2]);
uint64_t* xoroshiro_random(void);

uint16_t clockseq_read(const char *filename);
uint64_t macaddress_read(const char *filename);

uint8_t *sha_hash(const char *msg, int debug);
char *hostname(void);

#endif
