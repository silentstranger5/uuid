#include "uuid.h"

uint64_t uuid_timestamp(time_t t) {
    return t + 0x01B21DD213814000;
}

uint64_t *uuidv1(void) {
    uint64_t *uuid = malloc(2 * sizeof(uint64_t));
    uint16_t cseq = clockseq_read("clockseq.txt");
    uuid[0] = uuid_timestamp(time(NULL));
    uuid[1] = macaddress_read("macaddress.txt");
    uint8_t *b = (uint8_t *) &uuid[0];
    for (int i = 8; i > 1; i--) {
        b[i - 1] <<= 4;
        b[i - 1] |= b[i - 2] >> 4;
    }
    b[1] &= 0xf0;
    b[1] |= b[1] >> 4;
    b[1] &= 0x0f;
    b[1] |= 0x1 << 4;
    b = (uint8_t *) &cseq;
    b[1] &= 0x40 - 1;
    b[1] |= 0x2 << 6;
    uuid[1] &= (uint64_t) (1 << 49) - 1;
    uuid[1] |= (uint64_t) cseq << 48;
    return uuid;
}

uint64_t *uuidv4(void) {
    srand(time(NULL));
    splitmix64_seed(rand());
    uint64_t seed[2];
    for (int i = 0; i < 2; i++) {
        seed[i] = splitmix64_next();
    }
    xoroshiro_seed(seed);
    uint64_t *uuid = xoroshiro_random();
    uint8_t *b = (uint8_t *) uuid;
    b[1] &= 0x10 - 1;
    b[1] |= 0x4 << 4;
    b[15] &= 0x40 - 1;
    b[15] |= 0x2 << 6;
    return uuid;
}

uint64_t *uuidv5(void) {
    char *host = hostname();
    uint8_t *hash = sha_hash(host, 0);
    hash[6] &= 0x10 - 1;
    hash[6] |= 0x05 << 4;
    hash[8] &= 0x40 - 1;
    hash[8] |= 0x02 << 6;
    uint64_t *uuid = malloc(2 * sizeof(uint64_t));
    uint8_t *b = (uint8_t *) uuid;
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 8; j++) {
            b[8 * i + 8 - (j + 1)] = hash[8 * i + j];
        }
    }
    return uuid;
}

char *uuid_string(uint64_t *u) {
    uint8_t *b = (uint8_t *) u;
    char *s = malloc(37 * sizeof(char));
    int j = 0;
    for (int i = 8; i > 4; i--, j += 2) {
        sprintf(s + j, "%02x", b[i - 1]);
    }
    sprintf(s + j++, "-");
    for (int i = 4; i > 2; i--, j += 2) {
        sprintf(s + j, "%02x", b[i - 1]);
    }
    sprintf(s + j++, "-");
    for (int i = 2; i > 0; i--, j += 2) {
        sprintf(s + j, "%02x", b[i - 1]);
    }
    sprintf(s + j++, "-");
    for (int i = 16; i > 14; i--, j += 2) {
        sprintf(s + j, "%02x", b[i - 1]);
    }
    sprintf(s + j++, "-");
    for (int i = 14; i > 8; i--, j += 2) {
        sprintf(s + j, "%02x", b[i - 1]);
    }
    s[j] = 0;
    return s;
}

int main(int argc, char **argv) {
    int version = (argc == 3) ? atoi(argv[2]) : 4;
    if (!(argc == 1 || argc == 3)) {
        printf("usage: %s -v <version>\n", argv[0]);
        exit(1);
    }
    if (argc == 3 && strcmp(argv[1], "-v")) {
        printf("usage: %s -v <version>\n", argv[0]);
        exit(1);
    }
    uint64_t *u = NULL;
    switch (version) {
        case 1:
            u = uuidv1();
            break;
        case 4:
            u = uuidv4();
            break;
        case 5:
            u = uuidv5();
            break;
        default:
            printf("invalid uuid version: %s\n", argv[2]);
            exit(1);
    }
    char *s = uuid_string(u);
    puts(s);
    free(u);
    free(s);
    return 0;
}
