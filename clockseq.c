#include "uuid.h"

uint16_t clockseq(void) {
    srand(time(NULL));
    splitmix64_seed(rand());
    uint64_t s[2];
    for (int i = 0; i < 2; i++) {
        s[i] = splitmix64_next();
    }
    xoroshiro_seed(s);
    uint64_t *u = xoroshiro_random();
    uint16_t n = *(uint16_t *) u;
    return n;
}

void clockseq_write(const char *filename, uint16_t cseq) {
    FILE *f = fopen(filename, "w");
    char s[8] = {0};
    itoa(cseq, s, 10);
    int size = fwrite(s, sizeof(char), strlen(s), f);
    if (!size) {
        perror("failed to write file");
    }
    fclose(f);
}

uint16_t clockseq_read(const char *filename) {
    uint16_t cseq;
    FILE *f = fopen(filename, "r");
    if (!f) {
        cseq = clockseq();
        clockseq_write(filename, cseq);
        return cseq;
    }

    char s[8] = {0};
    int size = fread(s, sizeof(char), 8, f);
    if (!size) {
        perror("failed to read file");
        return 0;
    }
    fclose(f);
    return atoi(s);
}
