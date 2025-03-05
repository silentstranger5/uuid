#include "uuid.h"

#define w  32        // word   size in bits
#define ds 160       // digest size in bits
#define m  512       // block  size in bits

// algorithm functions
#define ROTL(x, n) ((x << n) | (x >> (w - n)))
#define ROTR(x, n) ((x >> n) | (x << (w - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define PARITY(x, y, z) (x ^ y ^ z)
#define S0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

// check if machine is big-endian
#define ENDIAN (*(uint16_t *)"\0\xff" < 0x100)

// byteswap functions
#define BSWAP32(x) ((uint32_t)((((x) & 0x000000FF) << 24) | \
                                (((x) & 0x0000FF00) << 8)  | \
                                (((x) & 0x00FF0000) >> 8)  | \
                                (((x) & 0xFF000000) >> 24)))
#define BSWAP64(x) ((uint64_t)((((x) & 0x00000000000000FFULL) << 56) | \
                                (((x) & 0x000000000000FF00ULL) << 40) | \
                                (((x) & 0x0000000000FF0000ULL) << 24) | \
                                (((x) & 0x00000000FF000000ULL) << 8)  | \
                                (((x) & 0x000000FF00000000ULL) >> 8)  | \
                                (((x) & 0x0000FF0000000000ULL) >> 24) | \
                                (((x) & 0x00FF000000000000ULL) >> 40) | \
                                (((x) & 0xFF00000000000000ULL) >> 56)))

// message block is block with 16 x 32 byte words = 512 bit
typedef uint32_t mblock[m/8];

// sha context
typedef struct {
    uint8_t *msg;
    mblock *mblocks;
    size_t size;
    size_t N;
    uint32_t debug;
    uint32_t H[5];
} sha_ctx;

#ifdef _WIN32
    #define popen _popen
#elif defined(__unix__)
    #define getline getline_f
#endif

// read line from standard input
int getline(uint8_t *s, uint32_t size);
// sha hash digest of msg
uint8_t *sha_hash(const char *msg, int debug);
// print digest value
void digest_print(uint8_t *digest);

// algorithm constants
const uint32_t K[] = {
    0x5a827999,
    0x6ed9eba1,
    0x8f1bbcdc,
    0xca62c1d6,
};

// initial hash values
const uint32_t H0[] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0,
};

// read line from standard input
int getline(uint8_t *s, uint32_t size) {
    fgets(s, size, stdin);
    *strchr(s, '\n') = 0;
    return (int) strlen(s);
}

// message padding
void sha_padding(sha_ctx *ctx) {
    uint64_t l = strlen(ctx->msg) * 8;
    uint32_t k = (l % 448) ? 448 - (l % 448) : m;
    uint64_t ls = ENDIAN ? l : BSWAP64(l);
    ctx->size = (l + k + 64) / 8;
    uint8_t *buf = calloc(ctx->size, sizeof(uint8_t));
    strcpy(buf, ctx->msg);
    buf[l / 8] = 1 << (8 - 1);
    memcpy(&buf[ctx->size-8], &ls, sizeof(uint64_t));
    ctx->msg = buf;
}

// parse message into message blocks
void sha_parse(sha_ctx *ctx) {
    ctx->N = ctx->size * 8 / m;
    ctx->mblocks = malloc(ctx->N * 16 * sizeof(uint32_t));
    uint32_t *wrdptr = (uint32_t *) ctx->msg;
    for (int i = 0; i < ctx->N; i++) {
        for (int j = 0; j < 16; j++) {
            uint32_t n = wrdptr[i * 16 + j];
            ctx->mblocks[i][j] = ENDIAN ? n : BSWAP32(n);
        }
    }
}

// print hash values
void sha_hash_print(sha_ctx *ctx) {
    for (int i = 0; i < 5; i++) {
        printf("H[%d] = %08X\n", i, ctx->H[i]);
    }
    putchar('\n');
}

// print block values
void sha_block_print(sha_ctx *ctx, int i) {
    puts("Block contents:");
    for (int j = 0; j < 16; j++) {
        printf("W[%d] = %08X\n", j, ctx->mblocks[i][j]);
    }
    putchar('\n');
}

// print variables
void sha_vars_print(uint32_t *vars) {
    for (int i = 0; i < 5; i++) {
        printf("%08X ", vars[i]);
    }
    putchar('\n');
}

// initialize context
void sha_init(sha_ctx *ctx) {
    memcpy(ctx->H, H0, 5 * sizeof(uint32_t));
    if (ctx->debug) {
        putchar('\n');
        puts("Initial hash value:");
        sha_hash_print(ctx);
    }
}

uint32_t f(int x, int y, int z, int t) {
    switch (t / 20) {
        case 0:
            return CH(x, y, z);
        case 1:
            return PARITY(x, y, z);
        case 2:
            return MAJ(x, y, z);
        case 3:
            return PARITY(x, y, z);
        default:
            return 0;
    }
}

// update context
void sha_update(sha_ctx *ctx, const uint8_t *msg) {
    uint32_t W[80] = {0};
    uint32_t a, b, c, d, e, T;
    ctx->msg = msg;
    sha_padding(ctx);
    sha_parse(ctx);
    for (int i = 0; i < ctx->N; i++) {
        for (int t = 0; t < 16; t++) {
            W[t] = ctx->mblocks[i][t];
        }
        if (ctx->debug) {
            sha_block_print(ctx, i);
        }
        for (int t = 16; t < 80; t++) {
            W[t] = ROTL((W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]), 1);
        }
        a = ctx->H[0];
        b = ctx->H[1];
        c = ctx->H[2];
        d = ctx->H[3];
        e = ctx->H[4];
        if (ctx->debug) {
            printf("  ");
            for (int i = 0; i < 5; i++) {
                printf("%9c", 'A' + i);
            }
            putchar('\n');
        }
        for (int t = 0; t < 80; t++) {
            T = ROTL(a, 5) + f(b, c, d, t) + e + K[t / 20] + W[t];
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = T;
            if (ctx->debug) {
                uint32_t vars[] = {a, b, c, d, e};
                printf("t=%2d: ", t);
                sha_vars_print(vars);
            }
        }
        ctx->H[0] += a;
        ctx->H[1] += b;
        ctx->H[2] += c;
        ctx->H[3] += d;
        ctx->H[4] += e;
        if (ctx->debug) {
            putchar('\n');
            sha_hash_print(ctx);
        }
    }
}

// copy hash value into digest buffer
void sha_final(sha_ctx *ctx, uint8_t *digest) {
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 4; j++) {
            uint32_t n = ENDIAN ? ctx->H[i] : BSWAP32(ctx->H[i]);
            memcpy(digest + i * 4, &n, sizeof(uint32_t));
        }
    }
}

// free data from context
void sha_free(sha_ctx *ctx) {
    free(ctx->msg);
    free(ctx->mblocks);
}

// print digest value
void digest_print(uint8_t *digest) {
    printf("Digest: ");
    for (int i = 0; i < ds / 8; i++) {
        if (i > 0 && i % 4 == 0) {
            putchar(' ');
        }
        printf("%02X", digest[i]);
    }
    putchar('\n');
}

// sha hash digest of msg
uint8_t *sha_hash(const char *msg, int debug) {
    uint8_t *digest = malloc(ds / 8);
    sha_ctx ctx = {0};
    ctx.debug = debug;
    sha_init(&ctx);
    sha_update(&ctx, msg);
    sha_final(&ctx, digest);
    sha_free(&ctx);
    return digest;
}

char *hostname(void) {
    char *s = calloc(32, sizeof(char));
    FILE *fp = popen("hostname", "r");
    fgets(s, 32, fp);
    *strchr(s, '\n') = 0;
    fclose(fp);
    return s;
}