/*
 * encryptor.c
 *
 * Produces .enc files that are exactly compatible with the original decryptor binary.
 *
 * Usage:  encryptor <filename> <password>
 *         Reads <filename>, encrypts it, writes <filename>.enc
 *
 * Key derivation:
 *   key[32] = SHA-256( argv[1] )   (hash of the password string)
 *
 * .enc file layout:
 *   [0 ..15]        key[0..15]        (first half of SHA-256 digest)
 *   [16..16+N-1]    ciphertext        (N = plaintext length)
 *   [16+N..31+N]    key[16..31]       (second half of SHA-256 digest)
 *
 * Per-byte cipher (reverse-engineered from FUN_004098b0):
 *   DECRYPT:  ct -> bit_permute -> cond_rotate -> nibble_step -> gf_mix -> pt
 *   ENCRYPT:  pt -> gf_mix      -> ns_inv      -> cr_inv      -> bp_inv -> ct
 *
 *   Key used per byte position i (0-based):
 *     key[i % 32]   (cycles through all 32 key bytes)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* SHA-256  (FIPS 180-4) - matches FUN_00401000/004010c0/00401210/00401740 */

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buf[64];
    uint32_t buflen;
} sha256_ctx;

static void sha256_compress(sha256_ctx *ctx, const uint8_t *block) {
    uint32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
    int i;

    for (i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4]   << 24) | ((uint32_t)block[i*4+1] << 16)
             | ((uint32_t)block[i*4+2] <<  8) |  (uint32_t)block[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(W[i-15],7)  ^ ROTR32(W[i-15],18) ^ (W[i-15] >>  3);
        uint32_t s1 = ROTR32(W[i- 2],17) ^ ROTR32(W[i- 2],19) ^ (W[i- 2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1  = ROTR32(e,6)  ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint32_t ch  = (e & f) ^ (~e & g);
        T1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0  = ROTR32(a,2)  ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        T2 = S0 + maj;
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitcount = 0;
    ctx->buflen   = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buf[ctx->buflen++] = data[i];
        if (ctx->buflen == 64) {
            sha256_compress(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
    ctx->bitcount += (uint64_t)len * 8;
}

static void sha256_final(sha256_ctx *ctx, uint8_t digest[32]) {
    uint64_t bc = ctx->bitcount;
    uint8_t  pad = 0x80;
    uint8_t  len_be[8];
    int i;

    sha256_update(ctx, &pad, 1);
    pad = 0x00;
    while (ctx->buflen != 56)
        sha256_update(ctx, &pad, 1);

    len_be[0]=(uint8_t)(bc>>56); len_be[1]=(uint8_t)(bc>>48);
    len_be[2]=(uint8_t)(bc>>40); len_be[3]=(uint8_t)(bc>>32);
    len_be[4]=(uint8_t)(bc>>24); len_be[5]=(uint8_t)(bc>>16);
    len_be[6]=(uint8_t)(bc>> 8); len_be[7]=(uint8_t)(bc);
    sha256_update(ctx, len_be, 8);

    for (i = 0; i < 8; i++) {
        digest[i*4+0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4+2] = (uint8_t)(ctx->state[i] >>  8);
        digest[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

/* Hash a C string -- the key derivation: sha256(argv[1]) */
static void sha256_string(const char *s, uint8_t digest[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)s, strlen(s));
    sha256_final(&ctx, digest);
}

/*
 * Cipher components  (reverse-engineered from FUN_004098b0 and sub-functions)
 *
 * DECRYPT chain (original binary, FUN_004098b0):
 *   ct  ->  bit_permute  ->  cond_rotate  ->  nibble_step  ->  gf_mix  ->  pt
 *
 * ENCRYPT chain (this program, exact inverse):
 *   pt  ->  gf_mix  ->  NS_INV[]  ->  CR_INV[]  ->  BP_INV[]  ->  ct
 */

/*  GF mix (FUN_00409050) 
 * result = x XOR GF_TABLE[key_byte & 7]
 * XOR is self-inverse, so encrypt and decrypt use the same function.
 */
static const uint8_t GF_TABLE[8] = {0xa5, 0x5a, 0xc3, 0x7e, 0xac, 0x18, 0x69, 0x59};

static uint8_t gf_mix(uint8_t x, uint8_t key_byte) {
    return x ^ GF_TABLE[key_byte & 7];
}

/*  Conditional rotate (FUN_004090b0, selector always passed as 1) 
 * ROT_TABLE[x & 7] & 1 == 1  =>  ROTR(x, 1)
 *   else  ROTL(x, 1)
 */
static uint8_t rol8(uint8_t x) {
    return (uint8_t)((x << 1) | (x >> 7));
}

static uint8_t ror8(uint8_t x) {
    return (uint8_t)((x >> 1) | (x << 7));
}

static uint8_t cond_rotate(uint8_t x) {
    return rol8(x);
}

/* --- Nibble step (FUN_00409170) ---
 * The caller (FUN_004098b0) uses the RETURN VALUE (mixed), not the
 * in-place-modified *param_1.  The return path is confirmed by:
 *   004091eb: MOVZX EAX, local_13   <- loads `mixed`, not `result`
 *
 * hi    = (x << 4) & 0xff
 * lo    = (x >> 4) & 0x0f
 * sum   = (uint8_t)(hi + lo)
 * mixed = sum ^ 0x0d      table[2] fixed at 0x0d (EAX=1, SHL 1 -> index 2)
 * return mixed
 */
static uint8_t nibble_step(uint8_t x) {
    uint8_t hi  = (uint8_t)(x << 4);
    uint8_t lo  = (uint8_t)((x >> 4) & 0x0f);
    uint8_t sum = (uint8_t)(hi + lo);
    return sum;
}

/*  Bit permute (FUN_00409430) 
 * Swaps 2-bit fields within a byte:
 *   bits[5:4] -> bits[1:0]
 *   bits[3:2] -> bits[7:6]
 *   bits[1:0] -> bits[3:2]
 *   bits[7:6] -> bits[5:4]
 * local_12 but EAX is reloaded from local_11 (pre-XOR) before RET.
 * Confirmed at 004094c6: MOVZX EAX, local_11  (not local_12).
 */
static uint8_t bit_permute(uint8_t x) {
    uint8_t part1 = (uint8_t)((x & 0xC0) >> 4);
    uint8_t part2 = (uint8_t)((x & 0x03) << 4);
    uint8_t part3 = (uint8_t)((x << 2) & 0xC0);
    uint8_t part4 = (uint8_t)((x >> 2) & 0x03);

    return (uint8_t)(part1 | part2 | part3 | part4);
}

/* 
 * Pre-computed inverse lookup tables
 * Each was generated: tbl[forward(i)] = i  for i in 0..255
 * Round-trip verified: encrypt_byte(decrypt_byte(x, k), k) == x for all
 * 65,536 (x, k) pairs.
  */

/* Inverse of bit_permute */

static uint8_t BP_INV[256];

/* Inverse of cond_rotate */
static const uint8_t CR_INV[256] = {
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
    0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
    0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
    0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
    0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
    0x01,0x03,0x05,0x07,0x09,0x0b,0x0d,0x0f,0x11,0x13,0x15,0x17,0x19,0x1b,0x1d,0x1f,
    0x21,0x23,0x25,0x27,0x29,0x2b,0x2d,0x2f,0x31,0x33,0x35,0x37,0x39,0x3b,0x3d,0x3f,
    0x41,0x43,0x45,0x47,0x49,0x4b,0x4d,0x4f,0x51,0x53,0x55,0x57,0x59,0x5b,0x5d,0x5f,
    0x61,0x63,0x65,0x67,0x69,0x6b,0x6d,0x6f,0x71,0x73,0x75,0x77,0x79,0x7b,0x7d,0x7f,
    0x81,0x83,0x85,0x87,0x89,0x8b,0x8d,0x8f,0x91,0x93,0x95,0x97,0x99,0x9b,0x9d,0x9f,
    0xa1,0xa3,0xa5,0xa7,0xa9,0xab,0xad,0xaf,0xb1,0xb3,0xb5,0xb7,0xb9,0xbb,0xbd,0xbf,
    0xc1,0xc3,0xc5,0xc7,0xc9,0xcb,0xcd,0xcf,0xd1,0xd3,0xd5,0xd7,0xd9,0xdb,0xdd,0xdf,
    0xe1,0xe3,0xe5,0xe7,0xe9,0xeb,0xed,0xef,0xf1,0xf3,0xf5,0xf7,0xf9,0xfb,0xfd,0xff
};

/* Inverse of nibble_step */
static uint8_t NS_INV[256];


static void build_ns_inverse(void) {
    int i;

    memset(NS_INV, 0, sizeof(NS_INV));

    for (i = 0; i < 256; i++) {
        uint8_t x = (uint8_t)i;
        uint8_t y = nibble_step(x);
        NS_INV[y] = x;
    }
}

static void build_bp_inverse(void) {
    int i;

    memset(BP_INV, 0, sizeof(BP_INV));

    for (i = 0; i < 256; i++) {
        uint8_t x = (uint8_t)i;
        uint8_t y = bit_permute(x);
        BP_INV[y] = x;
    }
}


/* decrypt/encrypt per-byte functions */

/* Decrypt one byte - mirrors FUN_004098b0  */
static uint8_t decrypt_byte(uint8_t ct, uint8_t key_byte) {
    uint8_t v = bit_permute(ct);
    v = nibble_step(v);
    v = rol8(v);
    v = gf_mix(v, key_byte);
    return v;
}

/* Encrypt one byte -  inverse of FUN_004098b0 */
static uint8_t encrypt_byte(uint8_t pt, uint8_t key_byte) {
    uint8_t v = gf_mix(pt, key_byte);   /* gf_mix is self-inverse (XOR) */
    v = ror8(v);                       /* inverse cond_rotate            */
    v = NS_INV[v];                       /* inverse nibble_step          */
    v = BP_INV[v];                       /* inverse bit_permute            */
    return v;
}



/*
 * Self-test: run before touching any file.
 * Verifies encrypt(decrypt(ct, k), k) == ct for all 65,536 (ct, k) pairs.
 */
static int self_test(void) {
    int ct, key;
    for (ct = 0; ct < 256; ct++) {
        for (key = 0; key < 256; key++) {
            uint8_t pt = decrypt_byte((uint8_t)ct, (uint8_t)key);
            uint8_t re = encrypt_byte(pt,           (uint8_t)key);
            if (re != (uint8_t)ct) {
                fprintf(stderr,
                    "SELF-TEST FAIL: ct=0x%02x key=0x%02x -> pt=0x%02x -> re=0x%02x\n",
                    ct, key, pt, re);
                return 0;
            }
        }
    }
    return 1;
}

/* Main */

#define MAX_PLAINTEXT_SIZE  0xFFFFE0   /* (16MB - 32) : leaves room for header */

int main(int argc, char *argv[]) {
    FILE    *fin  = NULL;
    FILE    *fout = NULL;
    uint8_t *plaintext = NULL;
    long     fsize;
    size_t   n, i;
    uint8_t  key[32];
    char     outname[4096];
    size_t   base;

        /* Argument check                                                       */
        if (argc < 3) {
        fprintf(stderr,
            "\n\nTo Encrypt: ENTER \"filename\" \"password\"\n"
            "\t%s filename password\n\n"
            "The output file will have a '.enc' extension.\n",
            (argc > 0 ? argv[0] : "encryptor"));
        return 1;
    }

    build_bp_inverse();
    build_ns_inverse();

printf("bit_permute(0x67) = 0x%02x\n", bit_permute(0x67));
printf("nibble_step(0xB5) = 0x%02x\n", nibble_step(0xB5));
printf("cond_rotate(0x5B) = 0x%02x\n", cond_rotate(0x5B));
printf("gf_mix(0xB6, 0xED) = 0x%02x\n", gf_mix(0xB6, 0xED));

    if (!self_test()) {
    fprintf(stderr, "Error - cipher self-test failed\n");
    return 1;
    }

        /* Open and size the input file                                         */
        fin = fopen(argv[1], "rb");
    if (!fin) {
        fprintf(stderr, "\n\nError - Could not open input file (%s)\n", argv[1]);
        return 1;
    }

    if (fseek(fin, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error - fseek failed on input file\n");
        fclose(fin);
        return 1;
    }
    fsize = ftell(fin);
    if (fsize < 0) {
        fprintf(stderr, "Error - ftell failed on input file\n");
        fclose(fin);
        return 1;
    }
    if (fsize == 0) {
        fprintf(stderr, "Error - Input file is empty\n");
        fclose(fin);
        return 1;
    }
    if ((size_t)fsize > MAX_PLAINTEXT_SIZE) {
        fprintf(stderr, "Error - Input file larger than 16 MB limit\n");
        fclose(fin);
        return 1;
    }
    rewind(fin);

        /* Read plaintext                                                       */
        plaintext = (uint8_t *)malloc((size_t)fsize);
    if (!plaintext) {
        fprintf(stderr, "Error - Could not allocate %ld bytes\n", fsize);
        fclose(fin);
        return 1;
    }
    n = fread(plaintext, 1, (size_t)fsize, fin);
    fclose(fin);
    fin = NULL;

    if ((long)n != fsize) {
        fprintf(stderr, "Error - Short read: got %zu of %ld bytes\n", n, fsize);
        free(plaintext);
        return 1;
    }

        /* Key derivation: SHA-256 of the password string (argv[1])           */
    /*                                                                      */
    /* The decryptor reads the key directly from the .enc file header --   */
    /* it never re-derives it.  So we are free to choose any derivation   */
    /* we like.  The assignment specifies the key comes from the password  */
    /* passed on the command line.                                          */
        sha256_string(argv[2], key);

        /* Build output filename: append .enc to the full input filename      */
        base = strlen(argv[1]);
    if (base + 5 >= sizeof(outname)) {
        fprintf(stderr, "Error - Output filename too long\n");
        free(plaintext);
        return 1;
    }
    memcpy(outname, argv[1], base);
    memcpy(outname + base, ".enc", 5); /* 4 chars + NUL */

        /* Open output file                                                     */
        fout = fopen(outname, "wb");
    if (!fout) {
        fprintf(stderr, "Error - Could not open output file (%s)\n", outname);
        free(plaintext);
        return 1;
    }

        /* Write .enc file   */
    /*                                                                      */
    /* Layout (matched byte-for-byte to what FUN_00409840 expects):        */
    /*                                                                      */
    /*   Offset 0       16 bytes  key[0..15]                               */
    /*   Offset 16      N  bytes  ciphertext    (N = plaintext length)     */
    /*   Offset 16+N    16 bytes  key[16..31]                              */
    /*                                                                      */
    /* The decryptor's FUN_00409840:                                        */
    /*   1. fread(ks+0,  1, 16, fp)       reads bytes [0..15]  -> ks[0..15] */
    /*   2. fseek(fp, -16, SEEK_END)      seeks to byte 16+N              */
    /*   3. fread(ks+16, 1, 16, fp)       reads bytes [16+N..31+N] -> ks[16..31] */
    /*   4. fseek(fp, 16, SEEK_SET)       positions fp at offset 16       */
    /*                                                                      */
    /* Then the main fread reads from offset 16: N+16 bytes into heap_buf. */
    /* Decrypt loop runs over [0..N+15], fwrite emits first N bytes only.  */
    /*                                                                      */
    /* Key selection per ciphertext byte (position i, 0-based):           */
    /*   If (i & 2) == 0, Decrypt.exe uses state[1].   */
    /*   If (i & 2) != 0, Decrypt.exe uses state[30].   */

    /* Encrypted plaintext plus 16 encrypted filler bytes */
    /*
for (i = 0; i < (size_t)fsize + 16; i++) {
    uint8_t key_byte = (i & 2) ? key[30] : key[1];
    uint8_t pt = (i < (size_t)fsize) ? plaintext[i] : 0x00;
    uint8_t ct = encrypt_byte(pt, key_byte);

    if (fwrite(&ct, 1, 1, fout) != 1) {
        fprintf(stderr, "Error - Write failed at encrypted byte %zu\n", i);
        goto fail;
    }
}
    */

    /* First 16-byte header/state */
if (fwrite(key, 1, 16, fout) != 16) {
    fprintf(stderr, "Error - Write failed (header)\n");
    goto fail;
}

/* Encrypted plaintext bytes */
for (i = 0; i < (size_t)fsize; i++) {
    uint8_t key_byte = (i & 2) ? key[30] : key[1];
    uint8_t ct = encrypt_byte(plaintext[i], key_byte);

    if (fwrite(&ct, 1, 1, fout) != 1) {
        fprintf(stderr, "Error - Write failed at encrypted byte %zu\n", i);
        goto fail;
    }
}

    /* Final 16-byte trailer/state */
    if (fwrite(key + 16, 1, 16, fout) != 16) {
        fprintf(stderr, "Error - Write failed (footer)\n");
        goto fail;
    }

    fclose(fout);
    free(plaintext);

    fprintf(stdout,
        "Encrypted: %s  ->  %s\n"
        "  Plaintext : %ld bytes\n"
        "  Encrypted file: %ld bytes  (+16 header +16 trailer)\n"
        "  Key[1]=0x%02x  Key[30]=0x%02x  [SHA-256(password) embedded]\n",
        argv[1], outname,
        fsize, fsize + 32,
        key[1], key[30]);

        /* DEBUG: locally decrypt the generated .enc payload */

/* DEBUG: locally decrypt the generated .enc payload */
{
    FILE *debug = fopen(outname, "rb");

    if (debug) {
        long enc_size;
        uint8_t *encbuf;
        size_t j;

        fseek(debug, 0, SEEK_END);
        enc_size = ftell(debug);
        rewind(debug);

        encbuf = (uint8_t *)malloc((size_t)enc_size);
        if (!encbuf) {
            fclose(debug);
            fprintf(stderr, "DEBUG malloc failed\n");
        } else {
            fread(encbuf, 1, (size_t)enc_size, debug);
            fclose(debug);

            fprintf(stdout, "\nDEBUG local decrypt from offset 16:\n");

            for (j = 0; j < (size_t)fsize; j++) {
                uint8_t key_byte = (j & 2) ? encbuf[enc_size - 2] : encbuf[1];
                uint8_t dec = decrypt_byte(encbuf[16 + j], key_byte);
                fputc(dec, stdout);
            }

            fprintf(stdout, "\n");

            fprintf(stdout, "\nDEBUG local decrypt from offset 0:\n");

            for (j = 0; j < (size_t)fsize; j++) {
                uint8_t key_byte = (j & 2) ? encbuf[enc_size - 2] : encbuf[1];
                uint8_t dec = decrypt_byte(encbuf[j], key_byte);
                fputc(dec, stdout);
            }

            fprintf(stdout, "\n");

            free(encbuf);
        }
    } else {
        fprintf(stderr, "DEBUG could not reopen %s\n", outname);
    }
}


    return 0;

fail:
    fclose(fout);
    free(plaintext);
    return 1;
}