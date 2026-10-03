/* ===========================================================================
 * FluxWAN Embedded Cryptographic Engine (Pure C, Zero Dependencies)
 *
 * Implements:
 *   - SHA-256 (FIPS 180-4)
 *   - SHA-512 (FIPS 180-4)
 *   - Ed25519 RFC 8032 Signature Verification (TweetNaCl core)
 *   - Base64 Encoding / Decoding
 *
 * Copyright (C) 2026 Ahmed Al-Dulaimi. All rights reserved.
 * =========================================================================== */

#include "crypto_ed25519.h"
#include <string.h>
#include <stdlib.h>

/* ── SHA-256 Implementation ────────────────────────────────────────────── */

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH256(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ256(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0_256(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SIG1_256(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define TH0_256(x)  (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define TH1_256(x)  (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t total_bits = (uint64_t)len * 8;
    size_t offset = 0;
    uint8_t block[64];

    while (offset + 64 <= len) {
        memcpy(block, data + offset, 64);
        offset += 64;
        
        uint32_t w[64];
        for (int t = 0; t < 16; t++) {
            w[t] = ((uint32_t)block[t*4] << 24) | ((uint32_t)block[t*4+1] << 16) |
                   ((uint32_t)block[t*4+2] << 8) | ((uint32_t)block[t*4+3]);
        }
        for (int t = 16; t < 64; t++) {
            w[t] = TH1_256(w[t-2]) + w[t-7] + TH0_256(w[t-15]) + w[t-16];
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int t = 0; t < 64; t++) {
            uint32_t t1 = h + SIG1_256(e) + CH256(e, f, g) + K256[t] + w[t];
            uint32_t t2 = SIG0_256(a) + MAJ256(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    size_t rem = len - offset;
    memcpy(block, data + offset, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        uint32_t w[64];
        for (int t = 0; t < 16; t++) {
            w[t] = ((uint32_t)block[t*4] << 24) | ((uint32_t)block[t*4+1] << 16) |
                   ((uint32_t)block[t*4+2] << 8) | ((uint32_t)block[t*4+3]);
        }
        for (int t = 16; t < 64; t++) {
            w[t] = TH1_256(w[t-2]) + w[t-7] + TH0_256(w[t-15]) + w[t-16];
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int t = 0; t < 64; t++) {
            uint32_t t1 = h + SIG1_256(e) + CH256(e, f, g) + K256[t] + w[t];
            uint32_t t2 = SIG0_256(a) + MAJ256(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);
    for (int i = 0; i < 8; i++) {
        block[56 + i] = (uint8_t)(total_bits >> (56 - i * 8));
    }
    uint32_t w[64];
    for (int t = 0; t < 16; t++) {
        w[t] = ((uint32_t)block[t*4] << 24) | ((uint32_t)block[t*4+1] << 16) |
               ((uint32_t)block[t*4+2] << 8) | ((uint32_t)block[t*4+3]);
    }
    for (int t = 16; t < 64; t++) {
        w[t] = TH1_256(w[t-2]) + w[t-7] + TH0_256(w[t-15]) + w[t-16];
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int t = 0; t < 64; t++) {
        uint32_t t1 = h + SIG1_256(e) + CH256(e, f, g) + K256[t] + w[t];
        uint32_t t2 = SIG0_256(a) + MAJ256(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(state[i] >> 24);
        out[i*4+1] = (uint8_t)(state[i] >> 16);
        out[i*4+2] = (uint8_t)(state[i] >> 8);
        out[i*4+3] = (uint8_t)(state[i]);
    }
}

/* ── SHA-512 Implementation ─────────────────────────────────────────────── */

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH512(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ512(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0_512(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define SIG1_512(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define TH0_512(x)  (ROR64(x, 1)  ^ ROR64(x, 8)  ^ ((x) >> 7))
#define TH1_512(x)  (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

void crypto_sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    uint64_t total_bits = (uint64_t)len * 8;
    size_t offset = 0;
    uint8_t block[128];

    while (offset + 128 <= len) {
        memcpy(block, data + offset, 128);
        offset += 128;
        
        uint64_t w[80];
        for (int t = 0; t < 16; t++) {
            w[t] = ((uint64_t)block[t*8]   << 56) | ((uint64_t)block[t*8+1] << 48) |
                   ((uint64_t)block[t*8+2] << 40) | ((uint64_t)block[t*8+3] << 32) |
                   ((uint64_t)block[t*8+4] << 24) | ((uint64_t)block[t*8+5] << 16) |
                   ((uint64_t)block[t*8+6] << 8)  | ((uint64_t)block[t*8+7]);
        }
        for (int t = 16; t < 80; t++) {
            w[t] = TH1_512(w[t-2]) + w[t-7] + TH0_512(w[t-15]) + w[t-16];
        }
        uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int t = 0; t < 80; t++) {
            uint64_t t1 = h + SIG1_512(e) + CH512(e, f, g) + K512[t] + w[t];
            uint64_t t2 = SIG0_512(a) + MAJ512(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    size_t rem = len - offset;
    memcpy(block, data + offset, rem);
    block[rem++] = 0x80;
    if (rem > 112) {
        memset(block + rem, 0, 128 - rem);
        uint64_t w[80];
        for (int t = 0; t < 16; t++) {
            w[t] = ((uint64_t)block[t*8]   << 56) | ((uint64_t)block[t*8+1] << 48) |
                   ((uint64_t)block[t*8+2] << 40) | ((uint64_t)block[t*8+3] << 32) |
                   ((uint64_t)block[t*8+4] << 24) | ((uint64_t)block[t*8+5] << 16) |
                   ((uint64_t)block[t*8+6] << 8)  | ((uint64_t)block[t*8+7]);
        }
        for (int t = 16; t < 80; t++) {
            w[t] = TH1_512(w[t-2]) + w[t-7] + TH0_512(w[t-15]) + w[t-16];
        }
        uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int t = 0; t < 80; t++) {
            uint64_t t1 = h + SIG1_512(e) + CH512(e, f, g) + K512[t] + w[t];
            uint64_t t2 = SIG0_512(a) + MAJ512(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        rem = 0;
    }
    memset(block + rem, 0, 112 - rem);
    memset(block + 112, 0, 8);
    for (int i = 0; i < 8; i++) {
        block[120 + i] = (uint8_t)(total_bits >> (56 - i * 8));
    }
    uint64_t w[80];
    for (int t = 0; t < 16; t++) {
        w[t] = ((uint64_t)block[t*8]   << 56) | ((uint64_t)block[t*8+1] << 48) |
               ((uint64_t)block[t*8+2] << 40) | ((uint64_t)block[t*8+3] << 32) |
               ((uint64_t)block[t*8+4] << 24) | ((uint64_t)block[t*8+5] << 16) |
               ((uint64_t)block[t*8+6] << 8)  | ((uint64_t)block[t*8+7]);
    }
    for (int t = 16; t < 80; t++) {
        w[t] = TH1_512(w[t-2]) + w[t-7] + TH0_512(w[t-15]) + w[t-16];
    }
    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int t = 0; t < 80; t++) {
        uint64_t t1 = h + SIG1_512(e) + CH512(e, f, g) + K512[t] + w[t];
        uint64_t t2 = SIG0_512(a) + MAJ512(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    for (int i = 0; i < 8; i++) {
        out[i*8]   = (uint8_t)(state[i] >> 56);
        out[i*8+1] = (uint8_t)(state[i] >> 48);
        out[i*8+2] = (uint8_t)(state[i] >> 40);
        out[i*8+3] = (uint8_t)(state[i] >> 32);
        out[i*8+4] = (uint8_t)(state[i] >> 24);
        out[i*8+5] = (uint8_t)(state[i] >> 16);
        out[i*8+6] = (uint8_t)(state[i] >> 8);
        out[i*8+7] = (uint8_t)(state[i]);
    }
}

/* ── Ed25519 Verification (TweetNaCl RFC 8032 Core) ─────────────────────── */

typedef int64_t gf[16];

static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
static const gf D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
static const gf X = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};
static const gf Y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};
static const gf I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};

static void set25519(gf o, const gf a) {
    for (int i = 0; i < 16; ++i) o[i] = a[i];
}

static void car25519(gf o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; ++i) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; ++i) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; ++i) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static int crypto_verify_32(const uint8_t *x, const uint8_t *y) {
    uint32_t d = 0;
    for (int i = 0; i < 32; ++i) d |= x[i] ^ y[i];
    return (1 & ((d - 1) >> 8)) - 1;
}

static int neq25519(const gf a, const gf b) {
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return crypto_verify_32(c, d);
}

static uint8_t par25519(const gf a) {
    uint8_t d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static void unpack25519(gf o, const uint8_t *n) {
    for (int i = 0; i < 16; ++i) {
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; ++i) {
        t[i] += 38 * t[i + 16];
    }
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    car25519(o); car25519(o);
}

static void S(gf o, const gf a) {
    M(o, a, a);
}

static void inv25519(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; ++a) c[a] = i[a];
    for (int a = 253; a >= 0; --a) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (int a = 0; a < 16; ++a) o[a] = c[a];
}

static void pow2523(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; ++a) c[a] = i[a];
    for (int a = 250; a >= 0; --a) {
        S(c, c);
        if (a != 1) M(c, c, i);
    }
    for (int a = 0; a < 16; ++a) o[a] = c[a];
}

static int unpackneg(gf r[4], const uint8_t p[32]) {
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);
    M(r[3], r[0], r[1]);
    return 0;
}

static void add(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], uint8_t b) {
    for (int i = 0; i < 4; ++i) sel25519(p[i], q[i], b);
}

static void pack(uint8_t *r, gf p[4]) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

static void scalarmult(gf p[4], gf q[4], const uint8_t *s) {
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (int i = 255; i >= 0; --i) {
        uint8_t b = (s[i / 8] >> (i % 8)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

static void scalarbase(gf p[4], const uint8_t *s) {
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

static const uint64_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
};

static void modL(uint8_t *r, int64_t x[64]) {
    int64_t carry;
    int i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; ++j) x[j] -= carry * L[j];
    for (i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void reduce(uint8_t *r) {
    int64_t x[64];
    for (int i = 0; i < 64; ++i) x[i] = (uint64_t)r[i];
    for (int i = 0; i < 64; ++i) r[i] = 0;
    modL(r, x);
}

int crypto_ed25519_verify(const uint8_t signature[64],
                          const uint8_t *message, size_t message_len,
                          const uint8_t public_key[32]) {
    uint8_t t[32], h[64];
    gf p[4], q[4];

    if (unpackneg(q, public_key) != 0) return 0;

    /* Assemble buffer for hash: R (32B) + pk (32B) + message (N bytes) */
    size_t total_len = 64 + message_len;
    uint8_t *m = malloc(total_len);
    if (!m) return 0;

    memcpy(m, signature, 32);             /* R */
    memcpy(m + 32, public_key, 32);       /* A */
    if (message_len > 0) {
        memcpy(m + 64, message, message_len); /* M */
    }

    crypto_sha512(m, total_len, h);
    free(m);

    reduce(h);

    /* p = -h * A */
    scalarmult(p, q, h);

    /* q = s * B */
    scalarbase(q, signature + 32);

    /* p = s * B - h * A */
    add(p, q);

    /* pack projective p into affine 32 bytes */
    pack(t, p);

    /* Compare with signature's R (first 32 bytes) */
    return (crypto_verify_32(signature, t) == 0) ? 1 : 0;
}

/* ── Curve25519 Montgomery Ladder (RFC 7748 / WireGuard) ────────────────── */

static const gf _121665 = {0xDB41, 1};

int crypto_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p) {
    uint8_t z[32];
    int64_t x[80];
    int i;
    gf a, b, c, d, e, f;
    for (i = 0; i < 31; ++i) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; ++i) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, _121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    M(a, a, c);
    pack25519(q, a);
    return 0;
}

static const uint8_t _curve25519_basepoint[32] = {9};

int crypto_scalarmult_base(uint8_t *q, const uint8_t *n) {
    return crypto_scalarmult(q, n, _curve25519_basepoint);
}

/* ── Base64 Implementation ──────────────────────────────────────────────── */

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int crypto_base64_encode(const uint8_t *src, size_t len, char *dst, size_t dst_max) {
    size_t out_len = 4 * ((len + 2) / 3);
    if (out_len + 1 > dst_max) return -1;

    size_t i = 0, j = 0;
    while (i < len) {
        size_t rem = len - i;
        uint32_t a = src[i++];
        uint32_t b = (rem > 1) ? src[i++] : 0;
        uint32_t c = (rem > 2) ? src[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        dst[j++] = b64_table[(triple >> 18) & 0x3F];
        dst[j++] = b64_table[(triple >> 12) & 0x3F];
        dst[j++] = (rem > 1) ? b64_table[(triple >> 6) & 0x3F] : '=';
        dst[j++] = (rem > 2) ? b64_table[triple & 0x3F] : '=';
    }
    dst[j] = '\0';
    return (int)j;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

int crypto_base64_decode(const char *src, uint8_t *dst, size_t dst_max, size_t *out_len) {
    size_t len = strlen(src);
    size_t i = 0, j = 0;

    while (i < len) {
        while (i < len && (src[i] == ' ' || src[i] == '\r' || src[i] == '\n' || src[i] == '-')) i++;
        if (i >= len) break;

        int b[4] = {-1, -1, -1, -1};
        for (int k = 0; k < 4 && i < len; k++) {
            while (i < len && (src[i] == ' ' || src[i] == '\r' || src[i] == '\n' || src[i] == '-')) i++;
            if (i < len) {
                if (src[i] == '=') b[k] = 0;
                else b[k] = b64_val(src[i]);
                i++;
            }
        }
        if (b[0] < 0 || b[1] < 0) break;
        if (j < dst_max) dst[j++] = (uint8_t)((b[0] << 2) | (b[1] >> 4));
        if (b[2] >= 0 && j < dst_max) dst[j++] = (uint8_t)(((b[1] & 0x0F) << 4) | (b[2] >> 2));
        if (b[3] >= 0 && j < dst_max) dst[j++] = (uint8_t)(((b[2] & 0x03) << 6) | b[3]);
    }
    if (out_len) *out_len = j;
    return (int)j;
}
