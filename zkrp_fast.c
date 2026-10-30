/*
 * zkrp_fast.c - zero-dependency C implementation of the zkrp_toy protocol.
 *
 * Same statement, same group, same Fiat-Shamir hash format as python/zkrp_toy.py, so proofs
 * made here verify in Python and vice versa (tested by c/test_fast.py).
 *
 * Speed techniques:
 *   - 256-bit Montgomery multiplication on four 64-bit limbs (unsigned __int128)
 *   - fixed-base comb tables (4-bit windows) for the generators g and h: no squarings
 *   - fixed-window exponentiation for variable bases
 *   - Horner recombination of the bit commitments, hash midstate caching, own SHA-256
 *
 * Build (Linux/macOS): cc -O3 -march=native -o zkrp_fast zkrp_fast.c
 * Build (Windows MinGW): gcc -O3 -march=native -o zkrp_fast.exe zkrp_fast.c -lbcrypt
 *
 * Usage:
 *   zkrp_fast selftest
 *   zkrp_fast verify PARAMS TRANSCRIPTS     one 0/1 per transcript line
 *   zkrp_fast prove  PARAMS PAIRS           PAIRS lines: "a b" (decimal); prints transcripts
 *   zkrp_fast bench  PARAMS N               N prove + N verify, prints timings
 *
 * NOT production crypto: 256-bit toy group, no constant-time guarantees, unaudited.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;
typedef unsigned __int128 u128;

#define NB 32 /* range is [0, 2^NB) */

/* ---------------------------------------------------------------- 256-bit integers */
typedef struct { u64 v[4]; } fe;

static int fe_cmp(const fe *a, const fe *b) {
    for (int i = 3; i >= 0; i--)
        if (a->v[i] != b->v[i]) return a->v[i] > b->v[i] ? 1 : -1;
    return 0;
}
static u64 fe_sub(fe *r, const fe *a, const fe *b) {
    u64 br = 0; fe t;
    for (int i = 0; i < 4; i++) { u128 d = (u128)a->v[i] - b->v[i] - br; t.v[i] = (u64)d; br = (u64)(d >> 64) & 1; }
    *r = t; return br;
}
static u64 fe_add(fe *r, const fe *a, const fe *b) {
    u64 c = 0; fe t;
    for (int i = 0; i < 4; i++) { u128 s = (u128)a->v[i] + b->v[i] + c; t.v[i] = (u64)s; c = (u64)(s >> 64); }
    *r = t; return c;
}
static void addmod(fe *r, const fe *a, const fe *b, const fe *m) {
    fe t; u64 c = fe_add(&t, a, b);
    if (c || fe_cmp(&t, m) >= 0) fe_sub(&t, &t, m);
    *r = t;
}
static void submod(fe *r, const fe *a, const fe *b, const fe *m) {
    fe t; u64 br = fe_sub(&t, a, b);
    if (br) fe_add(&t, &t, m);
    *r = t;
}
static void fe_red(fe *a, const fe *m) { while (fe_cmp(a, m) >= 0) fe_sub(a, a, m); }
static fe fe_u64(u64 x) { fe r = {{x, 0, 0, 0}}; return r; }
static int fe_is_zero(const fe *a) { return !(a->v[0] | a->v[1] | a->v[2] | a->v[3]); }
static int fe_bitlen(const fe *a) {
    for (int i = 3; i >= 0; i--) if (a->v[i]) return i * 64 + 64 - __builtin_clzll(a->v[i]);
    return 0;
}

static int fe_parse(const char *s, size_t n, fe *out) {
    memset(out, 0, sizeof *out);
    if (n == 0 || n > 64) return 0;
    for (size_t i = 0; i < n; i++) {
        char ch = s[n - 1 - i]; int d;
        if (ch >= '0' && ch <= '9') d = ch - '0';
        else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
        else return 0;
        out->v[i >> 4] |= (u64)d << ((i & 15) * 4);
    }
    return 1;
}
static void fe_print(FILE *f, const fe *a) {
    int i = 3; while (i > 0 && !a->v[i]) i--;
    fprintf(f, "%llx", (unsigned long long)a->v[i]);
    for (i--; i >= 0; i--) fprintf(f, "%016llx", (unsigned long long)a->v[i]);
}

static inline u64 divq(u64 hi, u64 lo, u64 d, u64 *rem) {
#if defined(__x86_64__) && !defined(_MSC_VER)
    u64 q, r;
    __asm__("divq %4" : "=a"(q), "=d"(r) : "a"(lo), "d"(hi), "r"(d) : "cc");
    *rem = r; return q;
#else
    u128 cur = ((u128)hi << 64) | lo; *rem = (u64)(cur % d); return (u64)(cur / d);
#endif
}

/* decimal string of a (the hash input uses Python's str(int)) */
static int fe_dec(const fe *a, char *out) {
    u64 x[4] = {a->v[0], a->v[1], a->v[2], a->v[3]};
    int n = 4; while (n > 0 && !x[n - 1]) n--;
    if (n == 0) { out[0] = '0'; return 1; }
    char buf[96]; int len = 0;
    const u64 D = 10000000000000000000ULL;
    while (n > 0) {
        u64 rem = 0;
        for (int i = n - 1; i >= 0; i--) x[i] = divq(rem, x[i], D, &rem);
        while (n > 0 && !x[n - 1]) n--;
        if (n > 0) { for (int k = 0; k < 19; k++) { buf[len++] = (char)('0' + rem % 10); rem /= 10; } }
        else { while (rem) { buf[len++] = (char)('0' + rem % 10); rem /= 10; } }
    }
    for (int i = 0; i < len; i++) out[i] = buf[len - 1 - i];
    return len;
}

/* ---------------------------------------------------------------- Montgomery arithmetic */
typedef struct { fe m, r2, one; u64 n0; } mont;

static void dblmod(fe *r, const fe *m) {
    u64 top = r->v[3] >> 63; fe t;
    for (int i = 3; i > 0; i--) t.v[i] = (r->v[i] << 1) | (r->v[i - 1] >> 63);
    t.v[0] = r->v[0] << 1;
    if (top || fe_cmp(&t, m) >= 0) fe_sub(&t, &t, m);
    *r = t;
}
static void mont_init(mont *M, const fe *m) {
    M->m = *m;
    u64 inv = m->v[0];
    for (int i = 0; i < 6; i++) inv *= 2 - m->v[0] * inv;
    M->n0 = (u64)0 - inv;
    fe r = fe_u64(1);
    for (int i = 0; i < 256; i++) dblmod(&r, m);
    M->one = r;
    for (int i = 0; i < 256; i++) dblmod(&r, m);
    M->r2 = r;
}
static inline void mmul(const mont *M, fe *r, const fe *a, const fe *b) {
    u64 t[6] = {0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; i++) {
        u128 c = 0;
        for (int j = 0; j < 4; j++) { c += (u128)a->v[j] * b->v[i] + t[j]; t[j] = (u64)c; c >>= 64; }
        c += t[4]; t[4] = (u64)c; t[5] = (u64)(c >> 64);
        u64 mm = t[0] * M->n0;
        c = (u128)mm * M->m.v[0] + t[0]; c >>= 64;
        for (int j = 1; j < 4; j++) { c += (u128)mm * M->m.v[j] + t[j]; t[j - 1] = (u64)c; c >>= 64; }
        c += t[4]; t[3] = (u64)c; c >>= 64;
        t[4] = t[5] + (u64)c;
    }
    fe res = {{t[0], t[1], t[2], t[3]}};
    if (t[4] || fe_cmp(&res, &M->m) >= 0) fe_sub(&res, &res, &M->m);
    *r = res;
}
static inline void to_mont(const mont *M, fe *r, const fe *a) { mmul(M, r, a, &M->r2); }
static inline void from_mont(const mont *M, fe *r, const fe *a) { fe one = fe_u64(1); mmul(M, r, a, &one); }
static void mulmod_plain(const mont *M, fe *r, const fe *a, const fe *b) { fe t; mmul(M, &t, a, b); mmul(M, r, &t, &M->r2); }

static inline unsigned nibble(const fe *e, int i) { return (unsigned)(e->v[i >> 4] >> ((i & 15) * 4)) & 15u; }

/* variable-base exponentiation: base and result in Montgomery form, exponent plain */
static void mexp_var(const mont *M, fe *r, const fe *base, const fe *e) {
    fe tbl[16];
    tbl[0] = M->one; tbl[1] = *base;
    for (int i = 2; i < 16; i++) mmul(M, &tbl[i], &tbl[i - 1], base);
    int top = 63; while (top >= 0 && nibble(e, top) == 0) top--;
    if (top < 0) { *r = M->one; return; }
    fe acc = tbl[nibble(e, top)];
    for (int i = top - 1; i >= 0; i--) {
        mmul(M, &acc, &acc, &acc); mmul(M, &acc, &acc, &acc);
        mmul(M, &acc, &acc, &acc); mmul(M, &acc, &acc, &acc);
        unsigned d = nibble(e, i);
        if (d) mmul(M, &acc, &acc, &tbl[d]);
    }
    *r = acc;
}

/* fixed-base comb: t[i][d] = base^(d * 16^i), Montgomery form */
typedef struct { fe t[64][16]; } fbase;
static void fb_init(const mont *M, fbase *F, const fe *base) {
    fe cur = *base;
    for (int i = 0; i < 64; i++) {
        F->t[i][0] = M->one; F->t[i][1] = cur;
        for (int d = 2; d < 16; d++) mmul(M, &F->t[i][d], &F->t[i][d - 1], &cur);
        mmul(M, &cur, &F->t[i][15], &cur);
    }
}
static void fb_exp(const mont *M, fe *r, const fbase *F, const fe *e) {
    fe acc = M->one;
    for (int i = 0; i < 64; i++) { unsigned d = nibble(e, i); if (d) mmul(M, &acc, &acc, &F->t[i][d]); }
    *r = acc;
}

/* ---------------------------------------------------------------- SHA-256 */
typedef struct { u32 h[8]; u8 buf[64]; u64 len; u32 fill; } sha;
static const u32 K256[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(sha *s, const u8 *p) {
    u32 w[64];
    for (int i = 0; i < 16; i++) w[i] = ((u32)p[4*i] << 24) | ((u32)p[4*i+1] << 16) | ((u32)p[4*i+2] << 8) | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        u32 s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        u32 s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    u32 a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; i++) {
        u32 S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25), ch = (e & f) ^ (~e & g);
        u32 t1 = h + S1 + ch + K256[i] + w[i];
        u32 S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22), mj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}
static void sha_init(sha *s) {
    static const u32 H0[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(s->h, H0, sizeof H0); s->len = 0; s->fill = 0;
}
static void sha_upd(sha *s, const void *data, size_t n) {
    const u8 *p = (const u8 *)data; s->len += n;
    if (s->fill) {
        size_t k = 64 - s->fill; if (k > n) k = n;
        memcpy(s->buf + s->fill, p, k); s->fill += (u32)k; p += k; n -= k;
        if (s->fill == 64) { sha_block(s, s->buf); s->fill = 0; }
    }
    while (n >= 64) { sha_block(s, p); p += 64; n -= 64; }
    if (n) { memcpy(s->buf, p, n); s->fill = (u32)n; }
}
static void sha_fin(sha *s, u8 out[32]) {
    u64 bits = s->len * 8; u8 pad = 0x80;
    sha_upd(s, &pad, 1); pad = 0;
    while (s->fill != 56) sha_upd(s, &pad, 1);
    u8 lb[8]; for (int i = 0; i < 8; i++) lb[i] = (u8)(bits >> (56 - 8 * i));
    sha_upd(s, lb, 8);
    for (int i = 0; i < 8; i++) { out[4*i] = (u8)(s->h[i] >> 24); out[4*i+1] = (u8)(s->h[i] >> 16); out[4*i+2] = (u8)(s->h[i] >> 8); out[4*i+3] = (u8)s->h[i]; }
}

/* ---------------------------------------------------------------- randomness, timing */
static void rng_bytes(void *buf, size_t n) {
    static u8 pool[4096]; static size_t pos = sizeof pool;
    u8 *o = (u8 *)buf;
    while (n) {
        if (pos == sizeof pool) {
#ifdef _WIN32
            if (BCryptGenRandom(NULL, pool, sizeof pool, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) { fputs("rng failure\n", stderr); exit(2); }
#else
            size_t got = 0;
            while (got < sizeof pool) { ssize_t k = getrandom(pool + got, sizeof pool - got, 0); if (k <= 0) { fputs("rng failure\n", stderr); exit(2); } got += (size_t)k; }
#endif
            pos = 0;
        }
        size_t k = sizeof pool - pos; if (k > n) k = n;
        memcpy(o, pool + pos, k); pos += k; o += k; n -= k;
    }
}
static double now_ms(void) {
#ifdef _WIN32
    LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
#else
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
#endif
}

/* ---------------------------------------------------------------- protocol state */
static fe P, Q, Gp, Hp;           /* plain parameters */
static mont MP, MQ;
static fe g_m, h_m, ginv_m;       /* Montgomery form mod P */
static fbase FG, FH;
static sha PREFIX;                /* hash state after "P|G|H|" */
static int qbits;

static void rnd_below_q(fe *r) {
    for (;;) {
        rng_bytes(r, sizeof *r);
        int sh = 256 - qbits;
        if (sh > 0) { r->v[3] &= ~0ULL >> sh; }
        if (fe_cmp(r, &Q) < 0) return;
    }
}
static void mulmod_q(fe *r, const fe *a, const fe *b) { mulmod_plain(&MQ, r, a, b); }
static void negmod_q(fe *r, const fe *a) { fe z = {{0, 0, 0, 0}}; submod(r, &z, a, &Q); }

static void digest_to_q(fe *e, const u8 d[32]) {
    for (int i = 0; i < 4; i++) { u64 w = 0; for (int k = 0; k < 8; k++) w = (w << 8) | d[8 * i + k]; e->v[3 - i] = w; }
    fe_red(e, &Q);
}
static void upd_dec(sha *s, const fe *a, int sep) {
    char d[100]; int n = fe_dec(a, d); if (sep) { d[n++] = '|'; } sha_upd(s, d, (size_t)n);
}
static void chal_or(fe *e, const char *ctx, const fe *B, const fe *T0, const fe *T1) {
    sha s = PREFIX; u8 dg[32];
    sha_upd(&s, ctx, strlen(ctx)); sha_upd(&s, "|", 1);
    upd_dec(&s, B, 1); upd_dec(&s, T0, 1); upd_dec(&s, T1, 0);
    sha_fin(&s, dg); digest_to_q(e, dg);
}
static void chal_schnorr(fe *e, const fe *c, const fe *Ca, const fe *Cb, const fe *T) {
    sha s = PREFIX; u8 dg[32];
    upd_dec(&s, c, 1); upd_dec(&s, Ca, 1); upd_dec(&s, Cb, 1); upd_dec(&s, T, 0);
    sha_fin(&s, dg); digest_to_q(e, dg);
}

static int proto_init(const fe *p, const fe *q, const fe *g, const fe *h) {
    P = *p; Q = *q; Gp = *g; Hp = *h;
    if (!(P.v[0] & 1) || !(Q.v[0] & 1)) return 0;
    qbits = fe_bitlen(&Q);
    mont_init(&MP, &P); mont_init(&MQ, &Q);
    to_mont(&MP, &g_m, &Gp); to_mont(&MP, &h_m, &Hp);
    fb_init(&MP, &FG, &g_m); fb_init(&MP, &FH, &h_m);
    fe qm1; fe one = fe_u64(1); fe_sub(&qm1, &Q, &one);
    fb_exp(&MP, &ginv_m, &FG, &qm1);                    /* g^-1 = g^(q-1) */
    sha_init(&PREFIX);
    upd_dec(&PREFIX, &P, 1); upd_dec(&PREFIX, &Gp, 1); upd_dec(&PREFIX, &Hp, 1);
    return 1;
}

/* ---------------------------------------------------------------- transcript */
typedef struct {
    fe c, Ca, Cb, T, z;
    fe B[2][NB];
    fe pr[2][NB][6];                /* T0 T1 e0 e1 z0 z1 */
} transcript;

static int below_p(const fe *a) { return fe_cmp(a, &P) < 0; }

static int verify_or(const fe *B, const fe *pr, const char *ctx) {
    fe e, e0 = pr[2], e1 = pr[3], s;
    chal_or(&e, ctx, B, &pr[0], &pr[1]);
    fe_red(&e0, &Q); fe_red(&e1, &Q); addmod(&s, &e0, &e1, &Q);
    if (fe_cmp(&s, &e) != 0) return 0;
    fe Bm, T0m, T1m, Y1, lhs, pw, rhs;
    to_mont(&MP, &Bm, B); to_mont(&MP, &T0m, &pr[0]); to_mont(&MP, &T1m, &pr[1]);
    mmul(&MP, &Y1, &Bm, &ginv_m);
    fb_exp(&MP, &lhs, &FH, &pr[4]); mexp_var(&MP, &pw, &Bm, &pr[2]); mmul(&MP, &rhs, &T0m, &pw);
    if (fe_cmp(&lhs, &rhs) != 0) return 0;
    fb_exp(&MP, &lhs, &FH, &pr[5]); mexp_var(&MP, &pw, &Y1, &pr[3]); mmul(&MP, &rhs, &T1m, &pw);
    return fe_cmp(&lhs, &rhs) == 0;
}

static int verify(const transcript *t) {
    if (!below_p(&t->Ca) || !below_p(&t->Cb) || !below_p(&t->T)) return 0;
    for (int r = 0; r < 2; r++) for (int i = 0; i < NB; i++) {
        if (!below_p(&t->B[r][i]) || !below_p(&t->pr[r][i][0]) || !below_p(&t->pr[r][i][1])) return 0;
    }
    /* cheap hash checks first */
    fe e; chal_schnorr(&e, &t->c, &t->Ca, &t->Cb, &t->T);
    /* Schnorr: h^z == T * D^e with D = Ca*Cb*g^(-2c) */
    fe cm = t->c; fe_red(&cm, &Q);
    fe c2; addmod(&c2, &cm, &cm, &Q);
    fe neg; negmod_q(&neg, &c2);
    fe Cam, Cbm, Tm, D, gneg, lhs, pw, rhs;
    to_mont(&MP, &Cam, &t->Ca); to_mont(&MP, &Cbm, &t->Cb); to_mont(&MP, &Tm, &t->T);
    fb_exp(&MP, &gneg, &FG, &neg);
    mmul(&MP, &D, &Cam, &Cbm); mmul(&MP, &D, &D, &gneg);
    fb_exp(&MP, &lhs, &FH, &t->z); mexp_var(&MP, &pw, &D, &e); mmul(&MP, &rhs, &Tm, &pw);
    if (fe_cmp(&lhs, &rhs) != 0) return 0;
    /* range proofs: recombination, then bit OR-proofs */
    fe gc; fb_exp(&MP, &gc, &FG, &cm);
    for (int r = 0; r < 2; r++) {
        fe acc, Bm;
        to_mont(&MP, &acc, &t->B[r][NB - 1]);
        for (int i = NB - 2; i >= 0; i--) { mmul(&MP, &acc, &acc, &acc); to_mont(&MP, &Bm, &t->B[r][i]); mmul(&MP, &acc, &acc, &Bm); }
        if (r == 0) { if (fe_cmp(&acc, &Cam) != 0) return 0; }
        else { mmul(&MP, &acc, &acc, &Cam); if (fe_cmp(&acc, &gc) != 0) return 0; }
    }
    char ctx[16];
    for (int r = 0; r < 2; r++) for (int i = 0; i < NB; i++) {
        snprintf(ctx, sizeof ctx, "%c:%d", r ? 'x' : 'a', i);
        if (!verify_or(&t->B[r][i], t->pr[r][i], ctx)) return 0;
    }
    return 1;
}

static void or_prove(const fe *Bm, int bit, const fe *r, const char *ctx, fe *B_plain, fe out[6]) {
    int real = bit, sim = 1 - bit;
    fe Y[2]; Y[0] = *Bm; mmul(&MP, &Y[1], Bm, &ginv_m);
    fe e_sim, z_sim, t, neg, a, b, Ts[2];
    rnd_below_q(&e_sim); rnd_below_q(&z_sim); rnd_below_q(&t);
    negmod_q(&neg, &e_sim);
    fb_exp(&MP, &a, &FH, &z_sim); mexp_var(&MP, &b, &Y[sim], &neg); mmul(&MP, &Ts[sim], &a, &b);
    fb_exp(&MP, &Ts[real], &FH, &t);
    fe T0, T1, e, e_real, prod, z_real;
    from_mont(&MP, B_plain, Bm); from_mont(&MP, &T0, &Ts[0]); from_mont(&MP, &T1, &Ts[1]);
    chal_or(&e, ctx, B_plain, &T0, &T1);
    submod(&e_real, &e, &e_sim, &Q);
    mulmod_q(&prod, &e_real, r); addmod(&z_real, &t, &prod, &Q);
    out[0] = T0; out[1] = T1;
    out[2 + real] = e_real; out[2 + sim] = e_sim;
    out[4 + real] = z_real; out[4 + sim] = z_sim;
}

static void range_prove(transcript *tr, int which, u64 m, const fe *r) {
    fe rs[NB], acc = fe_u64(0), s;
    for (int i = 1; i < NB; i++) rnd_below_q(&rs[i]);
    for (int i = NB - 1; i >= 1; i--) { addmod(&acc, &acc, &rs[i], &Q); addmod(&acc, &acc, &acc, &Q); }
    submod(&rs[0], r, &acc, &Q); (void)s;
    char ctx[16];
    for (int i = 0; i < NB; i++) {
        int bit = (int)((m >> i) & 1);
        fe Bm; fb_exp(&MP, &Bm, &FH, &rs[i]);
        if (bit) mmul(&MP, &Bm, &Bm, &g_m);
        snprintf(ctx, sizeof ctx, "%c:%d", which ? 'x' : 'a', i);
        or_prove(&Bm, bit, &rs[i], ctx, &tr->B[which][i], tr->pr[which][i]);
    }
}

static int prove(u64 a, u64 b, transcript *tr) {
    if (a > (1ULL << 62) || b > (1ULL << 62) || ((a + b) & 1)) return 0;
    u64 c = (a + b) / 2;
    if (a > c) return 0;
    u64 x = c - a;
    if ((a >> NB) || (x >> NB)) return 0;
    fe ra, rb, rx, ga, gb, hr, Cam, Cbm;
    rnd_below_q(&ra); rnd_below_q(&rb); negmod_q(&rx, &ra);
    fe av = fe_u64(a), bv = fe_u64(b);
    fb_exp(&MP, &ga, &FG, &av); fb_exp(&MP, &hr, &FH, &ra); mmul(&MP, &Cam, &ga, &hr);
    fb_exp(&MP, &gb, &FG, &bv); fb_exp(&MP, &hr, &FH, &rb); mmul(&MP, &Cbm, &gb, &hr);
    tr->c = fe_u64(c);
    from_mont(&MP, &tr->Ca, &Cam); from_mont(&MP, &tr->Cb, &Cbm);
    range_prove(tr, 0, a, &ra);
    range_prove(tr, 1, x, &rx);
    fe s, t, Tm, e, es;
    addmod(&s, &ra, &rb, &Q);
    rnd_below_q(&t); fb_exp(&MP, &Tm, &FH, &t); from_mont(&MP, &tr->T, &Tm);
    chal_schnorr(&e, &tr->c, &tr->Ca, &tr->Cb, &tr->T);
    mulmod_q(&es, &e, &s); addmod(&tr->z, &t, &es, &Q);
    return 1;
}

/* ---------------------------------------------------------------- I/O */
static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = (char *)malloc((size_t)n + 1); if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(b); return NULL; }
    fclose(f); b[n] = 0; if (len) *len = (size_t)n; return b;
}
/* next whitespace-separated token; returns 0 at end of buffer, sets *eol if a newline was crossed first */
static int next_tok(char **p, char **tok, size_t *n, int *eol) {
    char *s = *p; *eol = 0;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') { if (*s == '\n') *eol = 1; s++; }
    if (!*s) { *p = s; return 0; }
    *tok = s; while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n') s++;
    *n = (size_t)(s - *tok); *p = s; return 1;
}
static int read_fe(char **p, fe *out) {
    char *t; size_t n; int eol;
    return next_tok(p, &t, &n, &eol) && fe_parse(t, n, out);
}
static int load_params(const char *path) {
    char *buf = slurp(path, NULL); if (!buf) return 0;
    char *p = buf; fe a, b, c, d;
    int ok = read_fe(&p, &a) && read_fe(&p, &b) && read_fe(&p, &c) && read_fe(&p, &d);
    free(buf);
    return ok && proto_init(&a, &b, &c, &d);
}
static int read_transcript(char **p, transcript *t) {
    if (!(read_fe(p, &t->c) && read_fe(p, &t->Ca) && read_fe(p, &t->Cb) && read_fe(p, &t->T) && read_fe(p, &t->z))) return 0;
    for (int r = 0; r < 2; r++) {
        for (int i = 0; i < NB; i++) if (!read_fe(p, &t->B[r][i])) return 0;
        for (int i = 0; i < NB; i++) for (int k = 0; k < 6; k++) if (!read_fe(p, &t->pr[r][i][k])) return 0;
    }
    return 1;
}
static void write_transcript(FILE *f, const transcript *t) {
    fe_print(f, &t->c); fputc(' ', f); fe_print(f, &t->Ca); fputc(' ', f); fe_print(f, &t->Cb); fputc(' ', f);
    fe_print(f, &t->T); fputc(' ', f); fe_print(f, &t->z);
    for (int r = 0; r < 2; r++) {
        for (int i = 0; i < NB; i++) { fputc(' ', f); fe_print(f, &t->B[r][i]); }
        for (int i = 0; i < NB; i++) for (int k = 0; k < 6; k++) { fputc(' ', f); fe_print(f, &t->pr[r][i][k]); }
    }
    fputc('\n', f);
}

static int cmp_double(const void *a, const void *b) { double x = *(const double *)a, y = *(const double *)b; return (x > y) - (x < y); }

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "selftest")) {
        sha s; u8 d[32]; sha_init(&s); sha_upd(&s, "abc", 3); sha_fin(&s, d);
        static const u8 want[4] = {0xba, 0x78, 0x16, 0xbf};
        int ok = !memcmp(d, want, 4) && d[31] == 0xad;
        fe two255 = {{0, 0, 0, 1ULL << 63}}; char dec[100]; int n = fe_dec(&two255, dec); dec[n] = 0;
        int ok2 = !strcmp(dec, "57896044618658097711785492504343953926634992332820282019728792003956564819968");
        printf("sha256(abc) %s, decimal conversion %s\n", ok ? "OK" : "FAIL", ok2 ? "OK" : "FAIL");
        return ok && ok2 ? 0 : 1;
    }
    if (argc < 4) { fputs("usage: zkrp_fast selftest | verify PARAMS FILE | prove PARAMS FILE | bench PARAMS N\n", stderr); return 2; }
    if (!load_params(argv[2])) { fputs("bad params file\n", stderr); return 2; }
    static transcript tr;
    if (!strcmp(argv[1], "verify")) {
        char *buf = slurp(argv[3], NULL); if (!buf) { fputs("cannot read file\n", stderr); return 2; }
        char *p = buf;
        for (;;) {
            char *save = p, *tk; size_t n; int eol;
            if (!next_tok(&save, &tk, &n, &eol)) break;
            if (!read_transcript(&p, &tr)) { puts("ERR"); break; }
            puts(verify(&tr) ? "1" : "0");
        }
        free(buf); return 0;
    }
    if (!strcmp(argv[1], "prove")) {
        char *buf = slurp(argv[3], NULL); if (!buf) { fputs("cannot read file\n", stderr); return 2; }
        char *p = buf, *tk; size_t n; int eol;
        for (;;) {
            if (!next_tok(&p, &tk, &n, &eol)) break;
            u64 a = strtoull(tk, NULL, 10);
            if (!next_tok(&p, &tk, &n, &eol)) break;
            u64 b = strtoull(tk, NULL, 10);
            if (prove(a, b, &tr)) write_transcript(stdout, &tr); else puts("ERR");
        }
        free(buf); return 0;
    }
    if (!strcmp(argv[1], "bench")) {
        int N = atoi(argv[3]); if (N < 1) N = 1;
        double *tp = (double *)malloc(sizeof(double) * (size_t)N), *tv = (double *)malloc(sizeof(double) * (size_t)N);
        int allok = 1;
        for (int i = 0; i < N + 3; i++) {                       /* 3 warm-up rounds */
            u32 r1, r2; rng_bytes(&r1, 4); rng_bytes(&r2, 4);
            u64 a = r1 >> 2, b = a + 2 * (u64)(r2 >> 3);
            double t0 = now_ms(); int ok = prove(a, b, &tr); double t1 = now_ms();
            int v = verify(&tr); double t2 = now_ms();
            allok &= ok && v;
            if (i >= 3) { tp[i - 3] = t1 - t0; tv[i - 3] = t2 - t1; }
        }
        qsort(tp, (size_t)N, sizeof(double), cmp_double); qsort(tv, (size_t)N, sizeof(double), cmp_double);
        printf("prove_best_ms %.4f\nprove_median_ms %.4f\nverify_best_ms %.4f\nverify_median_ms %.4f\nall_valid %d\nproof_bytes_hex_tokens %d\n",
               tp[0], tp[N / 2], tv[0], tv[N / 2], allok, 5 + 2 * (NB + NB * 6));
        free(tp); free(tv); return allok ? 0 : 1;
    }
    fputs("unknown mode\n", stderr); return 2;
}
