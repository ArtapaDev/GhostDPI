/*
 * GhostDPI engine - TLS ClientHello helpers.
 * Copyright (c) 2026 Artapa.
 */
#include <string.h>
#include "tls.h"

static size_t rd16(const uint8_t *p) { return ((size_t)p[0] << 8) | p[1]; }

int tls_find_sni(const uint8_t *p, size_t plen, size_t *off, size_t *len)
{
    size_t i, end;

    /* Record: type 22 (handshake); handshake type 1 (ClientHello). */
    if (plen < 44 || p[0] != 0x16 || p[5] != 0x01)
        return 0;

    i = 43;                                   /* session id length */
    i += 1 + p[i];
    if (i + 2 > plen) return 0;
    i += 2 + rd16(p + i);                     /* cipher suites */
    if (i + 1 > plen) return 0;
    i += 1 + p[i];                            /* compression methods */
    if (i + 2 > plen) return 0;
    end = i + 2 + rd16(p + i);                /* end of the extensions */
    if (end > plen) end = plen;
    i += 2;

    while (i + 4 <= end) {
        size_t type = rd16(p + i);
        size_t elen = rd16(p + i + 2);
        i += 4;
        if (type == 0) {                      /* server_name */
            size_t n;
            if (i + 5 > end || p[i + 2] != 0) return 0;
            n = rd16(p + i + 3);
            if (n == 0 || i + 5 + n > end) return 0;
            *off = i + 5;
            *len = n;
            return 1;
        }
        i += elen;
    }
    return 0;
}

static uint32_t xorshift(uint32_t *s)
{
    uint32_t x = *s;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return *s = x;
}

size_t tls_build_hello_seeded(uint8_t *b, size_t cap, const char *sni, uint32_t seed)
{
    static const uint8_t ciphers[] = {
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c,
        0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c,
        0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35
    };
    static const uint8_t sigalgs[] = {
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
        0x08, 0x06, 0x06, 0x01
    };
    static const uint8_t alpn[] = { 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    const size_t target = 517;
    size_t n = strlen(sni), i = 0, ext_start, k;
    uint32_t st = (seed ? seed : 0x9e3779b9u) ^ (uint32_t)n;
    if (st == 0) st = 0x9e3779b9u;

#define PUT8(v)  (b[i++] = (uint8_t)((v) & 0xFF))
#define PUT16(v) (b[i++] = (uint8_t)(((v) >> 8) & 0xFF), b[i++] = (uint8_t)((v) & 0xFF))

    if (cap < target || n == 0 || n > 200)
        return 0;

    PUT8(0x16); PUT16(0x0301); PUT16(0);      /* record header, length below */
    PUT8(0x01); PUT8(0); PUT16(0);            /* handshake header, length below */
    PUT16(0x0303);                            /* legacy version TLS 1.2 */
    for (k = 0; k < 32; k++) PUT8(xorshift(&st));
    PUT8(32);                                 /* session id */
    for (k = 0; k < 32; k++) PUT8(xorshift(&st));
    PUT16(sizeof ciphers);
    memcpy(b + i, ciphers, sizeof ciphers); i += sizeof ciphers;
    PUT8(1); PUT8(0);                         /* compression: null */
    PUT16(0);                                 /* extensions length, below */
    ext_start = i;

    PUT16(0); PUT16(n + 5); PUT16(n + 3); PUT8(0); PUT16(n);     /* server_name */
    memcpy(b + i, sni, n); i += n;
    PUT16(10); PUT16(8); PUT16(6); PUT16(0x001d); PUT16(0x0017); PUT16(0x0018); /* groups */
    PUT16(11); PUT16(2); PUT8(1); PUT8(0);    /* ec_point_formats */
    PUT16(13); PUT16(sizeof sigalgs + 2); PUT16(sizeof sigalgs);
    memcpy(b + i, sigalgs, sizeof sigalgs); i += sizeof sigalgs;
    PUT16(16); PUT16(sizeof alpn + 2); PUT16(sizeof alpn);
    memcpy(b + i, alpn, sizeof alpn); i += sizeof alpn;
    PUT16(43); PUT16(5); PUT8(4); PUT16(0x0304); PUT16(0x0303); /* supported_versions */

    if (i + 4 < target) {                     /* padding up to a browser-like size */
        size_t pad = target - i - 4;
        PUT16(21); PUT16(pad);
        memset(b + i, 0, pad); i += pad;
    }

    b[ext_start - 2] = (uint8_t)((i - ext_start) >> 8);
    b[ext_start - 1] = (uint8_t)(i - ext_start);
    b[6] = 0; b[7] = (uint8_t)((i - 9) >> 8); b[8] = (uint8_t)(i - 9);
    b[3] = (uint8_t)((i - 5) >> 8); b[4] = (uint8_t)(i - 5);
#undef PUT8
#undef PUT16
    return i;
}

size_t tls_build_hello(uint8_t *b, size_t cap, const char *sni)
{
    return tls_build_hello_seeded(b, cap, sni, 0);
}
