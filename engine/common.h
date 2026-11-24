/*
 * GhostDPI engine - shared declarations.
 * Copyright (c) 2026 Artapa.
 */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include "windivert.h"

#define GHOSTDPI_VERSION "1.2.0"
#define GHOSTDPI_SERVICE L"GhostDPI"

/* Byte order helpers (network <-> host); avoids pulling in Winsock. */
static __inline UINT16 bswap16(UINT16 x) { return _byteswap_ushort(x); }
static __inline UINT32 bswap32(UINT32 x) { return _byteswap_ulong(x); }

typedef struct {
    int split_pos;     /* split the first data segment after this many bytes; 0 = no split */
    int split_sni;     /* split inside the TLS server name instead (falls back to split_pos) */
    int reverse;       /* send the second part first */
    int fake_badsum;   /* decoy request with a broken TCP checksum */
    int fake_badseq;   /* decoy request with a sequence number in the past */
    int fake_ttl;      /* TTL of decoys; 0 = keep the original */
    int fake_repeat;   /* how many times each decoy is sent */
    int http;          /* also handle plain HTTP requests on port 80 */
    int block_quic;    /* drop outgoing QUIC Initial packets (UDP 443) */
    int dns;           /* answer DNS queries over DNS-over-HTTPS */
    int verbose;       /* print what the engine does */
    const char *dns_profile;   /* DoH server profile ("standard", "adblock", ...) */
    const char *exclude_file;  /* domains skipped by DPI desync */
    const char *include_file;  /* if set, only these domains get DPI desync */
    const char *log_file;      /* optional error/lifecycle log file */
} ghost_opts;

extern ghost_opts g_opts;

void log_msg(const char *fmt, ...);
void log_event(const char *fmt, ...);
int  log_write_file(const char *path, const char *line);

/* engine.c */
int  engine_run(void);
void engine_stop(void);
const char *engine_filter(void);
const char *engine_quic_filter(void);
UINT build_segment(UINT8 *out, UINT cap, const UINT8 *pkt, UINT hdr_len, UINT tcp_off,
                   const UINT8 *payload, UINT plen, UINT32 seq_off,
                   int ttl, int badseq);
