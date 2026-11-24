/*
 * GhostDPI engine - TLS ClientHello helpers.
 * Copyright (c) 2026 Artapa.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Finds the server name in a (possibly truncated) ClientHello record.
 * Returns 1 and sets *off / *len (relative to p) when the whole name is present. */
int tls_find_sni(const uint8_t *p, size_t plen, size_t *off, size_t *len);

/* Writes a complete, plausible 517-byte ClientHello for `sni` into buf.
 * `seed` randomizes the Client Random and Session ID (0 uses a fixed default).
 * Returns its length, or 0 when buf is too small or the name too long. */
size_t tls_build_hello(uint8_t *buf, size_t cap, const char *sni);
size_t tls_build_hello_seeded(uint8_t *buf, size_t cap, const char *sni, uint32_t seed);
