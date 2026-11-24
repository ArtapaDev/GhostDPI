/*
 * GhostDPI engine - domain hostlist matching and HTTP Host parsing.
 * Copyright (c) 2026 Artapa.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char **items;
    size_t *lens;
    size_t count;
    size_t cap;
} hostlist;

void hostlist_init(hostlist *hl);
void hostlist_free(hostlist *hl);
int  hostlist_add(hostlist *hl, const char *domain);
int  hostlist_load_file(hostlist *hl, const char *path);
int  hostlist_match(const hostlist *hl, const char *host, size_t host_len);
size_t hostlist_count(const hostlist *hl);

/* Finds the Host header value in a plain HTTP request (trims spaces and :port). */
int http_find_host(const uint8_t *p, size_t plen, size_t *off, size_t *len);
