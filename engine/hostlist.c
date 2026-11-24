/*
 * GhostDPI engine - domain hostlist matching and HTTP Host parsing.
 * Copyright (c) 2026 Artapa.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hostlist.h"

static char to_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

void hostlist_init(hostlist *hl)
{
    hl->items = NULL;
    hl->lens = NULL;
    hl->count = 0;
    hl->cap = 0;
}

void hostlist_free(hostlist *hl)
{
    size_t i;
    for (i = 0; i < hl->count; i++)
        free(hl->items[i]);
    free(hl->items);
    free(hl->lens);
    hostlist_init(hl);
}

size_t hostlist_count(const hostlist *hl)
{
    return hl->count;
}

int hostlist_add(hostlist *hl, const char *domain)
{
    char norm[256];
    const char *s = domain;
    size_t n = 0, i;
    char *copy;

    if (!s)
        return 0;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n' || *s == '.')
        s++;
    if (*s == 0 || *s == '#')
        return 0;

    while (s[n] && s[n] != ' ' && s[n] != '\t' && s[n] != '\r' && s[n] != '\n' && s[n] != '#') {
        if (n + 1 >= sizeof norm)
            return 0;
        norm[n] = to_lower(s[n]);
        n++;
    }
    while (n > 0 && norm[n - 1] == '.')
        n--;
    if (n == 0)
        return 0;
    norm[n] = 0;

    for (i = 0; i < hl->count; i++)
        if (hl->lens[i] == n && memcmp(hl->items[i], norm, n) == 0)
            return 1;

    if (hl->count == hl->cap) {
        size_t ncap = hl->cap ? hl->cap * 2 : 16;
        char **ni = (char **)realloc(hl->items, ncap * sizeof(char *));
        size_t *nl;
        if (!ni)
            return 0;
        hl->items = ni;
        nl = (size_t *)realloc(hl->lens, ncap * sizeof(size_t));
        if (!nl)
            return 0;
        hl->lens = nl;
        hl->cap = ncap;
    }

    copy = (char *)malloc(n + 1);
    if (!copy)
        return 0;
    memcpy(copy, norm, n + 1);
    hl->items[hl->count] = copy;
    hl->lens[hl->count] = n;
    hl->count++;
    return 1;
}

int hostlist_load_file(hostlist *hl, const char *path)
{
    FILE *fp = NULL;
    char line[512];
    int first = 1;

    if (!path || !path[0] || fopen_s(&fp, path, "rb") != 0 || !fp)
        return 0;
    while (fgets(line, sizeof line, fp)) {
        const char *p = line;
        if (first && (unsigned char)p[0] == 0xEF &&
            (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF)
            p += 3;
        first = 0;
        hostlist_add(hl, p);
    }
    fclose(fp);
    return 1;
}

int hostlist_match(const hostlist *hl, const char *host, size_t host_len)
{
    size_t i, k;

    while (host_len > 0 && host[host_len - 1] == '.')
        host_len--;
    if (host_len == 0)
        return 0;

    for (i = 0; i < hl->count; i++) {
        size_t elen = hl->lens[i];
        const char *tail;
        int same = 1;

        if (host_len < elen)
            continue;
        if (host_len > elen && host[host_len - elen - 1] != '.')
            continue;
        tail = host + (host_len - elen);
        for (k = 0; k < elen; k++) {
            if (to_lower(tail[k]) != hl->items[i][k]) {
                same = 0;
                break;
            }
        }
        if (same)
            return 1;
    }
    return 0;
}

int http_find_host(const uint8_t *p, size_t plen, size_t *off, size_t *len)
{
    size_t i = 0;

    /* Skip the request line. */
    while (i < plen && p[i] != '\n')
        i++;
    if (i < plen)
        i++;

    while (i < plen) {
        size_t line_start = i, line_end;
        if (p[i] == '\r' || p[i] == '\n')
            break;
        while (i < plen && p[i] != '\n')
            i++;
        line_end = i;
        if (line_end > line_start && p[line_end - 1] == '\r')
            line_end--;
        if (i < plen)
            i++;

        if (line_end - line_start >= 5 &&
            to_lower((char)p[line_start])     == 'h' &&
            to_lower((char)p[line_start + 1]) == 'o' &&
            to_lower((char)p[line_start + 2]) == 's' &&
            to_lower((char)p[line_start + 3]) == 't' &&
            p[line_start + 4] == ':') {
            size_t v = line_start + 5, e = line_end, k;
            while (v < e && (p[v] == ' ' || p[v] == '\t'))
                v++;
            while (e > v && (p[e - 1] == ' ' || p[e - 1] == '\t'))
                e--;
            if (v < e && p[v] != '[') {
                for (k = v; k < e; k++) {
                    if (p[k] == ':') {
                        e = k;
                        break;
                    }
                }
            }
            if (e > v) {
                *off = v;
                *len = e - v;
                return 1;
            }
            return 0;
        }
    }
    return 0;
}
