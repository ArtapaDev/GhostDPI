/*
 * GhostDPI engine - DNS over HTTPS.
 *
 * Many ISPs intercept or poison plain DNS queries on port 53, returning empty or
 * false answers for blocked names. The engine catches outgoing UDP queries on port 53 and
 * answers them through DNS-over-HTTPS (RFC 8484) over WinHTTP's encrypted, kept-alive
 * connections, so no blocked name stays unresolvable. If every server fails, the original
 * query goes out untouched: DNS never stops working because of the engine.
 *
 * Copyright (c) 2026 Artapa.
 */
#include <string.h>
#include "dns.h"          /* brings in windows.h, which winhttp.h needs first */
#include <winhttp.h>

#define MAX_SERVERS 3

typedef struct {
    const char *name;
    size_t count;
    const wchar_t *hosts[MAX_SERVERS];
    const wchar_t *paths[MAX_SERVERS];
} doh_profile;

/* Addressed by IP with verified IP TLS certificates: reaching them needs no DNS lookup. */
static const doh_profile PROFILES[] = {
    { "standard",   3, { L"1.1.1.1",      L"8.8.8.8",         L"9.9.9.9" },
                       { L"/dns-query",   L"/dns-query",      L"/dns-query" } },
    { "adblock",    2, { L"94.140.14.14", L"94.140.15.15",    NULL },
                       { L"/dns-query",   L"/dns-query",      NULL } },
    { "cloudflare", 2, { L"1.1.1.1",      L"1.0.0.1",         NULL },
                       { L"/dns-query",   L"/dns-query",      NULL } },
    { "google",     2, { L"8.8.8.8",      L"8.8.4.4",         NULL },
                       { L"/dns-query",   L"/dns-query",      NULL } },
    { "quad9",      2, { L"9.9.9.9",      L"149.112.112.112", NULL },
                       { L"/dns-query",   L"/dns-query",      NULL } },
};
#define PROFILE_COUNT (sizeof PROFILES / sizeof PROFILES[0])

/* Queries wait on the network, so a few threads are plenty; the shared Windows pool grows
 * to about 57 threads and 10 MB during a burst of 40 lookups. Measured 2026-11-17 for 40
 * lookups: 4 threads 560 ms / 3.9 MB, 8 threads 375 ms / 4.5 MB, shared pool 260 ms / 10.5 MB.
 * HTTP/2 lets the queries share one connection per server. */
#ifndef DNS_THREADS_MAX
#define DNS_THREADS_MAX 8
#endif

static const doh_profile *g_profile = &PROFILES[0];
static HINTERNET g_session;
static HINTERNET g_connect[MAX_SERVERS];
static volatile LONG g_preferred;   /* index of the server that answered last */
static PTP_POOL g_pool;
static TP_CALLBACK_ENVIRON g_env;
static int g_env_init;
static volatile LONG g_stopping;
static volatile LONG g_inflight;
static HANDLE g_idle;

typedef struct {
    HANDLE handle;
    WINDIVERT_ADDRESS addr;
    UINT len;
    UINT8 pkt[1];
} dns_job;

static const doh_profile *find_profile(const char *name)
{
    size_t i;
    if (!name || !name[0])
        return &PROFILES[0];
    if (_stricmp(name, "adguard") == 0)
        return &PROFILES[1];
    for (i = 0; i < PROFILE_COUNT; i++)
        if (_stricmp(PROFILES[i].name, name) == 0)
            return &PROFILES[i];
    return NULL;
}

int dns_profile_valid(const char *name)
{
    return find_profile(name) != NULL;
}

const char *dns_active_profile(void)
{
    return g_profile ? g_profile->name : PROFILES[0].name;
}

static void dns_release(void)
{
    if (InterlockedDecrement(&g_inflight) == 0 && g_idle)
        SetEvent(g_idle);
}

int dns_init(void)
{
    DWORD http2 = WINHTTP_PROTOCOL_FLAG_HTTP2;
    const doh_profile *prof = find_profile(g_opts.dns_profile);
    size_t i;

    g_profile = prof ? prof : &PROFILES[0];
    g_preferred = 0;
    g_stopping = 0;
    g_inflight = 1;
    g_idle = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_idle)
        return 0;

    g_session = WinHttpOpen(L"GhostDPI", WINHTTP_ACCESS_TYPE_NO_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_session) {
        CloseHandle(g_idle);
        g_idle = NULL;
        g_inflight = 0;
        return 0;
    }
    WinHttpSetTimeouts(g_session, 2000, 2000, 2500, 2500);
    WinHttpSetOption(g_session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &http2, sizeof http2);
    for (i = 0; i < MAX_SERVERS; i++)
        g_connect[i] = NULL;
    for (i = 0; i < g_profile->count; i++)
        g_connect[i] = WinHttpConnect(g_session, g_profile->hosts[i], INTERNET_DEFAULT_HTTPS_PORT, 0);

    InitializeThreadpoolEnvironment(&g_env);
    g_env_init = 1;
    g_pool = CreateThreadpool(NULL);
    if (g_pool) {
        SetThreadpoolThreadMaximum(g_pool, DNS_THREADS_MAX);
        SetThreadpoolThreadMinimum(g_pool, 1);
        SetThreadpoolCallbackPool(&g_env, g_pool);
    }
    return 1;
}

int dns_submit(PTP_SIMPLE_CALLBACK fn, void *ctx)
{
#ifdef GHOST_SHARED_POOL                /* comparison builds only: the shared Windows pool */
    return TrySubmitThreadpoolCallback(fn, ctx, NULL) ? 1 : 0;
#else
    return TrySubmitThreadpoolCallback(fn, ctx, g_pool ? &g_env : NULL) ? 1 : 0;
#endif
}

void dns_shutdown(void)
{
    size_t i;

    InterlockedExchange(&g_stopping, 1);
    if (g_idle) {
        dns_release();
        if (WaitForSingleObject(g_idle, 8000) != WAIT_OBJECT_0)
            return;
        CloseHandle(g_idle);
        g_idle = NULL;
    }
    if (g_pool) {
        CloseThreadpool(g_pool);
        g_pool = NULL;
    }
    if (g_env_init) {
        DestroyThreadpoolEnvironment(&g_env);
        g_env_init = 0;
    }
    for (i = 0; i < MAX_SERVERS; i++) {
        if (g_connect[i]) WinHttpCloseHandle(g_connect[i]);
        g_connect[i] = NULL;
    }
    if (g_session) WinHttpCloseHandle(g_session);
    g_session = NULL;
}

static int doh_query_one(size_t s, const UINT8 *query, size_t qlen,
                         UINT8 *resp, size_t cap, size_t *rlen)
{
    static const wchar_t headers[] =
        L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n";
    HINTERNET req;
    DWORD status = 0, size = sizeof status, got = 0;
    size_t total = 0;
    int ok = 0;

    if (s >= g_profile->count || !g_connect[s])
        return 0;
    req = WinHttpOpenRequest(g_connect[s], L"POST", g_profile->paths[s], NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req)
        return 0;
    if (WinHttpSendRequest(req, headers, (DWORD)-1L, (LPVOID)query, (DWORD)qlen, (DWORD)qlen, 0) &&
        WinHttpReceiveResponse(req, NULL) &&
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) &&
        status == 200) {
        while (total < cap && WinHttpReadData(req, resp + total, (DWORD)(cap - total), &got) && got > 0)
            total += got;
        ok = total >= 12;
    }
    WinHttpCloseHandle(req);
    *rlen = total;
    return ok;
}

int doh_query(const UINT8 *query, size_t qlen, UINT8 *resp, size_t cap, size_t *rlen)
{
    LONG first = g_preferred;
    size_t count = g_profile ? g_profile->count : 0;
    size_t k;

    for (k = 0; k < count; k++) {
        size_t s = ((size_t)first + k) % count;
        if (g_stopping)
            return 0;
        if (doh_query_one(s, query, qlen, resp, cap, rlen)) {
            if ((LONG)s != first) InterlockedExchange(&g_preferred, (LONG)s);
            return 1;
        }
    }
    return 0;
}

int dns_question_name(const UINT8 *m, size_t len, char *name, size_t cap)
{
    size_t i = 12, o = 0;

    if (len < 17 || cap < 2) return 0;
    if ((m[2] & 0xF8) != 0) return 0;          /* QR=0 and OPCODE=0: a standard query */
    if (m[4] != 0 || m[5] != 1) return 0;      /* exactly one question */

    while (i < len && m[i] != 0) {
        size_t l = m[i++], k;
        if (l > 63 || i + l > len) return 0;   /* also rejects compression pointers */
        if (o != 0) { if (o + 1 >= cap) return 0; name[o++] = '.'; }
        for (k = 0; k < l; k++) {
            char c = (char)m[i + k];
            if (o + 1 >= cap) return 0;
            name[o++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        i += l;
    }
    if (i + 5 > len) return 0;                 /* root label + type + class */
    name[o] = 0;
    return 1;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && strcmp(s + a - b, suffix) == 0;
}

int dns_name_is_public(const char *name)
{
    static const char *const local_suffixes[] = {
        ".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".localhost",
        ".corp", ".intranet", ".private", ".in-addr.arpa", ".ip6.arpa", ".ts.net",
        ".tailscale.net", ".test", ".invalid",
    };
    size_t i;

    if (name[0] == 0 || strchr(name, '.') == NULL)
        return 0;                              /* single-label names belong to the LAN */
    for (i = 0; i < sizeof local_suffixes / sizeof local_suffixes[0]; i++)
        if (ends_with(name, local_suffixes[i]) || strcmp(name, local_suffixes[i] + 1) == 0)
            return 0;
    return 1;
}

UINT dns_build_reply(UINT8 *out, UINT cap, const UINT8 *pkt, UINT len,
                     const UINT8 *answer, UINT alen)
{
    PWINDIVERT_IPHDR ip = NULL;
    PWINDIVERT_IPV6HDR ip6 = NULL;
    PWINDIVERT_UDPHDR udp = NULL;
    PVOID data = NULL;
    UINT dlen = 0, hdr, total;

    if (!WinDivertHelperParsePacket(pkt, len, &ip, &ip6, NULL, NULL, NULL, NULL, &udp,
                                    &data, &dlen, NULL, NULL) || !udp || !data)
        return 0;
    hdr = (UINT)((const UINT8 *)data - pkt);
    total = hdr + alen;
    if (total > cap)
        return 0;
    memcpy(out, pkt, hdr);
    memcpy(out + hdr, answer, alen);

    if (ip) {
        PWINDIVERT_IPHDR r = (PWINDIVERT_IPHDR)out;
        UINT32 t = r->SrcAddr; r->SrcAddr = r->DstAddr; r->DstAddr = t;
        r->Length = bswap16((UINT16)total);
        r->TTL = 64;
    } else {
        PWINDIVERT_IPV6HDR r = (PWINDIVERT_IPV6HDR)out;
        UINT32 t[4];
        memcpy(t, r->SrcAddr, sizeof t);
        memcpy(r->SrcAddr, r->DstAddr, sizeof t);
        memcpy(r->DstAddr, t, sizeof t);
        r->Length = bswap16((UINT16)(total - sizeof(WINDIVERT_IPV6HDR)));
        r->HopLimit = 64;
    }
    {
        PWINDIVERT_UDPHDR u = (PWINDIVERT_UDPHDR)(out + ((const UINT8 *)udp - pkt));
        UINT16 p = u->SrcPort; u->SrcPort = u->DstPort; u->DstPort = p;
        u->Length = bswap16((UINT16)(sizeof(WINDIVERT_UDPHDR) + alen));
    }
    return total;
}

/* Resolvers that must keep answering for themselves (Tailscale's MagicDNS). */
static int is_vpn_resolver(const UINT8 *pkt, UINT len)
{
    PWINDIVERT_IPHDR ip = NULL;
    PWINDIVERT_IPV6HDR ip6 = NULL;
    static const UINT8 ts6[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 };

    if (!WinDivertHelperParsePacket(pkt, len, &ip, &ip6, NULL, NULL, NULL, NULL, NULL,
                                    NULL, NULL, NULL, NULL))
        return 0;
    if (ip) return ip->DstAddr == 0x64646464u;                 /* 100.100.100.100 */
    if (ip6) return memcmp(ip6->DstAddr, ts6, sizeof ts6) == 0; /* fd7a:115c:a1e0::53 */
    return 0;
}

static void reinject(dns_job *j)
{
    if (!g_stopping)
        WinDivertSend(j->handle, j->pkt, j->len, NULL, &j->addr);
}

static void CALLBACK dns_worker(PTP_CALLBACK_INSTANCE inst, PVOID ctx)
{
    dns_job *j = (dns_job *)ctx;
    /* Answers over 1400 bytes go back to the original resolver, so `out` stays small. */
    UINT8 query[1500], answer[4096], out[1600];
    PVOID data = NULL;
    UINT dlen = 0, olen;
    size_t alen = 0;
    char name[256];
    UINT16 id;
    WINDIVERT_ADDRESS a;

    (void)inst;
    if (g_stopping)
        goto done;
    if (!WinDivertHelperParsePacket(j->pkt, j->len, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                    &data, &dlen, NULL, NULL) || !data || dlen < 12 ||
        dlen > sizeof query || is_vpn_resolver(j->pkt, j->len) ||
        !dns_question_name((const UINT8 *)data, dlen, name, sizeof name) ||
        !dns_name_is_public(name)) {
        reinject(j);
        goto done;
    }

    memcpy(query, data, dlen);
    id = (UINT16)((query[0] << 8) | query[1]);
    query[0] = query[1] = 0;                   /* RFC 8484: id 0 keeps answers cacheable */

    if (!doh_query(query, dlen, answer, sizeof answer, &alen) || alen > 1400) {
        if (g_opts.verbose && !g_stopping)
            log_msg("dns: %s -> fallback to the original resolver\n", name);
        reinject(j);
        goto done;
    }
    if (g_stopping)
        goto done;
    answer[0] = (UINT8)(id >> 8);
    answer[1] = (UINT8)id;

    olen = dns_build_reply(out, sizeof out, j->pkt, j->len, answer, (UINT)alen);
    if (olen == 0) {
        reinject(j);
        goto done;
    }
    a = j->addr;
    a.Outbound = 0;
    WinDivertHelperCalcChecksums(out, olen, &a, 0);
    if (!g_stopping)
        WinDivertSend(j->handle, out, olen, NULL, &a);
    if (g_opts.verbose && !g_stopping)
        log_msg("dns: %s answered over HTTPS\n", name);

done:
    free(j);
    dns_release();
}

void dns_handle_packet(HANDLE h, const UINT8 *pkt, UINT len, const WINDIVERT_ADDRESS *addr)
{
    dns_job *j;

    if (g_stopping)
        return;
    j = (dns_job *)malloc(sizeof(dns_job) + len);
    if (!j) {
        WinDivertSend(h, pkt, len, NULL, addr);
        return;
    }
    j->handle = h;
    j->addr = *addr;
    j->len = len;
    memcpy(j->pkt, pkt, len);
    InterlockedIncrement(&g_inflight);
    if (!dns_submit(dns_worker, j)) {
        reinject(j);
        free(j);
        dns_release();
    }
}
