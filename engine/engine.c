/*
 * GhostDPI engine - packet loop and desynchronisation.
 *
 * Only the first data packet of a connection is ever touched: a TLS ClientHello on port
 * 443, or an HTTP request line on port 80 (the WinDivert filter matches nothing else, so
 * the rest of the traffic never leaves the kernel). That packet is sent in two parts, in
 * a chosen order, optionally after decoy requests the server will discard (a broken
 * checksum, an old sequence number or a TTL too short to reach it). Filters that read
 * the server name from one packet then see nothing to block.
 *
 * Copyright (c) 2026 Artapa.
 */
#include <stdio.h>
#include <string.h>
#include "common.h"
#include "tls.h"
#include "dns.h"
#include "hostlist.h"

static HANDLE g_main = INVALID_HANDLE_VALUE;
static HANDLE g_quic = INVALID_HANDLE_VALUE;
static volatile LONG g_stop;
static hostlist g_exclude;
static hostlist g_include;

static UINT8 g_fake_tls[600];
static UINT g_fake_tls_len;
static const char g_fake_http[] =
    "GET / HTTP/1.1\r\nHost: www.w3.org\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n";

static char g_filter[1024];

const char *engine_quic_filter(void)
{
    /* RFC 9000: QUIC v1/v2 Initial packets use Long Header (first byte >= 0xC0) and >= 1200 B. */
    return "outbound and !loopback and udp.DstPort == 443 and "
           "udp.PayloadLength >= 1200 and udp.Payload[0] >= 192";
}

const char *engine_filter(void)
{
    strcpy_s(g_filter, sizeof g_filter,
             "outbound and !loopback and ("
             "(tcp.DstPort == 443 and tcp.PayloadLength > 5 and "
             "tcp.Payload[0] == 22 and tcp.Payload[5] == 1)");
    if (g_opts.http)
        strcat_s(g_filter, sizeof g_filter,
                 " or (tcp.DstPort == 80 and tcp.PayloadLength > 4 and "
                 "(tcp.Payload32[0] == 0x47455420 or tcp.Payload32[0] == 0x504F5354 or "
                 "tcp.Payload32[0] == 0x48454144 or tcp.Payload32[0] == 0x50555420))");
    if (g_opts.dns)
        strcat_s(g_filter, sizeof g_filter, " or (udp.DstPort == 53 and udp.PayloadLength > 12)");
    strcat_s(g_filter, sizeof g_filter, ")");
    return g_filter;
}

/* Copies the IP/TCP headers of `pkt` in front of `payload` and fixes lengths, sequence and
 * TTL. Checksums are left to the caller. Returns the new length, or 0 if it does not fit. */
UINT build_segment(UINT8 *out, UINT cap, const UINT8 *pkt, UINT hdr_len, UINT tcp_off,
                   const UINT8 *payload, UINT plen, UINT32 seq_off, int ttl, int badseq)
{
    UINT total = hdr_len + plen;
    PWINDIVERT_TCPHDR tcp;

    if (total > cap || tcp_off + sizeof(WINDIVERT_TCPHDR) > hdr_len)
        return 0;
    memcpy(out, pkt, hdr_len);
    memcpy(out + hdr_len, payload, plen);

    if ((out[0] >> 4) == 4) {
        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)out;
        ip->Length = bswap16((UINT16)total);
        if (ttl > 0) ip->TTL = (UINT8)ttl;
    } else {
        PWINDIVERT_IPV6HDR ip6 = (PWINDIVERT_IPV6HDR)out;
        ip6->Length = bswap16((UINT16)(total - sizeof(WINDIVERT_IPV6HDR)));
        if (ttl > 0) ip6->HopLimit = (UINT8)ttl;
    }
    tcp = (PWINDIVERT_TCPHDR)(out + tcp_off);
    tcp->SeqNum = bswap32(bswap32(tcp->SeqNum) + seq_off);
    if (badseq) {
        tcp->SeqNum = bswap32(bswap32(tcp->SeqNum) - 10000);
        tcp->AckNum = bswap32(bswap32(tcp->AckNum) - 66000);
    }
    return total;
}

static void send_segment(const UINT8 *pkt, UINT hdr_len, UINT tcp_off, const WINDIVERT_ADDRESS *addr,
                         const UINT8 *payload, UINT plen, UINT32 seq_off,
                         int ttl, int badsum, int badseq)
{
    static UINT8 buf[WINDIVERT_MTU_MAX];       /* the packet loop runs on one thread */
    WINDIVERT_ADDRESS a = *addr;
    UINT len = build_segment(buf, sizeof buf, pkt, hdr_len, tcp_off, payload, plen, seq_off, ttl, badseq);

    if (len == 0)
        return;
    WinDivertHelperCalcChecksums(buf, len, &a, 0);
    if (badsum) {
        PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(buf + tcp_off);
        tcp->Checksum = bswap16((UINT16)(bswap16(tcp->Checksum) - 1));
    }
    WinDivertSend(g_main, buf, len, NULL, &a);
}

static void desync(const UINT8 *pkt, UINT len, const WINDIVERT_ADDRESS *addr)
{
    PWINDIVERT_TCPHDR tcp = NULL;
    PVOID data = NULL;
    UINT dlen = 0, hdr, tcp_off, pos, r;
    const UINT8 *payload, *fake;
    UINT fake_len;
    size_t sni_off = 0, sni_len = 0, host_off = 0, host_len = 0;
    int is_tls, has_sni = 0, has_host = 0;

    if (!WinDivertHelperParsePacket(pkt, len, NULL, NULL, NULL, NULL, NULL, &tcp, NULL,
                                    &data, &dlen, NULL, NULL) || !tcp || !data || dlen < 2) {
        WinDivertSend(g_main, pkt, len, NULL, addr);
        return;
    }
    payload = (const UINT8 *)data;
    hdr = (UINT)(payload - pkt);
    tcp_off = (UINT)((const UINT8 *)tcp - pkt);
    is_tls = bswap16(tcp->DstPort) == 443;

    if (hostlist_count(&g_exclude) > 0 || hostlist_count(&g_include) > 0 || g_opts.verbose) {
        if (is_tls) {
            has_sni = tls_find_sni(payload, dlen, &sni_off, &sni_len);
            has_host = has_sni; host_off = sni_off; host_len = sni_len;
        } else {
            has_host = http_find_host(payload, dlen, &host_off, &host_len);
        }
        if (hostlist_count(&g_exclude) > 0 && has_host &&
            hostlist_match(&g_exclude, (const char *)(payload + host_off), host_len)) {
            if (g_opts.verbose)
                log_msg("skip: %.*s (excluded)\n", (int)host_len, (const char *)(payload + host_off));
            WinDivertSend(g_main, pkt, len, NULL, addr);
            return;
        }
        if (hostlist_count(&g_include) > 0 &&
            (!has_host || !hostlist_match(&g_include, (const char *)(payload + host_off), host_len))) {
            WinDivertSend(g_main, pkt, len, NULL, addr);
            return;
        }
        if (g_opts.verbose && has_host)
            log_msg("desync: %.*s (%s)\n", (int)host_len, (const char *)(payload + host_off),
                    is_tls ? "tls" : "http");
    }

    fake = is_tls ? g_fake_tls : (const UINT8 *)g_fake_http;
    fake_len = is_tls ? g_fake_tls_len : (UINT)(sizeof g_fake_http - 1);

    /* 1. Decoys: reach the filter, never the server. */
    for (r = 0; r < (UINT)g_opts.fake_repeat; r++) {
        if (g_opts.fake_badsum)
            send_segment(pkt, hdr, tcp_off, addr, fake, fake_len, 0, g_opts.fake_ttl, 1, 0);
        if (g_opts.fake_badseq)
            send_segment(pkt, hdr, tcp_off, addr, fake, fake_len, 0, g_opts.fake_ttl, 0, 1);
        if (!g_opts.fake_badsum && !g_opts.fake_badseq && g_opts.fake_ttl > 0)
            send_segment(pkt, hdr, tcp_off, addr, fake, fake_len, 0, g_opts.fake_ttl, 0, 0);
    }

    /* 2. The real request, in two parts. */
    pos = (UINT)g_opts.split_pos;
    if (g_opts.split_sni && is_tls &&
        (has_sni || tls_find_sni(payload, dlen, &sni_off, &sni_len)))
        pos = (UINT)(sni_off + (sni_len > 1 ? sni_len / 2 : 0));
    if (pos == 0 || pos >= dlen) {
        WinDivertSend(g_main, pkt, len, NULL, addr);
        return;
    }
    if (g_opts.reverse) {
        send_segment(pkt, hdr, tcp_off, addr, payload + pos, dlen - pos, pos, 0, 0, 0);
        send_segment(pkt, hdr, tcp_off, addr, payload, pos, 0, 0, 0, 0);
    } else {
        send_segment(pkt, hdr, tcp_off, addr, payload, pos, 0, 0, 0, 0);
        send_segment(pkt, hdr, tcp_off, addr, payload + pos, dlen - pos, pos, 0, 0, 0);
    }
}

static const char *open_error(DWORD err)
{
    switch (err) {
    case ERROR_ACCESS_DENIED:      return "administrator rights are required";
    case ERROR_FILE_NOT_FOUND:     return "WinDivert64.sys was not found next to the engine";
    case ERROR_INVALID_IMAGE_HASH: return "Windows rejected the driver signature";
    case ERROR_DRIVER_BLOCKED:     return "the driver is blocked (security software?)";
    case ERROR_INVALID_PARAMETER:  return "invalid packet filter";
    default:                       return "could not open the packet driver";
    }
}

static uint32_t make_seed(void)
{
    LARGE_INTEGER pc;
    ULONGLONG ticks = GetTickCount64();
    uint32_t s;
    QueryPerformanceCounter(&pc);
    s = (uint32_t)(pc.LowPart ^ pc.HighPart ^ (DWORD)ticks ^ (DWORD)(ticks >> 32) ^
                   (GetCurrentProcessId() * 2654435761u));
    return s ? s : 0x9e3779b9u;
}

int engine_run(void)
{
    static UINT8 pkt[WINDIVERT_MTU_MAX];
    WINDIVERT_ADDRESS addr;
    UINT len;

    hostlist_init(&g_exclude);
    hostlist_init(&g_include);
    if (g_opts.exclude_file) {
        if (hostlist_load_file(&g_exclude, g_opts.exclude_file))
            log_event("loaded %zu excluded domains\n", hostlist_count(&g_exclude));
        else
            log_event("warning: could not read exclude list: %s\n", g_opts.exclude_file);
    }
    if (g_opts.include_file) {
        if (hostlist_load_file(&g_include, g_opts.include_file))
            log_event("loaded %zu included domains\n", hostlist_count(&g_include));
        else
            log_event("warning: could not read include list: %s\n", g_opts.include_file);
    }

    g_fake_tls_len = (UINT)tls_build_hello_seeded(g_fake_tls, sizeof g_fake_tls,
                                                  "www.w3.org", make_seed());
    if (g_opts.dns && !dns_init()) {
        log_event("warning: DNS-over-HTTPS unavailable; DNS queries pass through unchanged\n");
        g_opts.dns = 0;
    }

    g_main = WinDivertOpen(engine_filter(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (g_main == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        log_event("error %lu: %s\n", err, open_error(err));
        if (g_opts.dns) dns_shutdown();
        hostlist_free(&g_exclude);
        hostlist_free(&g_include);
        return (int)err;
    }
    WinDivertSetParam(g_main, WINDIVERT_PARAM_QUEUE_TIME, 2000);

    if (g_opts.block_quic) {
        /* Dropped inside the kernel: no packet is ever copied to the engine. */
        g_quic = WinDivertOpen(engine_quic_filter(), WINDIVERT_LAYER_NETWORK, 1, WINDIVERT_FLAG_DROP);
        if (g_quic == INVALID_HANDLE_VALUE)
            log_event("warning: could not block QUIC (error %lu)\n", GetLastError());
    }

    log_event("GhostDPI engine %s running (dns=%s, quic=%s)\n", GHOSTDPI_VERSION,
              g_opts.dns ? dns_active_profile() : "off", g_opts.block_quic ? "on" : "off");
    while (!g_stop) {
        PWINDIVERT_UDPHDR udp = NULL;
        if (!WinDivertRecv(g_main, pkt, sizeof pkt, &len, &addr)) {
            if (g_stop || GetLastError() == ERROR_NO_DATA) break;
            continue;
        }
        WinDivertHelperParsePacket(pkt, len, NULL, NULL, NULL, NULL, NULL, NULL, &udp,
                                   NULL, NULL, NULL, NULL);
        if (udp)
            dns_handle_packet(g_main, pkt, len, &addr);
        else
            desync(pkt, len, &addr);
    }

    if (g_quic != INVALID_HANDLE_VALUE) WinDivertClose(g_quic);
    if (g_opts.dns) dns_shutdown();
    WinDivertClose(g_main);
    hostlist_free(&g_exclude);
    hostlist_free(&g_include);
    g_quic = g_main = INVALID_HANDLE_VALUE;
    log_event("GhostDPI engine stopped\n");
    return 0;
}

void engine_stop(void)
{
    InterlockedExchange(&g_stop, 1);
    if (g_main != INVALID_HANDLE_VALUE)
        WinDivertShutdown(g_main, WINDIVERT_SHUTDOWN_BOTH);
}
