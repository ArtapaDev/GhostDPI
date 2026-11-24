/*
 * GhostDPI engine - self-test. Runs without administrator rights and captures nothing:
 * it checks the parsers, the packet builders, the packet filter and (online) DoH.
 * Copyright (c) 2026 Artapa.
 */
#include <stdio.h>
#include <string.h>
#include "common.h"
#include <tlhelp32.h>
#include <psapi.h>
#include "tls.h"
#include "dns.h"
#include "hostlist.h"

static int g_failed;

static void check(int ok, const char *what)
{
    printf("%s  %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) g_failed++;
}

static void test_tls(void)
{
    UINT8 hello[600], hello2[600];
    size_t len = tls_build_hello_seeded(hello, sizeof hello, "discord.com", 0x12345678u);
    size_t len2 = tls_build_hello_seeded(hello2, sizeof hello2, "discord.com", 0x87654321u);
    size_t off = 0, n = 0, cut;
    int truncated_ok = 1;

    check(len == 517 && len2 == 517, "decoy ClientHello is 517 bytes");
    check(memcmp(hello, hello2, 517) != 0, "different seeds produce distinct decoy ClientHellos");
    check(tls_find_sni(hello, len, &off, &n) && n == 11 && memcmp(hello + off, "discord.com", 11) == 0,
          "server name found in a ClientHello");
    for (cut = 0; cut < off + n; cut++) {      /* every truncated prefix is handled safely */
        size_t o2, n2;
        if (tls_find_sni(hello, cut, &o2, &n2)) truncated_ok = 0;
    }
    check(truncated_ok, "truncated ClientHello never reports a partial name");
    hello[5] = 2;
    check(!tls_find_sni(hello, len, &off, &n), "non-ClientHello rejected");
}

/* A minimal IPv4/TCP packet carrying `payload`, with valid checksums. */
static UINT make_tcp_packet(UINT8 *buf, const UINT8 *payload, UINT plen)
{
    PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)buf;
    PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(buf + 20);
    UINT total = 40 + plen;

    memset(buf, 0, 40);
    ip->Version = 4; ip->HdrLength = 5; ip->Length = bswap16((UINT16)total);
    ip->TTL = 128; ip->Protocol = 6;
    ip->SrcAddr = 0x0101A8C0u;                 /* 192.168.1.1 */
    ip->DstAddr = 0x08080808u;
    tcp->SrcPort = bswap16(50000); tcp->DstPort = bswap16(443);
    tcp->SeqNum = bswap32(1000); tcp->AckNum = bswap32(2000);
    tcp->HdrLength = 5; tcp->Ack = 1; tcp->Psh = 1; tcp->Window = bswap16(64240);
    memcpy(buf + 40, payload, plen);
    WinDivertHelperCalcChecksums(buf, total, NULL, 0);
    return total;
}

static void test_segments(void)
{
    UINT8 hello[600], pkt[1500], seg[1500], copy[1500];
    UINT plen = (UINT)tls_build_hello(hello, sizeof hello, "example.org");
    UINT len = make_tcp_packet(pkt, hello, plen), slen;
    PWINDIVERT_TCPHDR tcp = NULL;
    PVOID data = NULL;
    UINT dlen = 0;

    slen = build_segment(seg, sizeof seg, pkt, 40, 20, hello + 2, plen - 2, 2, 0, 0);
    WinDivertHelperCalcChecksums(seg, slen, NULL, 0);
    check(slen == 40 + plen - 2 &&
          WinDivertHelperParsePacket(seg, slen, NULL, NULL, NULL, NULL, NULL, &tcp, NULL, &data, &dlen, NULL, NULL) &&
          tcp && bswap32(tcp->SeqNum) == 1002 && dlen == plen - 2 && memcmp(data, hello + 2, dlen) == 0,
          "second part keeps the right sequence number and data");

    memcpy(copy, seg, slen);
    WinDivertHelperCalcChecksums(copy, slen, NULL, 0);
    check(memcmp(copy, seg, slen) == 0, "rebuilt part has valid checksums");

    slen = build_segment(seg, sizeof seg, pkt, 40, 20, hello, plen, 0, 5, 1);
    tcp = (PWINDIVERT_TCPHDR)(seg + 20);
    check(seg[8] == 5 && bswap32(tcp->SeqNum) == (UINT32)(1000u - 10000u) &&
          bswap32(tcp->AckNum) == (UINT32)(2000u - 66000u),
          "decoy gets its TTL and an old sequence number");
    (void)len;
}

static void test_filter(void)
{
    const char *err = NULL;
    UINT pos = 0;
    BOOL ok = WinDivertHelperCompileFilter(engine_filter(), WINDIVERT_LAYER_NETWORK, NULL, 0, &err, &pos);
    if (!ok) printf("      filter error at %u: %s\n", pos, err ? err : "?");
    check(ok, "packet filter compiles");
    check(WinDivertHelperCompileFilter(engine_quic_filter(),
                                       WINDIVERT_LAYER_NETWORK, NULL, 0, NULL, NULL),
          "QUIC Initial filter compiles");
}

static void test_hostlist(void)
{
    static const char req[] = "GET /index.html HTTP/1.1\r\nUser-Agent: test\r\nhOsT:  Example.ORG:80 \r\n\r\n";
    size_t off = 0, len = 0;
    hostlist hl;

    check(http_find_host((const uint8_t *)req, sizeof req - 1, &off, &len) &&
          len == 11 && memcmp(req + off, "Example.ORG", 11) == 0,
          "HTTP Host header extracted with port trimmed");

    hostlist_init(&hl);
    hostlist_add(&hl, "  .Bank.Com.TR # comment\r\n");
    hostlist_add(&hl, "discord.com");
    hostlist_add(&hl, "# ignored");
    check(hostlist_count(&hl) == 2 &&
          hostlist_match(&hl, "bank.com.tr", 11) &&
          hostlist_match(&hl, "SUB.BANK.COM.TR.", 16) &&
          !hostlist_match(&hl, "mybank.com.tr", 13) &&
          hostlist_match(&hl, "gateway.discord.com", 19),
          "hostlist matches exact and subdomain only");
    hostlist_free(&hl);
}

static UINT make_query(UINT8 *q, const char *name)
{
    UINT i = 12;
    const char *p = name;
    memset(q, 0, 12);
    q[0] = 0x12; q[1] = 0x34; q[2] = 0x01; q[5] = 1;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        q[i++] = (UINT8)l;
        memcpy(q + i, p, l); i += (UINT)l;
        p += l + (dot ? 1 : 0);
    }
    q[i++] = 0; q[i++] = 0; q[i++] = 1; q[i++] = 0; q[i++] = 1;
    return i;
}

static void test_dns_offline(void)
{
    UINT8 q[300], pkt[400], reply[600];
    char name[256];
    UINT qlen = make_query(q, "Tr.RbxCdn.com"), len, rlen;
    PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)pkt;
    PWINDIVERT_UDPHDR udp = (PWINDIVERT_UDPHDR)(pkt + 20);
    PWINDIVERT_IPHDR rip = (PWINDIVERT_IPHDR)reply;
    PWINDIVERT_UDPHDR rudp = (PWINDIVERT_UDPHDR)(reply + 20);

    check(dns_question_name(q, qlen, name, sizeof name) && strcmp(name, "tr.rbxcdn.com") == 0,
          "DNS question name read and lower-cased");
    check(dns_name_is_public("discord.com") && !dns_name_is_public("router") &&
          !dns_name_is_public("printer.local") && !dns_name_is_public("1.168.192.in-addr.arpa") &&
          !dns_name_is_public("pc.tail2f7266.ts.net") && !dns_name_is_public("home.arpa"),
          "local names stay with the local resolver");

    memset(pkt, 0, 28);
    ip->Version = 4; ip->HdrLength = 5; ip->TTL = 128; ip->Protocol = 17;
    ip->SrcAddr = 0x0101A8C0u; ip->DstAddr = 0x0202C2C2u;
    udp->SrcPort = bswap16(55555); udp->DstPort = bswap16(53);
    len = 28 + qlen;
    ip->Length = bswap16((UINT16)len); udp->Length = bswap16((UINT16)(8 + qlen));
    memcpy(pkt + 28, q, qlen);

    rlen = dns_build_reply(reply, sizeof reply, pkt, len, q, qlen);
    check(rlen == len && rip->SrcAddr == ip->DstAddr && rip->DstAddr == ip->SrcAddr &&
          bswap16(rudp->SrcPort) == 53 && bswap16(rudp->DstPort) == 55555,
          "DNS reply goes back to the asking program");
    check(dns_profile_valid("standard") && dns_profile_valid("adblock") &&
          dns_profile_valid("adguard") && dns_profile_valid("quad9") &&
          !dns_profile_valid("unknown-provider"),
          "DNS profile names validated");
}

static void test_dns_online(void)
{
    UINT8 q[300], a[4096];
    size_t alen = 0;
    UINT qlen = make_query(q, "tr.rbxcdn.com");
    const char *saved_profile = g_opts.dns_profile;
    DWORD t0;

    q[0] = q[1] = 0;
    g_opts.dns_profile = "standard";
    check(dns_init(), "WinHTTP ready");
    t0 = GetTickCount();
    check(doh_query(q, qlen, a, sizeof a, &alen) && (a[3] & 0x0F) == 0 && (a[6] | a[7]) != 0,
          "DNS-over-HTTPS answers a lookup");
    printf("      first answer in %lu ms\n", GetTickCount() - t0);
    t0 = GetTickCount();
    check(doh_query(q, qlen, a, sizeof a, &alen), "second query reuses the connection");
    printf("      second answer in %lu ms\n", GetTickCount() - t0);
    dns_shutdown();

    g_opts.dns_profile = "adblock";
    check(dns_init() && doh_query(q, qlen, a, sizeof a, &alen) && (a[3] & 0x0F) == 0,
          "adblock DNS profile (AdGuard) answers a lookup");
    dns_shutdown();

    g_opts.dns_profile = "quad9";
    check(dns_init() && doh_query(q, qlen, a, sizeof a, &alen) && (a[3] & 0x0F) == 0,
          "Quad9 DNS profile answers a lookup");
    dns_shutdown();
    g_opts.dns_profile = saved_profile;
}

/* ---- burst: 40 lookups at once through the engine's DNS pool ---- */

static volatile LONG g_pending;
static volatile LONG g_answered;
static HANDLE g_done;

static void CALLBACK burst_worker(PTP_CALLBACK_INSTANCE inst, PVOID ctx)
{
    UINT8 q[300], a[4096];
    size_t alen;
    UINT qlen = make_query(q, (const char *)ctx);
    (void)inst;
    q[0] = q[1] = 0;
    if (doh_query(q, qlen, a, sizeof a, &alen)) InterlockedIncrement(&g_answered);
    if (InterlockedDecrement(&g_pending) == 0) SetEvent(g_done);
}

static DWORD thread_count(void)
{
    DWORD pid = GetCurrentProcessId(), n = 0;
    THREADENTRY32 te;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    te.dwSize = sizeof te;
    if (Thread32First(snap, &te))
        do { if (te.th32OwnerProcessID == pid) n++; } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    return n;
}

static void print_memory(const char *when)
{
    PROCESS_MEMORY_COUNTERS_EX pmc;
    pmc.cb = sizeof pmc;
    if (K32GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof pmc))
        printf("      %-14s %5.1f MB working set, %5.1f MB private, %lu threads\n", when,
               pmc.WorkingSetSize / 1048576.0, pmc.PrivateUsage / 1048576.0, thread_count());
}

static void test_dns_burst(void)
{
    static const char *const names[] = {
        "discord.com", "roblox.com", "google.com", "cloudflare.com", "wikipedia.org",
        "github.com", "youtube.com", "microsoft.com", "apple.com", "amazon.com",
    };
    DWORD peak = 0, t0, k;
    int ok;

    check(dns_init(), "DNS pool re-initializes cleanly after shutdown");
    print_memory("before burst");
    g_done = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_pending = 40;
    g_answered = 0;
    t0 = GetTickCount();
    for (k = 0; k < 40; k++)
        if (!dns_submit(burst_worker, (void *)names[k % 10]) && InterlockedDecrement(&g_pending) == 0)
            SetEvent(g_done);
    while (WaitForSingleObject(g_done, 20) == WAIT_TIMEOUT) {
        DWORD n = thread_count();
        if (n > peak) peak = n;
    }
    ok = g_answered == 40;
    printf("      40 lookups in %lu ms, peak %lu threads\n", GetTickCount() - t0, peak);
    print_memory("after burst");
    check(ok, "burst of 40 lookups answered");
    check(peak <= 28, "DNS burst stays within a few threads (shared pool: about 57)");
    dns_shutdown();
    CloseHandle(g_done);
}

int selftest_run(int with_network)
{
    printf("GhostDPI engine %s self-test\n", GHOSTDPI_VERSION);
    test_tls();
    test_segments();
    test_filter();
    test_hostlist();
    test_dns_offline();
    if (with_network) { test_dns_online(); test_dns_burst(); }
    printf(g_failed ? "SELFTEST FAILED (%d)\n" : "SELFTEST OK\n", g_failed);
    return g_failed ? 1 : 0;
}
