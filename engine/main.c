/*
 * GhostDPI engine - command line, Windows service and console entry points.
 * Copyright (c) 2026 Artapa.
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "common.h"
#include "dns.h"

int selftest_run(int with_network);

ghost_opts g_opts = {
    2,      /* split_pos */
    0,      /* split_sni */
    1,      /* reverse */
    0, 0,   /* fake_badsum, fake_badseq */
    0,      /* fake_ttl */
    1,      /* fake_repeat */
    1,      /* http */
    1,      /* block_quic */
    1,      /* dns */
    0,      /* verbose */
    "standard", /* dns_profile */
    NULL,   /* exclude_file */
    NULL,   /* include_file */
    NULL,   /* log_file */
};

static int g_service_mode;
static SERVICE_STATUS_HANDLE g_status_handle;
static SERVICE_STATUS g_status;
static SRWLOCK g_log_lock = SRWLOCK_INIT;

void log_msg(const char *fmt, ...)
{
    va_list ap;
    if (g_service_mode)
        return;                                /* a service has no console */
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

int log_write_file(const char *path, const char *line)
{
    FILE *fp = NULL;
    SYSTEMTIME st;
    long sz = 0;
    const char *mode = "ab";

    if (!path || !path[0] || !line)
        return 0;
    AcquireSRWLockExclusive(&g_log_lock);
    if (fopen_s(&fp, path, "rb") == 0 && fp) {
        if (fseek(fp, 0, SEEK_END) == 0)
            sz = ftell(fp);
        fclose(fp);
        fp = NULL;
        if (sz >= 32768)
            mode = "wb";
    }
    if (fopen_s(&fp, path, mode) != 0 || !fp) {
        ReleaseSRWLockExclusive(&g_log_lock);
        return 0;
    }
    GetLocalTime(&st);
    fprintf(fp, "[%04u-%02u-%02u %02u:%02u:%02u] %s",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, line);
    if (line[0] == 0 || line[strlen(line) - 1] != '\n')
        fputc('\n', fp);
    fclose(fp);
    ReleaseSRWLockExclusive(&g_log_lock);
    return 1;
}

void log_event(const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (!g_service_mode)
        fputs(buf, stderr);
    if (g_opts.log_file)
        log_write_file(g_opts.log_file, buf);
}

static void usage(void)
{
    fprintf(stderr,
        "GhostDPI engine %s - (c) 2026 Artapa\n"
        "\n"
        "  --split N             split the first data packet after N bytes (default 2; 0 = off)\n"
        "  --split-sni           split inside the TLS server name\n"
        "  --no-reverse          send the parts in order (default: second part first)\n"
        "  --fake-badsum         send a decoy request with a broken checksum\n"
        "  --fake-badseq         send a decoy request with an old sequence number\n"
        "  --fake-ttl N          TTL of the decoys (alone: a decoy that expires on the way)\n"
        "  --fake-repeat N       send each decoy N times (default 1)\n"
        "  --no-http             leave plain HTTP alone\n"
        "  --no-quic-block       let QUIC through\n"
        "  --no-dns              leave DNS alone (default: answer it over DNS-over-HTTPS)\n"
        "  --dns-profile NAME    DoH profile: standard, adblock, cloudflare, google, quad9\n"
        "  --exclude-file PATH   skip DPI desync for domains listed in PATH\n"
        "  --include-file PATH   apply DPI desync only to domains listed in PATH\n"
        "  --log-file PATH       write lifecycle and error events to PATH (max 32 KB)\n"
        "  --verbose             print what the engine does\n"
        "  --service             run as the GhostDPI Windows service\n"
        "  --self-test           check the engine without capturing packets (no admin needed)\n",
        GHOSTDPI_VERSION);
}

static int parse_int(const char *s, int lo, int hi, int *out)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*s == 0 || *end != 0 || v < lo || v > hi) return 0;
    *out = (int)v;
    return 1;
}

/* Returns 1 on success (sets *selftest for self-test modes), -1 on a bad argument. */
static int parse_args(int argc, char **argv, int *selftest)
{
    int i;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *next = i + 1 < argc ? argv[i + 1] : "";
        if      (!strcmp(a, "--split") && parse_int(next, 0, 1400, &g_opts.split_pos)) i++;
        else if (!strcmp(a, "--split-sni"))     g_opts.split_sni = 1;
        else if (!strcmp(a, "--no-reverse"))    g_opts.reverse = 0;
        else if (!strcmp(a, "--fake-badsum"))   g_opts.fake_badsum = 1;
        else if (!strcmp(a, "--fake-badseq"))   g_opts.fake_badseq = 1;
        else if (!strcmp(a, "--fake-ttl") && parse_int(next, 1, 64, &g_opts.fake_ttl)) i++;
        else if (!strcmp(a, "--fake-repeat") && parse_int(next, 1, 5, &g_opts.fake_repeat)) i++;
        else if (!strcmp(a, "--no-http"))       g_opts.http = 0;
        else if (!strcmp(a, "--no-quic-block")) g_opts.block_quic = 0;
        else if (!strcmp(a, "--no-dns"))        g_opts.dns = 0;
        else if (!strcmp(a, "--dns-profile") && next[0] && dns_profile_valid(next)) { g_opts.dns_profile = next; i++; }
        else if (!strcmp(a, "--exclude-file") && next[0]) { g_opts.exclude_file = next; i++; }
        else if (!strcmp(a, "--include-file") && next[0]) { g_opts.include_file = next; i++; }
        else if (!strcmp(a, "--log-file") && next[0])     { g_opts.log_file = next; i++; }
        else if (!strcmp(a, "--verbose"))       g_opts.verbose = 1;
        else if (!strcmp(a, "--service"))       g_service_mode = 1;
        else if (!strcmp(a, "--self-test"))     *selftest = 1;
        else if (!strcmp(a, "--self-test-offline")) *selftest = 2;
        else { fprintf(stderr, "unknown or invalid option: %s\n\n", a); return -1; }
    }
    return 1;
}

static void set_status(DWORD state, DWORD exit_code)
{
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    g_status.dwWin32ExitCode = exit_code;
    g_status.dwWaitHint = state == SERVICE_RUNNING || state == SERVICE_STOPPED ? 0 : 5000;
    SetServiceStatus(g_status_handle, &g_status);
}

static void WINAPI service_control(DWORD control)
{
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        set_status(SERVICE_STOP_PENDING, NO_ERROR);
        engine_stop();
    }
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv)
{
    int rc;
    (void)argc; (void)argv;
    g_status_handle = RegisterServiceCtrlHandlerW(GHOSTDPI_SERVICE, service_control);
    if (!g_status_handle)
        return;
    set_status(SERVICE_RUNNING, NO_ERROR);
    rc = engine_run();
    set_status(SERVICE_STOPPED, rc == 0 ? NO_ERROR : (DWORD)rc);
}

static BOOL WINAPI console_control(DWORD type)
{
    (void)type;
    engine_stop();
    return TRUE;
}

int main(int argc, char **argv)
{
    int selftest = 0;

    if (parse_args(argc, argv, &selftest) < 0) {
        usage();
        return 2;
    }
    if (selftest)
        return selftest_run(selftest == 1);

    if (g_service_mode) {
        SERVICE_TABLE_ENTRYW table[] = { { (LPWSTR)GHOSTDPI_SERVICE, service_main }, { NULL, NULL } };
        return StartServiceCtrlDispatcherW(table) ? 0 : (int)GetLastError();
    }

    SetConsoleCtrlHandler(console_control, TRUE);
    return engine_run();
}
