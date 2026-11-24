/*
 * GhostDPI engine - DNS over HTTPS.
 * Copyright (c) 2026 Artapa.
 */
#pragma once

#include "common.h"

int  dns_init(void);
void dns_shutdown(void);
int  dns_profile_valid(const char *name);
const char *dns_active_profile(void);

/* Runs fn(ctx) on the engine's small DNS thread pool. Returns 0 if it could not be queued. */
int  dns_submit(PTP_SIMPLE_CALLBACK fn, void *ctx);

/* Takes a captured outbound DNS query and answers it asynchronously over DNS-over-HTTPS.
 * Queries that should stay local (single-label names, .local, reverse lookups, VPN
 * resolvers) and queries that cannot be answered are re-injected unchanged. */
void dns_handle_packet(HANDLE h, const UINT8 *pkt, UINT len, const WINDIVERT_ADDRESS *addr);

/* Reads the question name of a DNS message into `name` (lower case, no trailing dot).
 * Returns 0 for anything that is not a single standard query. */
int dns_question_name(const UINT8 *msg, size_t len, char *name, size_t cap);

/* Whether a query for `name` should be answered through DNS-over-HTTPS. */
int dns_name_is_public(const char *name);

/* Sends `query` to the DNS-over-HTTPS servers in turn. Returns 1 with the answer in resp. */
int doh_query(const UINT8 *query, size_t qlen, UINT8 *resp, size_t cap, size_t *rlen);

/* Builds the inbound UDP reply to a captured query packet. Returns its length or 0. */
UINT dns_build_reply(UINT8 *out, UINT cap, const UINT8 *pkt, UINT len,
                     const UINT8 *answer, UINT alen);
