#ifndef HEADER_CURL_DOH_H
#define HEADER_CURL_DOH_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "urldata.h"
#include "curl_addrinfo.h"
#ifdef USE_HTTPSRR
# include <stdint.h>
# include "httpsrr.h"
#endif

#ifndef CURL_DISABLE_DOH

typedef enum {
  DOH_OK,
  DOH_DNS_BAD_LABEL,    /* 1 */
  DOH_DNS_OUT_OF_RANGE, /* 2 */
  DOH_DNS_LABEL_LOOP,   /* 3 */
  DOH_TOO_SMALL_BUFFER, /* 4 */
  DOH_OUT_OF_MEM,       /* 5 */
  DOH_DNS_RDATA_LEN,    /* 6 */
  DOH_DNS_MALFORMAT,    /* 7 */
  DOH_DNS_BAD_RCODE,    /* 8 - no such name */
  DOH_DNS_UNEXPECTED_TYPE,  /* 9 */
  DOH_DNS_UNEXPECTED_CLASS, /* 10 */
  DOH_NO_CONTENT,           /* 11 */
  DOH_DNS_BAD_ID,           /* 12 */
  DOH_DNS_NAME_TOO_LONG     /* 13 */
} DOHcode;

typedef enum {
  DNS_TYPE_A = 1,
  DNS_TYPE_NS = 2,
  DNS_TYPE_CNAME = 5,
  DNS_TYPE_AAAA = 28,
  DNS_TYPE_DNAME = 39,           /* RFC6672 */
  DNS_TYPE_HTTPS = 65
} DNStype;

enum doh_slot_num {
  /* Explicit values for first two symbols so as to match hard-coded
   * constants in existing code
   */
  DOH_SLOT_IPV4 = 0, /* make 'V4' stand out for readability */
  DOH_SLOT_IPV6 = 1, /* 'V6' likewise */

  /* Space here for (possibly build-specific) additional slot definitions */
#ifdef USE_HTTPSRR
  DOH_SLOT_HTTPS_RR = 2,     /* for HTTPS RR */
#endif

  /* for example */
  /* #ifdef WANT_DOH_FOOBAR_TXT */
  /*   DOH_PROBE_SLOT_FOOBAR_TXT, */
  /* #endif */

  /* AFTER all slot definitions, establish how many we have */
  DOH_SLOT_COUNT
};

#define CURL_EZM_DOH_PROBE   "ezm:doh-p"

/* the largest one we can make, based on RFCs 1034, 1035 */
#define DOH_MAX_DNSREQ_SIZE (256 + 16)

/* each DoH probe request has this
 * as easy meta for CURL_EZM_DOH_PROBE */
struct doh_request {
  unsigned char req_body[DOH_MAX_DNSREQ_SIZE];
  struct curl_slist *req_hds;
  struct dynbuf resp_body;
  size_t req_body_len;
  DNStype dnstype;
};

struct doh_response {
  unsigned int probe_mid;
  struct dynbuf body;
  DNStype dnstype;
  CURLcode result;
};

/* each transfer firing off DoH requests has this
 * as easy meta for CURL_EZM_DOH_MASTER */
struct doh_probes {
  struct doh_response probe_resp[DOH_SLOT_COUNT];
  unsigned int pending; /* still outstanding probes */
  int port;
  const char *host;
};

/*
 * Curl_doh() resolve a name using DoH (DNS-over-HTTPS). It resolves a name
 * and returns a 'Curl_addrinfo *' with the address information.
 */

struct Curl_addrinfo *Curl_doh(struct Curl_easy *data,
                               const char *hostname,
                               int port,
                               int ip_version,
                               int *waitp);

CURLcode Curl_doh_is_resolved(struct Curl_easy *data,
                              struct Curl_dns_entry **dns);

#define DOH_MAX_ADDR 24
#define DOH_MAX_CNAME 4
#define DOH_MAX_HTTPS 4

struct dohaddr {
  int type;
  union {
    unsigned char v4[4]; /* network byte order */
    unsigned char v6[16];
  } ip;
};

#ifdef USE_HTTPSRR

/*
 * These may need escaping when found within an ALPN string
 * value.
 */
#define COMMA_CHAR                    ','
#define BACKSLASH_CHAR                '\\'

struct dohhttps_rr {
  uint16_t len; /* raw encoded length */
  unsigned char *val; /* raw encoded octets */
};
#endif

struct dohentry {
  struct dynbuf cname[DOH_MAX_CNAME];
  struct dohaddr addr[DOH_MAX_ADDR];
  int numaddr;
  unsigned int ttl;
  int numcname;
#ifdef USE_HTTPSRR
  struct dohhttps_rr https_rrs[DOH_MAX_HTTPS];
  int numhttps_rrs;
#endif
};

void Curl_doh_close(struct Curl_easy *data);
void Curl_doh_cleanup(struct Curl_easy *data);

#ifdef UNITTESTS
UNITTEST DOHcode doh_req_encode(const char *host,
                                DNStype dnstype,
                                unsigned char *dnsp,  /* buffer */
                                size_t len,  /* buffer size */
                                size_t *olen);  /* output length */
UNITTEST DOHcode doh_resp_decode(const unsigned char *doh,
                                 size_t dohlen,
                                 DNStype dnstype,
                                 struct dohentry *d);

UNITTEST void de_init(struct dohentry *d);
UNITTEST void de_cleanup(struct dohentry *d);
#endif

#else /* if DoH is disabled */
#define Curl_doh(a,b,c,d,e) NULL
#define Curl_doh_is_resolved(x,y) CURLE_COULDNT_RESOLVE_HOST
#endif

#endif /* HEADER_CURL_DOH_H */
