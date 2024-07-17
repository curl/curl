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

/* one of these for each DoH request */
struct dnsprobe {
  CURL *easy;
  DNStype dnstype;
  unsigned char dohbuffer[512];
  size_t dohlen;
  struct dynbuf serverdoh;
};

struct dohdata {
  struct curl_slist *headers;
  struct dnsprobe probe[DOH_PROBE_SLOTS];
  unsigned int pending; /* still outstanding requests */
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
 * These are the code points for DNS wire format SvcParams as
 * per draft-ietf-dnsop-svcb-https
 * Not all are supported now, and even those that are may need
 * more work in future to fully support the spec.
 */
#define HTTPS_RR_CODE_ALPN            0x01
#define HTTPS_RR_CODE_NO_DEF_ALPN     0x02
#define HTTPS_RR_CODE_PORT            0x03
#define HTTPS_RR_CODE_IPV4            0x04
#define HTTPS_RR_CODE_ECH             0x05
#define HTTPS_RR_CODE_IPV6            0x06

/*
 * These may need escaping when found within an alpn string
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
UNITTEST DOHcode doh_encode(const char *host,
                            DNStype dnstype,
                            unsigned char *dnsp,  /* buffer */
                            size_t len,  /* buffer size */
                            size_t *olen);  /* output length */
UNITTEST DOHcode doh_decode(const unsigned char *doh,
                            size_t dohlen,
                            DNStype dnstype,
                            struct dohentry *d);

UNITTEST void de_init(struct dohentry *d);
UNITTEST void de_cleanup(struct dohentry *d);
#endif

extern struct curl_trc_feat Curl_doh_trc;

#else /* if DoH is disabled */
#define Curl_doh(a,b,c,d) NULL
#define Curl_doh_is_resolved(x,y) CURLE_COULDNT_RESOLVE_HOST
#endif

#endif /* HEADER_CURL_DOH_H */
