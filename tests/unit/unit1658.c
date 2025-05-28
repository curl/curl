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
#include "curlcheck.h"

#include "doh.h" /* from the lib dir */

static CURLcode unit_setup(void)
{
  /* whatever you want done first */
  curl_global_init(CURL_GLOBAL_ALL);
  return CURLE_OK;
}

static void unit_stop(void)
{
  curl_global_cleanup();
  /* done before shutting down and exiting */
}

/* DoH + HTTPSRR are required */
#if !defined(CURL_DISABLE_DOH) && defined(USE_HTTPSRR)

extern CURLcode doh_resp_decode_httpsrr(struct Curl_easy *data,
                                        const unsigned char *cp, size_t len,
                                        struct Curl_https_rrinfo **hrr);
extern void doh_print_httpsrr(struct Curl_easy *data,
                              struct Curl_https_rrinfo *hrr);

struct test {
  const char *name;
  const unsigned char *dns;
  size_t len; /* size of the dns packet */
  const char *expect;
};

/*
 * The idea here is that we pass one DNS packet at the time to the decoder. we
 * then generate a string output with the results and compare if it matches
 * the expected. One by one.
 */

static char rrbuffer[256];
static void rrresults(struct Curl_https_rrinfo *rr, CURLcode result)
{
  char *p = rrbuffer;
  char *pend = rrbuffer + sizeof(rrbuffer);
  curl_msnprintf(rrbuffer, sizeof(rrbuffer), "r:%d|", (int)result);
  p += strlen(rrbuffer);

  if(rr) {
    unsigned int i;
    curl_msnprintf(p, pend - p, "p:%d|", rr->priority);
    p += strlen(p);

    curl_msnprintf(p, pend - p, "%s|", rr->target ? rr->target : "-");
    p += strlen(p);

    for(i = 0; i < MAX_HTTPSRR_ALPNS && rr->alpns[i] != ALPN_none; i++) {
      curl_msnprintf(p, pend - p, "alpn:%x|", rr->alpns[i]);
      p += strlen(p);
    }
    if(rr->no_def_alpn) {
      curl_msnprintf(p, pend - p, "no-def-alpn|");
      p += strlen(p);
    }
    if(rr->port >= 0) {
      curl_msnprintf(p, pend - p, "port:%d|", rr->port);
      p += strlen(p);
    }
    if(rr->ipv4hints) {
      for(i = 0; i < rr->ipv4hints_len; i += 4) {
        curl_msnprintf(p, pend - p, "ipv4:%d.%d.%d.%d|",
                       rr->ipv4hints[i],
                       rr->ipv4hints[i + 1],
                       rr->ipv4hints[i + 2],
                       rr->ipv4hints[i + 3]);
        p += strlen(p);
      }
    }
    if(rr->echconfiglist) {
      curl_msnprintf(p, pend - p, "ech:");
      p += strlen(p);
      for(i = 0; i < rr->echconfiglist_len; i++) {
        curl_msnprintf(p, pend - p, "%02x", rr->echconfiglist[i]);
        p += strlen(p);
      }
      curl_msnprintf(p, pend - p, "|");
      p += strlen(p);
    }
    if(rr->ipv6hints) {
      for(i = 0; i < rr->ipv6hints_len; i += 16) {
        int x;
        curl_msnprintf(p, pend - p, "ipv6:");
        p += strlen(p);
        for(x = 0; x < 16; x += 2) {
          curl_msnprintf(p, pend - p, "%s%02x%02x",
                         x ? ":" : "",
                         rr->ipv6hints[i + x],
                         rr->ipv6hints[i + x + 1]);
          p += strlen(p);
        }
        curl_msnprintf(p, pend - p, "|");
        p += strlen(p);
      }
    }
  }
}

UNITTEST_START
{
  /* The "SvcParamKeys" specified within the HTTPS RR packet *must* be
     provided in numerical order. */

  static struct test t[] = {
    {
      "single h2 alpn",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* length byte */
      "h2",
      15,
      "r:0|p:0|name.|alpn:10|"
    },
    {
      "single h2 alpn missing last byte",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* length byte */
      "h", /* missing byte */
      14,
      "r:8|"
    },
    {
      "two alpns",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x04some\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x06" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x02" /* APLN length byte */
      "h3",
      23,
      "r:0|p:0|name.some.|alpn:10|alpn:20|"
    },
    {
      "wrong syntax alpns",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x04some\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x06" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x03" /* APLN length byte (WRONG) */
      "h3",
      23,
      "r:61|"
    },
    {
      "five alpns (ignore dupes)", /* we only support four */
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x04some\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x0f" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x02" /* ALPN length byte */
      "h2"
      "\x02" /* ALPN length byte */
      "h2"
      "\x02" /* ALPN length byte */
      "h2"
      "\x02" /* APLN length byte */
      "h3",
      32,
      "r:0|p:0|name.some.|alpn:10|alpn:20|"
    },
    {
      "rname only",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x04some\x00", /* RNAME */
      13,
      "r:0|p:0|name.some.|"
    },
    {
      "rname with low ascii byte",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x04som\x03\x00", /* RNAME */
      13,
      "r:8|"
    },
    {
      "rname with null byte",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04sa\x00e\x04some\x00", /* RNAME */
      13,
      "r:27|"
    },
    {
      "rname only (missing byte)",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x05some\x00", /* RNAME */
      /* it lacks a byte */
      13,
      "r:27|"
    },
    {
      "unrecognized alpn",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x04some\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x06" /* data size */
      "\x02" /* ALPN length byte */
      "h8" /* unrecognized */
      "\x02" /* APLN length byte */
      "h1",
      23,
      "r:0|p:0|name.some.|alpn:8|"
    },
    {
      "alnt + no-default-alpn",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x04some\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x02" /* RR (2 == NO DEFAULT ALPN) */
      "\x00\x00", /* must be zero */
      24,
      "r:0|p:0|name.some.|alpn:10|no-def-alpn|"
    },
    {
      "alnt + no-default-alpn with size",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x04some\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x02" /* RR (2 == NO DEFAULT ALPN) */
      "\x00\x01" /* must be zero */
      "\xff",
      25,
      "r:43|"
    },
    {
      "alnt + no-default-alpn with size too short package",
      (const unsigned char *)"\x00\x00" /* 16-bit prio */
      "\x04name\x04some\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x02" /* RR (2 == NO DEFAULT ALPN) */
      "\x00\x01", /* must be zero */
      /* missing last byte in the packet */
      24,
      "r:8|"
    },
    {
      "rname + blank alpn field",
      (const unsigned char *)"\x11\x11" /* 16-bit prio */
      "\x04name\x04some\x00" /* RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x00", /* data size, strictly speaking this is illegal:
                     "one or more alpn-ids" */
      17,
      "r:0|p:4369|name.some.|"
    },
    {
      "no rname + blank alpn",
      (const unsigned char *)"\x00\x11" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x00", /* data size */
      7,
      "r:0|p:17|.|"
    },
    {
      "unsupported field",
      (const unsigned char *)"\xff\xff" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x07" /* RR (7 == not a supported data) */
      "\x00\x02" /* data size */
      "FF", /* unknown to curl */
      9,
      "r:0|p:65535|.|"
    },
    {
      "unsupported field (wrong size)",
      (const unsigned char *)"\xff\xff" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x07" /* RR (7 == not a supported data) */
      "\x00\x02" /* data size */
      "F", /* unknown to curl */
      8,
      "r:8|"
    },
    {
      "port number",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x03" /* RR (3 == PORT) */
      "\x00\x02" /* data size */
      "\x12\x34", /* port number */
      16,
      "r:0|p:16|.|alpn:10|port:4660|"
    },
    {
      "port number with wrong size (3 bytes)",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x03" /* RR (3 == PORT) */
      "\x00\x03" /* data size */
      "\x12\x34\x00", /* 24 bit port number! */
      17,
      "r:43|"
    },
    {
      "port number with wrong size (1 byte)",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x03" /* RR (3 == PORT) */
      "\x00\x01" /* data size */
      "\x12", /* 8 bit port number! */
      15,
      "r:43|"
    },
    {
      "alpn + two ipv4 addreses",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x04" /* RR (4 == Ipv4hints) */
      "\x00\x08" /* data size */
      "\xc0\xa8\x00\x01"  /* 32 bits */
      "\xc0\xa8\x00\x02", /* 32 bits */
      22,
      "r:0|p:16|.|alpn:10|ipv4:192.168.0.1|ipv4:192.168.0.2|"
    },
    {
      "alpn + two ipv4 addreses in wrong order",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x04" /* RR (4 == Ipv4hints) */
      "\x00\x08" /* data size */
      "\xc0\xa8\x00\x01"  /* 32 bits */
      "\xc0\xa8\x00\x02" /* 32 bits */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2",
      22,
      "r:8|"
    },
    {
      "alpn + ipv4 address with wrong size",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x04" /* RR (4 == Ipv4hints) */
      "\x00\x05" /* data size */
      "\xc0\xa8\x00\x01\xff",  /* 32 + 8 bits */
      19,
      "r:43|"
    },
    {
      "alpn + one ipv6 address",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x06" /* RR (6 == Ipv6hints) */
      "\x00\x10" /* data size */
      "\xfe\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x23",
      30,
      "r:0|p:16|.|alpn:10|ipv6:fe80:dabb:c1ff:fea3:8a22:1234:5678:9123|"
    },
    {
      "alpn + one ipv6 address with wrong size",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x06" /* RR (6 == Ipv6hints) */
      "\x00\x11" /* data size */
      "\xfe\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x23\x45",
      31,
      "r:43|"
    },
    {
      "alpn + two ipv6 addresses",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x06" /* RR (6 == Ipv6hints) */
      "\x00\x20" /* data size */
      "\xfe\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x23"
      "\xee\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x25",
      46,
      "r:0|p:16|.|alpn:10|ipv6:fe80:dabb:c1ff:fea3:8a22:1234:5678:9123|"
      "ipv6:ee80:dabb:c1ff:fea3:8a22:1234:5678:9125|"
    },
    {
      "alpn + ech",
      (const unsigned char *)"\x00\x10" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x03" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x00\x05" /* RR (5 == ECH) */
      "\x00\x10" /* data size */
      "\xfe\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x23",
      30,
      "r:0|p:16|.|alpn:10|ech:fe80dabbc1fffea38a22123456789123|"
    },
    {
      "fully packed",
      (const unsigned char *)"\xa0\x0b" /* 16-bit prio */
      "\x00" /* no RNAME */
      "\x00\x00" /* RR (0 == MANDATORY) */
      "\x00\x00" /* data size */
      "\x00\x01" /* RR (1 == ALPN) */
      "\x00\x06" /* data size */
      "\x02" /* ALPN length byte */
      "h2"
      "\x02" /* ALPN length byte */
      "h1"
      "\x00\x02" /* RR (2 == NO DEFAULT ALPN) */
      "\x00\x00" /* must be zero */
      "\x00\x03" /* RR (3 == PORT) */
      "\x00\x02" /* data size */
      "\xbc\x71" /* port number */
      "\x00\x04" /* RR (4 == Ipv4hints) */
      "\x00\x08" /* data size */
      "\xc0\xa8\x00\x01" /* 32 bits */
      "\xc0\xa8\x00\x02" /* 32 bits */
      "\x00\x05" /* RR (5 == ECH) */
      "\x00\x10" /* data size */
      "\xfe\x80\xda\xbb\xc1\xff\x7e\xb3\x8a\x22\x12\x34\x56\x78\x91\x23"
      "\x00\x06" /* RR (6 == Ipv6hints) */
      "\x00\x20" /* data size */
      "\xfe\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x23"
      "\xee\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x25"
      "\x01\x07" /* RR (263 == not supported) */
      "\x00\x04" /* data size */
      "FFAA", /* unknown to the world */
      103,
      "r:0|p:40971|.|alpn:10|alpn:8|no-def-alpn|port:48241|"
      "ipv4:192.168.0.1|ipv4:192.168.0.2|"
      "ech:fe80dabbc1ff7eb38a22123456789123|"
      "ipv6:fe80:dabb:c1ff:fea3:8a22:1234:5678:9123|"
      "ipv6:ee80:dabb:c1ff:fea3:8a22:1234:5678:9125|"
    }
  };

  CURLcode result = CURLE_OUT_OF_MEMORY;
  CURL *easy;

  easy = curl_easy_init();
  /* so that we get the log output: */
  curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  if(easy) {
    unsigned int i;

    for(i = 0; i < CURL_ARRAYSIZE(t); i++) {
      struct Curl_https_rrinfo *hrr;

      printf("test %i: %s\n", i, t[i].name);

      result = doh_resp_decode_httpsrr(easy, t[i].dns, t[i].len, &hrr);

      /* create an output */
      rrresults(hrr, result);

      /* is the output the expected? */
      if(strcmp(rrbuffer, t[i].expect)) {
        curl_mfprintf(stderr, "Test %s (%i) failed\n"
                      "Expected: %s\n"
                      "Received: %s\n", t[i].name, i, t[i].expect, rrbuffer);
        unitfail++;
      }

      /* free the generated struct */
      if(hrr) {
        Curl_httpsrr_cleanup(hrr);
        curl_free(hrr);
      }
    }
    curl_easy_cleanup(easy);
  }
}
UNITTEST_STOP

#else /* CURL_DISABLE_DOH or not HTTPSRR enabled */

UNITTEST_START
/* nothing to do, just succeed */
UNITTEST_STOP

#endif
