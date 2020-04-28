/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2018 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curlcheck.h"

#include "doh.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

#ifndef CURL_DISABLE_DOH
#define DNS_PREAMBLE "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
#define LABEL_TEST "\x04\x74\x65\x73\x74"
#define LABEL_HOST "\x04\x68\x6f\x73\x74"
#define LABEL_NAME "\x04\x6e\x61\x6d\x65"
#define DNSA_TYPE "\x01"
#define DNSAAAA_TYPE "\x1c"
#define DNSA_EPILOGUE "\x00\x00" DNSA_TYPE "\x00\x01"
#define DNSAAAA_EPILOGUE "\x00\x00" DNSAAAA_TYPE "\x00\x01"

#define DNS_Q1 DNS_PREAMBLE LABEL_TEST LABEL_HOST LABEL_NAME DNSA_EPILOGUE
#define DNS_Q2 DNS_PREAMBLE LABEL_TEST LABEL_HOST LABEL_NAME DNSAAAA_EPILOGUE

struct dohrequest {
  /* input */
  const char *name;
  DNStype type;

  /* output */
  const char *packet;
  size_t size;
  int rc;
};


static struct dohrequest req[] = {
  {"test.host.name", DNS_TYPE_A, DNS_Q1, sizeof(DNS_Q1)-1, 0 },
  {"test.host.name", DNS_TYPE_AAAA, DNS_Q2, sizeof(DNS_Q2)-1, 0 },
  {"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
   ".host.name",
   DNS_TYPE_AAAA, NULL, 0, DOH_DNS_BAD_LABEL }
};

struct dohresp {
  /* input */
  const char *packet;
  size_t size;
  DNStype type;

  /* output */
  int rc;
  const char *out;
};

#define DNS_FOO_EXAMPLE_COM                                          \
  "\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03\x66\x6f\x6f" \
  "\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00" \
  "\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x37\x00\x04\x7f\x00\x00" \
  "\x01"

static const char full49[] = DNS_FOO_EXAMPLE_COM;

static struct dohresp resp[] = {
  {"\x00\x00", 2, DNS_TYPE_A, DOH_TOO_SMALL_BUFFER, NULL },
  {"\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01", 12,
   DNS_TYPE_A, DOH_DNS_BAD_ID, NULL },
  {"\x00\x00\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01", 12,
   DNS_TYPE_A, DOH_DNS_BAD_RCODE, NULL },
  {"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03\x66\x6f\x6f", 16,
   DNS_TYPE_A, DOH_DNS_OUT_OF_RANGE, NULL },
  {"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03\x66\x6f\x6f\x00", 17,
   DNS_TYPE_A, DOH_DNS_OUT_OF_RANGE, NULL },
  {"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03\x66\x6f\x6f\x00"
   "\x00\x01\x00\x01", 21,
   DNS_TYPE_A, DOH_DNS_OUT_OF_RANGE, NULL },
  {"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03\x66\x6f\x6f\x00"
   "\x00\x01\x00\x01"
   "\x04", 18,
   DNS_TYPE_A, DOH_DNS_OUT_OF_RANGE, NULL },

  {"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x04\x63\x75\x72"
   "\x6c\x04\x63\x75\x72\x6c\x00\x00\x05\x00\x01\xc0\x0c\x00\x05\x00"
   "\x01\x00\x00\x00\x37\x00\x11\x08\x61\x6e\x79\x77\x68\x65\x72\x65"
   "\x06\x72\x65\x61\x6c\x6c\x79\x00", 56,
   DNS_TYPE_A, DOH_OK, "anywhere.really "},

  {DNS_FOO_EXAMPLE_COM, 49, DNS_TYPE_A, DOH_OK, "127.0.0.1 "},

  {"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x04\x61\x61\x61"
   "\x61\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c"
   "\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x37\x00\x10\x20\x20"
   "\x20\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x20", 62,
   DNS_TYPE_AAAA, DOH_OK,
   "2020:2020:0000:0000:0000:0000:0000:2020 " },

  {"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x04\x63\x75\x72"
   "\x6c\x04\x63\x75\x72\x6c\x00\x00\x05\x00\x01\xc0\x0c\x00\x05\x00"
   "\x01\x00\x00\x00\x37\x00"
   "\x07\x03\x61\x6e\x79\xc0\x27\x00", 46,
   DNS_TYPE_A, DOH_DNS_LABEL_LOOP, NULL},

  /* packet with NSCOUNT == 1 */
  {"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x01\x00\x00\x04\x61\x61\x61"
   "\x61\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c"
   "\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x37\x00\x10\x20\x20"
   "\x20\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x20"
   LABEL_TEST LABEL_HOST LABEL_NAME DNSAAAA_EPILOGUE "\x00\x00\x00\x01"
   "\00\x04\x01\x01\x01\x01", /* RDDATA */

   62 + 30,
   DNS_TYPE_AAAA, DOH_OK,
   "2020:2020:0000:0000:0000:0000:0000:2020 " },

  /* packet with ARCOUNT == 1 */
  {"\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x01\x04\x61\x61\x61"
   "\x61\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c"
   "\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x37\x00\x10\x20\x20"
   "\x20\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x20"
   LABEL_TEST LABEL_HOST LABEL_NAME DNSAAAA_EPILOGUE "\x00\x00\x00\x01"
   "\00\x04\x01\x01\x01\x01", /* RDDATA */

   62 + 30,
   DNS_TYPE_AAAA, DOH_OK,
   "2020:2020:0000:0000:0000:0000:0000:2020 " },

};

UNITTEST_START
{
  size_t size = 0;
  unsigned char buffer[256];
  size_t i;
  unsigned char *p;
  for(i = 0; i < sizeof(req) / sizeof(req[0]); i++) {
    int rc = doh_encode(req[i].name, req[i].type,
                        buffer, sizeof(buffer), &size);
    if(rc != req[i].rc) {
      fprintf(stderr, "req %zu: Expected return code %d got %d\n", i,
              req[i].rc, rc);
      return 1;
    }
    else if(size != req[i].size) {
      fprintf(stderr, "req %zu: Expected size %zu got %zu\n", i,
              req[i].size, size);
      fprintf(stderr, "DNS encode made: %s\n", hexdump(buffer, size));
      return 2;
    }
    else if(req[i].packet && memcmp(req[i].packet, buffer, size)) {
      fprintf(stderr, "DNS encode made: %s\n", hexdump(buffer, size));
      fprintf(stderr, "... instead of: %s\n",
             hexdump((unsigned char *)req[i].packet, size));
      return 3;
    }
  }

  for(i = 0; i < sizeof(resp) / sizeof(resp[0]); i++) {
    struct dohentry d;
    int rc;
    char *ptr;
    size_t len;
    int u;
    memset(&d, 0, sizeof(d));
    rc = doh_decode((const unsigned char *)resp[i].packet, resp[i].size,
                    resp[i].type, &d);
    if(rc != resp[i].rc) {
      fprintf(stderr, "resp %zu: Expected return code %d got %d\n", i,
              resp[i].rc, rc);
      return 4;
    }
    len = sizeof(buffer);
    ptr = (char *)buffer;
    for(u = 0; u < d.numaddr; u++) {
      size_t o;
      struct dohaddr *a;
      a = &d.addr[u];
      if(resp[i].type == DNS_TYPE_A) {
        p = &a->ip.v4[0];
        msnprintf(ptr, len, "%u.%u.%u.%u ", p[0], p[1], p[2], p[3]);
        o = strlen(ptr);
        len -= o;
        ptr += o;
      }
      else {
        int j;
        for(j = 0; j < 16; j += 2) {
          size_t l;
          msnprintf(ptr, len, "%s%02x%02x", j?":":"", a->ip.v6[j],
                   a->ip.v6[j + 1]);
          l = strlen(ptr);
          len -= l;
          ptr += l;
        }
        msnprintf(ptr, len, " ");
        len--;
        ptr++;
      }
    }
    for(u = 0; u < d.numcname; u++) {
      size_t o;
      msnprintf(ptr, len, "%s ", d.cname[u].alloc);
      o = strlen(ptr);
      len -= o;
      ptr += o;
    }
    de_cleanup(&d);
    if(resp[i].out && strcmp((char *)buffer, resp[i].out)) {
      fprintf(stderr, "resp %zu: Expected %s got %s\n", i,
              resp[i].out, buffer);
      return 1;
    }
  }

  {
    /* pass all sizes into the decoder until full */
    for(i = 0; i < sizeof(full49)-1; i++) {
      struct dohentry d;
      int rc;
      memset(&d, 0, sizeof(d));
      rc = doh_decode((const unsigned char *)full49, i, DNS_TYPE_A, &d);
      if(!rc) {
        /* none of them should work */
        fprintf(stderr, "%zu: %d\n", i, rc);
        return 5;
      }
    }
    /* and try all pieces from the other end of the packet */
    for(i = 1; i < sizeof(full49); i++) {
      struct dohentry d;
      int rc;
      memset(&d, 0, sizeof(d));
      rc = doh_decode((const unsigned char *)&full49[i], sizeof(full49)-i-1,
                      DNS_TYPE_A, &d);
      if(!rc) {
        /* none of them should work */
        fprintf(stderr, "2 %zu: %d\n", i, rc);
        return 7;
      }
    }
    {
      int rc;
      struct dohentry d;
      struct dohaddr *a;
      memset(&d, 0, sizeof(d));
      rc = doh_decode((const unsigned char *)full49, sizeof(full49)-1,
                      DNS_TYPE_A, &d);
      fail_if(d.numaddr != 1, "missing address");
      a = &d.addr[0];
      p = &a->ip.v4[0];
      msnprintf((char *)buffer, sizeof(buffer),
                "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
      if(rc || strcmp((char *)buffer, "127.0.0.1")) {
        fprintf(stderr, "bad address decoded: %s, rc == %d\n", buffer, rc);
        return 7;
      }
      fail_if(d.numcname, "bad cname counter");
    }
  }
}
UNITTEST_STOP

#else /* CURL_DISABLE_DOH */
UNITTEST_START
{
  return 1; /* nothing to do, just fail */
}
UNITTEST_STOP


#endif
