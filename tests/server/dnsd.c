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
#include "first.h"

static int dnsd_wrotepidfile = 0;
static int dnsd_wroteportfile = 0;

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef __AMIGA__
#error building dnsd on AMIGA os is unsupported
#endif

static uint16_t get16bit(const unsigned char **pkt, size_t *size)
{
  const unsigned char *p = *pkt;
  (*pkt) += 2;
  *size -= 2;
  return (uint16_t)((p[0] << 8) | p[1]);
}

#define BLOB_MAX_LEN         4096

struct blob {
  uint8_t data[BLOB_MAX_LEN];
  size_t dlen;
};

static void blob_reset(struct blob *b)
{
  memset(b->data, 0, sizeof(b->data));
  b->dlen = 0;
}

static int blob_add(struct blob *b, uint8_t n)
{
  if(b->dlen + 1 > BLOB_MAX_LEN)
    return 1;
  b->data[b->dlen] = n;
  b->dlen += 1;
  return 0;
}

static int blob_addn(struct blob *b, const uint8_t *data, size_t n)
{
  if(b->dlen + n > BLOB_MAX_LEN)
    return 1;
  memcpy(&b->data[b->dlen], data, n);
  b->dlen += n;
  return 0;
}

static int blob_add_uint16(struct blob *b, uint16_t n)
{
  if(b->dlen + 2 > BLOB_MAX_LEN)
    return 1;
  b->data[b->dlen] = (n >> 8) & 0xffU;
  b->data[b->dlen + 1] = n & 0xffU;
  b->dlen += 2;
  return 0;
}

static int blob_addchars(struct blob *b, const char *data, size_t n)
{
  return blob_addn(b, (const uint8_t *)data, n);
}

static int qname2str(const unsigned char **pkt, size_t *size,
                     char *name, size_t name_max)
{
  unsigned char length;
  size_t o = 0;
  const unsigned char *p = *pkt;

  do {
    int i;
    length = *p++;
    if(*size < length)
      /* too long */
      return 1;
    if(length && o)
      name[o++] = '.';
    if(o + length >= name_max - 1)
      return 1;
    for(i = 0; i < length; i++) {
      name[o++] = *p++;
    }
  } while(length);
  *size -= (p - *pkt);
  *pkt = p;
  name[o] = '\0';
  return 0;
}

static int blob_add_qname_part(struct blob *b, struct Curl_str *str)
{
  size_t dot, skip;

  for(dot = 0; dot < str->len; ++dot) {
    if(str->str[dot] == '.')
      break;
  }
  if(!dot || (dot > 63)) /* RFC 1035, ch. 3.1 */
    return 1;
  if(blob_add(b, (uint8_t)dot) ||
     (dot && blob_addchars(b, str->str, dot)))
    return 1;

  skip = dot;
  if(dot < str->len)
    skip += 1;
  str->str += skip;
  str->len -= skip;
  return 0;
}

static int blob_add_qname(struct blob *b, const struct Curl_str *str)
{
  struct Curl_str s = *str;

  while(s.len) {
    if(s.str[0] == '.') {
      if(s.len != 1)
        return 1;
      break;
    }
    else {
      if(blob_add_qname_part(b, &s))
        return 1;
    }
  }
  return blob_add(b, 0);
}

#define QTYPE_A     1
#define QTYPE_AAAA  28
#define QTYPE_HTTPS 0x41

#define HTTPS_RR_CODE_MANDATORY       0x00
#define HTTPS_RR_CODE_ALPN            0x01
#define HTTPS_RR_CODE_NO_DEF_ALPN     0x02
#define HTTPS_RR_CODE_PORT            0x03
#define HTTPS_RR_CODE_IPV4            0x04
#define HTTPS_RR_CODE_ECH             0x05
#define HTTPS_RR_CODE_IPV6            0x06

static const char *type2string(uint16_t qtype)
{
  switch(qtype) {
  case QTYPE_A:
    return "A";
  case QTYPE_AAAA:
    return "AAAA";
  case QTYPE_HTTPS:
    return "HTTPS";
  }
  return "<unknown>";
}

/*
 * Handle initial connection protocol.
 *
 * Return query (qname + type + class), type and id.
 */
static int store_incoming(int qid, const unsigned char *data, size_t size,
                          unsigned char *qbuf, size_t qbuflen, size_t *qlen,
                          uint16_t *qtype, uint16_t *idp)
{
  FILE *server;
  char dumpfile[256];
#if 0
  size_t i;
#endif
  uint16_t qd;
  const uint8_t *qptr;
  char name[256];
  size_t qsize;

  *qlen = 0;
  *qtype = 0;
  *idp = 0;

  snprintf(dumpfile, sizeof(dumpfile), "%s/dnsd.input", logdir);

  /* Open request dump file. */
  server = curlx_fopen(dumpfile, "ab");
  if(!server) {
    char errbuf[STRERROR_LEN];
    int error = errno;
    logmsg("fopen() failed with error (%d) %s",
           error, curlx_strerror(error, errbuf, sizeof(errbuf)));
    logmsg("Error opening file '%s'", dumpfile);
    return -1;
  }

  /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
  *idp = get16bit(&data, &size);
  data += 2; /* skip the next 16 bits */
  size -= 2;
#if 0
  fprintf(server, "QR: %x\n", (*idp & 0x8000) > 15);
  fprintf(server, "OPCODE: %x\n", (*idp & 0x7800) >> 11);
  fprintf(server, "TC: %x\n", (*idp & 0x200) >> 9);
  fprintf(server, "RD: %x\n", (*idp & 0x100) >> 8);
  fprintf(server, "Z: %x\n", (*idp & 0x70) >> 4);
  fprintf(server, "RCODE: %x\n", (*idp & 0x0f));
#endif
  (void)get16bit(&data, &size);

  data += 6; /* skip ANCOUNT, NSCOUNT and ARCOUNT */
  size -= 6;

  /* store pointer and size at the QD point */
  qsize = size;
  qptr = data;

  if(!qname2str(&data, &size, name, sizeof(name))) {
    qd = get16bit(&data, &size);
    fprintf(server, "QNAME %s QTYPE %s\n", name, type2string(qd));
    *qtype = qd;
    logmsg("[%d] Question for '%s' type %x / %s",
           qid, name, qd, type2string(qd));

    (void)get16bit(&data, &size);

    *qlen = qsize - size; /* total size of the query */
    if(*qlen > qbuflen) {
      logmsg("dnsd: query too large: %lu > %lu",
             (unsigned long)*qlen, (unsigned long)qbuflen);
      curlx_fclose(server);
      return -1;
    }
    memcpy(qbuf, qptr, *qlen);
  }
  else
    logmsg("Bad input qname");
#if 0
  for(i = 0; i < size; i++) {
    fprintf(server, "%02d", (unsigned int)data[i]);
  }
  fprintf(server, "\n");
#endif

  curlx_fclose(server);

  return 0;
}

static int add_answer(struct blob *body,
                      const unsigned char *a, size_t alen,
                      uint16_t qtype)
{
  uint8_t prefix[10] = {
    0xc0, 0x0c, /* points to the query at this fixed packet index */
    0x00, 0x00,
    0x00, 0x01, /* QCLASS IN */
    0x00, 0x00,
    0x0a, 0x14, /* TTL, Time to live: 2580 (43 minutes) */
  };

  /* QTYPE */
  prefix[2] = (unsigned char)(qtype >> 8);
  prefix[3] = (unsigned char)(qtype & 0xff);

  if(blob_addn(body, prefix, sizeof(prefix)))
    return 1;
  if((alen > UINT16_MAX) || blob_add_uint16(body, (uint16_t)alen))
    return 1;
  return blob_addn(body, a, alen);
}

#ifdef _WIN32
#define SENDTO3 int
#else
#define SENDTO3 size_t
#endif

#define INSTRUCTIONS "dnsd.cmd"

static curlx_struct_stat finfo_last;
static unsigned char ipv4_pref[4];
static unsigned char ipv6_pref[16];
static unsigned char ancount_a;
static unsigned char ancount_aaaa;

static timediff_t a_delay_ms;
static timediff_t aaaa_delay_ms;
static timediff_t https_delay_ms;

static int query_id = -1;

static struct blob httpsrr;

struct resp {
  struct resp *next;
  int qid;
  struct curltime send_ts;
  struct sockaddr addr;
  curl_socklen_t addrlen;
  struct blob body;
};

static struct resp *resp_queue;

static CURLcode send_resp(curl_socket_t sock, struct resp *resp)
{
  ssize_t rc;

sending:
  rc = sendto(sock, (const void *)resp->body.data, (SENDTO3)resp->body.dlen, 0,
              &resp->addr, resp->addrlen);
  if((rc < 0) && (SOCKERRNO == SOCKEINTR))
    goto sending;
  if(rc != (ssize_t)resp->body.dlen) {
    logmsg("failed sending %d bytes, errno=%d\n",
           (int)resp->body.dlen, SOCKERRNO);
    return CURLE_SEND_ERROR;
  }
  logmsg("[%d] sent response", resp->qid);
  return CURLE_OK;
}

static void queue_resp(struct resp *resp)
{
  struct resp **panchor = &resp_queue;
  while(*panchor) {
    timediff_t ms = curlx_ptimediff_ms(&(*panchor)->send_ts, &resp->send_ts);
    if(ms > 0) /* resp is to be sent before *panchor */
      break;
    panchor = &(*panchor)->next;
  }
  resp->next = *panchor;
  *panchor = resp;
}

static timediff_t send_resp_queue(curl_socket_t sock)
{
  struct resp **panchor = &resp_queue;
  struct curltime now = curlx_now();
  timediff_t timeout_ms = 0;

  while(*panchor) {
    struct resp *resp = *panchor;
    timediff_t ms = curlx_ptimediff_ms(&resp->send_ts, &now);

    if(ms > 0) {
      timeout_ms = ms;
      break;
    }
    *panchor = resp->next;
    send_resp(sock, resp);
    curlx_free(resp);
  }
  return timeout_ms;
}

static void clear_resp_queue(void)
{
  while(resp_queue) {
    struct resp *resp = resp_queue;
    resp_queue = resp->next;
    curlx_free(resp);
  }
}

/* this is an answer to a question */
static struct resp *
create_resp(int qid, const struct sockaddr *addr, curl_socklen_t addrlen,
            const unsigned char *qbuf, size_t qlen,
            uint16_t qtype, uint16_t id)
{
  struct resp *resp;
  int a;
  timediff_t delay_ms = 0;
  char addrbuf[128]; /* IP address buffer */
  uint8_t header[12] = {
    0x80, 0xea, /* ID, overwrite */
    0x81, 0x80,
    /*
    Flags: 0x8180 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .0.. .... .... = Authoritative: Server is not an authority for
                              domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... 1... .... = Recursion available: Server can do recursive
                              queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion
                              was not authenticated by the server
        .... .... ...0 .... = Non-authenticated data: Unacceptable
        .... .... .... 0000 = Reply code: No error (0)
    */
    0x0, 0x1, /* QDCOUNT a single question */
    0x0, 0x0, /* ANCOUNT number of answers */
    0x0, 0x0, /* NSCOUNT */
    0x0, 0x0  /* ARCOUNT */
  };
  uint16_t ancount = 0;

  switch(qtype) {
  case QTYPE_A:
    ancount = ancount_a;
    delay_ms = a_delay_ms;
    break;
  case QTYPE_AAAA:
    ancount = ancount_aaaa;
    delay_ms = aaaa_delay_ms;
    break;
  case QTYPE_HTTPS:
    if(httpsrr.dlen)
      ancount = 1;
    delay_ms = https_delay_ms;
    break;
  }

  resp = curlx_calloc(1, sizeof(*resp));
  if(!resp)
    goto error;

  resp->qid = qid;
  /* on some platforms `curl_socklen_t` is an `int`. Casting might
  * wrap this, but then it still has to fit our record size. */
  if((size_t)addrlen > sizeof(resp->addr)) {
    logmsg("unable to handle addrlen of %zu", (size_t)addrlen);
    goto error;
  }
  memcpy(&resp->addr, CURL_UNCONST(addr), addrlen);
  resp->addrlen = addrlen;

  header[0] = (uint8_t)(id >> 8);
  header[1] = (uint8_t)(id & 0xff);

  header[6] = (uint8_t)(ancount >> 8);
  header[7] = (uint8_t)(ancount & 0xff);

  if(blob_addn(&resp->body, header, sizeof(header)))
    goto error;

  if(blob_addn(&resp->body, qbuf, qlen)) {
    logmsg("unable to handle query of length %zu", qlen);
    goto error;
  }

  switch(qtype) {
  case QTYPE_A:
    for(a = 0; a < ancount_a; a++) {
      const unsigned char *store = ipv4_pref;
      if(add_answer(&resp->body, store, sizeof(ipv4_pref), QTYPE_A))
        goto error;
      logmsg("[%d] response A (%x) '%s'", qid, QTYPE_A,
             curlx_inet_ntop(AF_INET, store, addrbuf, sizeof(addrbuf)));
    }
    if(!ancount_a)
      logmsg("[%d] response A empty", qid);
    break;
  case QTYPE_AAAA:
    for(a = 0; a < ancount_aaaa; a++) {
      const unsigned char *store = ipv6_pref;
      if(add_answer(&resp->body, store, sizeof(ipv6_pref), QTYPE_AAAA))
        goto error;
      logmsg("[%d] response AAAA (%x) '%s'", qid, QTYPE_AAAA,
             curlx_inet_ntop(AF_INET6, store, addrbuf, sizeof(addrbuf)));
    }
    if(!ancount_aaaa)
      logmsg("[%d] response AAAA empty", qid);
    break;
  case QTYPE_HTTPS:
    if(httpsrr.dlen) {
      if(add_answer(&resp->body, httpsrr.data, httpsrr.dlen, QTYPE_HTTPS)) {
        logmsg("[%d] error adding https %zu response bytes", qid,
               httpsrr.dlen);
        goto error;
      }
      logmsg("[%d] response HTTPS (%x), %zu bytes", qid, QTYPE_HTTPS,
             httpsrr.dlen);
    }
    else
      logmsg("[%d] response HTTPS, no record", qid);
    break;
  }

  resp->send_ts = curlx_now();
  if(delay_ms > 0) {
    int usec = (int)((delay_ms % 1000) * 1000);
    resp->send_ts.tv_sec += (time_t)(delay_ms / 1000);
    resp->send_ts.tv_usec += usec;
    if(resp->send_ts.tv_usec >= 1000000) {
      resp->send_ts.tv_sec++;
      resp->send_ts.tv_usec -= 1000000;
    }
    logmsg("[%d] delay response by %" FMT_TIMEDIFF_T "ms", qid, delay_ms);
  }
  return resp;

error:
  logmsg("[%d] failed to create response", qid);
  curlx_free(resp);
  return NULL;
}

static int read_https_alpn_part(struct blob *b, struct Curl_str *str)
{
  size_t i, skip;

  for(i = 0; i < str->len; ++i) {
    if(str->str[i] == ',')
      break;
  }
  if(i > 256)
    return 1;
  if(blob_add(b, (uint8_t)i) || blob_addchars(b, str->str, i))
    return 1;
  skip = i + ((i < str->len) ? 1 : 0);
  str->str += skip;
  str->len -= skip;
  return 0;
}

static int read_https_alpn(struct blob *b, const char **ps)
{
  struct Curl_str word;
  struct blob tmp;

  blob_reset(&tmp);
  if(curlx_str_word(ps, &word, UINT16_MAX))
    return 1;
  while(word.len) {
    if(read_https_alpn_part(&tmp, &word))
      return 1;
  }

  if(tmp.dlen > UINT16_MAX)
    return 1;

  if(blob_add_uint16(b, HTTPS_RR_CODE_ALPN) ||
     blob_add_uint16(b, (uint16_t)tmp.dlen) ||
     blob_addn(b, tmp.data, tmp.dlen))
    return 1;
  return 0;
}

static int read_https(struct blob *b, const char *s)
{
  struct Curl_str word;
  curl_off_t n;

  blob_reset(b);
  /* Parse a HTTPS textual representation inspired by RFC 9460 */
  curlx_str_passblanks(&s);
  if(curlx_str_number(&s, &n, UINT16_MAX))
    return 1;
  if(blob_add_uint16(b, (uint16_t)n))
    return 1;

  curlx_str_passblanks(&s);
  if(curlx_str_word(&s, &word, UINT16_MAX)) {
    logmsg("https: unable to read target qname, input=%s", s);
    return 1;
  }
  if(blob_add_qname(b, &word))
    return 1;

  while(*s) {
    curlx_str_passblanks(&s);
    if(!*s)
      break;
    if(!strncmp("alpn=", s, 5)) {
      s += 5;
      if(read_https_alpn(b, &s))
        return 1;
    }
    else if(!strncmp("no-default-alpn", s, 15)) {
      s += 15;
      if(blob_add_uint16(b, HTTPS_RR_CODE_NO_DEF_ALPN) ||
         blob_add_uint16(b, 0))
        return 1;
    }
    else
      return 1;
  }
  return 0;
}

static void read_instructions(void)
{
  char file[256];
  FILE *f;
  curlx_struct_stat finfo;

  snprintf(file, sizeof(file), "%s/" INSTRUCTIONS, logdir);
  if((curlx_stat(file, &finfo) == 0) &&
     (finfo.st_mtime == finfo_last.st_mtime) &&
     (finfo.st_size == finfo_last.st_size)
#ifndef _WIN32
     && (finfo.st_ino == finfo_last.st_ino)
#endif
#ifdef __APPLE__
     && (finfo.st_mtimespec.tv_nsec == finfo_last.st_mtimespec.tv_nsec)
#elif defined(_POSIX_C_SOURCE)
#if _POSIX_C_SOURCE >= 200809L
     && (finfo.st_mtim.tv_nsec == finfo_last.st_mtim.tv_nsec)
#endif
#endif
     ) {
    /* looks the same as before, skip reading it again */
    return;
  }
  /* reset defaults */
  a_delay_ms = aaaa_delay_ms = https_delay_ms = 0;
  blob_reset(&httpsrr);
  finfo_last = finfo;

  logmsg("read instructions from %s", file);
  f = curlx_fopen(file, FOPEN_READTEXT);
  if(f) {
    char buf[256];
    ancount_aaaa = ancount_a = 0;
    while(fgets(buf, sizeof(buf), f)) {
      const char *rtype = NULL;
      char *p = strchr(buf, '\n');
      if(p) {
        int rc;
        *p = 0;
        if(!strncmp("A: ", buf, 3)) {
          rc = curlx_inet_pton(AF_INET, &buf[3], ipv4_pref);
          ancount_a = (rc == 1);
          rtype = "A";
        }
        else if(!strncmp("AAAA: ", buf, 6)) {
          char *p6 = &buf[6];
          if(*p6 == '[') {
            char *pt = strchr(p6, ']');
            if(pt)
              *pt = 0;
            p6++;
          }
          rc = curlx_inet_pton(AF_INET6, p6, ipv6_pref);
          ancount_aaaa = (rc == 1);
          rtype = "AAAA";
        }
        else if(!strncmp("HTTPS: ", buf, 7)) {
          rc = read_https(&httpsrr, &buf[7]) ? 0 : 1;
          rtype = "HTTPS";
        }
        else if(!strncmp("Delay-A: ", buf, 9)) {
          curl_off_t ms;
          const char *pms = &buf[9];
          rc = 0;
          if(!curlx_str_number(&pms, &ms, 100000)) {
            a_delay_ms = (timediff_t)ms;
            rc = 1;
          }
        }
        else if(!strncmp("Delay-AAAA: ", buf, 12)) {
          curl_off_t ms;
          const char *pms = &buf[12];
          rc = 0;
          if(!curlx_str_number(&pms, &ms, 100000)) {
            aaaa_delay_ms = (timediff_t)ms;
            rc = 1;
          }
        }
        else if(!strncmp("Delay-HTTPS: ", buf, 13)) {
          curl_off_t ms;
          const char *pms = &buf[13];
          rc = 0;
          if(!curlx_str_number(&pms, &ms, 100000)) {
            https_delay_ms = (timediff_t)ms;
            rc = 1;
          }
        }
        else {
          /* accept empty line */
          rc = buf[0] ? 0 : 1;
        }
        if(rc != 1) {
          logmsg("Bad line in %s: '%s'\n", file, buf);
        }
        else if(rtype) {
          logmsg("added %s record via '%s'", rtype, buf);
        }
      }
    }
    logmsg("set delays: A=%" FMT_TIMEDIFF_T "ms AAAA=%" FMT_TIMEDIFF_T
           "ms HTTPS=%" FMT_TIMEDIFF_T "ms",
           a_delay_ms, aaaa_delay_ms, https_delay_ms);
    curlx_fclose(f);
  }
  else
    logmsg("Error opening file '%s'", file);
}

static int test_dnsd(int argc, const char **argv)
{
  srvr_sockaddr_union_t me;
  ssize_t n = 0;
  int arg = 1;
  uint16_t port = 9123; /* UDP */
  curl_socket_t sock = CURL_SOCKET_BAD;
  int flag;
  int rc;
  int error;
  char errbuf[STRERROR_LEN];
  int result = 0;
  struct resp *resp;

  pidname = ".dnsd.pid";
  serverlogfile = "log/dnsd.log";
  serverlogslocked = 0;

  while(argc > arg) {
    const char *opt;
    curl_off_t num;
    if(!strcmp("--verbose", argv[arg])) {
      arg++;
      /* nothing yet */
    }
    else if(!strcmp("--version", argv[arg])) {
      printf("dnsd IPv4%s\n",
#ifdef USE_IPV6
             "/IPv6"
#else
             ""
#endif
      );
      return 0;
    }
    else if(!strcmp("--pidfile", argv[arg])) {
      arg++;
      if(argc > arg)
        pidname = argv[arg++];
    }
    else if(!strcmp("--portfile", argv[arg])) {
      arg++;
      if(argc > arg)
        portname = argv[arg++];
    }
    else if(!strcmp("--logfile", argv[arg])) {
      arg++;
      if(argc > arg)
        serverlogfile = argv[arg++];
    }
    else if(!strcmp("--logdir", argv[arg])) {
      arg++;
      if(argc > arg)
        logdir = argv[arg++];
    }
    else if(!strcmp("--ipv4", argv[arg])) {
#ifdef USE_IPV6
      ipv_inuse = "IPv4";
      use_ipv6 = FALSE;
#endif
      arg++;
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef USE_IPV6
      ipv_inuse = "IPv6";
      use_ipv6 = TRUE;
#endif
      arg++;
    }
    else if(!strcmp("--port", argv[arg])) {
      arg++;
      if(argc > arg) {
        opt = argv[arg];
        if(!curlx_str_number(&opt, &num, 0xffff))
          port = (uint16_t)num;
        arg++;
      }
    }
    else {
      if(argv[arg])
        fprintf(stderr, "unknown option: %s\n", argv[arg]);
      puts("Usage: dnsd [option]\n"
           " --version\n"
           " --logfile [file]\n"
           " --logdir [directory]\n"
           " --pidfile [file]\n"
           " --portfile [file]\n"
           " --ipv4\n"
           " --ipv6\n"
           " --port [port]\n");
      return 0;
    }
  }

  snprintf(loglockfile, sizeof(loglockfile), "%s/%s/dnsd-%s.lock",
           logdir, SERVERLOGS_LOCKDIR, ipv_inuse);

#ifdef USE_IPV6
  if(!use_ipv6)
#endif
    sock = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef USE_IPV6
  else
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
#endif

  if(sock == CURL_SOCKET_BAD) {
    error = SOCKERRNO;
    logmsg("Error creating socket (%d) %s",
           error, curlx_strerror(error, errbuf, sizeof(errbuf)));
    result = 1;
    goto dnsd_cleanup;
  }

  flag = 1;
  if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&flag, sizeof(flag))) {
    error = SOCKERRNO;
    logmsg("setsockopt(SO_REUSEADDR) failed with error (%d) %s",
           error, curlx_strerror(error, errbuf, sizeof(errbuf)));
    result = 1;
    goto dnsd_cleanup;
  }

#ifdef USE_IPV6
  if(!use_ipv6) {
#endif
    memset(&me.sa4, 0, sizeof(me.sa4));
    me.sa4.sin_family = AF_INET;
    me.sa4.sin_addr.s_addr = INADDR_ANY;
    me.sa4.sin_port = htons(port);
    rc = bind(sock, &me.sa, sizeof(me.sa4));
#ifdef USE_IPV6
  }
  else {
    memset(&me.sa6, 0, sizeof(me.sa6));
    me.sa6.sin6_family = AF_INET6;
    me.sa6.sin6_addr = in6addr_any;
    me.sa6.sin6_port = htons(port);
    rc = bind(sock, &me.sa, sizeof(me.sa6));
  }
#endif /* USE_IPV6 */
  if(rc) {
    error = SOCKERRNO;
    logmsg("Error binding socket on port %hu (%d) %s", port,
           error, curlx_strerror(error, errbuf, sizeof(errbuf)));
    result = 1;
    goto dnsd_cleanup;
  }

  if(!port) {
    /* The system was supposed to choose a port number, figure out which
       port we actually got and update the listener port value with it. */
    curl_socklen_t la_size;
    srvr_sockaddr_union_t localaddr;
    memset(&localaddr, 0, sizeof(localaddr));
#ifdef USE_IPV6
    if(!use_ipv6)
#endif
      la_size = sizeof(localaddr.sa4);
#ifdef USE_IPV6
    else
      la_size = sizeof(localaddr.sa6);
#endif
    if(getsockname(sock, &localaddr.sa, &la_size) < 0) {
      error = SOCKERRNO;
      logmsg("getsockname() failed with error (%d) %s",
             error, curlx_strerror(error, errbuf, sizeof(errbuf)));
      sclose(sock);
      goto dnsd_cleanup;
    }
    switch(localaddr.sa.sa_family) {
    case AF_INET:
      port = ntohs(localaddr.sa4.sin_port);
      break;
#ifdef USE_IPV6
    case AF_INET6:
      port = ntohs(localaddr.sa6.sin6_port);
      break;
#endif
    default:
      break;
    }
    if(!port) {
      /* Real failure, listener port shall not be zero beyond this point. */
      logmsg("Apparently getsockname() succeeded, with listener port zero.");
      logmsg("A valid reason for this failure is a binary built without");
      logmsg("proper network library linkage. This might not be the only");
      logmsg("reason, but double check it before anything else.");
      result = 2;
      goto dnsd_cleanup;
    }
  }

  dnsd_wrotepidfile = write_pidfile(pidname);
  if(!dnsd_wrotepidfile) {
    result = 1;
    goto dnsd_cleanup;
  }

  if(portname) {
    dnsd_wroteportfile = write_portfile(portname, port);
    if(!dnsd_wroteportfile) {
      result = 1;
      goto dnsd_cleanup;
    }
  }

  logmsg("Running %s version on port UDP/%d", ipv_inuse, (int)port);
  curlx_nonblock(sock, TRUE);

  for(;;) {
    uint16_t id = 0;
    uint8_t inbuffer[1500];
    srvr_sockaddr_union_t from;
    curl_socklen_t fromlen;
    uint8_t qbuf[256]; /* query storage */
    size_t qlen = 0; /* query size */
    uint16_t qtype = 0;
    timediff_t timeout_ms = 0;
    fromlen = sizeof(from);
#ifdef USE_IPV6
    if(!use_ipv6)
#endif
      fromlen = sizeof(from.sa4);
#ifdef USE_IPV6
    else
      fromlen = sizeof(from.sa6);
#endif

    timeout_ms = send_resp_queue(sock);

    {
      fd_set readfds;
      struct timeval tv;
      int maxfd = (int)sock;

      FD_ZERO(&readfds);
      FD_SET(sock, &readfds);
      if(!timeout_ms || (timeout_ms > 100))
        timeout_ms = 100;

      rc = select(maxfd + 1, &readfds, NULL, NULL,
                  curlx_mstotv(&tv, timeout_ms));

      if(rc == -1) {
        logmsg("error %d returned by select()", SOCKERRNO);
      }
      else if(!rc) { /* timeout */
        continue;
      }
    }
    n = (ssize_t)recvfrom(sock, (char *)inbuffer, sizeof(inbuffer), 0,
                          &from.sa, &fromlen);
    if(got_exit_signal)
      break;
    if(n < 0) {
      logmsg("recvfrom");
      result = 3;
      break;
    }

    /* read once per incoming query, which is probably more than one
       per test case */
    read_instructions();

    ++query_id;
    store_incoming(query_id, inbuffer, n,
                   qbuf, sizeof(qbuf), &qlen, &qtype, &id);

    set_advisor_read_lock(loglockfile);
    serverlogslocked = 1;

    resp = create_resp(query_id, &from.sa, fromlen, qbuf,
                       qlen, qtype, id);
    if(!resp)
      logmsg("error creating response");
    else
      queue_resp(resp);

    if(got_exit_signal)
      break;

    if(serverlogslocked) {
      serverlogslocked = 0;
      clear_advisor_read_lock(loglockfile);
    }
  }

dnsd_cleanup:

#if 0
  if((peer != sock) && (peer != CURL_SOCKET_BAD))
    sclose(peer);
#endif

  if(sock != CURL_SOCKET_BAD)
    sclose(sock);

  if(got_exit_signal)
    logmsg("signalled to die");

  if(dnsd_wrotepidfile)
    unlink(pidname);
  if(dnsd_wroteportfile)
    unlink(portname);

  if(serverlogslocked) {
    serverlogslocked = 0;
    clear_advisor_read_lock(loglockfile);
  }

  clear_resp_queue();
  restore_signal_handlers(true);

  if(got_exit_signal) {
    logmsg("========> %s dnsd (port: %d pid: %ld) exits with signal (%d)",
           ipv_inuse, (int)port, (long)our_getpid(), exit_signal);
    /*
     * To properly set the return status of the process we
     * must raise the same signal SIGINT or SIGTERM that we
     * caught and let the old handler take care of it.
     */
    raise(exit_signal);
  }

  logmsg("========> dnsd quits");
  return result;
}
