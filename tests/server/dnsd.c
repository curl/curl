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

#ifndef __AMIGA__

static int dnsd_wrotepidfile = 0;
static int dnsd_wroteportfile = 0;

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
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

#if 0
#define HTTPS_RR_CODE_MANDATORY       0x00
#endif
#define HTTPS_RR_CODE_ALPN            0x01
#define HTTPS_RR_CODE_NO_DEF_ALPN     0x02
#if 0
#define HTTPS_RR_CODE_PORT            0x03
#define HTTPS_RR_CODE_IPV4            0x04
#define HTTPS_RR_CODE_ECH             0x05
#define HTTPS_RR_CODE_IPV6            0x06
#endif

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
static int store_incoming(const char *source, int query_id,
                          const unsigned char *data, size_t datalen,
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
  size_t qsize, size;

  *qlen = 0;
  *qtype = 0;
  *idp = 0;

  size = datalen;
  if(datalen < 16) {
    logmsg("query data size is too small: %ld", (long)datalen);
    return -1;
  }

  snprintf(dumpfile, sizeof(dumpfile), "%s/dnsd.input", logdir);

  /* Open request dump file. */
  server = curlx_fopen(dumpfile, "ab");
  if(!server) {
    char errbuf[STRERROR_LEN];
    int error = errno;
    logmsg("fopen() failed with error (%d) %s",
           error, curlx_strerror(error, errbuf, sizeof(errbuf)));
    logmsg("[%s] Error opening file '%s'", source, dumpfile);
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
  fprintf(server, "[%s] QR: %x\n", source, (*idp & 0x8000) > 15);
  fprintf(server, "[%s] OPCODE: %x\n", source, (*idp & 0x7800) >> 11);
  fprintf(server, "[%s] TC: %x\n", source, (*idp & 0x200) >> 9);
  fprintf(server, "[%s] RD: %x\n", source, (*idp & 0x100) >> 8);
  fprintf(server, "[%s] Z: %x\n", source, (*idp & 0x70) >> 4);
  fprintf(server, "[%s] RCODE: %x\n", source, (*idp & 0x0f));
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
    logmsg("[%d] [%s] Question for '%s' type %x / %s",
           query_id, source, name, qd, type2string(qd));

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

static void fdset_add_sock(fd_set *fds, curl_socket_t sock, int *pmaxfd)
{
  FD_SET(sock, fds);
  if((int)sock > *pmaxfd)
    *pmaxfd = (int)sock;
}

static struct curltime now_plus(timediff_t delta_ms)
{
  struct curltime ts = curlx_now();
  if(delta_ms > 0) {
    int usec = (int)((delta_ms % 1000) * 1000);
    ts.tv_sec += (time_t)(delta_ms / 1000);
    ts.tv_usec += usec;
    if(ts.tv_usec >= 1000000) {
      ts.tv_sec++;
      ts.tv_usec -= 1000000;
    }
  }
  return ts;
}

static int read_https_alpn_part(struct blob *b, struct Curl_str *str)
{
  size_t i, skip;

  for(i = 0; i < str->len; ++i) {
    if(str->str[i] == ',')
      break;
  }
  if(i >= 256)
    return 1;
  if(blob_add(b, (uint8_t)i) || blob_addchars(b, str->str, i))
    return 1;
  skip = i + ((i < str->len) ? 1 : 0);
  str->str += skip;
  str->len -= skip;
  return 0;
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
static unsigned char rcode_a;
static unsigned char rcode_aaaa;
static struct blob httpsrr;

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
    logmsg("[CONFIG] https: unable to read target qname, input=%s", s);
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
  rcode_a = rcode_aaaa = 0;
  blob_reset(&httpsrr);
  finfo_last = finfo;

  logmsg("[CONFIG] reading from %s", file);
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
        else if(!strncmp("Rcode-A: ", buf, 9)) {
          curl_off_t code;
          const char *pc = &buf[9];
          rc = 0;
          if(!curlx_str_number(&pc, &code, 15)) {
            rcode_a = (unsigned char)code;
            rc = 1;
          }
        }
        else if(!strncmp("Rcode-AAAA: ", buf, 12)) {
          curl_off_t code;
          const char *pc = &buf[12];
          rc = 0;
          if(!curlx_str_number(&pc, &code, 15)) {
            rcode_aaaa = (unsigned char)code;
            rc = 1;
          }
        }
        else {
          /* accept empty line */
          rc = buf[0] ? 0 : 1;
        }
        if(rc != 1) {
          logmsg("[CONFIG] Bad line in %s: '%s'", file, buf);
        }
        else if(rtype) {
          logmsg("[CONFIG] added %s record via '%s'", rtype, buf);
        }
      }
    }
    logmsg("[CONFIG] set delays: A=%" FMT_TIMEDIFF_T "ms AAAA=%"
           FMT_TIMEDIFF_T "ms HTTPS=%" FMT_TIMEDIFF_T "ms",
           a_delay_ms, aaaa_delay_ms, https_delay_ms);
    curlx_fclose(f);
  }
  else
    logmsg("[CONFIG] Error opening file '%s'", file);
}

static int last_query_id = -1;

static int dnsd_make_answer(struct blob *blob, int query_id,
                            const uint8_t *qbuf, size_t qlen,
                            uint16_t qtype, uint16_t id,
                            timediff_t *pdelay_ms)
{
  int a;
  char addrbuf[128]; /* IP address buffer */
  uint8_t header[12] = {
    0x80, 0xea, /* ID, overwrite */
    0x81, 0x80,
    /* Flags: 0x8180 Standard query response, No error

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
  unsigned char rcode = 0;
  CURLcode result;

  /* read once per incoming query, which is probably more than one
     per test case */
  read_instructions();

  switch(qtype) {
  case QTYPE_A:
    ancount = ancount_a;
    *pdelay_ms = a_delay_ms;
    rcode = rcode_a;
    break;
  case QTYPE_AAAA:
    ancount = ancount_aaaa;
    *pdelay_ms = aaaa_delay_ms;
    rcode = rcode_aaaa;
    break;
  case QTYPE_HTTPS:
    if(httpsrr.dlen)
      ancount = 1;
    *pdelay_ms = https_delay_ms;
    break;
  default:
    *pdelay_ms = 0;
  }
  if(rcode)
    ancount = 0;

  header[0] = (uint8_t)(id >> 8);
  header[1] = (uint8_t)(id & 0xff);

  if(rcode) {
    header[3] = (uint8_t)((header[3] & 0xf0) | (rcode & 0x0f));
    logmsg("[%d] response rcode %u", query_id, (unsigned int)rcode);
  }

  header[6] = (uint8_t)(ancount >> 8);
  header[7] = (uint8_t)(ancount & 0xff);

  if(blob_addn(blob, header, sizeof(header)))
    return 1;

  if(blob_addn(blob, qbuf, qlen)) {
    logmsg("unable to handle query of length %zu", qlen);
    return 1;
  }

  switch(qtype) {
  case QTYPE_A:
    for(a = 0; !rcode && (a < ancount_a); a++) {
      const unsigned char *store = ipv4_pref;
      if(add_answer(blob, store, sizeof(ipv4_pref), QTYPE_A))
        return 1;
      result = curlx_inet_ntop(AF_INET, store, addrbuf, sizeof(addrbuf));
      logmsg("[%d] response A (%x) '%s' (%d)", query_id,
             (unsigned int)QTYPE_A, result ? "?" : addrbuf, (int)result);
    }
    if(!ancount_a)
      logmsg("[%d] response A empty", query_id);
    break;
  case QTYPE_AAAA:
    for(a = 0; !rcode && (a < ancount_aaaa); a++) {
      const unsigned char *store = ipv6_pref;
      if(add_answer(blob, store, sizeof(ipv6_pref), QTYPE_AAAA))
        return 1;
      result = curlx_inet_ntop(AF_INET6, store, addrbuf, sizeof(addrbuf));
      logmsg("[%d] response AAAA (%x) '%s' (%d)", query_id,
             (unsigned int)QTYPE_AAAA, result ? "?" : addrbuf, (int)result);
    }
    if(!ancount_aaaa)
      logmsg("[%d] response AAAA empty", query_id);
    break;
  case QTYPE_HTTPS:
    if(httpsrr.dlen) {
      if(add_answer(blob, httpsrr.data, httpsrr.dlen, QTYPE_HTTPS)) {
        logmsg("[%d] error adding https %zu response bytes", query_id,
               httpsrr.dlen);
        return 1;
      }
      logmsg("[%d] response HTTPS (%x), %zu bytes", query_id,
             (unsigned int)QTYPE_HTTPS, httpsrr.dlen);
    }
    else
      logmsg("[%d] response HTTPS, no record", query_id);
    break;
  }

  return 0;
}

struct udp_resp {
  struct udp_resp *next;
  int query_id;
  struct curltime send_ts;
  struct sockaddr addr;
  curl_socklen_t addrlen;
  struct blob body;
};

static struct udp_resp *udp_resp_queue;

static CURLcode send_udp_resp(curl_socket_t sock, struct udp_resp *resp)
{
  ssize_t rc;
  int sockerr = 0;

  do {
    rc = sendto(sock, (const void *)resp->body.data, (SENDTO3)resp->body.dlen,
                0, &resp->addr, resp->addrlen);
  } while((rc < 0) && ((sockerr = SOCKERRNO) == SOCKEINTR));
  if(rc < 0) {
    char errbuf[STRERROR_LEN];
    logmsg("[%d-UDP] failed sending %zu bytes, error: (%d) %s",
           resp->query_id, resp->body.dlen,
           sockerr, curlx_strerror(sockerr, errbuf, sizeof(errbuf)));
    return CURLE_SEND_ERROR;
  }
  else if(rc != (ssize_t)resp->body.dlen) {
    logmsg("[%d-UDP] failed sending %zu bytes, sent: %zd",
           resp->query_id, resp->body.dlen, rc);
    return CURLE_SEND_ERROR;
  }
  logmsg("[%d-UDP] sent response", resp->query_id);
  return CURLE_OK;
}

static void queue_udp_resp(struct udp_resp *resp)
{
  struct udp_resp **panchor = &udp_resp_queue;
  while(*panchor) {
    timediff_t ms = curlx_ptimediff_ms(&(*panchor)->send_ts, &resp->send_ts);
    if(ms > 0) /* resp is to be sent before *panchor */
      break;
    panchor = &(*panchor)->next;
  }
  resp->next = *panchor;
  *panchor = resp;
}

static timediff_t queue_udp_next_ms(struct curltime *pnow)
{
  timediff_t next_ms = 1000;
  struct udp_resp *r;

  for(r = udp_resp_queue; r; r = r->next) {
    timediff_t ms = curlx_ptimediff_ms(&r->send_ts, pnow);
    if((ms > 0) && (ms < next_ms))
      next_ms = ms;
    else if(ms <= 0)
      return 0;
  }
  return next_ms;
}

static void queue_udp_send(curl_socket_t sock, struct curltime *pnow)
{
  struct udp_resp **panchor = &udp_resp_queue;

  while(*panchor) {
    struct udp_resp *resp = *panchor;
    timediff_t ms = curlx_ptimediff_ms(&resp->send_ts, pnow);

    /* if not due yet, break as response queue is time sorted */
    if(ms > 0)
      break;
    *panchor = resp->next;
    send_udp_resp(sock, resp);
    curlx_free(resp);
  }
}

static void queue_udp_clear(void)
{
  while(udp_resp_queue) {
    struct udp_resp *resp = udp_resp_queue;
    udp_resp_queue = resp->next;
    curlx_free(resp);
  }
}

/* this is an answer to a question */
static struct udp_resp *udp_resp_create(int query_id,
                                        const struct sockaddr *addr,
                                        curl_socklen_t addrlen,
                                        const unsigned char *qbuf, size_t qlen,
                                        uint16_t qtype, uint16_t id)
{
  struct udp_resp *resp;
  timediff_t delay_ms = 0;

  resp = curlx_calloc(1, sizeof(*resp));
  if(!resp)
    goto error;

  resp->query_id = query_id;
  /* on some platforms `curl_socklen_t` is an `int`. Casting might
   * wrap this, but then it still has to fit our record size. */
  if((size_t)addrlen > sizeof(resp->addr)) {
    logmsg("[%d-UDP] unable to handle addrlen of %zu",
           query_id, (size_t)addrlen);
    goto error;
  }
  memcpy(&resp->addr, CURL_UNCONST(addr), addrlen);
  resp->addrlen = addrlen;

  if(dnsd_make_answer(&resp->body, query_id, qbuf, qlen, qtype, id, &delay_ms))
    goto error;

  resp->send_ts = now_plus(delay_ms);
  if(delay_ms > 0)
    logmsg("[%d-UDP] delay response by %" FMT_TIMEDIFF_T "ms",
           query_id, delay_ms);
  return resp;

error:
  logmsg("[%d-UDP] failed to create response", query_id);
  curlx_free(resp);
  return NULL;
}

static int udp_recv_req(curl_socket_t sock)
{
  srvr_sockaddr_union_t from;
  curl_socklen_t fromlen;
  uint8_t inbuffer[1500];
  uint8_t qbuf[256]; /* query storage */
  size_t qlen = 0; /* query size */
  struct udp_resp *resp;
  uint16_t qtype = 0, id;
  ssize_t n;
  int result = 0;

  fromlen = sizeof(from);
#ifdef USE_IPV6
  if(socket_domain == AF_INET6)
    fromlen = sizeof(from.sa6);
  else
#endif
    fromlen = sizeof(from.sa4);

  n = (ssize_t)recvfrom(sock, (char *)inbuffer, sizeof(inbuffer), 0,
                        &from.sa, &fromlen);
  if(got_exit_signal)
    goto out;
  if(n < 0) {
    logmsg("UDP, recvfrom error");
    result = 3;
    goto out;
  }

  ++last_query_id;
  store_incoming("UDP", last_query_id, inbuffer, n,
                 qbuf, sizeof(qbuf), &qlen, &qtype, &id);

  set_advisor_read_lock(loglockfile);
  serverlogslocked = 1;

  resp = udp_resp_create(last_query_id, &from.sa, fromlen, qbuf,
                         qlen, qtype, id);
  if(!resp)
    logmsg("[%d-UDP] error creating response", last_query_id);
  else
    queue_udp_resp(resp);

out:
  return result;
}

#define MAX_DOH_CONNS 512
#define MAX_DOH_INBUF_LEN (8 * 1024)
#define MAX_DOH_OUTBUF_LEN (8 * 1024)

struct doh_conn {
  curl_socket_t sock;
  int index;
  int query_id;
  char inbuf[MAX_DOH_INBUF_LEN];
  size_t inblen;
  size_t inbody_offset;
  size_t inbody_len;
  char outbuf[MAX_DOH_OUTBUF_LEN];
  size_t outblen;
  struct curltime send_ts;
  BIT(want_recv);
  BIT(want_send);
  BIT(close_pending);
};

static struct doh_conn doh_conns[MAX_DOH_CONNS];

static void doh_conns_init(void)
{
  int i;
  for(i = 0; i < MAX_DOH_CONNS; ++i) {
    doh_conns[i].sock = CURL_SOCKET_BAD;
    doh_conns[i].index = i;
  }
}

static int doh_conns_add(curl_socket_t sock)
{
  int i;
  for(i = 0; i < MAX_DOH_CONNS; ++i) {
    if(doh_conns[i].sock == CURL_SOCKET_BAD) {
      doh_conns[i].sock = sock;
      doh_conns[i].want_recv = TRUE;
      logmsg("[x-%d-DOH] accepted new connection, fd=%ld", i, (long)sock);
      return 0;
    }
  }
  logmsg("Too many open DoH connections, closing incoming.");
  sclose(sock);
  return 1;
}

static void doh_conn_close(size_t i)
{
  if(i >= MAX_DOH_CONNS)
    return;
  if(doh_conns[i].sock != CURL_SOCKET_BAD)
    sclose(doh_conns[i].sock);
  doh_conns[i].sock = CURL_SOCKET_BAD;
  doh_conns[i].want_recv = FALSE;
  doh_conns[i].want_send = FALSE;
  logmsg("[x-%d-DOH] connection closed", (int)i);
}

static void doh_conns_close_all(void)
{
  size_t i;
  for(i = 0; i < MAX_DOH_CONNS; ++i) {
    doh_conn_close(i);
  }
}

static void doh_conns_fdsets(fd_set *readfds, fd_set *writefds,
                             struct curltime *pnow,
                             int *pmaxfd,
                             timediff_t *ptimeout_ms)
{
  size_t i;
  for(i = 0; i < MAX_DOH_CONNS; ++i) {
    struct doh_conn *c = &doh_conns[i];
    if((c->sock != CURL_SOCKET_BAD)) {
      if(!c->want_send && c->outblen) { /* check delayed send */
        timediff_t ms = curlx_ptimediff_ms(&c->send_ts, pnow);
        if(ms <= 0)
          c->want_send = TRUE;
        else if((ms < *ptimeout_ms) || !*ptimeout_ms)
          *ptimeout_ms = ms;
      }
      if(c->want_send)
        FD_SET(c->sock, writefds);
      if(c->want_recv)
        FD_SET(c->sock, readfds);

      if((FD_ISSET(c->sock, readfds) || FD_ISSET(c->sock, writefds)) &&
         (int)c->sock > *pmaxfd)
        *pmaxfd = (int)c->sock;
    }
  }
}

static int doh_conn_send(struct doh_conn *c, struct curltime *pnow)
{
  char errbuf[STRERROR_LEN];
  ssize_t rc;
  int sockerr;

  if(c->outblen) {
    timediff_t ms = curlx_ptimediff_ms(&c->send_ts, pnow);
    size_t n;

    if(ms > 0) { /* not due yet */
      c->want_send = FALSE;
      goto out;
    }

    rc = swrite(c->sock, c->outbuf, c->outblen);
    if(rc < 0) {
      sockerr = SOCKERRNO;
      if((sockerr == SOCKEINPROGRESS) || SOCK_EAGAIN(sockerr))
        return 0;
      sockerr = SOCKERRNO;
      logmsg("[%d-%d-DOH] swrite(%ld) failed with error (%d) %s",
             c->query_id, c->index, (long)c->sock,
             sockerr, curlx_strerror(sockerr, errbuf, sizeof(errbuf)));
      return 1;
    }
    n = (size_t)rc;
    if(n >= c->outblen) { /* all sent */
      c->outblen = 0;
      logmsg("[%d-%d-DOH] last response byte sent", c->query_id, c->index);
    }
    else {
      c->outblen -= n;
      memmove(c->outbuf, c->outbuf + n, c->outblen);
    }
  }

out:
  if(!c->outblen) {
    c->want_send = FALSE;
    if(c->close_pending)
      return 1;
    else {
      logmsg("[x-%d-DOH] switching to recv", c->index);
      c->want_recv = TRUE;
    }
  }
  return 0;
}

static const char *http_status_descr(int http_status)
{
  switch(http_status) {
  case 200:
    return "Ok";
  case 400:
    return "Bad Request";
  case 404:
    return "Not Found";
  case 405:
    return "Method Not Allowed";
  default:
    if(http_status < 100)
      return "This is wrong";
    if(http_status < 200)
      return "Just Kidding";
    if(http_status < 300)
      return "Lgtm";
    if(http_status < 400)
      return "Follow Me For More Requests";
    if(http_status < 500)
      return "You were wrong";
    return "We did something wrong";
  }
}

static int doh_conn_send_err(struct doh_conn *c, int http_status)
{
  c->inblen = 0;
  c->close_pending = TRUE;
  c->want_recv = FALSE;
  if(c->outblen) {
    logmsg("[%d-%d-DOH] error sending response with %zu bytes still outgoing",
           c->query_id, c->index, c->outblen);
    return 1;
  }

  memset(c->outbuf, 0, sizeof(c->outbuf));
  snprintf(c->outbuf, sizeof(c->outbuf) - 1,
           "HTTP/1.1 %d %s\r\n"
           "Content-Length: 0\r\n"
           "Connection: close\r\n"
           "\r\n",
           http_status, http_status_descr(http_status));
  c->outblen = strlen(c->outbuf);
  c->want_send = TRUE;
  logmsg("[%d-%d-DOH] sending HTTP response %d",
         c->query_id, c->index, http_status);
  return 0;
}

static int doh_conn_send_answer(struct doh_conn *c, struct blob *body,
                                timediff_t delay_ms)
{
  if(c->outblen) { /* Should not happen */
    logmsg("[%d-%d-DOH] trying to send an answer with outbuf still having "
           "%zu bytes", c->query_id, c->index, c->outblen);
    return 1;
  }
  memset(c->outbuf, 0, sizeof(c->outbuf));
  snprintf(c->outbuf, sizeof(c->outbuf) - 1,
           "HTTP/1.1 200 %s\r\n"
           "Server: curl/test-dnsd\r\n"
           "Date: Thu, 06 Aug 2026 08:42:00 GMT\r\n"
           "Content-Type: application/dns-message\r\n"
           "Content-Length: %ld\r\n"
           "\r\n",
           http_status_descr(200), (long)body->dlen);
  c->outblen = strlen(c->outbuf);
  if((c->outblen + body->dlen) > sizeof(c->outbuf)) {
    logmsg("[%d-%d-DOH] response size of %zu too large for outbuf",
           c->query_id, c->index, c->outblen + body->dlen);
    c->outblen = 0;
    return 1;
  }
  memcpy(c->outbuf + c->outblen, body->data, body->dlen);
  c->outblen += body->dlen;
  c->send_ts = now_plus(delay_ms);
  if(delay_ms > 0)
    logmsg("[%d-%d-DOH] delay response by %" FMT_TIMEDIFF_T "ms",
           c->query_id, c->index, delay_ms);
  else
    c->want_send = TRUE;
  c->want_recv = FALSE;
  logmsg("[%d-%d-DOH] sending HTTP response 200",
         c->query_id, c->index);
  return 0;
}

static int doh_req_parse_headers(const char **pstr,
                                 size_t *pcontent_length,
                                 bool *pcomplete)
{
  static const struct Curl_str HD_content_length = {
    STRCONST("Content-Length:")
  };
  static const struct Curl_str HD_content_type = {
    STRCONST("Content-Type:")
  };
  static const struct Curl_str HD_wanted_type = {
    STRCONST("application/dns-message")
  };
  const char *p = *pstr;
  bool ct_ok = FALSE;
  bool cl_ok = FALSE;
  bool eoh = FALSE;

  *pcomplete = FALSE;
  *pcontent_length = 0;
  while(p[0]) {
    const char *nl, *start = p;
    struct Curl_str hd_name, hd_val;

    if((p[0] == '\r') && (p[1] == '\n')) {
      p += 2;
      eoh = TRUE;
      break;
    }
    nl = strchr(p, '\n');
    if(!nl) /* incomplete */
      break;
    if(curlx_str_word(&p, &hd_name, 1024) ||
       curlx_str_singlespace(&p) ||
       curlx_str_untilnl(&p, &hd_val, 1024) ||
       curlx_str_newline(&p) ||
       curlx_str_newline(&p)) {
      logmsg("unrecognized request header '%.*s'",
             (int)(nl - start), start);
      return 1;
    }
    if(curlx_str_case_equal(&HD_content_type, &hd_name)) {
      if(!curlx_str_case_equal(&HD_wanted_type, &hd_val)) {
        logmsg("wrong content-type: '%.*s'", (int)hd_val.len, hd_val.str);
        return 1;
      }
      ct_ok = TRUE;
    }
    else if(curlx_str_case_equal(&HD_content_length, &hd_name)) {
      const char *s = hd_val.str;
      curl_off_t offt;
      if(curlx_str_number(&s, &offt, 4096)) {
        logmsg("wrong content-length: '%.*s'", (int)hd_val.len, hd_val.str);
        return 1;
      }
      *pcontent_length = (size_t)offt;
      cl_ok = TRUE;
    }
    else {
      /* ignore this header */
    }
  }

  *pstr = p;
  if(!eoh)
    return 0; /* need more */
  if(!ct_ok) {
    logmsg("request missing Content-Type");
    return 1;
  }
  if(!cl_ok) {
    logmsg("request missing Content-Length");
    return 1;
  }
  *pcomplete = TRUE;
  return 0;
}

static int doh_conn_do_req(struct doh_conn *c, bool eos)
{
  static const struct Curl_str DOH_PROTO = { STRCONST("HTTP/1.1") };
  static const struct Curl_str DOH_METHOD = { STRCONST("POST") };
  static const struct Curl_str DOH_PATH = { STRCONST("/") };
  const char *first_nl;
  bool complete = FALSE;

  if(!c->inblen && eos)
    return 1;

  if(!c->inbody_offset) {
    first_nl = strchr(c->inbuf, '\n');
    if(first_nl) {
      /* This is a poor man's HTTP/1.1 parser and we should rather have
       * one in curlx that we can share. */
      const char *p = c->inbuf;
      struct Curl_str method, path, proto;

      if(curlx_str_word(&p, &method, 1024) || curlx_str_singlespace(&p)) {
        logmsg("[x-%d-DOH] unrecognized first request line method '%.*s'",
               c->index, (int)(first_nl - c->inbuf), c->inbuf);
        return 1;
      }
      if(curlx_str_word(&p, &path, 1024) || curlx_str_singlespace(&p)) {
        logmsg("[x-%d-DOH] unrecognized first request line path '%.*s'",
               c->index, (int)(first_nl - c->inbuf), c->inbuf);
        return 1;
      }
      if(curlx_str_untilnl(&p, &proto, 1024) ||
         curlx_str_newline(&p) ||
         curlx_str_newline(&p)) {
        logmsg("[x-%d-DOH] unrecognized first request line proto '%.*s'",
               c->index, (int)(first_nl - c->inbuf), c->inbuf);
        return 1;
      }
      if(!curlx_str_case_equal(&DOH_PROTO, &proto)) {
        logmsg("[x-%d-DOH] unrecognized request protocol '%.*s'",
               c->index, (int)proto.len, proto.str);
        return 1;
      }
      if(!curlx_str_case_equal(&DOH_METHOD, &method)) {
        logmsg("[x-%d-DOH] unsupported request method '%.*s'",
               c->index, (int)method.len, method.str);
        return doh_conn_send_err(c, 405);
      }
      if(!curlx_str_case_equal(&DOH_PATH, &path)) {
        logmsg("[x-%d-DOH] request path not fond '%.*s'",
               c->index, (int)path.len, path.str);
        return doh_conn_send_err(c, 404);
      }
      if(doh_req_parse_headers(&p, &c->inbody_len, &complete)) {
        return doh_conn_send_err(c, 400);
      }
      /* Looks ok, remember the start of the body bytes */
      c->inbody_offset = (p - c->inbuf);
    }
    if(!complete)
      return eos ? 1 : 0; /* want more, error if client close */
  }

  if(c->inblen >= (c->inbody_offset + c->inbody_len)) {
    /* We have all bytes for processing the request */
    uint8_t qbuf[256]; /* query storage */
    size_t qlen = 0; /* query size */
    size_t rlen = c->inbody_offset + c->inbody_len; /* request size */
    uint16_t qtype = 0, id;
    struct blob blob;
    timediff_t delay_ms;

    c->query_id = ++last_query_id;
    if(store_incoming("DoH", c->query_id, (const uint8_t *)c->inbuf +
                      c->inbody_offset, c->inbody_len,
                      qbuf, sizeof(qbuf), &qlen, &qtype, &id)) {
      logmsg("[%d-%d-DOH] error storing incoming request",
             c->query_id, c->index);
      return doh_conn_send_err(c, 400);
    }

    /* remove handled request from inbuf */
    if(rlen >= c->inblen)
      c->inblen = 0;
    else {
      memmove(c->inbuf, c->inbuf + rlen, c->inblen - rlen);
      c->inblen -= rlen;
    }
    c->inbody_len = c->inbody_offset = 0;

    memset(&blob, 0, sizeof(blob));
    if(dnsd_make_answer(&blob, c->query_id, qbuf, qlen, qtype, id,
                        &delay_ms)) {
      return doh_conn_send_err(c, 500);
    }
    return doh_conn_send_answer(c, &blob, delay_ms);
  }
  return 0;
}

static int doh_conn_recv(struct doh_conn *c)
{
  char errbuf[STRERROR_LEN];
  ssize_t n;
  int sockerr;

  n = sread(c->sock, c->inbuf + c->inblen, sizeof(c->inbuf) - 1 - c->inblen);
  if(n < 0) {
    sockerr = SOCKERRNO;
    if((sockerr == SOCKEINPROGRESS) || SOCK_EAGAIN(sockerr))
      return 0;
    sockerr = SOCKERRNO;
    logmsg("[x-%d-DOH] sread() failed with error (%d) %s", c->index,
           sockerr, curlx_strerror(sockerr, errbuf, sizeof(errbuf)));
    return 1;
  }
  else if(n == 0) {
    logmsg("[x-%d-DOH] sread() == 0, client closed connection", c->index);
    return doh_conn_do_req(c, TRUE);
  }
  else {
    c->inblen += (size_t)n;
    c->inbuf[c->inblen] = 0;
    logmsg("[x-%d-DOH] sread() == %zu, processing", c->index, (size_t)n);
    return doh_conn_do_req(c, FALSE);
  }
}

static int doh_conns_serve(fd_set *readfds, fd_set *writefds)
{
  struct curltime now;
  size_t i;

  for(i = 0; i < MAX_DOH_CONNS; ++i) {
    struct doh_conn *c = &doh_conns[i];
    if(c->sock != CURL_SOCKET_BAD) {
      if(c->want_send && FD_ISSET(c->sock, writefds)) {
        now = curlx_now();
        if(doh_conn_send(c, &now)) {
          doh_conn_close(i);
          continue;
        }
      }
      if(c->want_recv && FD_ISSET(c->sock, readfds)) {
        if(doh_conn_recv(c)) {
          doh_conn_close(i);
          continue;
        }
      }
    }
  }
  return 0;
}

static int test_dnsd(int argc, const char **argv)
{
  int arg = 1;
  curl_socket_t sock_udp = CURL_SOCKET_BAD;
  curl_socket_t sock_tcp_listen = CURL_SOCKET_BAD;
  char errbuf[STRERROR_LEN];
  int rc, sockerr;
  int result = 0;

  pidname = ".dnsd.pid";
  serverlogfile = "log/dnsd.log";
  serverlogslocked = 0;
  server_port = 9123; /* UDP */
  socket_domain = AF_INET;

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
      socket_type = "IPv4";
      socket_domain = AF_INET;
      arg++;
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef USE_IPV6
      socket_type = "IPv6";
      socket_domain = AF_INET6;
#endif
      arg++;
    }
    else if(!strcmp("--port", argv[arg])) {
      arg++;
      if(argc > arg) {
        opt = argv[arg];
        if(!curlx_str_number(&opt, &num, 0xffff))
          server_port = (uint16_t)num;
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
           logdir, SERVERLOGS_LOCKDIR, socket_type);

  install_signal_handlers(FALSE);

  result = open_stream_sock(&sock_tcp_listen, &server_port);
  if(result)
    goto dnsd_cleanup;
  doh_conns_init();

  result = open_udp_sock(&sock_udp, &server_port);
  if(result)
    goto dnsd_cleanup;

  dnsd_wrotepidfile = write_pidfile(pidname);
  if(!dnsd_wrotepidfile) {
    result = 1;
    goto dnsd_cleanup;
  }

  if(portname) {
    dnsd_wroteportfile = write_portfile(portname, server_port);
    if(!dnsd_wroteportfile) {
      result = 1;
      goto dnsd_cleanup;
    }
  }

  /* start accepting connections */
  if(listen(sock_tcp_listen, 50)) {
    sockerr = SOCKERRNO;
    logmsg("listen() failed with error (%d) %s",
           sockerr, curlx_strerror(sockerr, errbuf, sizeof(errbuf)));
    result = 1;
    goto dnsd_cleanup;
  }

  logmsg("Running %s on port UDP+TCP/%u", socket_type, server_port);
  curlx_nonblock(sock_udp, TRUE);
  curlx_nonblock(sock_tcp_listen, TRUE);

  for(;;) {
    timediff_t timeout_ms = 0;
    fd_set readfds, writefds;
    struct timeval tv;
    int maxfd = 0;
    struct curltime now = curlx_now();

    FD_ZERO(&readfds);
    fdset_add_sock(&readfds, sock_udp, &maxfd);
    fdset_add_sock(&readfds, sock_tcp_listen, &maxfd);

    FD_ZERO(&writefds);
    timeout_ms = queue_udp_next_ms(&now);
    if(!timeout_ms)
      fdset_add_sock(&writefds, sock_udp, &maxfd);

    doh_conns_fdsets(&readfds, &writefds, &now, &maxfd, &timeout_ms);

    if(!timeout_ms || (timeout_ms > 100))
      timeout_ms = 100;

    rc = select(maxfd + 1, &readfds, &writefds, NULL,
                curlx_mstotv(&tv, timeout_ms));

    if(rc == -1) {
      logmsg("error %d returned by select()", SOCKERRNO);
    }
    else if(!rc) { /* timeout */
      continue;
    }

    if(FD_ISSET(sock_udp, &writefds)) {
      now = curlx_now();
      queue_udp_send(sock_udp, &now);
    }
    if(FD_ISSET(sock_udp, &readfds)) {
      result = udp_recv_req(sock_udp);
      if(result)
        break;
    }

    result = doh_conns_serve(&readfds, &writefds);
    if(result)
      break;

    if(FD_ISSET(sock_tcp_listen, &readfds)) {
      /* Service all queued connections */
      curl_socket_t sock_conn;
      while(TRUE) {
        sock_conn = accept_connection(sock_tcp_listen);
        if(!sock_conn) /* no more connections to accept */
          break;
        if(sock_conn == CURL_SOCKET_BAD)
          goto dnsd_cleanup;
        doh_conns_add(sock_conn);
      }
    }

    if(got_exit_signal)
      break;

    if(serverlogslocked) {
      serverlogslocked = 0;
      clear_advisor_read_lock(loglockfile);
    }
  }

dnsd_cleanup:
  if(sock_udp != CURL_SOCKET_BAD)
    sclose(sock_udp);
  if(sock_tcp_listen != CURL_SOCKET_BAD)
    sclose(sock_tcp_listen);

  doh_conns_close_all();

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

  queue_udp_clear();

  restore_signal_handlers(FALSE);

  return result;
}
#else
static int test_dnsd(int argc, const char **argv)
{
  (void)argc;
  (void)argv;
  fprintf(stderr, "dnsd on AmigaOS is unsupported\n");
  return 1;
}
#endif
