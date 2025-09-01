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
/*
 * The Alt-Svc: header is defined in RFC 7838:
 * https://datatracker.ietf.org/doc/html/rfc7838
 */
#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_ALTSVC)
#include <curl/curl.h>
#include "urldata.h"
#include "altsvc.h"
#include "curl_get_line.h"
#include "parsedate.h"
#include "sendf.h"
#include "curlx/warnless.h"
#include "fopen.h"
#include "rename.h"
#include "strdup.h"
#include "curlx/inet_pton.h"
#include "curlx/strparse.h"
#include "connect.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define MAX_ALTSVC_LINE 4095
#define MAX_ALTSVC_DATELEN 256
#define MAX_ALTSVC_HOSTLEN 2048
#define MAX_ALTSVC_ALPNLEN 10

#define H3VERSION "h3"

/* Given the ALPN ID, return the name */
const char *Curl_alpnid2str(enum alpnid id)
{
  switch(id) {
  case ALPN_h1:
    return "h1";
  case ALPN_h2:
    return "h2";
  case ALPN_h3:
    return H3VERSION;
  default:
    return ""; /* bad */
  }
}


static void altsvc_free(struct altsvc *as)
{
  free(as->src.host);
  free(as->dst.host);
  free(as);
}

static struct altsvc *altsvc_createid(const char *srchost,
                                      size_t hlen,
                                      const char *dsthost,
                                      size_t dlen, /* dsthost length */
                                      enum alpnid srcalpnid,
                                      enum alpnid dstalpnid,
                                      size_t srcport,
                                      size_t dstport)
{
  struct altsvc *as = calloc(1, sizeof(struct altsvc));
  if(!as)
    return NULL;
  DEBUGASSERT(hlen);
  DEBUGASSERT(dlen);
  if(!hlen || !dlen)
    /* bad input */
    goto error;
  if((hlen > 2) && srchost[0] == '[') {
    /* IPv6 address, strip off brackets */
    srchost++;
    hlen -= 2;
  }
  else if(srchost[hlen - 1] == '.') {
    /* strip off trailing dot */
    hlen--;
    if(!hlen)
      goto error;
  }
  if((dlen > 2) && dsthost[0] == '[') {
    /* IPv6 address, strip off brackets */
    dsthost++;
    dlen -= 2;
  }

  as->src.host = Curl_memdup0(srchost, hlen);
  if(!as->src.host)
    goto error;

  as->dst.host = Curl_memdup0(dsthost, dlen);
  if(!as->dst.host)
    goto error;

  as->src.alpnid = srcalpnid;
  as->dst.alpnid = dstalpnid;
  as->src.port = (unsigned short)srcport;
  as->dst.port = (unsigned short)dstport;

  return as;
error:
  altsvc_free(as);
  return NULL;
}

static struct altsvc *altsvc_create(struct Curl_str *srchost,
                                    struct Curl_str *dsthost,
                                    struct Curl_str *srcalpn,
                                    struct Curl_str *dstalpn,
                                    size_t srcport,
                                    size_t dstport)
{
  enum alpnid dstalpnid =
    Curl_alpn2alpnid(curlx_str(dstalpn), curlx_strlen(dstalpn));
  enum alpnid srcalpnid =
    Curl_alpn2alpnid(curlx_str(srcalpn), curlx_strlen(srcalpn));
  if(!srcalpnid || !dstalpnid)
    return NULL;
  return altsvc_createid(curlx_str(srchost), curlx_strlen(srchost),
                         curlx_str(dsthost), curlx_strlen(dsthost),
                         srcalpnid, dstalpnid,
                         srcport, dstport);
}

/* only returns SERIOUS errors */
static CURLcode altsvc_add(struct altsvcinfo *asi, const char *line)
{
  /* Example line:
     h2 example.com 443 h3 shiny.example.com 8443 "20191231 10:00:00" 1
   */
  struct Curl_str srchost;
  struct Curl_str dsthost;
  struct Curl_str srcalpn;
  struct Curl_str dstalpn;
  struct Curl_str date;
  curl_off_t srcport;
  curl_off_t dstport;
  curl_off_t persist;
  curl_off_t prio;

  if(curlx_str_word(&line, &srcalpn, MAX_ALTSVC_ALPNLEN) ||
     curlx_str_singlespace(&line) ||
     curlx_str_word(&line, &srchost, MAX_ALTSVC_HOSTLEN) ||
     curlx_str_singlespace(&line) ||
     curlx_str_number(&line, &srcport, 65535) ||
     curlx_str_singlespace(&line) ||
     curlx_str_word(&line, &dstalpn, MAX_ALTSVC_ALPNLEN) ||
     curlx_str_singlespace(&line) ||
     curlx_str_word(&line, &dsthost, MAX_ALTSVC_HOSTLEN) ||
     curlx_str_singlespace(&line) ||
     curlx_str_number(&line, &dstport, 65535) ||
     curlx_str_singlespace(&line) ||
     curlx_str_quotedword(&line, &date, MAX_ALTSVC_DATELEN) ||
     curlx_str_singlespace(&line) ||
     curlx_str_number(&line, &persist, 1) ||
     curlx_str_singlespace(&line) ||
     curlx_str_number(&line, &prio, 0) ||
     curlx_str_newline(&line))
    ;
  else {
    struct altsvc *as;
    char dbuf[MAX_ALTSVC_DATELEN + 1];
    time_t expires = 0;

    /* The date parser works on a null-terminated string. The maximum length
       is upheld by curlx_str_quotedword(). */
    memcpy(dbuf, curlx_str(&date), curlx_strlen(&date));
    dbuf[curlx_strlen(&date)] = 0;
    Curl_getdate_capped(dbuf, &expires);
    as = altsvc_create(&srchost, &dsthost, &srcalpn, &dstalpn,
                       (size_t)srcport, (size_t)dstport);
    if(as) {
      as->expires = expires;
      as->prio = 0; /* not supported to just set zero */
      as->persist = persist ? 1 : 0;
      Curl_llist_append(&asi->list, as, &as->node);
    }
  }

  return CURLE_OK;
}

/*
 * Load alt-svc entries from the given file. The text based line-oriented file
 * format is documented here: https://curl.se/docs/alt-svc.html
 *
 * This function only returns error on major problems that prevent alt-svc
 * handling to work completely. It will ignore individual syntactical errors
 * etc.
 */
static CURLcode altsvc_load(struct altsvcinfo *asi, const char *file)
{
  CURLcode result = CURLE_OK;
  FILE *fp;

  /* we need a private copy of the filename so that the altsvc cache file
     name survives an easy handle reset */
  free(asi->filename);
  asi->filename = strdup(file);
  if(!asi->filename)
    return CURLE_OUT_OF_MEMORY;

  fp = fopen(file, FOPEN_READTEXT);
  if(fp) {
    struct dynbuf buf;
    curlx_dyn_init(&buf, MAX_ALTSVC_LINE);
    while(Curl_get_line(&buf, fp)) {
      const char *lineptr = curlx_dyn_ptr(&buf);
      curlx_str_passblanks(&lineptr);
      if(curlx_str_single(&lineptr, '#'))
        altsvc_add(asi, lineptr);
    }
    curlx_dyn_free(&buf); /* free the line buffer */
    fclose(fp);
  }
  return result;
}

/*
 * Write this single altsvc entry to a single output line
 */

static CURLcode altsvc_out(struct altsvc *as, FILE *fp)
{
  struct tm stamp;
  const char *dst6_pre = "";
  const char *dst6_post = "";
  const char *src6_pre = "";
  const char *src6_post = "";
  CURLcode result = Curl_gmtime(as->expires, &stamp);
  if(result)
    return result;
#ifdef USE_IPV6
  else {
    char ipv6_unused[16];
    if(curlx_inet_pton(AF_INET6, as->dst.host, ipv6_unused) == 1) {
      dst6_pre = "[";
      dst6_post = "]";
    }
    if(curlx_inet_pton(AF_INET6, as->src.host, ipv6_unused) == 1) {
      src6_pre = "[";
      src6_post = "]";
    }
  }
#endif
  fprintf(fp,
          "%s %s%s%s %u "
          "%s %s%s%s %u "
          "\"%d%02d%02d "
          "%02d:%02d:%02d\" "
          "%u %u\n",
          Curl_alpnid2str(as->src.alpnid),
          src6_pre, as->src.host, src6_post,
          as->src.port,

          Curl_alpnid2str(as->dst.alpnid),
          dst6_pre, as->dst.host, dst6_post,
          as->dst.port,

          stamp.tm_year + 1900, stamp.tm_mon + 1, stamp.tm_mday,
          stamp.tm_hour, stamp.tm_min, stamp.tm_sec,
          as->persist, as->prio);
  return CURLE_OK;
}

/* ---- library-wide functions below ---- */

/*
 * Curl_altsvc_init() creates a new altsvc cache.
 * It returns the new instance or NULL if something goes wrong.
 */
struct altsvcinfo *Curl_altsvc_init(void)
{
  struct altsvcinfo *asi = calloc(1, sizeof(struct altsvcinfo));
  if(!asi)
    return NULL;
  Curl_llist_init(&asi->list, NULL);

  /* set default behavior */
  asi->flags = CURLALTSVC_H1
#ifdef USE_HTTP2
    | CURLALTSVC_H2
#endif
#ifdef USE_HTTP3
    | CURLALTSVC_H3
#endif
    ;
  return asi;
}

/*
 * Curl_altsvc_load() loads alt-svc from file.
 */
CURLcode Curl_altsvc_load(struct altsvcinfo *asi, const char *file)
{
  DEBUGASSERT(asi);
  return altsvc_load(asi, file);
}

/*
 * Curl_altsvc_ctrl() passes on the external bitmask.
 */
CURLcode Curl_altsvc_ctrl(struct altsvcinfo *asi, const long ctrl)
{
  DEBUGASSERT(asi);
  asi->flags = ctrl;
  return CURLE_OK;
}

/*
 * Curl_altsvc_cleanup() frees an altsvc cache instance and all associated
 * resources.
 */
void Curl_altsvc_cleanup(struct altsvcinfo **altsvcp)
{
  if(*altsvcp) {
    struct Curl_llist_node *e;
    struct Curl_llist_node *n;
    struct altsvcinfo *altsvc = *altsvcp;
    for(e = Curl_llist_head(&altsvc->list); e; e = n) {
      struct altsvc *as = Curl_node_elem(e);
      n = Curl_node_next(e);
      altsvc_free(as);
    }
    free(altsvc->filename);
    free(altsvc);
    *altsvcp = NULL; /* clear the pointer */
  }
}

/*
 * Curl_altsvc_save() writes the altsvc cache to a file.
 */
CURLcode Curl_altsvc_save(struct Curl_easy *data,
                          struct altsvcinfo *altsvc, const char *file)
{
  CURLcode result = CURLE_OK;
  FILE *out;
  char *tempstore = NULL;

  if(!altsvc)
    /* no cache activated */
    return CURLE_OK;

  /* if not new name is given, use the one we stored from the load */
  if(!file && altsvc->filename)
    file = altsvc->filename;

  if((altsvc->flags & CURLALTSVC_READONLYFILE) || !file || !file[0])
    /* marked as read-only, no file or zero length filename */
    return CURLE_OK;

  result = Curl_fopen(data, file, &out, &tempstore);
  if(!result) {
    struct Curl_llist_node *e;
    struct Curl_llist_node *n;
    fputs("# Your alt-svc cache. https://curl.se/docs/alt-svc.html\n"
          "# This file was generated by libcurl! Edit at your own risk.\n",
          out);
    for(e = Curl_llist_head(&altsvc->list); e; e = n) {
      struct altsvc *as = Curl_node_elem(e);
      n = Curl_node_next(e);
      result = altsvc_out(as, out);
      if(result)
        break;
    }
    fclose(out);
    if(!result && tempstore && Curl_rename(tempstore, file))
      result = CURLE_WRITE_ERROR;

    if(result && tempstore)
      unlink(tempstore);
  }
  free(tempstore);
  return result;
}

/* hostcompare() returns true if 'host' matches 'check'. The first host
 * argument may have a trailing dot present that will be ignored.
 */
static bool hostcompare(const char *host, const char *check)
{
  size_t hlen = strlen(host);
  size_t clen = strlen(check);

  if(hlen && (host[hlen - 1] == '.'))
    hlen--;
  if(hlen != clen)
    /* they cannot match if they have different lengths */
    return FALSE;
  return curl_strnequal(host, check, hlen);
}

/* altsvc_flush() removes all alternatives for this source origin from the
   list */
static void altsvc_flush(struct altsvcinfo *asi, enum alpnid srcalpnid,
                         const char *srchost, unsigned short srcport)
{
  struct Curl_llist_node *e;
  struct Curl_llist_node *n;
  for(e = Curl_llist_head(&asi->list); e; e = n) {
    struct altsvc *as = Curl_node_elem(e);
    n = Curl_node_next(e);
    if((srcalpnid == as->src.alpnid) &&
       (srcport == as->src.port) &&
       hostcompare(srchost, as->src.host)) {
      Curl_node_remove(e);
      altsvc_free(as);
    }
  }
}

#if defined(DEBUGBUILD) || defined(UNITTESTS)
/* to play well with debug builds, we can *set* a fixed time this will
   return */
static time_t altsvc_debugtime(void *unused)
{
  const char *timestr = getenv("CURL_TIME");
  (void)unused;
  if(timestr) {
    curl_off_t val;
    curlx_str_number(&timestr, &val, TIME_T_MAX);
    return (time_t)val;
  }
  return time(NULL);
}
#undef time
#define time(x) altsvc_debugtime(x)
#endif

/*
 * Curl_altsvc_parse() takes an incoming alt-svc response header and stores
 * the data correctly in the cache.
 *
 * 'value' points to the header *value*. That is contents to the right of the
 * header name.
 *
 * Currently this function rejects invalid data without returning an error.
 * Invalid hostname, port number will result in the specific alternative
 * being rejected. Unknown protocols are skipped.
 */
CURLcode Curl_altsvc_parse(struct Curl_easy *data,
                           struct altsvcinfo *asi, const char *value,
                           enum alpnid srcalpnid, const char *srchost,
                           unsigned short srcport)
{
  const char *p = value;
  struct altsvc *as;
  unsigned short dstport = srcport; /* the same by default */
  size_t entries = 0;
  struct Curl_str alpn;
  const char *sp;
  time_t maxage = 24 * 3600; /* default is 24 hours */
  bool persist = FALSE;
#ifdef CURL_DISABLE_VERBOSE_STRINGS
  (void)data;
#endif

  DEBUGASSERT(asi);

  /* initial check for "clear" */
  if(!curlx_str_cspn(&p, &alpn, ";\n\r")) {
    curlx_str_trimblanks(&alpn);
    /* "clear" is a magic keyword */
    if(curlx_str_casecompare(&alpn, "clear")) {
      /* Flush cached alternatives for this source origin */
      altsvc_flush(asi, srcalpnid, srchost, srcport);
      return CURLE_OK;
    }
  }

  p = value;

  if(curlx_str_until(&p, &alpn, MAX_ALTSVC_LINE, '='))
    return CURLE_OK; /* strange line */

  curlx_str_trimblanks(&alpn);

  /* Handle the optional 'ma' and 'persist' flags once first, as they need to
     be known for each alternative service. Unknown flags are skipped. */
  sp = strchr(p, ';');
  if(sp) {
    sp++; /* pass the semicolon */
    for(;;) {
      struct Curl_str name;
      struct Curl_str val;
      const char *vp;
      curl_off_t num;
      bool quoted;
      /* allow some extra whitespaces around name and value */
      if(curlx_str_until(&sp, &name, 20, '=') ||
         curlx_str_single(&sp, '=') ||
         curlx_str_until(&sp, &val, 80, ';'))
        break;
      curlx_str_trimblanks(&name);
      curlx_str_trimblanks(&val);
      /* the value might be quoted */
      vp = curlx_str(&val);
      quoted = (*vp == '\"');
      if(quoted)
        vp++;
      if(!curlx_str_number(&vp, &num, TIME_T_MAX)) {
        if(curlx_str_casecompare(&name, "ma"))
          maxage = (time_t)num;
        else if(curlx_str_casecompare(&name, "persist") && (num == 1))
          persist = TRUE;
      }
      if(quoted && curlx_str_single(&sp, '\"'))
        break;
      if(curlx_str_single(&sp, ';'))
        break;
    }
  }

  do {
    if(!curlx_str_single(&p, '=')) {
      /* [protocol]="[host][:port], [protocol]="[host][:port]" */
      enum alpnid dstalpnid =
        Curl_alpn2alpnid(curlx_str(&alpn), curlx_strlen(&alpn));
      if(!curlx_str_single(&p, '\"')) {
        struct Curl_str dsthost;
        curl_off_t port = 0;
        if(curlx_str_single(&p, ':')) {
          /* hostname starts here */
          if(curlx_str_single(&p, '[')) {
            if(curlx_str_until(&p, &dsthost, MAX_ALTSVC_HOSTLEN, ':')) {
              infof(data, "Bad alt-svc hostname, ignoring.");
              break;
            }
          }
          else {
            /* IPv6 host name */
            if(curlx_str_until(&p, &dsthost, MAX_IPADR_LEN, ']') ||
               curlx_str_single(&p, ']')) {
              infof(data, "Bad alt-svc IPv6 hostname, ignoring.");
              break;
            }
          }
          if(curlx_str_single(&p, ':'))
            break;
        }
        else
          /* no destination name, use source host */
          curlx_str_assign(&dsthost, srchost, strlen(srchost));

        if(curlx_str_number(&p, &port, 0xffff)) {
          infof(data, "Unknown alt-svc port number, ignoring.");
          break;
        }

        dstport = (unsigned short)port;

        if(curlx_str_single(&p, '\"'))
          break;

        if(dstalpnid) {
          if(!entries++)
            /* Flush cached alternatives for this source origin, if any - when
               this is the first entry of the line. */
            altsvc_flush(asi, srcalpnid, srchost, srcport);

          as = altsvc_createid(srchost, strlen(srchost),
                               curlx_str(&dsthost),
                               curlx_strlen(&dsthost),
                               srcalpnid, dstalpnid,
                               srcport, dstport);
          if(as) {
            time_t secs = time(NULL);
            /* The expires time also needs to take the Age: value (if any)
               into account. [See RFC 7838 section 3.1] */
            if(maxage > (TIME_T_MAX - secs))
              as->expires = TIME_T_MAX;
            else
              as->expires = maxage + secs;
            as->persist = persist;
            Curl_llist_append(&asi->list, as, &as->node);
            infof(data, "Added alt-svc: %.*s:%d over %s",
                  (int)curlx_strlen(&dsthost), curlx_str(&dsthost),
                  dstport, Curl_alpnid2str(dstalpnid));
          }
        }
      }
      else
        break;

      /* after the double quote there can be a comma if there is another
         string or a semicolon if no more */
      if(curlx_str_single(&p, ','))
        break;

      /* comma means another alternative is present */
      if(curlx_str_until(&p, &alpn, MAX_ALTSVC_LINE, '='))
        break;
      curlx_str_trimblanks(&alpn);
    }
    else
      break;
  } while(1);

  return CURLE_OK;
}

/*
 * Return TRUE on a match
 */
bool Curl_altsvc_lookup(struct altsvcinfo *asi,
                        enum alpnid srcalpnid, const char *srchost,
                        int srcport,
                        struct altsvc **dstentry,
                        const int versions) /* one or more bits */
{
  struct Curl_llist_node *e;
  struct Curl_llist_node *n;
  time_t now = time(NULL);
  DEBUGASSERT(asi);
  DEBUGASSERT(srchost);
  DEBUGASSERT(dstentry);

  for(e = Curl_llist_head(&asi->list); e; e = n) {
    struct altsvc *as = Curl_node_elem(e);
    n = Curl_node_next(e);
    if(as->expires < now) {
      /* an expired entry, remove */
      Curl_node_remove(e);
      altsvc_free(as);
      continue;
    }
    if((as->src.alpnid == srcalpnid) &&
       hostcompare(srchost, as->src.host) &&
       (as->src.port == srcport) &&
       (versions & (int)as->dst.alpnid)) {
      /* match */
      *dstentry = as;
      return TRUE;
    }
  }
  return FALSE;
}

#if defined(DEBUGBUILD) || defined(UNITTESTS)
#undef time
#endif

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_ALTSVC */
