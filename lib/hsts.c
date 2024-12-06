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
 * The Strict-Transport-Security header is defined in RFC 6797:
 * https://datatracker.ietf.org/doc/html/rfc6797
 */
#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_HSTS)
#include <curl/curl.h>
#include "urldata.h"
#include "llist.h"
#include "hsts.h"
#include "curl_get_line.h"
#include "strcase.h"
#include "sendf.h"
#include "strtoofft.h"
#include "parsedate.h"
#include "fopen.h"
#include "rename.h"
#include "share.h"
#include "strdup.h"
#include "strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define MAX_HSTS_LINE 4095
#define MAX_HSTS_HOSTLEN 2048
#define MAX_HSTS_DATELEN 256
#define UNLIMITED "unlimited"

#if defined(DEBUGBUILD) || defined(UNITTESTS)
/* to play well with debug builds, we can *set* a fixed time this will
   return */
time_t deltatime; /* allow for "adjustments" for unit test purposes */
static time_t hsts_debugtime(void *unused)
{
  char *timestr = getenv("CURL_TIME");
  (void)unused;
  if(timestr) {
    curl_off_t val;
    (void)curlx_strtoofft(timestr, NULL, 10, &val);

    val += (curl_off_t)deltatime;
    return (time_t)val;
  }
  return time(NULL);
}
#undef time
#define time(x) hsts_debugtime(x)
#endif

struct hsts *Curl_hsts_init(void)
{
  struct hsts *h = calloc(1, sizeof(struct hsts));
  if(h) {
    Curl_llist_init(&h->list, NULL);
  }
  return h;
}

static void hsts_free(struct stsentry *e)
{
  free((char *)e->host);
  free(e);
}

void Curl_hsts_cleanup(struct hsts **hp)
{
  struct hsts *h = *hp;
  if(h) {
    struct Curl_llist_node *e;
    struct Curl_llist_node *n;
    for(e = Curl_llist_head(&h->list); e; e = n) {
      struct stsentry *sts = Curl_node_elem(e);
      n = Curl_node_next(e);
      hsts_free(sts);
    }
    free(h->filename);
    free(h);
    *hp = NULL;
  }
}

static CURLcode hsts_create(struct hsts *h,
                            const char *hostname,
                            size_t hlen,
                            bool subdomains,
                            curl_off_t expires)
{
  DEBUGASSERT(h);
  DEBUGASSERT(hostname);

  if(hlen && (hostname[hlen - 1] == '.'))
    /* strip off any trailing dot */
    --hlen;
  if(hlen) {
    char *duphost;
    struct stsentry *sts = calloc(1, sizeof(struct stsentry));
    if(!sts)
      return CURLE_OUT_OF_MEMORY;

    duphost = Curl_memdup0(hostname, hlen);
    if(!duphost) {
      free(sts);
      return CURLE_OUT_OF_MEMORY;
    }

    sts->host = duphost;
    sts->expires = expires;
    sts->includeSubDomains = subdomains;
    Curl_llist_append(&h->list, sts, &sts->node);
  }
  return CURLE_OK;
}

CURLcode Curl_hsts_parse(struct hsts *h, const char *hostname,
                         const char *header)
{
  const char *p = header;
  curl_off_t expires = 0;
  bool gotma = FALSE;
  bool gotinc = FALSE;
  bool subdomains = FALSE;
  struct stsentry *sts;
  time_t now = time(NULL);
  size_t hlen = strlen(hostname);

  if(Curl_host_is_ipnum(hostname))
    /* "explicit IP address identification of all forms is excluded."
       / RFC 6797 */
    return CURLE_OK;

  do {
    while(*p && ISBLANK(*p))
      p++;
    if(strncasecompare("max-age", p, 7)) {
      bool quoted = FALSE;
      CURLofft offt;
      char *endp;

      if(gotma)
        return CURLE_BAD_FUNCTION_ARGUMENT;

      p += 7;
      while(*p && ISBLANK(*p))
        p++;
      if(*p++ != '=')
        return CURLE_BAD_FUNCTION_ARGUMENT;
      while(*p && ISBLANK(*p))
        p++;

      if(*p == '\"') {
        p++;
        quoted = TRUE;
      }
      offt = curlx_strtoofft(p, &endp, 10, &expires);
      if(offt == CURL_OFFT_FLOW)
        expires = CURL_OFF_T_MAX;
      else if(offt)
        /* invalid max-age */
        return CURLE_BAD_FUNCTION_ARGUMENT;
      p = endp;
      if(quoted) {
        if(*p != '\"')
          return CURLE_BAD_FUNCTION_ARGUMENT;
        p++;
      }
      gotma = TRUE;
    }
    else if(strncasecompare("includesubdomains", p, 17)) {
      if(gotinc)
        return CURLE_BAD_FUNCTION_ARGUMENT;
      subdomains = TRUE;
      p += 17;
      gotinc = TRUE;
    }
    else {
      /* unknown directive, do a lame attempt to skip */
      while(*p && (*p != ';'))
        p++;
    }

    while(*p && ISBLANK(*p))
      p++;
    if(*p == ';')
      p++;
  } while(*p);

  if(!gotma)
    /* max-age is mandatory */
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(!expires) {
    /* remove the entry if present verbatim (without subdomain match) */
    sts = Curl_hsts(h, hostname, hlen, FALSE);
    if(sts) {
      Curl_node_remove(&sts->node);
      hsts_free(sts);
    }
    return CURLE_OK;
  }

  if(CURL_OFF_T_MAX - now < expires)
    /* would overflow, use maximum value */
    expires = CURL_OFF_T_MAX;
  else
    expires += now;

  /* check if it already exists */
  sts = Curl_hsts(h, hostname, hlen, FALSE);
  if(sts) {
    /* just update these fields */
    sts->expires = expires;
    sts->includeSubDomains = subdomains;
  }
  else
    return hsts_create(h, hostname, hlen, subdomains, expires);

  return CURLE_OK;
}

/*
 * Return TRUE if the given hostname is currently an HSTS one.
 *
 * The 'subdomain' argument tells the function if subdomain matching should be
 * attempted.
 */
struct stsentry *Curl_hsts(struct hsts *h, const char *hostname,
                           size_t hlen, bool subdomain)
{
  struct stsentry *bestsub = NULL;
  if(h) {
    time_t now = time(NULL);
    struct Curl_llist_node *e;
    struct Curl_llist_node *n;
    size_t blen = 0;

    if((hlen > MAX_HSTS_HOSTLEN) || !hlen)
      return NULL;
    if(hostname[hlen-1] == '.')
      /* remove the trailing dot */
      --hlen;

    for(e = Curl_llist_head(&h->list); e; e = n) {
      struct stsentry *sts = Curl_node_elem(e);
      size_t ntail;
      n = Curl_node_next(e);
      if(sts->expires <= now) {
        /* remove expired entries */
        Curl_node_remove(&sts->node);
        hsts_free(sts);
        continue;
      }
      ntail = strlen(sts->host);
      if((subdomain && sts->includeSubDomains) && (ntail < hlen)) {
        size_t offs = hlen - ntail;
        if((hostname[offs-1] == '.') &&
           strncasecompare(&hostname[offs], sts->host, ntail) &&
           (ntail > blen)) {
          /* save the tail match with the longest tail */
          bestsub = sts;
          blen = ntail;
        }
      }
      /* avoid strcasecompare because the host name is not null terminated */
      if((hlen == ntail) && strncasecompare(hostname, sts->host, hlen))
        return sts;
    }
  }
  return bestsub;
}

/*
 * Send this HSTS entry to the write callback.
 */
static CURLcode hsts_push(struct Curl_easy *data,
                          struct curl_index *i,
                          struct stsentry *sts,
                          bool *stop)
{
  struct curl_hstsentry e;
  CURLSTScode sc;
  struct tm stamp;
  CURLcode result;

  e.name = (char *)sts->host;
  e.namelen = strlen(sts->host);
  e.includeSubDomains = sts->includeSubDomains;

  if(sts->expires != TIME_T_MAX) {
    result = Curl_gmtime((time_t)sts->expires, &stamp);
    if(result)
      return result;

    msnprintf(e.expire, sizeof(e.expire), "%d%02d%02d %02d:%02d:%02d",
              stamp.tm_year + 1900, stamp.tm_mon + 1, stamp.tm_mday,
              stamp.tm_hour, stamp.tm_min, stamp.tm_sec);
  }
  else
    strcpy(e.expire, UNLIMITED);

  sc = data->set.hsts_write(data, &e, i,
                            data->set.hsts_write_userp);
  *stop = (sc != CURLSTS_OK);
  return sc == CURLSTS_FAIL ? CURLE_BAD_FUNCTION_ARGUMENT : CURLE_OK;
}

/*
 * Write this single hsts entry to a single output line
 */
static CURLcode hsts_out(struct stsentry *sts, FILE *fp)
{
  struct tm stamp;
  if(sts->expires != TIME_T_MAX) {
    CURLcode result = Curl_gmtime((time_t)sts->expires, &stamp);
    if(result)
      return result;
    fprintf(fp, "%s%s \"%d%02d%02d %02d:%02d:%02d\"\n",
            sts->includeSubDomains ? ".": "", sts->host,
            stamp.tm_year + 1900, stamp.tm_mon + 1, stamp.tm_mday,
            stamp.tm_hour, stamp.tm_min, stamp.tm_sec);
  }
  else
    fprintf(fp, "%s%s \"%s\"\n",
            sts->includeSubDomains ? ".": "", sts->host, UNLIMITED);
  return CURLE_OK;
}


/*
 * Curl_https_save() writes the HSTS cache to file and callback.
 */
CURLcode Curl_hsts_save(struct Curl_easy *data, struct hsts *h,
                        const char *file)
{
  struct Curl_llist_node *e;
  struct Curl_llist_node *n;
  CURLcode result = CURLE_OK;
  FILE *out;
  char *tempstore = NULL;

  if(!h)
    /* no cache activated */
    return CURLE_OK;

  /* if no new name is given, use the one we stored from the load */
  if(!file && h->filename)
    file = h->filename;

  if((h->flags & CURLHSTS_READONLYFILE) || !file || !file[0])
    /* marked as read-only, no file or zero length filename */
    goto skipsave;

  result = Curl_fopen(data, file, &out, &tempstore);
  if(!result) {
    fputs("# Your HSTS cache. https://curl.se/docs/hsts.html\n"
          "# This file was generated by libcurl! Edit at your own risk.\n",
          out);
    for(e = Curl_llist_head(&h->list); e; e = n) {
      struct stsentry *sts = Curl_node_elem(e);
      n = Curl_node_next(e);
      result = hsts_out(sts, out);
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
skipsave:
  if(data->set.hsts_write) {
    /* if there is a write callback */
    struct curl_index i; /* count */
    i.total = Curl_llist_count(&h->list);
    i.index = 0;
    for(e = Curl_llist_head(&h->list); e; e = n) {
      struct stsentry *sts = Curl_node_elem(e);
      bool stop;
      n = Curl_node_next(e);
      result = hsts_push(data, &i, sts, &stop);
      if(result || stop)
        break;
      i.index++;
    }
  }
  return result;
}

/* only returns SERIOUS errors */
static CURLcode hsts_add(struct hsts *h, char *line)
{
  /* Example lines:
     example.com "20191231 10:00:00"
     .example.net "20191231 10:00:00"
   */
  struct Curl_str host;
  struct Curl_str date;

  if(Curl_str_word(&line, &host, MAX_HSTS_HOSTLEN) ||
     Curl_str_singlespace(&line) ||
     Curl_str_quotedword(&line, &date, MAX_HSTS_DATELEN) ||
     Curl_str_newline(&line))
    ;
  else {
    CURLcode result = CURLE_OK;
    bool subdomain = FALSE;
    struct stsentry *e;
    char dbuf[MAX_HSTS_DATELEN + 1];
    time_t expires;

    /* The date parser works on a null terminated string. The maximum length
       is upheld by Curl_str_quotedword(). */
    memcpy(dbuf, date.str, date.len);
    dbuf[date.len] = 0;

    expires = strcmp(dbuf, UNLIMITED) ? Curl_getdate_capped(dbuf) :
      TIME_T_MAX;

    if(host.str[0] == '.') {
      host.str++;
      host.len--;
      subdomain = TRUE;
    }
    /* only add it if not already present */
    e = Curl_hsts(h, host.str, host.len, subdomain);
    if(!e)
      result = hsts_create(h, host.str, host.len, subdomain, expires);
    else if((strlen(e->host) == host.len) &&
            strncasecompare(host.str, e->host, host.len)) {
      /* the same hostname, use the largest expire time */
      if(expires > e->expires)
        e->expires = expires;
    }
    if(result)
      return result;
  }

  return CURLE_OK;
}

/*
 * Load HSTS data from callback.
 *
 */
static CURLcode hsts_pull(struct Curl_easy *data, struct hsts *h)
{
  /* if the HSTS read callback is set, use it */
  if(data->set.hsts_read) {
    CURLSTScode sc;
    DEBUGASSERT(h);
    do {
      char buffer[MAX_HSTS_HOSTLEN + 1];
      struct curl_hstsentry e;
      e.name = buffer;
      e.namelen = sizeof(buffer)-1;
      e.includeSubDomains = FALSE; /* default */
      e.expire[0] = 0;
      e.name[0] = 0; /* just to make it clean */
      sc = data->set.hsts_read(data, &e, data->set.hsts_read_userp);
      if(sc == CURLSTS_OK) {
        time_t expires;
        CURLcode result;
        DEBUGASSERT(e.name[0]);
        if(!e.name[0])
          /* bail out if no name was stored */
          return CURLE_BAD_FUNCTION_ARGUMENT;
        if(e.expire[0])
          expires = Curl_getdate_capped(e.expire);
        else
          expires = TIME_T_MAX; /* the end of time */
        result = hsts_create(h, e.name, strlen(e.name),
                             /* bitfield to bool conversion: */
                             e.includeSubDomains ? TRUE : FALSE,
                             expires);
        if(result)
          return result;
      }
      else if(sc == CURLSTS_FAIL)
        return CURLE_ABORTED_BY_CALLBACK;
    } while(sc == CURLSTS_OK);
  }
  return CURLE_OK;
}

/*
 * Load the HSTS cache from the given file. The text based line-oriented file
 * format is documented here: https://curl.se/docs/hsts.html
 *
 * This function only returns error on major problems that prevent hsts
 * handling to work completely. It will ignore individual syntactical errors
 * etc.
 */
static CURLcode hsts_load(struct hsts *h, const char *file)
{
  CURLcode result = CURLE_OK;
  FILE *fp;

  /* we need a private copy of the filename so that the hsts cache file
     name survives an easy handle reset */
  free(h->filename);
  h->filename = strdup(file);
  if(!h->filename)
    return CURLE_OUT_OF_MEMORY;

  fp = fopen(file, FOPEN_READTEXT);
  if(fp) {
    struct dynbuf buf;
    Curl_dyn_init(&buf, MAX_HSTS_LINE);
    while(Curl_get_line(&buf, fp)) {
      char *lineptr = Curl_dyn_ptr(&buf);
      while(*lineptr && ISBLANK(*lineptr))
        lineptr++;
      /*
       * Skip empty or commented lines, since we know the line will have a
       * trailing newline from Curl_get_line we can treat length 1 as empty.
       */
      if((*lineptr == '#') || strlen(lineptr) <= 1)
        continue;

      hsts_add(h, lineptr);
    }
    Curl_dyn_free(&buf); /* free the line buffer */
    fclose(fp);
  }
  return result;
}

/*
 * Curl_hsts_loadfile() loads HSTS from file
 */
CURLcode Curl_hsts_loadfile(struct Curl_easy *data,
                            struct hsts *h, const char *file)
{
  DEBUGASSERT(h);
  (void)data;
  return hsts_load(h, file);
}

/*
 * Curl_hsts_loadcb() loads HSTS from callback
 */
CURLcode Curl_hsts_loadcb(struct Curl_easy *data, struct hsts *h)
{
  if(h)
    return hsts_pull(data, h);
  return CURLE_OK;
}

void Curl_hsts_loadfiles(struct Curl_easy *data)
{
  struct curl_slist *l = data->state.hstslist;
  if(l) {
    Curl_share_lock(data, CURL_LOCK_DATA_HSTS, CURL_LOCK_ACCESS_SINGLE);

    while(l) {
      (void)Curl_hsts_loadfile(data, data->hsts, l->data);
      l = l->next;
    }
    Curl_share_unlock(data, CURL_LOCK_DATA_HSTS);
  }
}

#endif /* CURL_DISABLE_HTTP || CURL_DISABLE_HSTS */
