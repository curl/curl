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

/***


RECEIVING COOKIE INFORMATION
============================

Curl_cookie_init()

        Inits a cookie struct to store data in a local file. This is always
        called before any cookies are set.

Curl_cookie_add()

        Adds a cookie to the in-memory cookie jar.


SENDING COOKIE INFORMATION
==========================

Curl_cookie_getlist()

        For a given host and path, return a linked list of cookies that
        the client should send to the server if used now. The secure
        boolean informs the cookie if a secure connection is achieved or
        not.

        It shall only return cookies that have not expired.

Example set of cookies:

    Set-cookie: PRODUCTINFO=webxpress; domain=.fidelity.com; path=/; secure
    Set-cookie: PERSONALIZE=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/ftgw; secure
    Set-cookie: FidHist=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/; secure
    Set-cookie: FidOrder=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/; secure
    Set-cookie: DisPend=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/; secure
    Set-cookie: FidDis=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/; secure
    Set-cookie:
    Session_Key@6791a9e0-901a-11d0-a1c8-9b012c88aa77=none;expires=Monday,
    13-Jun-1988 03:04:55 GMT; domain=.fidelity.com; path=/; secure
****/


#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)

#include "urldata.h"
#include "cookie.h"
#include "psl.h"
#include "strtok.h"
#include "sendf.h"
#include "slist.h"
#include "share.h"
#include "strtoofft.h"
#include "strcase.h"
#include "curl_get_line.h"
#include "curl_memrchr.h"
#include "parsedate.h"
#include "rename.h"
#include "fopen.h"
#include "strdup.h"
#include "llist.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static void strstore(char **str, const char *newstr, size_t len);

/* number of seconds in 400 days */
#define COOKIES_MAXAGE (400*24*3600)

/* Make sure cookies never expire further away in time than 400 days into the
   future. (from RFC6265bis draft-19)

   For the sake of easier testing, align the capped time to an even 60 second
   boundary.
*/
static void cap_expires(time_t now, struct Cookie *co)
{
  if((TIME_T_MAX - COOKIES_MAXAGE - 30) > now) {
    timediff_t cap = now + COOKIES_MAXAGE;
    if(co->expires > cap) {
      cap += 30;
      co->expires = (cap/60)*60;
    }
  }
}

static void freecookie(struct Cookie *co)
{
  free(co->domain);
  free(co->path);
  free(co->spath);
  free(co->name);
  free(co->value);
  free(co);
}

static bool cookie_tailmatch(const char *cookie_domain,
                             size_t cookie_domain_len,
                             const char *hostname)
{
  size_t hostname_len = strlen(hostname);

  if(hostname_len < cookie_domain_len)
    return FALSE;

  if(!strncasecompare(cookie_domain,
                      hostname + hostname_len-cookie_domain_len,
                      cookie_domain_len))
    return FALSE;

  /*
   * A lead char of cookie_domain is not '.'.
   * RFC6265 4.1.2.3. The Domain Attribute says:
   * For example, if the value of the Domain attribute is
   * "example.com", the user agent will include the cookie in the Cookie
   * header when making HTTP requests to example.com, www.example.com, and
   * www.corp.example.com.
   */
  if(hostname_len == cookie_domain_len)
    return TRUE;
  if('.' == *(hostname + hostname_len - cookie_domain_len - 1))
    return TRUE;
  return FALSE;
}

/*
 * matching cookie path and URL path
 * RFC6265 5.1.4 Paths and Path-Match
 */
static bool pathmatch(const char *cookie_path, const char *request_uri)
{
  size_t cookie_path_len;
  size_t uri_path_len;
  char *uri_path = NULL;
  char *pos;
  bool ret = FALSE;

  /* cookie_path must not have last '/' separator. ex: /sample */
  cookie_path_len = strlen(cookie_path);
  if(1 == cookie_path_len) {
    /* cookie_path must be '/' */
    return TRUE;
  }

  uri_path = strdup(request_uri);
  if(!uri_path)
    return FALSE;
  pos = strchr(uri_path, '?');
  if(pos)
    *pos = 0x0;

  /* #-fragments are already cut off! */
  if(0 == strlen(uri_path) || uri_path[0] != '/') {
    strstore(&uri_path, "/", 1);
    if(!uri_path)
      return FALSE;
  }

  /*
   * here, RFC6265 5.1.4 says
   *  4. Output the characters of the uri-path from the first character up
   *     to, but not including, the right-most %x2F ("/").
   *  but URL path /hoge?fuga=xxx means /hoge/index.cgi?fuga=xxx in some site
   *  without redirect.
   *  Ignore this algorithm because /hoge is uri path for this case
   *  (uri path is not /).
   */

  uri_path_len = strlen(uri_path);

  if(uri_path_len < cookie_path_len) {
    ret = FALSE;
    goto pathmatched;
  }

  /* not using checkprefix() because matching should be case-sensitive */
  if(strncmp(cookie_path, uri_path, cookie_path_len)) {
    ret = FALSE;
    goto pathmatched;
  }

  /* The cookie-path and the uri-path are identical. */
  if(cookie_path_len == uri_path_len) {
    ret = TRUE;
    goto pathmatched;
  }

  /* here, cookie_path_len < uri_path_len */
  if(uri_path[cookie_path_len] == '/') {
    ret = TRUE;
    goto pathmatched;
  }

  ret = FALSE;

pathmatched:
  free(uri_path);
  return ret;
}

/*
 * Return the top-level domain, for optimal hashing.
 */
static const char *get_top_domain(const char * const domain, size_t *outlen)
{
  size_t len = 0;
  const char *first = NULL, *last;

  if(domain) {
    len = strlen(domain);
    last = memrchr(domain, '.', len);
    if(last) {
      first = memrchr(domain, '.', (last - domain));
      if(first)
        len -= (++first - domain);
    }
  }

  if(outlen)
    *outlen = len;

  return first ? first : domain;
}

/* Avoid C1001, an "internal error" with MSVC14 */
#if defined(_MSC_VER) && (_MSC_VER == 1900)
#pragma optimize("", off)
#endif

/*
 * A case-insensitive hash for the cookie domains.
 */
static size_t cookie_hash_domain(const char *domain, const size_t len)
{
  const char *end = domain + len;
  size_t h = 5381;

  while(domain < end) {
    size_t j = (size_t)Curl_raw_toupper(*domain++);
    h += h << 5;
    h ^= j;
  }

  return (h % COOKIE_HASH_SIZE);
}

#if defined(_MSC_VER) && (_MSC_VER == 1900)
#pragma optimize("", on)
#endif

/*
 * Hash this domain.
 */
static size_t cookiehash(const char * const domain)
{
  const char *top;
  size_t len;

  if(!domain || Curl_host_is_ipnum(domain))
    return 0;

  top = get_top_domain(domain, &len);
  return cookie_hash_domain(top, len);
}

/*
 * cookie path sanitize
 */
static char *sanitize_cookie_path(const char *cookie_path)
{
  size_t len;
  char *new_path = strdup(cookie_path);
  if(!new_path)
    return NULL;

  /* some stupid site sends path attribute with '"'. */
  len = strlen(new_path);
  if(new_path[0] == '\"') {
    memmove(new_path, new_path + 1, len);
    len--;
  }
  if(len && (new_path[len - 1] == '\"')) {
    new_path[--len] = 0x0;
  }

  /* RFC6265 5.2.4 The Path Attribute */
  if(new_path[0] != '/') {
    /* Let cookie-path be the default-path. */
    strstore(&new_path, "/", 1);
    return new_path;
  }

  /* convert /hoge/ to /hoge */
  if(len && new_path[len - 1] == '/') {
    new_path[len - 1] = 0x0;
  }

  return new_path;
}

/*
 * Load cookies from all given cookie files (CURLOPT_COOKIEFILE).
 *
 * NOTE: OOM or cookie parsing failures are ignored.
 */
void Curl_cookie_loadfiles(struct Curl_easy *data)
{
  struct curl_slist *list = data->state.cookielist;
  if(list) {
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    while(list) {
      struct CookieInfo *ci =
        Curl_cookie_init(data, list->data, data->cookies,
                         data->set.cookiesession);
      if(!ci)
        /*
         * Failure may be due to OOM or a bad cookie; both are ignored
         * but only the first should be
         */
        infof(data, "ignoring failed cookie_init for %s", list->data);
      else
        data->cookies = ci;
      list = list->next;
    }
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  }
}

/*
 * strstore
 *
 * A thin wrapper around strdup which ensures that any memory allocated at
 * *str will be freed before the string allocated by strdup is stored there.
 * The intended usecase is repeated assignments to the same variable during
 * parsing in a last-wins scenario. The caller is responsible for checking
 * for OOM errors.
 */
static void strstore(char **str, const char *newstr, size_t len)
{
  DEBUGASSERT(newstr);
  DEBUGASSERT(str);
  free(*str);
  *str = Curl_memdup0(newstr, len);
}

/*
 * remove_expired
 *
 * Remove expired cookies from the hash by inspecting the expires timestamp on
 * each cookie in the hash, freeing and deleting any where the timestamp is in
 * the past. If the cookiejar has recorded the next timestamp at which one or
 * more cookies expire, then processing will exit early in case this timestamp
 * is in the future.
 */
static void remove_expired(struct CookieInfo *ci)
{
  struct Cookie *co;
  curl_off_t now = (curl_off_t)time(NULL);
  unsigned int i;

  /*
   * If the earliest expiration timestamp in the jar is in the future we can
   * skip scanning the whole jar and instead exit early as there will not be
   * any cookies to evict. If we need to evict however, reset the
   * next_expiration counter in order to track the next one. In case the
   * recorded first expiration is the max offset, then perform the safe
   * fallback of checking all cookies.
   */
  if(now < ci->next_expiration &&
     ci->next_expiration != CURL_OFF_T_MAX)
    return;
  else
    ci->next_expiration = CURL_OFF_T_MAX;

  for(i = 0; i < COOKIE_HASH_SIZE; i++) {
    struct Curl_llist_node *n;
    struct Curl_llist_node *e = NULL;

    for(n = Curl_llist_head(&ci->cookielist[i]); n; n = e) {
      co = Curl_node_elem(n);
      e = Curl_node_next(n);
      if(co->expires && co->expires < now) {
        Curl_node_remove(n);
        freecookie(co);
        ci->numcookies--;
      }
      else {
        /*
         * If this cookie has an expiration timestamp earlier than what we
         * have seen so far then record it for the next round of expirations.
         */
        if(co->expires && co->expires < ci->next_expiration)
          ci->next_expiration = co->expires;
      }
    }
  }
}

#ifndef USE_LIBPSL
/* Make sure domain contains a dot or is localhost. */
static bool bad_domain(const char *domain, size_t len)
{
  if((len == 9) && strncasecompare(domain, "localhost", 9))
    return FALSE;
  else {
    /* there must be a dot present, but that dot must not be a trailing dot */
    char *dot = memchr(domain, '.', len);
    if(dot) {
      size_t i = dot - domain;
      if((len - i) > 1)
        /* the dot is not the last byte */
        return FALSE;
    }
  }
  return TRUE;
}
#endif

/*
  RFC 6265 section 4.1.1 says a server should accept this range:

  cookie-octet    = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E

  But Firefox and Chrome as of June 2022 accept space, comma and double-quotes
  fine. The prime reason for filtering out control bytes is that some HTTP
  servers return 400 for requests that contain such.
*/
static bool invalid_octets(const char *p)
{
  /* Reject all bytes \x01 - \x1f (*except* \x09, TAB) + \x7f */
  static const char badoctets[] = {
    "\x01\x02\x03\x04\x05\x06\x07\x08\x0a"
    "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
    "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f"
  };
  size_t len;
  /* scan for all the octets that are *not* in cookie-octet */
  len = strcspn(p, badoctets);
  return p[len] != '\0';
}

#define CERR_OK            0
#define CERR_TOO_LONG      1 /* input line too long */
#define CERR_TAB           2 /* in a wrong place */
#define CERR_TOO_BIG       3 /* name/value too large */
#define CERR_BAD           4 /* deemed incorrect */
#define CERR_NO_SEP        5 /* semicolon problem */
#define CERR_NO_NAME_VALUE 6 /* name or value problem */
#define CERR_INVALID_OCTET 7 /* bad content */
#define CERR_BAD_SECURE    8 /* secure in a bad place */
#define CERR_OUT_OF_MEMORY 9
#define CERR_NO_TAILMATCH  10
#define CERR_COMMENT       11 /* a commented line */
#define CERR_RANGE         12 /* expire range problem */
#define CERR_FIELDS        13 /* incomplete netscape line */
#define CERR_PSL           14 /* a public suffix */
#define CERR_LIVE_WINS     15

/* The maximum length we accept a date string for the 'expire' keyword. The
   standard date formats are within the 30 bytes range. This adds an extra
   margin just to make sure it realistically works with what is used out
   there.
*/
#define MAX_DATE_LENGTH 80

static int
parse_cookie_header(struct Curl_easy *data,
                    struct Cookie *co,
                    struct CookieInfo *ci,
                    const char *ptr,
                    const char *domain, /* default domain */
                    const char *path,   /* full path used when this cookie is
                                           set, used to get default path for
                                           the cookie unless set */
                    bool secure)  /* TRUE if connection is over secure
                                     origin */
{
  /* This line was read off an HTTP-header */
  time_t now;
  size_t linelength = strlen(ptr);
  if(linelength > MAX_COOKIE_LINE)
    /* discard overly long lines at once */
    return CERR_TOO_LONG;

  now = time(NULL);
  do {
    size_t vlen;
    size_t nlen;

    while(*ptr && ISBLANK(*ptr))
      ptr++;

    /* we have a <name>=<value> pair or a stand-alone word here */
    nlen = strcspn(ptr, ";\t\r\n=");
    if(nlen) {
      bool done = FALSE;
      bool sep = FALSE;
      const char *namep = ptr;
      const char *valuep;

      ptr += nlen;

      /* trim trailing spaces and tabs after name */
      while(nlen && ISBLANK(namep[nlen - 1]))
        nlen--;

      if(*ptr == '=') {
        vlen = strcspn(++ptr, ";\r\n");
        valuep = ptr;
        sep = TRUE;
        ptr = &valuep[vlen];

        /* Strip off trailing whitespace from the value */
        while(vlen && ISBLANK(valuep[vlen-1]))
          vlen--;

        /* Skip leading whitespace from the value */
        while(vlen && ISBLANK(*valuep)) {
          valuep++;
          vlen--;
        }

        /* Reject cookies with a TAB inside the value */
        if(memchr(valuep, '\t', vlen)) {
          infof(data, "cookie contains TAB, dropping");
          return CERR_TAB;
        }
      }
      else {
        valuep = NULL;
        vlen = 0;
      }

      /*
       * Check for too long individual name or contents, or too long
       * combination of name + contents. Chrome and Firefox support 4095 or
       * 4096 bytes combo
       */
      if(nlen >= (MAX_NAME-1) || vlen >= (MAX_NAME-1) ||
         ((nlen + vlen) > MAX_NAME)) {
        infof(data, "oversized cookie dropped, name/val %zu + %zu bytes",
              nlen, vlen);
        return CERR_TOO_BIG;
      }

      /*
       * Check if we have a reserved prefix set before anything else, as we
       * otherwise have to test for the prefix in both the cookie name and
       * "the rest". Prefixes must start with '__' and end with a '-', so
       * only test for names where that can possibly be true.
       */
      if(nlen >= 7 && namep[0] == '_' && namep[1] == '_') {
        if(strncasecompare("__Secure-", namep, 9))
          co->prefix_secure = TRUE;
        else if(strncasecompare("__Host-", namep, 7))
          co->prefix_host = TRUE;
      }

      /*
       * Use strstore() below to properly deal with received cookie
       * headers that have the same string property set more than once,
       * and then we use the last one.
       */

      if(!co->name) {
        /* The very first name/value pair is the actual cookie name */
        if(!sep)
          /* Bad name/value pair. */
          return CERR_NO_SEP;

        strstore(&co->name, namep, nlen);
        strstore(&co->value, valuep, vlen);
        done = TRUE;
        if(!co->name || !co->value)
          return CERR_NO_NAME_VALUE;

        if(invalid_octets(co->value) || invalid_octets(co->name)) {
          infof(data, "invalid octets in name/value, cookie dropped");
          return CERR_INVALID_OCTET;
        }
      }
      else if(!vlen) {
        /*
         * this was a "<name>=" with no content, and we must allow
         * 'secure' and 'httponly' specified this weirdly
         */
        done = TRUE;
        /*
         * secure cookies are only allowed to be set when the connection is
         * using a secure protocol, or when the cookie is being set by
         * reading from file
         */
        if((nlen == 6) && strncasecompare("secure", namep, 6)) {
          if(secure || !ci->running) {
            co->secure = TRUE;
          }
          else {
            return CERR_BAD_SECURE;
          }
        }
        else if((nlen == 8) && strncasecompare("httponly", namep, 8))
          co->httponly = TRUE;
        else if(sep)
          /* there was a '=' so we are not done parsing this field */
          done = FALSE;
      }
      if(done)
        ;
      else if((nlen == 4) && strncasecompare("path", namep, 4)) {
        strstore(&co->path, valuep, vlen);
        if(!co->path)
          return CERR_OUT_OF_MEMORY;
        free(co->spath); /* if this is set again */
        co->spath = sanitize_cookie_path(co->path);
        if(!co->spath)
          return CERR_OUT_OF_MEMORY;
      }
      else if((nlen == 6) &&
              strncasecompare("domain", namep, 6) && vlen) {
        bool is_ip;

        /*
         * Now, we make sure that our host is within the given domain, or
         * the given domain is not valid and thus cannot be set.
         */

        if('.' == valuep[0]) {
          valuep++; /* ignore preceding dot */
          vlen--;
        }

#ifndef USE_LIBPSL
        /*
         * Without PSL we do not know when the incoming cookie is set on a
         * TLD or otherwise "protected" suffix. To reduce risk, we require a
         * dot OR the exact hostname being "localhost".
         */
        if(bad_domain(valuep, vlen))
          domain = ":";
#endif

        is_ip = Curl_host_is_ipnum(domain ? domain : valuep);

        if(!domain
           || (is_ip && !strncmp(valuep, domain, vlen) &&
               (vlen == strlen(domain)))
           || (!is_ip && cookie_tailmatch(valuep, vlen, domain))) {
          strstore(&co->domain, valuep, vlen);
          if(!co->domain)
            return CERR_OUT_OF_MEMORY;

          if(!is_ip)
            co->tailmatch = TRUE; /* we always do that if the domain name was
                                     given */
        }
        else {
          /*
           * We did not get a tailmatch and then the attempted set domain is
           * not a domain to which the current host belongs. Mark as bad.
           */
          infof(data, "skipped cookie with bad tailmatch domain: %s",
                valuep);
          return CERR_NO_TAILMATCH;
        }
      }
      else if((nlen == 7) && strncasecompare("version", namep, 7)) {
        /* just ignore */
      }
      else if((nlen == 7) && strncasecompare("max-age", namep, 7)) {
        /*
         * Defined in RFC2109:
         *
         * Optional. The Max-Age attribute defines the lifetime of the
         * cookie, in seconds. The delta-seconds value is a decimal non-
         * negative integer. After delta-seconds seconds elapse, the
         * client should discard the cookie. A value of zero means the
         * cookie should be discarded immediately.
         */
        CURLofft offt;
        const char *maxage = valuep;
        offt = curlx_strtoofft((*maxage == '\"') ?
                               &maxage[1] : &maxage[0], NULL, 10,
                               &co->expires);
        switch(offt) {
        case CURL_OFFT_FLOW:
          /* overflow, used max value */
          co->expires = CURL_OFF_T_MAX;
          break;
        case CURL_OFFT_INVAL:
          /* negative or otherwise bad, expire */
          co->expires = 1;
          break;
        case CURL_OFFT_OK:
          if(!co->expires)
            /* already expired */
            co->expires = 1;
          else if(CURL_OFF_T_MAX - now < co->expires)
            /* would overflow */
            co->expires = CURL_OFF_T_MAX;
          else
            co->expires += now;
          break;
        }
        cap_expires(now, co);
      }
      else if((nlen == 7) && strncasecompare("expires", namep, 7)) {
        if(!co->expires && (vlen < MAX_DATE_LENGTH)) {
          /*
           * Let max-age have priority.
           *
           * If the date cannot get parsed for whatever reason, the cookie
           * will be treated as a session cookie
           */
          char dbuf[MAX_DATE_LENGTH + 1];
          memcpy(dbuf, valuep, vlen);
          dbuf[vlen] = 0;
          co->expires = Curl_getdate_capped(dbuf);

          /*
           * Session cookies have expires set to 0 so if we get that back
           * from the date parser let's add a second to make it a
           * non-session cookie
           */
          if(co->expires == 0)
            co->expires = 1;
          else if(co->expires < 0)
            co->expires = 0;
          cap_expires(now, co);
        }
      }

      /*
       * Else, this is the second (or more) name we do not know about!
       */
    }
    else {
      /* this is an "illegal" <what>=<this> pair */
    }

    while(*ptr && ISBLANK(*ptr))
      ptr++;
    if(*ptr == ';')
      ptr++;
    else
      break;
  } while(1);

  if(!co->domain && domain) {
    /* no domain was given in the header line, set the default */
    co->domain = strdup(domain);
    if(!co->domain)
      return CERR_OUT_OF_MEMORY;
  }

  if(!co->path && path) {
    /*
     * No path was given in the header line, set the default. Note that the
     * passed-in path to this function MAY have a '?' and following part that
     * MUST NOT be stored as part of the path.
     */
    char *queryp = strchr(path, '?');

    /*
     * queryp is where the interesting part of the path ends, so now we
     * want to the find the last
     */
    char *endslash;
    if(!queryp)
      endslash = strrchr(path, '/');
    else
      endslash = memrchr(path, '/', (queryp - path));
    if(endslash) {
      size_t pathlen = (endslash-path + 1); /* include end slash */
      co->path = Curl_memdup0(path, pathlen);
      if(co->path) {
        co->spath = sanitize_cookie_path(co->path);
        if(!co->spath)
          return CERR_OUT_OF_MEMORY;
      }
      else
        return CERR_OUT_OF_MEMORY;
    }
  }

  /*
   * If we did not get a cookie name, or a bad one, the this is an illegal
   * line so bail out.
   */
  if(!co->name)
    return CERR_BAD;

  data->req.setcookies++;
  return CERR_OK;
}

static int
parse_netscape(struct Cookie *co,
               struct CookieInfo *ci,
               const char *lineptr,
               bool secure)  /* TRUE if connection is over secure
                                origin */
{
  /*
   * This line is NOT an HTTP header style line, we do offer support for
   * reading the odd netscape cookies-file format here
   */
  const char *ptr, *next;
  int fields;
  size_t len;

  /*
   * In 2008, Internet Explorer introduced HTTP-only cookies to prevent XSS
   * attacks. Cookies marked httpOnly are not accessible to JavaScript. In
   * Firefox's cookie files, they are prefixed #HttpOnly_ and the rest
   * remains as usual, so we skip 10 characters of the line.
   */
  if(strncmp(lineptr, "#HttpOnly_", 10) == 0) {
    lineptr += 10;
    co->httponly = TRUE;
  }

  if(lineptr[0]=='#')
    /* do not even try the comments */
    return CERR_COMMENT;

  /*
   * Now loop through the fields and init the struct we already have
   * allocated
   */
  fields = 0;
  for(next = lineptr; next; fields++) {
    ptr = next;
    len = strcspn(ptr, "\t\r\n");
    next = (ptr[len] == '\t' ? &ptr[len + 1] : NULL);
    switch(fields) {
    case 0:
      if(ptr[0]=='.') { /* skip preceding dots */
        ptr++;
        len--;
      }
      co->domain = Curl_memdup0(ptr, len);
      if(!co->domain)
        return CERR_OUT_OF_MEMORY;
      break;
    case 1:
      /*
       * flag: A TRUE/FALSE value indicating if all machines within a given
       * domain can access the variable. Set TRUE when the cookie says
       * .domain.com and to false when the domain is complete www.domain.com
       */
      co->tailmatch = !!strncasecompare(ptr, "TRUE", len);
      break;
    case 2:
      /* The file format allows the path field to remain not filled in */
      if(strncmp("TRUE", ptr, len) && strncmp("FALSE", ptr, len)) {
        /* only if the path does not look like a boolean option! */
        co->path = Curl_memdup0(ptr, len);
        if(!co->path)
          return CERR_OUT_OF_MEMORY;
        else {
          co->spath = sanitize_cookie_path(co->path);
          if(!co->spath)
            return CERR_OUT_OF_MEMORY;
        }
        break;
      }
      /* this does not look like a path, make one up! */
      co->path = strdup("/");
      if(!co->path)
        return CERR_OUT_OF_MEMORY;
      co->spath = strdup("/");
      if(!co->spath)
        return CERR_OUT_OF_MEMORY;
      fields++; /* add a field and fall down to secure */
      FALLTHROUGH();
    case 3:
      co->secure = FALSE;
      if(strncasecompare(ptr, "TRUE", len)) {
        if(secure || ci->running)
          co->secure = TRUE;
        else
          return CERR_BAD_SECURE;
      }
      break;
    case 4:
      {
        char *endp;
        const char *p;
        /* make sure curlx_strtoofft won't read past the current field */
        for(p = ptr; p < &ptr[len] && ISDIGIT(*p); ++p)
          ;
        if(p == ptr || p != &ptr[len] ||
           curlx_strtoofft(ptr, &endp, 10, &co->expires) || endp != &ptr[len])
          return CERR_RANGE;
      }
      break;
    case 5:
      co->name = Curl_memdup0(ptr, len);
      if(!co->name)
        return CERR_OUT_OF_MEMORY;
      else {
        /* For Netscape file format cookies we check prefix on the name */
        if(strncasecompare("__Secure-", co->name, 9))
          co->prefix_secure = TRUE;
        else if(strncasecompare("__Host-", co->name, 7))
          co->prefix_host = TRUE;
      }
      break;
    case 6:
      co->value = Curl_memdup0(ptr, len);
      if(!co->value)
        return CERR_OUT_OF_MEMORY;
      break;
    }
  }
  if(6 == fields) {
    /* we got a cookie with blank contents, fix it */
    co->value = strdup("");
    if(!co->value)
      return CERR_OUT_OF_MEMORY;
    else
      fields++;
  }

  if(7 != fields)
    /* we did not find the sufficient number of fields */
    return CERR_FIELDS;

  return CERR_OK;
}

static int
is_public_suffix(struct Curl_easy *data,
                 struct Cookie *co,
                 const char *domain)
{
#ifdef USE_LIBPSL
  /*
   * Check if the domain is a Public Suffix and if yes, ignore the cookie. We
   * must also check that the data handle is not NULL since the psl code will
   * dereference it.
   */
  DEBUGF(infof(data, "PSL check set-cookie '%s' for domain=%s in %s",
         co->name, co->domain, domain));
  if(data && (domain && co->domain && !Curl_host_is_ipnum(co->domain))) {
    bool acceptable = FALSE;
    char lcase[256];
    char lcookie[256];
    size_t dlen = strlen(domain);
    size_t clen = strlen(co->domain);
    if((dlen < sizeof(lcase)) && (clen < sizeof(lcookie))) {
      const psl_ctx_t *psl = Curl_psl_use(data);
      if(psl) {
        /* the PSL check requires lowercase domain name and pattern */
        Curl_strntolower(lcase, domain, dlen + 1);
        Curl_strntolower(lcookie, co->domain, clen + 1);
        acceptable = psl_is_cookie_domain_acceptable(psl, lcase, lcookie);
        Curl_psl_release(data);
      }
      else
        infof(data, "libpsl problem, rejecting cookie for satety");
    }

    if(!acceptable) {
      infof(data, "cookie '%s' dropped, domain '%s' must not "
            "set cookies for '%s'", co->name, domain, co->domain);
      return CERR_PSL;
    }
  }
#else
  (void)data;
  (void)co;
  (void)domain;
  DEBUGF(infof(data, "NO PSL to check set-cookie '%s' for domain=%s in %s",
         co->name, co->domain, domain));
#endif
  return CERR_OK;
}

static int
replace_existing(struct Curl_easy *data,
                 struct Cookie *co,
                 struct CookieInfo *ci,
                 bool secure,
                 bool *replacep)
{
  bool replace_old = FALSE;
  struct Curl_llist_node *replace_n = NULL;
  struct Curl_llist_node *n;
  size_t myhash = cookiehash(co->domain);
  for(n = Curl_llist_head(&ci->cookielist[myhash]); n; n = Curl_node_next(n)) {
    struct Cookie *clist = Curl_node_elem(n);
    if(!strcmp(clist->name, co->name)) {
      /* the names are identical */
      bool matching_domains = FALSE;

      if(clist->domain && co->domain) {
        if(strcasecompare(clist->domain, co->domain))
          /* The domains are identical */
          matching_domains = TRUE;
      }
      else if(!clist->domain && !co->domain)
        matching_domains = TRUE;

      if(matching_domains && /* the domains were identical */
         clist->spath && co->spath && /* both have paths */
         clist->secure && !co->secure && !secure) {
        size_t cllen;
        const char *sep;

        /*
         * A non-secure cookie may not overlay an existing secure cookie.
         * For an existing cookie "a" with path "/login", refuse a new
         * cookie "a" with for example path "/login/en", while the path
         * "/loginhelper" is ok.
         */

        sep = strchr(clist->spath + 1, '/');

        if(sep)
          cllen = sep - clist->spath;
        else
          cllen = strlen(clist->spath);

        if(strncasecompare(clist->spath, co->spath, cllen)) {
          infof(data, "cookie '%s' for domain '%s' dropped, would "
                "overlay an existing cookie", co->name, co->domain);
          return CERR_BAD_SECURE;
        }
      }
    }

    if(!replace_n && !strcmp(clist->name, co->name)) {
      /* the names are identical */

      if(clist->domain && co->domain) {
        if(strcasecompare(clist->domain, co->domain) &&
          (clist->tailmatch == co->tailmatch))
          /* The domains are identical */
          replace_old = TRUE;
      }
      else if(!clist->domain && !co->domain)
        replace_old = TRUE;

      if(replace_old) {
        /* the domains were identical */

        if(clist->spath && co->spath &&
           !strcasecompare(clist->spath, co->spath))
          replace_old = FALSE;
        else if(!clist->spath != !co->spath)
          replace_old = FALSE;
      }

      if(replace_old && !co->livecookie && clist->livecookie) {
        /*
         * Both cookies matched fine, except that the already present cookie
         * is "live", which means it was set from a header, while the new one
         * was read from a file and thus is not "live". "live" cookies are
         * preferred so the new cookie is freed.
         */
        return CERR_LIVE_WINS;
      }
      if(replace_old)
        replace_n = n;
    }
  }
  if(replace_n) {
    struct Cookie *repl = Curl_node_elem(replace_n);

    /* when replacing, creationtime is kept from old */
    co->creationtime = repl->creationtime;

    /* unlink the old */
    Curl_node_remove(replace_n);

    /* free the old cookie */
    freecookie(repl);
  }
  *replacep = replace_old;
  return CERR_OK;
}

/*
 * Curl_cookie_add
 *
 * Add a single cookie line to the cookie keeping object. Be aware that
 * sometimes we get an IP-only hostname, and that might also be a numerical
 * IPv6 address.
 *
 * Returns NULL on out of memory or invalid cookie. This is suboptimal,
 * as they should be treated separately.
 */
struct Cookie *
Curl_cookie_add(struct Curl_easy *data,
                struct CookieInfo *ci,
                bool httpheader, /* TRUE if HTTP header-style line */
                bool noexpire, /* if TRUE, skip remove_expired() */
                const char *lineptr,   /* first character of the line */
                const char *domain, /* default domain */
                const char *path,   /* full path used when this cookie is set,
                                       used to get default path for the cookie
                                       unless set */
                bool secure)  /* TRUE if connection is over secure origin */
{
  struct Cookie *co;
  size_t myhash;
  int rc;
  bool replaces = FALSE;

  DEBUGASSERT(data);
  DEBUGASSERT(MAX_SET_COOKIE_AMOUNT <= 255); /* counter is an unsigned char */
  if(data->req.setcookies >= MAX_SET_COOKIE_AMOUNT)
    return NULL;

  /* First, alloc and init a new struct for it */
  co = calloc(1, sizeof(struct Cookie));
  if(!co)
    return NULL; /* bail out if we are this low on memory */

  if(httpheader)
    rc = parse_cookie_header(data, co, ci, lineptr, domain, path, secure);
  else
    rc = parse_netscape(co, ci, lineptr, secure);

  if(rc)
    goto fail;

  if(co->prefix_secure && !co->secure)
    /* The __Secure- prefix only requires that the cookie be set secure */
    goto fail;

  if(co->prefix_host) {
    /*
     * The __Host- prefix requires the cookie to be secure, have a "/" path
     * and not have a domain set.
     */
    if(co->secure && co->path && strcmp(co->path, "/") == 0 && !co->tailmatch)
      ;
    else
      goto fail;
  }

  if(!ci->running &&    /* read from a file */
     ci->newsession &&  /* clean session cookies */
     !co->expires)      /* this is a session cookie since it does not expire */
    goto fail;

  co->livecookie = ci->running;
  co->creationtime = ++ci->lastct;

  /*
   * Now we have parsed the incoming line, we must now check if this supersedes
   * an already existing cookie, which it may if the previous have the same
   * domain and path as this.
   */

  /* remove expired cookies */
  if(!noexpire)
    remove_expired(ci);

  if(is_public_suffix(data, co, domain))
    goto fail;

  if(replace_existing(data, co, ci, secure, &replaces))
    goto fail;

  /* add this cookie to the list */
  myhash = cookiehash(co->domain);
  Curl_llist_append(&ci->cookielist[myhash], co, &co->node);

  if(ci->running)
    /* Only show this when NOT reading the cookies from a file */
    infof(data, "%s cookie %s=\"%s\" for domain %s, path %s, "
          "expire %" FMT_OFF_T,
          replaces ? "Replaced":"Added", co->name, co->value,
          co->domain, co->path, co->expires);

  if(!replaces)
    ci->numcookies++; /* one more cookie in the jar */

  /*
   * Now that we have added a new cookie to the jar, update the expiration
   * tracker in case it is the next one to expire.
   */
  if(co->expires && (co->expires < ci->next_expiration))
    ci->next_expiration = co->expires;

  return co;
fail:
  freecookie(co);
  return NULL;
}


/*
 * Curl_cookie_init()
 *
 * Inits a cookie struct to read data from a local file. This is always
 * called before any cookies are set. File may be NULL in which case only the
 * struct is initialized. Is file is "-" then STDIN is read.
 *
 * If 'newsession' is TRUE, discard all "session cookies" on read from file.
 *
 * Note that 'data' might be called as NULL pointer. If data is NULL, 'file'
 * will be ignored.
 *
 * Returns NULL on out of memory. Invalid cookies are ignored.
 */
struct CookieInfo *Curl_cookie_init(struct Curl_easy *data,
                                    const char *file,
                                    struct CookieInfo *ci,
                                    bool newsession)
{
  FILE *handle = NULL;

  if(!ci) {
    int i;

    /* we did not get a struct, create one */
    ci = calloc(1, sizeof(struct CookieInfo));
    if(!ci)
      return NULL; /* failed to get memory */

    /* This does not use the destructor callback since we want to add
       and remove to lists while keeping the cookie struct intact */
    for(i = 0; i < COOKIE_HASH_SIZE; i++)
      Curl_llist_init(&ci->cookielist[i], NULL);
    /*
     * Initialize the next_expiration time to signal that we do not have enough
     * information yet.
     */
    ci->next_expiration = CURL_OFF_T_MAX;
  }
  ci->newsession = newsession; /* new session? */

  if(data) {
    FILE *fp = NULL;
    if(file && *file) {
      if(!strcmp(file, "-"))
        fp = stdin;
      else {
        fp = fopen(file, "rb");
        if(!fp)
          infof(data, "WARNING: failed to open cookie file \"%s\"", file);
        else
          handle = fp;
      }
    }

    ci->running = FALSE; /* this is not running, this is init */
    if(fp) {
      struct dynbuf buf;
      Curl_dyn_init(&buf, MAX_COOKIE_LINE);
      while(Curl_get_line(&buf, fp)) {
        char *lineptr = Curl_dyn_ptr(&buf);
        bool headerline = FALSE;
        if(checkprefix("Set-Cookie:", lineptr)) {
          /* This is a cookie line, get it! */
          lineptr += 11;
          headerline = TRUE;
          while(*lineptr && ISBLANK(*lineptr))
            lineptr++;
        }

        Curl_cookie_add(data, ci, headerline, TRUE, lineptr, NULL, NULL, TRUE);
      }
      Curl_dyn_free(&buf); /* free the line buffer */

      /*
       * Remove expired cookies from the hash. We must make sure to run this
       * after reading the file, and not on every cookie.
       */
      remove_expired(ci);

      if(handle)
        fclose(handle);
    }
    data->state.cookie_engine = TRUE;
  }
  ci->running = TRUE;          /* now, we are running */

  return ci;
}

/*
 * cookie_sort
 *
 * Helper function to sort cookies such that the longest path gets before the
 * shorter path. Path, domain and name lengths are considered in that order,
 * with the creationtime as the tiebreaker. The creationtime is guaranteed to
 * be unique per cookie, so we know we will get an ordering at that point.
 */
static int cookie_sort(const void *p1, const void *p2)
{
  struct Cookie *c1 = *(struct Cookie **)p1;
  struct Cookie *c2 = *(struct Cookie **)p2;
  size_t l1, l2;

  /* 1 - compare cookie path lengths */
  l1 = c1->path ? strlen(c1->path) : 0;
  l2 = c2->path ? strlen(c2->path) : 0;

  if(l1 != l2)
    return (l2 > l1) ? 1 : -1; /* avoid size_t <=> int conversions */

  /* 2 - compare cookie domain lengths */
  l1 = c1->domain ? strlen(c1->domain) : 0;
  l2 = c2->domain ? strlen(c2->domain) : 0;

  if(l1 != l2)
    return (l2 > l1) ? 1 : -1; /* avoid size_t <=> int conversions */

  /* 3 - compare cookie name lengths */
  l1 = c1->name ? strlen(c1->name) : 0;
  l2 = c2->name ? strlen(c2->name) : 0;

  if(l1 != l2)
    return (l2 > l1) ? 1 : -1;

  /* 4 - compare cookie creation time */
  return (c2->creationtime > c1->creationtime) ? 1 : -1;
}

/*
 * cookie_sort_ct
 *
 * Helper function to sort cookies according to creation time.
 */
static int cookie_sort_ct(const void *p1, const void *p2)
{
  struct Cookie *c1 = *(struct Cookie **)p1;
  struct Cookie *c2 = *(struct Cookie **)p2;

  return (c2->creationtime > c1->creationtime) ? 1 : -1;
}

/*
 * Curl_cookie_getlist
 *
 * For a given host and path, return a linked list of cookies that the client
 * should send to the server if used now. The secure boolean informs the cookie
 * if a secure connection is achieved or not.
 *
 * It shall only return cookies that have not expired.
 *
 * Returns 0 when there is a list returned. Otherwise non-zero.
 */
int Curl_cookie_getlist(struct Curl_easy *data,
                        struct CookieInfo *ci,
                        const char *host, const char *path,
                        bool secure,
                        struct Curl_llist *list)
{
  size_t matches = 0;
  bool is_ip;
  const size_t myhash = cookiehash(host);
  struct Curl_llist_node *n;

  Curl_llist_init(list, NULL);

  if(!ci || !Curl_llist_count(&ci->cookielist[myhash]))
    return 1; /* no cookie struct or no cookies in the struct */

  /* at first, remove expired cookies */
  remove_expired(ci);

  /* check if host is an IP(v4|v6) address */
  is_ip = Curl_host_is_ipnum(host);

  for(n = Curl_llist_head(&ci->cookielist[myhash]);
      n; n = Curl_node_next(n)) {
    struct Cookie *co = Curl_node_elem(n);

    /* if the cookie requires we are secure we must only continue if we are! */
    if(co->secure ? secure : TRUE) {

      /* now check if the domain is correct */
      if(!co->domain ||
         (co->tailmatch && !is_ip &&
          cookie_tailmatch(co->domain, strlen(co->domain), host)) ||
         ((!co->tailmatch || is_ip) && strcasecompare(host, co->domain)) ) {
        /*
         * the right part of the host matches the domain stuff in the
         * cookie data
         */

        /*
         * now check the left part of the path with the cookies path
         * requirement
         */
        if(!co->spath || pathmatch(co->spath, path) ) {

          /*
           * This is a match and we add it to the return-linked-list
           */
          Curl_llist_append(list, co, &co->getnode);
          matches++;
          if(matches >= MAX_COOKIE_SEND_AMOUNT) {
            infof(data, "Included max number of cookies (%zu) in request!",
                  matches);
            break;
          }
        }
      }
    }
  }

  if(matches) {
    /*
     * Now we need to make sure that if there is a name appearing more than
     * once, the longest specified path version comes first. To make this
     * the swiftest way, we just sort them all based on path length.
     */
    struct Cookie **array;
    size_t i;

    /* alloc an array and store all cookie pointers */
    array = malloc(sizeof(struct Cookie *) * matches);
    if(!array)
      goto fail;

    n = Curl_llist_head(list);

    for(i = 0; n; n = Curl_node_next(n))
      array[i++] = Curl_node_elem(n);

    /* now sort the cookie pointers in path length order */
    qsort(array, matches, sizeof(struct Cookie *), cookie_sort);

    /* remake the linked list order according to the new order */
    Curl_llist_destroy(list, NULL);

    for(i = 0; i < matches; i++)
      Curl_llist_append(list, array[i], &array[i]->getnode);

    free(array); /* remove the temporary data again */
  }

  return 0; /* success */

fail:
  /* failure, clear up the allocated chain and return NULL */
  Curl_llist_destroy(list, NULL);
  return 2; /* error */
}

/*
 * Curl_cookie_clearall
 *
 * Clear all existing cookies and reset the counter.
 */
void Curl_cookie_clearall(struct CookieInfo *ci)
{
  if(ci) {
    unsigned int i;
    for(i = 0; i < COOKIE_HASH_SIZE; i++) {
      struct Curl_llist_node *n;
      for(n = Curl_llist_head(&ci->cookielist[i]); n;) {
        struct Cookie *c = Curl_node_elem(n);
        struct Curl_llist_node *e = Curl_node_next(n);
        Curl_node_remove(n);
        freecookie(c);
        n = e;
      }
    }
    ci->numcookies = 0;
  }
}

/*
 * Curl_cookie_clearsess
 *
 * Free all session cookies in the cookies list.
 */
void Curl_cookie_clearsess(struct CookieInfo *ci)
{
  unsigned int i;

  if(!ci)
    return;

  for(i = 0; i < COOKIE_HASH_SIZE; i++) {
    struct Curl_llist_node *n = Curl_llist_head(&ci->cookielist[i]);
    struct Curl_llist_node *e = NULL;

    for(; n; n = e) {
      struct Cookie *curr = Curl_node_elem(n);
      e = Curl_node_next(n); /* in case the node is removed, get it early */
      if(!curr->expires) {
        Curl_node_remove(n);
        freecookie(curr);
        ci->numcookies--;
      }
    }
  }
}

/*
 * Curl_cookie_cleanup()
 *
 * Free a "cookie object" previous created with Curl_cookie_init().
 */
void Curl_cookie_cleanup(struct CookieInfo *ci)
{
  if(ci) {
    Curl_cookie_clearall(ci);
    free(ci); /* free the base struct as well */
  }
}

/*
 * get_netscape_format()
 *
 * Formats a string for Netscape output file, w/o a newline at the end.
 * Function returns a char * to a formatted line. The caller is responsible
 * for freeing the returned pointer.
 */
static char *get_netscape_format(const struct Cookie *co)
{
  return aprintf(
    "%s"     /* httponly preamble */
    "%s%s\t" /* domain */
    "%s\t"   /* tailmatch */
    "%s\t"   /* path */
    "%s\t"   /* secure */
    "%" FMT_OFF_T "\t"   /* expires */
    "%s\t"   /* name */
    "%s",    /* value */
    co->httponly ? "#HttpOnly_" : "",
    /*
     * Make sure all domains are prefixed with a dot if they allow
     * tailmatching. This is Mozilla-style.
     */
    (co->tailmatch && co->domain && co->domain[0] != '.') ? "." : "",
    co->domain ? co->domain : "unknown",
    co->tailmatch ? "TRUE" : "FALSE",
    co->path ? co->path : "/",
    co->secure ? "TRUE" : "FALSE",
    co->expires,
    co->name,
    co->value ? co->value : "");
}

/*
 * cookie_output()
 *
 * Writes all internally known cookies to the specified file. Specify
 * "-" as filename to write to stdout.
 *
 * The function returns non-zero on write failure.
 */
static CURLcode cookie_output(struct Curl_easy *data,
                              struct CookieInfo *ci,
                              const char *filename)
{
  FILE *out = NULL;
  bool use_stdout = FALSE;
  char *tempstore = NULL;
  CURLcode error = CURLE_OK;

  if(!ci)
    /* no cookie engine alive */
    return CURLE_OK;

  /* at first, remove expired cookies */
  remove_expired(ci);

  if(!strcmp("-", filename)) {
    /* use stdout */
    out = stdout;
    use_stdout = TRUE;
  }
  else {
    error = Curl_fopen(data, filename, &out, &tempstore);
    if(error)
      goto error;
  }

  fputs("# Netscape HTTP Cookie File\n"
        "# https://curl.se/docs/http-cookies.html\n"
        "# This file was generated by libcurl! Edit at your own risk.\n\n",
        out);

  if(ci->numcookies) {
    unsigned int i;
    size_t nvalid = 0;
    struct Cookie **array;
    struct Curl_llist_node *n;

    array = calloc(1, sizeof(struct Cookie *) * ci->numcookies);
    if(!array) {
      error = CURLE_OUT_OF_MEMORY;
      goto error;
    }

    /* only sort the cookies with a domain property */
    for(i = 0; i < COOKIE_HASH_SIZE; i++) {
      for(n = Curl_llist_head(&ci->cookielist[i]); n;
          n = Curl_node_next(n)) {
        struct Cookie *co = Curl_node_elem(n);
        if(!co->domain)
          continue;
        array[nvalid++] = co;
      }
    }

    qsort(array, nvalid, sizeof(struct Cookie *), cookie_sort_ct);

    for(i = 0; i < nvalid; i++) {
      char *format_ptr = get_netscape_format(array[i]);
      if(!format_ptr) {
        free(array);
        error = CURLE_OUT_OF_MEMORY;
        goto error;
      }
      fprintf(out, "%s\n", format_ptr);
      free(format_ptr);
    }

    free(array);
  }

  if(!use_stdout) {
    fclose(out);
    out = NULL;
    if(tempstore && Curl_rename(tempstore, filename)) {
      unlink(tempstore);
      error = CURLE_WRITE_ERROR;
      goto error;
    }
  }

  /*
   * If we reach here we have successfully written a cookie file so there is
   * no need to inspect the error, any error case should have jumped into the
   * error block below.
   */
  free(tempstore);
  return CURLE_OK;

error:
  if(out && !use_stdout)
    fclose(out);
  free(tempstore);
  return error;
}

static struct curl_slist *cookie_list(struct Curl_easy *data)
{
  struct curl_slist *list = NULL;
  struct curl_slist *beg;
  unsigned int i;
  struct Curl_llist_node *n;

  if(!data->cookies || (data->cookies->numcookies == 0))
    return NULL;

  for(i = 0; i < COOKIE_HASH_SIZE; i++) {
    for(n = Curl_llist_head(&data->cookies->cookielist[i]); n;
        n = Curl_node_next(n)) {
      struct Cookie *c = Curl_node_elem(n);
      char *line;
      if(!c->domain)
        continue;
      line = get_netscape_format(c);
      if(!line) {
        curl_slist_free_all(list);
        return NULL;
      }
      beg = Curl_slist_append_nodup(list, line);
      if(!beg) {
        free(line);
        curl_slist_free_all(list);
        return NULL;
      }
      list = beg;
    }
  }

  return list;
}

struct curl_slist *Curl_cookie_list(struct Curl_easy *data)
{
  struct curl_slist *list;
  Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
  list = cookie_list(data);
  Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  return list;
}

void Curl_flush_cookies(struct Curl_easy *data, bool cleanup)
{
  CURLcode res;

  if(data->set.str[STRING_COOKIEJAR]) {
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);

    /* if we have a destination file for all the cookies to get dumped to */
    res = cookie_output(data, data->cookies, data->set.str[STRING_COOKIEJAR]);
    if(res)
      infof(data, "WARNING: failed to save cookies in %s: %s",
            data->set.str[STRING_COOKIEJAR], curl_easy_strerror(res));
  }
  else {
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
  }

  if(cleanup && (!data->share || (data->cookies != data->share->cookies))) {
    Curl_cookie_cleanup(data->cookies);
    data->cookies = NULL;
  }
  Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
}

#endif /* CURL_DISABLE_HTTP || CURL_DISABLE_COOKIES */
