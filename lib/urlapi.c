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

#include "curl_setup.h"

#include "urldata.h"
#include "urlapi-int.h"
#include "strcase.h"
#include "url.h"
#include "escape.h"
#include "curl_ctype.h"
#include "inet_pton.h"
#include "inet_ntop.h"
#include "strdup.h"
#include "idn.h"
#include "curl_memrchr.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

  /* MSDOS/Windows style drive prefix, eg c: in c:foo */
#define STARTS_WITH_DRIVE_PREFIX(str) \
  ((('a' <= str[0] && str[0] <= 'z') || \
    ('A' <= str[0] && str[0] <= 'Z')) && \
   (str[1] == ':'))

  /* MSDOS/Windows style drive prefix, optionally with
   * a '|' instead of ':', followed by a slash or NUL */
#define STARTS_WITH_URL_DRIVE_PREFIX(str) \
  ((('a' <= (str)[0] && (str)[0] <= 'z') || \
    ('A' <= (str)[0] && (str)[0] <= 'Z')) && \
   ((str)[1] == ':' || (str)[1] == '|') && \
   ((str)[2] == '/' || (str)[2] == '\\' || (str)[2] == 0))

/* scheme is not URL encoded, the longest libcurl supported ones are... */
#define MAX_SCHEME_LEN 40

/*
 * If USE_IPV6 is disabled, we still want to parse IPv6 addresses, so make
 * sure we have _some_ value for AF_INET6 without polluting our fake value
 * everywhere.
 */
#if !defined(USE_IPV6) && !defined(AF_INET6)
#define AF_INET6 (AF_INET + 1)
#endif

/* Internal representation of CURLU. Point to URL-encoded strings. */
struct Curl_URL {
  char *scheme;
  char *user;
  char *password;
  char *options; /* IMAP only? */
  char *host;
  char *zoneid; /* for numerical IPv6 addresses */
  char *port;
  char *path;
  char *query;
  char *fragment;
  unsigned short portnum; /* the numerical version (if 'port' is set) */
  BIT(query_present);    /* to support blank */
  BIT(fragment_present); /* to support blank */
  BIT(guessed_scheme);   /* when a URL without scheme is parsed */
};

#define DEFAULT_SCHEME "https"

static void free_urlhandle(struct Curl_URL *u)
{
  free(u->scheme);
  free(u->user);
  free(u->password);
  free(u->options);
  free(u->host);
  free(u->zoneid);
  free(u->port);
  free(u->path);
  free(u->query);
  free(u->fragment);
}

/*
 * Find the separator at the end of the hostname, or the '?' in cases like
 * http://www.example.com?id=2380
 */
static const char *find_host_sep(const char *url)
{
  const char *sep;
  const char *query;

  /* Find the start of the hostname */
  sep = strstr(url, "//");
  if(!sep)
    sep = url;
  else
    sep += 2;

  query = strchr(sep, '?');
  sep = strchr(sep, '/');

  if(!sep)
    sep = url + strlen(url);

  if(!query)
    query = url + strlen(url);

  return sep < query ? sep : query;
}

/* convert CURLcode to CURLUcode */
#define cc2cu(x) ((x) == CURLE_TOO_LARGE ? CURLUE_TOO_LARGE :   \
                  CURLUE_OUT_OF_MEMORY)
/*
 * Decide whether a character in a URL must be escaped.
 */
#define urlchar_needs_escaping(c) (!(ISCNTRL(c) || ISSPACE(c) || ISGRAPH(c)))

static const char hexdigits[] = "0123456789abcdef";
/* urlencode_str() writes data into an output dynbuf and URL-encodes the
 * spaces in the source URL accordingly.
 *
 * URL encoding should be skipped for hostnames, otherwise IDN resolution
 * will fail.
 */
static CURLUcode urlencode_str(struct dynbuf *o, const char *url,
                               size_t len, bool relative,
                               bool query)
{
  /* we must add this with whitespace-replacing */
  bool left = !query;
  const unsigned char *iptr;
  const unsigned char *host_sep = (const unsigned char *) url;
  CURLcode result;

  if(!relative)
    host_sep = (const unsigned char *) find_host_sep(url);

  for(iptr = (unsigned char *)url;    /* read from here */
      len; iptr++, len--) {

    if(iptr < host_sep) {
      result = Curl_dyn_addn(o, iptr, 1);
      if(result)
        return cc2cu(result);
      continue;
    }

    if(*iptr == ' ') {
      if(left)
        result = Curl_dyn_addn(o, "%20", 3);
      else
        result = Curl_dyn_addn(o, "+", 1);
      if(result)
        return cc2cu(result);
      continue;
    }

    if(*iptr == '?')
      left = FALSE;

    if(urlchar_needs_escaping(*iptr)) {
      char out[3]={'%'};
      out[1] = hexdigits[*iptr>>4];
      out[2] = hexdigits[*iptr & 0xf];
      result = Curl_dyn_addn(o, out, 3);
    }
    else
      result = Curl_dyn_addn(o, iptr, 1);
    if(result)
      return cc2cu(result);
  }

  return CURLUE_OK;
}

/*
 * Returns the length of the scheme if the given URL is absolute (as opposed
 * to relative). Stores the scheme in the buffer if TRUE and 'buf' is
 * non-NULL. The buflen must be larger than MAX_SCHEME_LEN if buf is set.
 *
 * If 'guess_scheme' is TRUE, it means the URL might be provided without
 * scheme.
 */
size_t Curl_is_absolute_url(const char *url, char *buf, size_t buflen,
                            bool guess_scheme)
{
  size_t i = 0;
  DEBUGASSERT(!buf || (buflen > MAX_SCHEME_LEN));
  (void)buflen; /* only used in debug-builds */
  if(buf)
    buf[0] = 0; /* always leave a defined value in buf */
#ifdef _WIN32
  if(guess_scheme && STARTS_WITH_DRIVE_PREFIX(url))
    return 0;
#endif
  if(ISALPHA(url[0]))
    for(i = 1; i < MAX_SCHEME_LEN; ++i) {
      char s = url[i];
      if(s && (ISALNUM(s) || (s == '+') || (s == '-') || (s == '.') )) {
        /* RFC 3986 3.1 explains:
           scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        */
      }
      else {
        break;
      }
    }
  if(i && (url[i] == ':') && ((url[i + 1] == '/') || !guess_scheme)) {
    /* If this does not guess scheme, the scheme always ends with the colon so
       that this also detects data: URLs etc. In guessing mode, data: could
       be the hostname "data" with a specified port number. */

    /* the length of the scheme is the name part only */
    size_t len = i;
    if(buf) {
      Curl_strntolower(buf, url, i);
      buf[i] = 0;
    }
    return len;
  }
  return 0;
}

/*
 * Concatenate a relative URL to a base URL making it absolute.
 * URL-encodes any spaces.
 * The returned pointer must be freed by the caller unless NULL
 * (returns NULL on out of memory).
 *
 * Note that this function destroys the 'base' string.
 */
static CURLcode concat_url(char *base, const char *relurl, char **newurl)
{
  /***
   TRY to append this new path to the old URL
   to the right of the host part. Oh crap, this is doomed to cause
   problems in the future...
  */
  struct dynbuf newest;
  char *protsep;
  char *pathsep;
  bool host_changed = FALSE;
  const char *useurl = relurl;
  CURLcode result = CURLE_OK;
  CURLUcode uc;
  bool skip_slash = FALSE;
  *newurl = NULL;

  /* protsep points to the start of the hostname */
  protsep = strstr(base, "//");
  if(!protsep)
    protsep = base;
  else
    protsep += 2; /* pass the slashes */

  if('/' != relurl[0]) {
    int level = 0;

    /* First we need to find out if there is a ?-letter in the URL,
       and cut it and the right-side of that off */
    pathsep = strchr(protsep, '?');
    if(pathsep)
      *pathsep = 0;

    /* we have a relative path to append to the last slash if there is one
       available, or the new URL is just a query string (starts with a '?') or
       a fragment (starts with '#') we append the new one at the end of the
       current URL */
    if((useurl[0] != '?') && (useurl[0] != '#')) {
      pathsep = strrchr(protsep, '/');
      if(pathsep)
        *pathsep = 0;

      /* Check if there is any slash after the hostname, and if so, remember
         that position instead */
      pathsep = strchr(protsep, '/');
      if(pathsep)
        protsep = pathsep + 1;
      else
        protsep = NULL;

      /* now deal with one "./" or any amount of "../" in the newurl
         and act accordingly */

      if((useurl[0] == '.') && (useurl[1] == '/'))
        useurl += 2; /* just skip the "./" */

      while((useurl[0] == '.') &&
            (useurl[1] == '.') &&
            (useurl[2] == '/')) {
        level++;
        useurl += 3; /* pass the "../" */
      }

      if(protsep) {
        while(level--) {
          /* cut off one more level from the right of the original URL */
          pathsep = strrchr(protsep, '/');
          if(pathsep)
            *pathsep = 0;
          else {
            *protsep = 0;
            break;
          }
        }
      }
    }
    else
      skip_slash = TRUE;
  }
  else {
    /* We got a new absolute path for this server */

    if(relurl[1] == '/') {
      /* the new URL starts with //, just keep the protocol part from the
         original one */
      *protsep = 0;
      useurl = &relurl[2]; /* we keep the slashes from the original, so we
                              skip the new ones */
      host_changed = TRUE;
    }
    else {
      /* cut off the original URL from the first slash, or deal with URLs
         without slash */
      pathsep = strchr(protsep, '/');
      if(pathsep) {
        /* When people use badly formatted URLs, such as
           "http://www.example.com?dir=/home/daniel" we must not use the first
           slash, if there is a ?-letter before it! */
        char *sep = strchr(protsep, '?');
        if(sep && (sep < pathsep))
          pathsep = sep;
        *pathsep = 0;
      }
      else {
        /* There was no slash. Now, since we might be operating on a badly
           formatted URL, such as "http://www.example.com?id=2380" which does
           not use a slash separator as it is supposed to, we need to check
           for a ?-letter as well! */
        pathsep = strchr(protsep, '?');
        if(pathsep)
          *pathsep = 0;
      }
    }
  }

  Curl_dyn_init(&newest, CURL_MAX_INPUT_LENGTH);

  /* copy over the root URL part */
  result = Curl_dyn_add(&newest, base);
  if(result)
    return result;

  /* check if we need to append a slash */
  if(('/' == useurl[0]) || (protsep && !*protsep) || skip_slash)
    ;
  else {
    result = Curl_dyn_addn(&newest, "/", 1);
    if(result)
      return result;
  }

  /* then append the new piece on the right side */
  uc = urlencode_str(&newest, useurl, strlen(useurl), !host_changed,
                     FALSE);
  if(uc)
    return (uc == CURLUE_TOO_LARGE) ? CURLE_TOO_LARGE : CURLE_OUT_OF_MEMORY;

  *newurl = Curl_dyn_ptr(&newest);
  return CURLE_OK;
}

/* scan for byte values <= 31, 127 and sometimes space */
static CURLUcode junkscan(const char *url, size_t *urllen, unsigned int flags)
{
  static const char badbytes[]={
    /* */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x7f, 0x00 /* null-terminate */
  };
  size_t n = strlen(url);
  size_t nfine;

  if(n > CURL_MAX_INPUT_LENGTH)
    /* excessive input length */
    return CURLUE_MALFORMED_INPUT;

  nfine = strcspn(url, badbytes);
  if((nfine != n) ||
     (!(flags & CURLU_ALLOW_SPACE) && strchr(url, ' ')))
    return CURLUE_MALFORMED_INPUT;

  *urllen = n;
  return CURLUE_OK;
}

/*
 * parse_hostname_login()
 *
 * Parse the login details (username, password and options) from the URL and
 * strip them out of the hostname
 *
 */
static CURLUcode parse_hostname_login(struct Curl_URL *u,
                                      const char *login,
                                      size_t len,
                                      unsigned int flags,
                                      size_t *offset) /* to the hostname */
{
  CURLUcode result = CURLUE_OK;
  CURLcode ccode;
  char *userp = NULL;
  char *passwdp = NULL;
  char *optionsp = NULL;
  const struct Curl_handler *h = NULL;

  /* At this point, we assume all the other special cases have been taken
   * care of, so the host is at most
   *
   *   [user[:password][;options]]@]hostname
   *
   * We need somewhere to put the embedded details, so do that first.
   */
  char *ptr;

  DEBUGASSERT(login);

  *offset = 0;
  ptr = memchr(login, '@', len);
  if(!ptr)
    goto out;

  /* We will now try to extract the
   * possible login information in a string like:
   * ftp://user:password@ftp.my.site:8021/README */
  ptr++;

  /* if this is a known scheme, get some details */
  if(u->scheme)
    h = Curl_get_scheme_handler(u->scheme);

  /* We could use the login information in the URL so extract it. Only parse
     options if the handler says we should. Note that 'h' might be NULL! */
  ccode = Curl_parse_login_details(login, ptr - login - 1,
                                   &userp, &passwdp,
                                   (h && (h->flags & PROTOPT_URLOPTIONS)) ?
                                   &optionsp:NULL);
  if(ccode) {
    result = CURLUE_BAD_LOGIN;
    goto out;
  }

  if(userp) {
    if(flags & CURLU_DISALLOW_USER) {
      /* Option DISALLOW_USER is set and URL contains username. */
      result = CURLUE_USER_NOT_ALLOWED;
      goto out;
    }
    free(u->user);
    u->user = userp;
  }

  if(passwdp) {
    free(u->password);
    u->password = passwdp;
  }

  if(optionsp) {
    free(u->options);
    u->options = optionsp;
  }

  /* the hostname starts at this offset */
  *offset = ptr - login;
  return CURLUE_OK;

out:

  free(userp);
  free(passwdp);
  free(optionsp);
  u->user = NULL;
  u->password = NULL;
  u->options = NULL;

  return result;
}

UNITTEST CURLUcode Curl_parse_port(struct Curl_URL *u, struct dynbuf *host,
                                   bool has_scheme)
{
  char *portptr;
  char *hostname = Curl_dyn_ptr(host);
  /*
   * Find the end of an IPv6 address on the ']' ending bracket.
   */
  if(hostname[0] == '[') {
    portptr = strchr(hostname, ']');
    if(!portptr)
      return CURLUE_BAD_IPV6;
    portptr++;
    /* this is a RFC2732-style specified IP-address */
    if(*portptr) {
      if(*portptr != ':')
        return CURLUE_BAD_PORT_NUMBER;
    }
    else
      portptr = NULL;
  }
  else
    portptr = strchr(hostname, ':');

  if(portptr) {
    char *rest = NULL;
    unsigned long port;
    size_t keep = portptr - hostname;

    /* Browser behavior adaptation. If there is a colon with no digits after,
       just cut off the name there which makes us ignore the colon and just
       use the default port. Firefox, Chrome and Safari all do that.

       Do not do it if the URL has no scheme, to make something that looks like
       a scheme not work!
    */
    Curl_dyn_setlen(host, keep);
    portptr++;
    if(!*portptr)
      return has_scheme ? CURLUE_OK : CURLUE_BAD_PORT_NUMBER;

    if(!ISDIGIT(*portptr))
      return CURLUE_BAD_PORT_NUMBER;

    errno = 0;
    port = strtoul(portptr, &rest, 10);  /* Port number must be decimal */

    if(errno || (port > 0xffff) || *rest)
      return CURLUE_BAD_PORT_NUMBER;

    u->portnum = (unsigned short) port;
    /* generate a new port number string to get rid of leading zeroes etc */
    free(u->port);
    u->port = aprintf("%ld", port);
    if(!u->port)
      return CURLUE_OUT_OF_MEMORY;
  }

  return CURLUE_OK;
}

/* this assumes 'hostname' now starts with [ */
static CURLUcode ipv6_parse(struct Curl_URL *u, char *hostname,
                            size_t hlen) /* length of hostname */
{
  size_t len;
  DEBUGASSERT(*hostname == '[');
  if(hlen < 4) /* '[::]' is the shortest possible valid string */
    return CURLUE_BAD_IPV6;
  hostname++;
  hlen -= 2;

  /* only valid IPv6 letters are ok */
  len = strspn(hostname, "0123456789abcdefABCDEF:.");

  if(hlen != len) {
    hlen = len;
    if(hostname[len] == '%') {
      /* this could now be '%[zone id]' */
      char zoneid[16];
      int i = 0;
      char *h = &hostname[len + 1];
      /* pass '25' if present and is a URL encoded percent sign */
      if(!strncmp(h, "25", 2) && h[2] && (h[2] != ']'))
        h += 2;
      while(*h && (*h != ']') && (i < 15))
        zoneid[i++] = *h++;
      if(!i || (']' != *h))
        return CURLUE_BAD_IPV6;
      zoneid[i] = 0;
      u->zoneid = strdup(zoneid);
      if(!u->zoneid)
        return CURLUE_OUT_OF_MEMORY;
      hostname[len] = ']'; /* insert end bracket */
      hostname[len + 1] = 0; /* terminate the hostname */
    }
    else
      return CURLUE_BAD_IPV6;
    /* hostname is fine */
  }

  /* Check the IPv6 address. */
  {
    char dest[16]; /* fits a binary IPv6 address */
    char norm[MAX_IPADR_LEN];
    hostname[hlen] = 0; /* end the address there */
    if(1 != Curl_inet_pton(AF_INET6, hostname, dest))
      return CURLUE_BAD_IPV6;

    /* check if it can be done shorter */
    if(Curl_inet_ntop(AF_INET6, dest, norm, sizeof(norm)) &&
       (strlen(norm) < hlen)) {
      strcpy(hostname, norm);
      hlen = strlen(norm);
      hostname[hlen + 1] = 0;
    }
    hostname[hlen] = ']'; /* restore ending bracket */
  }
  return CURLUE_OK;
}

static CURLUcode hostname_check(struct Curl_URL *u, char *hostname,
                                size_t hlen) /* length of hostname */
{
  size_t len;
  DEBUGASSERT(hostname);

  if(!hlen)
    return CURLUE_NO_HOST;
  else if(hostname[0] == '[')
    return ipv6_parse(u, hostname, hlen);
  else {
    /* letters from the second string are not ok */
    len = strcspn(hostname, " \r\n\t/:#?!@{}[]\\$\'\"^`*<>=;,+&()%");
    if(hlen != len)
      /* hostname with bad content */
      return CURLUE_BAD_HOSTNAME;
  }
  return CURLUE_OK;
}

/*
 * Handle partial IPv4 numerical addresses and different bases, like
 * '16843009', '0x7f', '0x7f.1' '0177.1.1.1' etc.
 *
 * If the given input string is syntactically wrong IPv4 or any part for
 * example is too big, this function returns HOST_NAME.
 *
 * Output the "normalized" version of that input string in plain quad decimal
 * integers.
 *
 * Returns the host type.
 */

#define HOST_ERROR   -1 /* out of memory */

#define HOST_NAME    1
#define HOST_IPV4    2
#define HOST_IPV6    3

static int ipv4_normalize(struct dynbuf *host)
{
  bool done = FALSE;
  int n = 0;
  const char *c = Curl_dyn_ptr(host);
  unsigned long parts[4] = {0, 0, 0, 0};
  CURLcode result = CURLE_OK;

  if(*c == '[')
    return HOST_IPV6;

  errno = 0; /* for strtoul */
  while(!done) {
    char *endp = NULL;
    unsigned long l;
    if(!ISDIGIT(*c))
      /* most importantly this does not allow a leading plus or minus */
      return HOST_NAME;
    l = strtoul(c, &endp, 0);
    if(errno)
      return HOST_NAME;
#if SIZEOF_LONG > 4
    /* a value larger than 32 bits */
    if(l > UINT_MAX)
      return HOST_NAME;
#endif

    parts[n] = l;
    c = endp;

    switch(*c) {
    case '.':
      if(n == 3)
        return HOST_NAME;
      n++;
      c++;
      break;

    case '\0':
      done = TRUE;
      break;

    default:
      return HOST_NAME;
    }
  }

  switch(n) {
  case 0: /* a -- 32 bits */
    Curl_dyn_reset(host);

    result = Curl_dyn_addf(host, "%u.%u.%u.%u",
                           (unsigned int)(parts[0] >> 24),
                           (unsigned int)((parts[0] >> 16) & 0xff),
                           (unsigned int)((parts[0] >> 8) & 0xff),
                           (unsigned int)(parts[0] & 0xff));
    break;
  case 1: /* a.b -- 8.24 bits */
    if((parts[0] > 0xff) || (parts[1] > 0xffffff))
      return HOST_NAME;
    Curl_dyn_reset(host);
    result = Curl_dyn_addf(host, "%u.%u.%u.%u",
                           (unsigned int)(parts[0]),
                           (unsigned int)((parts[1] >> 16) & 0xff),
                           (unsigned int)((parts[1] >> 8) & 0xff),
                           (unsigned int)(parts[1] & 0xff));
    break;
  case 2: /* a.b.c -- 8.8.16 bits */
    if((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xffff))
      return HOST_NAME;
    Curl_dyn_reset(host);
    result = Curl_dyn_addf(host, "%u.%u.%u.%u",
                           (unsigned int)(parts[0]),
                           (unsigned int)(parts[1]),
                           (unsigned int)((parts[2] >> 8) & 0xff),
                           (unsigned int)(parts[2] & 0xff));
    break;
  case 3: /* a.b.c.d -- 8.8.8.8 bits */
    if((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff) ||
       (parts[3] > 0xff))
      return HOST_NAME;
    Curl_dyn_reset(host);
    result = Curl_dyn_addf(host, "%u.%u.%u.%u",
                           (unsigned int)(parts[0]),
                           (unsigned int)(parts[1]),
                           (unsigned int)(parts[2]),
                           (unsigned int)(parts[3]));
    break;
  }
  if(result)
    return HOST_ERROR;
  return HOST_IPV4;
}

/* if necessary, replace the host content with a URL decoded version */
static CURLUcode urldecode_host(struct dynbuf *host)
{
  char *per = NULL;
  const char *hostname = Curl_dyn_ptr(host);
  per = strchr(hostname, '%');
  if(!per)
    /* nothing to decode */
    return CURLUE_OK;
  else {
    /* encoded */
    size_t dlen;
    char *decoded;
    CURLcode result = Curl_urldecode(hostname, 0, &decoded, &dlen,
                                     REJECT_CTRL);
    if(result)
      return CURLUE_BAD_HOSTNAME;
    Curl_dyn_reset(host);
    result = Curl_dyn_addn(host, decoded, dlen);
    free(decoded);
    if(result)
      return cc2cu(result);
  }

  return CURLUE_OK;
}

static CURLUcode parse_authority(struct Curl_URL *u,
                                 const char *auth, size_t authlen,
                                 unsigned int flags,
                                 struct dynbuf *host,
                                 bool has_scheme)
{
  size_t offset;
  CURLUcode uc;
  CURLcode result;

  /*
   * Parse the login details and strip them out of the hostname.
   */
  uc = parse_hostname_login(u, auth, authlen, flags, &offset);
  if(uc)
    goto out;

  result = Curl_dyn_addn(host, auth + offset, authlen - offset);
  if(result) {
    uc = cc2cu(result);
    goto out;
  }

  uc = Curl_parse_port(u, host, has_scheme);
  if(uc)
    goto out;

  if(!Curl_dyn_len(host))
    return CURLUE_NO_HOST;

  switch(ipv4_normalize(host)) {
  case HOST_IPV4:
    break;
  case HOST_IPV6:
    uc = ipv6_parse(u, Curl_dyn_ptr(host), Curl_dyn_len(host));
    break;
  case HOST_NAME:
    uc = urldecode_host(host);
    if(!uc)
      uc = hostname_check(u, Curl_dyn_ptr(host), Curl_dyn_len(host));
    break;
  case HOST_ERROR:
    uc = CURLUE_OUT_OF_MEMORY;
    break;
  default:
    uc = CURLUE_BAD_HOSTNAME; /* Bad IPv4 address even */
    break;
  }

out:
  return uc;
}

/* used for HTTP/2 server push */
CURLUcode Curl_url_set_authority(CURLU *u, const char *authority)
{
  CURLUcode result;
  struct dynbuf host;

  DEBUGASSERT(authority);
  Curl_dyn_init(&host, CURL_MAX_INPUT_LENGTH);

  result = parse_authority(u, authority, strlen(authority),
                           CURLU_DISALLOW_USER, &host, !!u->scheme);
  if(result)
    Curl_dyn_free(&host);
  else {
    free(u->host);
    u->host = Curl_dyn_ptr(&host);
  }
  return result;
}

/*
 * "Remove Dot Segments"
 * https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4
 */

/*
 * dedotdotify()
 * @unittest: 1395
 *
 * This function gets a null-terminated path with dot and dotdot sequences
 * passed in and strips them off according to the rules in RFC 3986 section
 * 5.2.4.
 *
 * The function handles a query part ('?' + stuff) appended but it expects
 * that fragments ('#' + stuff) have already been cut off.
 *
 * RETURNS
 *
 * Zero for success and 'out' set to an allocated dedotdotified string.
 */
UNITTEST int dedotdotify(const char *input, size_t clen, char **outp);
UNITTEST int dedotdotify(const char *input, size_t clen, char **outp)
{
  char *outptr;
  const char *endp = &input[clen];
  char *out;

  *outp = NULL;
  /* the path always starts with a slash, and a slash has not dot */
  if((clen < 2) || !memchr(input, '.', clen))
    return 0;

  out = malloc(clen + 1);
  if(!out)
    return 1; /* out of memory */

  *out = 0; /* null-terminates, for inputs like "./" */
  outptr = out;

  do {
    bool dotdot = TRUE;
    if(*input == '.') {
      /*  A. If the input buffer begins with a prefix of "../" or "./", then
          remove that prefix from the input buffer; otherwise, */

      if(!strncmp("./", input, 2)) {
        input += 2;
        clen -= 2;
      }
      else if(!strncmp("../", input, 3)) {
        input += 3;
        clen -= 3;
      }
      /*  D. if the input buffer consists only of "." or "..", then remove
          that from the input buffer; otherwise, */

      else if(!strcmp(".", input) || !strcmp("..", input) ||
              !strncmp(".?", input, 2) || !strncmp("..?", input, 3)) {
        *out = 0;
        break;
      }
      else
        dotdot = FALSE;
    }
    else if(*input == '/') {
      /*  B. if the input buffer begins with a prefix of "/./" or "/.", where
          "."  is a complete path segment, then replace that prefix with "/" in
          the input buffer; otherwise, */
      if(!strncmp("/./", input, 3)) {
        input += 2;
        clen -= 2;
      }
      else if(!strcmp("/.", input) || !strncmp("/.?", input, 3)) {
        *outptr++ = '/';
        *outptr = 0;
        break;
      }

      /*  C. if the input buffer begins with a prefix of "/../" or "/..",
          where ".." is a complete path segment, then replace that prefix with
          "/" in the input buffer and remove the last segment and its
          preceding "/" (if any) from the output buffer; otherwise, */

      else if(!strncmp("/../", input, 4)) {
        input += 3;
        clen -= 3;
        /* remove the last segment from the output buffer */
        while(outptr > out) {
          outptr--;
          if(*outptr == '/')
            break;
        }
        *outptr = 0; /* null-terminate where it stops */
      }
      else if(!strcmp("/..", input) || !strncmp("/..?", input, 4)) {
        /* remove the last segment from the output buffer */
        while(outptr > out) {
          outptr--;
          if(*outptr == '/')
            break;
        }
        *outptr++ = '/';
        *outptr = 0; /* null-terminate where it stops */
        break;
      }
      else
        dotdot = FALSE;
    }
    else
      dotdot = FALSE;

    if(!dotdot) {
      /*  E. move the first path segment in the input buffer to the end of
          the output buffer, including the initial "/" character (if any) and
          any subsequent characters up to, but not including, the next "/"
          character or the end of the input buffer. */

      do {
        *outptr++ = *input++;
        clen--;
      } while(*input && (*input != '/') && (*input != '?'));
      *outptr = 0;
    }

    /* continue until end of path */
  } while(input < endp);

  *outp = out;
  return 0; /* success */
}

static CURLUcode parseurl(const char *url, CURLU *u, unsigned int flags)
{
  const char *path;
  size_t pathlen;
  char *query = NULL;
  char *fragment = NULL;
  char schemebuf[MAX_SCHEME_LEN + 1];
  size_t schemelen = 0;
  size_t urllen;
  CURLUcode result = CURLUE_OK;
  size_t fraglen = 0;
  struct dynbuf host;

  DEBUGASSERT(url);

  Curl_dyn_init(&host, CURL_MAX_INPUT_LENGTH);

  result = junkscan(url, &urllen, flags);
  if(result)
    goto fail;

  schemelen = Curl_is_absolute_url(url, schemebuf, sizeof(schemebuf),
                                   flags & (CURLU_GUESS_SCHEME|
                                            CURLU_DEFAULT_SCHEME));

  /* handle the file: scheme */
  if(schemelen && !strcmp(schemebuf, "file")) {
    bool uncpath = FALSE;
    if(urllen <= 6) {
      /* file:/ is not enough to actually be a complete file: URL */
      result = CURLUE_BAD_FILE_URL;
      goto fail;
    }

    /* path has been allocated large enough to hold this */
    path = (char *)&url[5];
    pathlen = urllen - 5;

    u->scheme = strdup("file");
    if(!u->scheme) {
      result = CURLUE_OUT_OF_MEMORY;
      goto fail;
    }

    /* Extra handling URLs with an authority component (i.e. that start with
     * "file://")
     *
     * We allow omitted hostname (e.g. file:/<path>) -- valid according to
     * RFC 8089, but not the (current) WHAT-WG URL spec.
     */
    if(path[0] == '/' && path[1] == '/') {
      /* swallow the two slashes */
      const char *ptr = &path[2];

      /*
       * According to RFC 8089, a file: URL can be reliably dereferenced if:
       *
       *  o it has no/blank hostname, or
       *
       *  o the hostname matches "localhost" (case-insensitively), or
       *
       *  o the hostname is a FQDN that resolves to this machine, or
       *
       *  o it is an UNC String transformed to an URI (Windows only, RFC 8089
       *    Appendix E.3).
       *
       * For brevity, we only consider URLs with empty, "localhost", or
       * "127.0.0.1" hostnames as local, otherwise as an UNC String.
       *
       * Additionally, there is an exception for URLs with a Windows drive
       * letter in the authority (which was accidentally omitted from RFC 8089
       * Appendix E, but believe me, it was meant to be there. --MK)
       */
      if(ptr[0] != '/' && !STARTS_WITH_URL_DRIVE_PREFIX(ptr)) {
        /* the URL includes a hostname, it must match "localhost" or
           "127.0.0.1" to be valid */
        if(checkprefix("localhost/", ptr) ||
           checkprefix("127.0.0.1/", ptr)) {
          ptr += 9; /* now points to the slash after the host */
        }
        else {
#if defined(_WIN32)
          size_t len;

          /* the hostname, NetBIOS computer name, can not contain disallowed
             chars, and the delimiting slash character must be appended to the
             hostname */
          path = strpbrk(ptr, "/\\:*?\"<>|");
          if(!path || *path != '/') {
            result = CURLUE_BAD_FILE_URL;
            goto fail;
          }

          len = path - ptr;
          if(len) {
            CURLcode code = Curl_dyn_addn(&host, ptr, len);
            if(code) {
              result = cc2cu(code);
              goto fail;
            }
            uncpath = TRUE;
          }

          ptr -= 2; /* now points to the // before the host in UNC */
#else
          /* Invalid file://hostname/, expected localhost or 127.0.0.1 or
             none */
          result = CURLUE_BAD_FILE_URL;
          goto fail;
#endif
        }
      }

      path = ptr;
      pathlen = urllen - (ptr - url);
    }

    if(!uncpath)
      /* no host for file: URLs by default */
      Curl_dyn_reset(&host);

#if !defined(_WIN32) && !defined(MSDOS) && !defined(__CYGWIN__)
    /* Do not allow Windows drive letters when not in Windows.
     * This catches both "file:/c:" and "file:c:" */
    if(('/' == path[0] && STARTS_WITH_URL_DRIVE_PREFIX(&path[1])) ||
       STARTS_WITH_URL_DRIVE_PREFIX(path)) {
      /* File drive letters are only accepted in MSDOS/Windows */
      result = CURLUE_BAD_FILE_URL;
      goto fail;
    }
#else
    /* If the path starts with a slash and a drive letter, ditch the slash */
    if('/' == path[0] && STARTS_WITH_URL_DRIVE_PREFIX(&path[1])) {
      /* This cannot be done with strcpy, as the memory chunks overlap! */
      path++;
      pathlen--;
    }
#endif

  }
  else {
    /* clear path */
    const char *schemep = NULL;
    const char *hostp;
    size_t hostlen;

    if(schemelen) {
      int i = 0;
      const char *p = &url[schemelen + 1];
      while((*p == '/') && (i < 4)) {
        p++;
        i++;
      }

      schemep = schemebuf;
      if(!Curl_get_scheme_handler(schemep) &&
         !(flags & CURLU_NON_SUPPORT_SCHEME)) {
        result = CURLUE_UNSUPPORTED_SCHEME;
        goto fail;
      }

      if((i < 1) || (i > 3)) {
        /* less than one or more than three slashes */
        result = CURLUE_BAD_SLASHES;
        goto fail;
      }
      hostp = p; /* hostname starts here */
    }
    else {
      /* no scheme! */

      if(!(flags & (CURLU_DEFAULT_SCHEME|CURLU_GUESS_SCHEME))) {
        result = CURLUE_BAD_SCHEME;
        goto fail;
      }
      if(flags & CURLU_DEFAULT_SCHEME)
        schemep = DEFAULT_SCHEME;

      /*
       * The URL was badly formatted, let's try without scheme specified.
       */
      hostp = url;
    }

    if(schemep) {
      u->scheme = strdup(schemep);
      if(!u->scheme) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
    }

    /* find the end of the hostname + port number */
    hostlen = strcspn(hostp, "/?#");
    path = &hostp[hostlen];

    /* this pathlen also contains the query and the fragment */
    pathlen = urllen - (path - url);
    if(hostlen) {

      result = parse_authority(u, hostp, hostlen, flags, &host, schemelen);
      if(result)
        goto fail;

      if((flags & CURLU_GUESS_SCHEME) && !schemep) {
        const char *hostname = Curl_dyn_ptr(&host);
        /* legacy curl-style guess based on hostname */
        if(checkprefix("ftp.", hostname))
          schemep = "ftp";
        else if(checkprefix("dict.", hostname))
          schemep = "dict";
        else if(checkprefix("ldap.", hostname))
          schemep = "ldap";
        else if(checkprefix("imap.", hostname))
          schemep = "imap";
        else if(checkprefix("smtp.", hostname))
          schemep = "smtp";
        else if(checkprefix("pop3.", hostname))
          schemep = "pop3";
        else
          schemep = "http";

        u->scheme = strdup(schemep);
        if(!u->scheme) {
          result = CURLUE_OUT_OF_MEMORY;
          goto fail;
        }
        u->guessed_scheme = TRUE;
      }
    }
    else if(flags & CURLU_NO_AUTHORITY) {
      /* allowed to be empty. */
      if(Curl_dyn_add(&host, "")) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
    }
    else {
      result = CURLUE_NO_HOST;
      goto fail;
    }
  }

  fragment = strchr(path, '#');
  if(fragment) {
    fraglen = pathlen - (fragment - path);
    u->fragment_present = TRUE;
    if(fraglen > 1) {
      /* skip the leading '#' in the copy but include the terminating null */
      if(flags & CURLU_URLENCODE) {
        struct dynbuf enc;
        Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
        result = urlencode_str(&enc, fragment + 1, fraglen - 1, TRUE, FALSE);
        if(result)
          goto fail;
        u->fragment = Curl_dyn_ptr(&enc);
      }
      else {
        u->fragment = Curl_memdup0(fragment + 1, fraglen - 1);
        if(!u->fragment) {
          result = CURLUE_OUT_OF_MEMORY;
          goto fail;
        }
      }
    }
    /* after this, pathlen still contains the query */
    pathlen -= fraglen;
  }

  query = memchr(path, '?', pathlen);
  if(query) {
    size_t qlen = fragment ? (size_t)(fragment - query) :
      pathlen - (query - path);
    pathlen -= qlen;
    u->query_present = TRUE;
    if(qlen > 1) {
      if(flags & CURLU_URLENCODE) {
        struct dynbuf enc;
        Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
        /* skip the leading question mark */
        result = urlencode_str(&enc, query + 1, qlen - 1, TRUE, TRUE);
        if(result)
          goto fail;
        u->query = Curl_dyn_ptr(&enc);
      }
      else {
        u->query = Curl_memdup0(query + 1, qlen - 1);
        if(!u->query) {
          result = CURLUE_OUT_OF_MEMORY;
          goto fail;
        }
      }
    }
    else {
      /* single byte query */
      u->query = strdup("");
      if(!u->query) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
    }
  }

  if(pathlen && (flags & CURLU_URLENCODE)) {
    struct dynbuf enc;
    Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
    result = urlencode_str(&enc, path, pathlen, TRUE, FALSE);
    if(result)
      goto fail;
    pathlen = Curl_dyn_len(&enc);
    path = u->path = Curl_dyn_ptr(&enc);
  }

  if(pathlen <= 1) {
    /* there is no path left or just the slash, unset */
    path = NULL;
  }
  else {
    if(!u->path) {
      u->path = Curl_memdup0(path, pathlen);
      if(!u->path) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
      path = u->path;
    }
    else if(flags & CURLU_URLENCODE)
      /* it might have encoded more than just the path so cut it */
      u->path[pathlen] = 0;

    if(!(flags & CURLU_PATH_AS_IS)) {
      /* remove ../ and ./ sequences according to RFC3986 */
      char *dedot;
      int err = dedotdotify((char *)path, pathlen, &dedot);
      if(err) {
        result = CURLUE_OUT_OF_MEMORY;
        goto fail;
      }
      if(dedot) {
        free(u->path);
        u->path = dedot;
      }
    }
  }

  u->host = Curl_dyn_ptr(&host);

  return result;
fail:
  Curl_dyn_free(&host);
  free_urlhandle(u);
  return result;
}

/*
 * Parse the URL and, if successful, replace everything in the Curl_URL struct.
 */
static CURLUcode parseurl_and_replace(const char *url, CURLU *u,
                                      unsigned int flags)
{
  CURLUcode result;
  CURLU tmpurl;
  memset(&tmpurl, 0, sizeof(tmpurl));
  result = parseurl(url, &tmpurl, flags);
  if(!result) {
    free_urlhandle(u);
    *u = tmpurl;
  }
  return result;
}

/*
 */
CURLU *curl_url(void)
{
  return calloc(1, sizeof(struct Curl_URL));
}

void curl_url_cleanup(CURLU *u)
{
  if(u) {
    free_urlhandle(u);
    free(u);
  }
}

#define DUP(dest, src, name)                    \
  do {                                          \
    if(src->name) {                             \
      dest->name = strdup(src->name);           \
      if(!dest->name)                           \
        goto fail;                              \
    }                                           \
  } while(0)

CURLU *curl_url_dup(const CURLU *in)
{
  struct Curl_URL *u = calloc(1, sizeof(struct Curl_URL));
  if(u) {
    DUP(u, in, scheme);
    DUP(u, in, user);
    DUP(u, in, password);
    DUP(u, in, options);
    DUP(u, in, host);
    DUP(u, in, port);
    DUP(u, in, path);
    DUP(u, in, query);
    DUP(u, in, fragment);
    DUP(u, in, zoneid);
    u->portnum = in->portnum;
    u->fragment_present = in->fragment_present;
    u->query_present = in->query_present;
  }
  return u;
fail:
  curl_url_cleanup(u);
  return NULL;
}

CURLUcode curl_url_get(const CURLU *u, CURLUPart what,
                       char **part, unsigned int flags)
{
  const char *ptr;
  CURLUcode ifmissing = CURLUE_UNKNOWN_PART;
  char portbuf[7];
  bool urldecode = (flags & CURLU_URLDECODE)?1:0;
  bool urlencode = (flags & CURLU_URLENCODE)?1:0;
  bool punycode = FALSE;
  bool depunyfy = FALSE;
  bool plusdecode = FALSE;
  (void)flags;
  if(!u)
    return CURLUE_BAD_HANDLE;
  if(!part)
    return CURLUE_BAD_PARTPOINTER;
  *part = NULL;

  switch(what) {
  case CURLUPART_SCHEME:
    ptr = u->scheme;
    ifmissing = CURLUE_NO_SCHEME;
    urldecode = FALSE; /* never for schemes */
    if((flags & CURLU_NO_GUESS_SCHEME) && u->guessed_scheme)
      return CURLUE_NO_SCHEME;
    break;
  case CURLUPART_USER:
    ptr = u->user;
    ifmissing = CURLUE_NO_USER;
    break;
  case CURLUPART_PASSWORD:
    ptr = u->password;
    ifmissing = CURLUE_NO_PASSWORD;
    break;
  case CURLUPART_OPTIONS:
    ptr = u->options;
    ifmissing = CURLUE_NO_OPTIONS;
    break;
  case CURLUPART_HOST:
    ptr = u->host;
    ifmissing = CURLUE_NO_HOST;
    punycode = (flags & CURLU_PUNYCODE)?1:0;
    depunyfy = (flags & CURLU_PUNY2IDN)?1:0;
    break;
  case CURLUPART_ZONEID:
    ptr = u->zoneid;
    ifmissing = CURLUE_NO_ZONEID;
    break;
  case CURLUPART_PORT:
    ptr = u->port;
    ifmissing = CURLUE_NO_PORT;
    urldecode = FALSE; /* never for port */
    if(!ptr && (flags & CURLU_DEFAULT_PORT) && u->scheme) {
      /* there is no stored port number, but asked to deliver
         a default one for the scheme */
      const struct Curl_handler *h = Curl_get_scheme_handler(u->scheme);
      if(h) {
        msnprintf(portbuf, sizeof(portbuf), "%u", h->defport);
        ptr = portbuf;
      }
    }
    else if(ptr && u->scheme) {
      /* there is a stored port number, but ask to inhibit if
         it matches the default one for the scheme */
      const struct Curl_handler *h = Curl_get_scheme_handler(u->scheme);
      if(h && (h->defport == u->portnum) &&
         (flags & CURLU_NO_DEFAULT_PORT))
        ptr = NULL;
    }
    break;
  case CURLUPART_PATH:
    ptr = u->path;
    if(!ptr)
      ptr = "/";
    break;
  case CURLUPART_QUERY:
    ptr = u->query;
    ifmissing = CURLUE_NO_QUERY;
    plusdecode = urldecode;
    if(ptr && !ptr[0] && !(flags & CURLU_GET_EMPTY))
      /* there was a blank query and the user do not ask for it */
      ptr = NULL;
    break;
  case CURLUPART_FRAGMENT:
    ptr = u->fragment;
    ifmissing = CURLUE_NO_FRAGMENT;
    if(!ptr && u->fragment_present && flags & CURLU_GET_EMPTY)
      /* there was a blank fragment and the user asks for it */
      ptr = "";
    break;
  case CURLUPART_URL: {
    char *url;
    char *scheme;
    char *options = u->options;
    char *port = u->port;
    char *allochost = NULL;
    bool show_fragment =
      u->fragment || (u->fragment_present && flags & CURLU_GET_EMPTY);
    bool show_query =
      (u->query && u->query[0]) ||
      (u->query_present && flags & CURLU_GET_EMPTY);
    punycode = (flags & CURLU_PUNYCODE)?1:0;
    depunyfy = (flags & CURLU_PUNY2IDN)?1:0;
    if(u->scheme && strcasecompare("file", u->scheme)) {
      url = aprintf("file://%s%s%s",
                    u->path,
                    show_fragment ? "#": "",
                    u->fragment ? u->fragment : "");
    }
    else if(!u->host)
      return CURLUE_NO_HOST;
    else {
      const struct Curl_handler *h = NULL;
      char schemebuf[MAX_SCHEME_LEN + 5];
      if(u->scheme)
        scheme = u->scheme;
      else if(flags & CURLU_DEFAULT_SCHEME)
        scheme = (char *) DEFAULT_SCHEME;
      else
        return CURLUE_NO_SCHEME;

      h = Curl_get_scheme_handler(scheme);
      if(!port && (flags & CURLU_DEFAULT_PORT)) {
        /* there is no stored port number, but asked to deliver
           a default one for the scheme */
        if(h) {
          msnprintf(portbuf, sizeof(portbuf), "%u", h->defport);
          port = portbuf;
        }
      }
      else if(port) {
        /* there is a stored port number, but asked to inhibit if it matches
           the default one for the scheme */
        if(h && (h->defport == u->portnum) &&
           (flags & CURLU_NO_DEFAULT_PORT))
          port = NULL;
      }

      if(h && !(h->flags & PROTOPT_URLOPTIONS))
        options = NULL;

      if(u->host[0] == '[') {
        if(u->zoneid) {
          /* make it '[ host %25 zoneid ]' */
          struct dynbuf enc;
          size_t hostlen = strlen(u->host);
          Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
          if(Curl_dyn_addf(&enc, "%.*s%%25%s]", (int)hostlen - 1, u->host,
                           u->zoneid))
            return CURLUE_OUT_OF_MEMORY;
          allochost = Curl_dyn_ptr(&enc);
        }
      }
      else if(urlencode) {
        allochost = curl_easy_escape(NULL, u->host, 0);
        if(!allochost)
          return CURLUE_OUT_OF_MEMORY;
      }
      else if(punycode) {
        if(!Curl_is_ASCII_name(u->host)) {
#ifndef USE_IDN
          return CURLUE_LACKS_IDN;
#else
          CURLcode result = Curl_idn_decode(u->host, &allochost);
          if(result)
            return (result == CURLE_OUT_OF_MEMORY) ?
              CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
#endif
        }
      }
      else if(depunyfy) {
        if(Curl_is_ASCII_name(u->host) && !strncmp("xn--", u->host, 4)) {
#ifndef USE_IDN
          return CURLUE_LACKS_IDN;
#else
          CURLcode result = Curl_idn_encode(u->host, &allochost);
          if(result)
            /* this is the most likely error */
            return (result == CURLE_OUT_OF_MEMORY) ?
              CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
#endif
        }
      }

      if(!(flags & CURLU_NO_GUESS_SCHEME) || !u->guessed_scheme)
        msnprintf(schemebuf, sizeof(schemebuf), "%s://", scheme);
      else
        schemebuf[0] = 0;

      url = aprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                    schemebuf,
                    u->user ? u->user : "",
                    u->password ? ":": "",
                    u->password ? u->password : "",
                    options ? ";" : "",
                    options ? options : "",
                    (u->user || u->password || options) ? "@": "",
                    allochost ? allochost : u->host,
                    port ? ":": "",
                    port ? port : "",
                    u->path ? u->path : "/",
                    show_query ? "?": "",
                    u->query ? u->query : "",
                    show_fragment ? "#": "",
                    u->fragment? u->fragment : "");
      free(allochost);
    }
    if(!url)
      return CURLUE_OUT_OF_MEMORY;
    *part = url;
    return CURLUE_OK;
  }
  default:
    ptr = NULL;
    break;
  }
  if(ptr) {
    size_t partlen = strlen(ptr);
    size_t i = 0;
    *part = Curl_memdup0(ptr, partlen);
    if(!*part)
      return CURLUE_OUT_OF_MEMORY;
    if(plusdecode) {
      /* convert + to space */
      char *plus = *part;
      for(i = 0; i < partlen; ++plus, i++) {
        if(*plus == '+')
          *plus = ' ';
      }
    }
    if(urldecode) {
      char *decoded;
      size_t dlen;
      /* this unconditional rejection of control bytes is documented
         API behavior */
      CURLcode res = Curl_urldecode(*part, 0, &decoded, &dlen, REJECT_CTRL);
      free(*part);
      if(res) {
        *part = NULL;
        return CURLUE_URLDECODE;
      }
      *part = decoded;
      partlen = dlen;
    }
    if(urlencode) {
      struct dynbuf enc;
      CURLUcode uc;
      Curl_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
      uc = urlencode_str(&enc, *part, partlen, TRUE, what == CURLUPART_QUERY);
      if(uc)
        return uc;
      free(*part);
      *part = Curl_dyn_ptr(&enc);
    }
    else if(punycode) {
      if(!Curl_is_ASCII_name(u->host)) {
#ifndef USE_IDN
        return CURLUE_LACKS_IDN;
#else
        char *allochost;
        CURLcode result = Curl_idn_decode(*part, &allochost);
        if(result)
          return (result == CURLE_OUT_OF_MEMORY) ?
            CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
        free(*part);
        *part = allochost;
#endif
      }
    }
    else if(depunyfy) {
      if(Curl_is_ASCII_name(u->host)  && !strncmp("xn--", u->host, 4)) {
#ifndef USE_IDN
        return CURLUE_LACKS_IDN;
#else
        char *allochost;
        CURLcode result = Curl_idn_encode(*part, &allochost);
        if(result)
          return (result == CURLE_OUT_OF_MEMORY) ?
            CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
        free(*part);
        *part = allochost;
#endif
      }
    }

    return CURLUE_OK;
  }
  else
    return ifmissing;
}

CURLUcode curl_url_set(CURLU *u, CURLUPart what,
                       const char *part, unsigned int flags)
{
  char **storep = NULL;
  bool urlencode = (flags & CURLU_URLENCODE)? 1 : 0;
  bool plusencode = FALSE;
  bool urlskipslash = FALSE;
  bool leadingslash = FALSE;
  bool appendquery = FALSE;
  bool equalsencode = FALSE;
  size_t nalloc;

  if(!u)
    return CURLUE_BAD_HANDLE;
  if(!part) {
    /* setting a part to NULL clears it */
    switch(what) {
    case CURLUPART_URL:
      break;
    case CURLUPART_SCHEME:
      storep = &u->scheme;
      u->guessed_scheme = FALSE;
      break;
    case CURLUPART_USER:
      storep = &u->user;
      break;
    case CURLUPART_PASSWORD:
      storep = &u->password;
      break;
    case CURLUPART_OPTIONS:
      storep = &u->options;
      break;
    case CURLUPART_HOST:
      storep = &u->host;
      break;
    case CURLUPART_ZONEID:
      storep = &u->zoneid;
      break;
    case CURLUPART_PORT:
      u->portnum = 0;
      storep = &u->port;
      break;
    case CURLUPART_PATH:
      storep = &u->path;
      break;
    case CURLUPART_QUERY:
      storep = &u->query;
      u->query_present = FALSE;
      break;
    case CURLUPART_FRAGMENT:
      storep = &u->fragment;
      u->fragment_present = FALSE;
      break;
    default:
      return CURLUE_UNKNOWN_PART;
    }
    if(storep && *storep) {
      Curl_safefree(*storep);
    }
    else if(!storep) {
      free_urlhandle(u);
      memset(u, 0, sizeof(struct Curl_URL));
    }
    return CURLUE_OK;
  }

  nalloc = strlen(part);
  if(nalloc > CURL_MAX_INPUT_LENGTH)
    /* excessive input length */
    return CURLUE_MALFORMED_INPUT;

  switch(what) {
  case CURLUPART_SCHEME: {
    size_t plen = strlen(part);
    const char *s = part;
    if((plen > MAX_SCHEME_LEN) || (plen < 1))
      /* too long or too short */
      return CURLUE_BAD_SCHEME;
   /* verify that it is a fine scheme */
    if(!(flags & CURLU_NON_SUPPORT_SCHEME) && !Curl_get_scheme_handler(part))
      return CURLUE_UNSUPPORTED_SCHEME;
    storep = &u->scheme;
    urlencode = FALSE; /* never */
    if(ISALPHA(*s)) {
      /* ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
      while(--plen) {
        if(ISALNUM(*s) || (*s == '+') || (*s == '-') || (*s == '.'))
          s++; /* fine */
        else
          return CURLUE_BAD_SCHEME;
      }
    }
    else
      return CURLUE_BAD_SCHEME;
    u->guessed_scheme = FALSE;
    break;
  }
  case CURLUPART_USER:
    storep = &u->user;
    break;
  case CURLUPART_PASSWORD:
    storep = &u->password;
    break;
  case CURLUPART_OPTIONS:
    storep = &u->options;
    break;
  case CURLUPART_HOST:
    storep = &u->host;
    Curl_safefree(u->zoneid);
    break;
  case CURLUPART_ZONEID:
    storep = &u->zoneid;
    break;
  case CURLUPART_PORT:
    if(!ISDIGIT(part[0]))
      /* not a number */
      return CURLUE_BAD_PORT_NUMBER;
    else {
      char *tmp;
      char *endp;
      unsigned long port;
      errno = 0;
      port = strtoul(part, &endp, 10);  /* must be decimal */
      if(errno || (port > 0xffff) || *endp)
        /* weirdly provided number, not good! */
        return CURLUE_BAD_PORT_NUMBER;
      tmp = strdup(part);
      if(!tmp)
        return CURLUE_OUT_OF_MEMORY;
      free(u->port);
      u->port = tmp;
      u->portnum = (unsigned short)port;
      return CURLUE_OK;
    }
  case CURLUPART_PATH:
    urlskipslash = TRUE;
    leadingslash = TRUE; /* enforce */
    storep = &u->path;
    break;
  case CURLUPART_QUERY:
    plusencode = urlencode;
    appendquery = (flags & CURLU_APPENDQUERY)?1:0;
    equalsencode = appendquery;
    storep = &u->query;
    u->query_present = TRUE;
    break;
  case CURLUPART_FRAGMENT:
    storep = &u->fragment;
    u->fragment_present = TRUE;
    break;
  case CURLUPART_URL: {
    /*
     * Allow a new URL to replace the existing (if any) contents.
     *
     * If the existing contents is enough for a URL, allow a relative URL to
     * replace it.
     */
    CURLcode result;
    CURLUcode uc;
    char *oldurl;
    char *redired_url;

    if(!nalloc)
      /* a blank URL is not a valid URL */
      return CURLUE_MALFORMED_INPUT;

    /* if the new thing is absolute or the old one is not
     * (we could not get an absolute URL in 'oldurl'),
     * then replace the existing with the new. */
    if(Curl_is_absolute_url(part, NULL, 0,
                            flags & (CURLU_GUESS_SCHEME|
                                     CURLU_DEFAULT_SCHEME))
       || curl_url_get(u, CURLUPART_URL, &oldurl, flags)) {
      return parseurl_and_replace(part, u, flags);
    }

    /* apply the relative part to create a new URL
     * and replace the existing one with it. */
    result = concat_url(oldurl, part, &redired_url);
    free(oldurl);
    if(result)
      return cc2cu(result);

    uc = parseurl_and_replace(redired_url, u, flags);
    free(redired_url);
    return uc;
  }
  default:
    return CURLUE_UNKNOWN_PART;
  }
  DEBUGASSERT(storep);
  {
    const char *newp;
    struct dynbuf enc;
    Curl_dyn_init(&enc, nalloc * 3 + 1 + leadingslash);

    if(leadingslash && (part[0] != '/')) {
      CURLcode result = Curl_dyn_addn(&enc, "/", 1);
      if(result)
        return cc2cu(result);
    }
    if(urlencode) {
      const unsigned char *i;

      for(i = (const unsigned char *)part; *i; i++) {
        CURLcode result;
        if((*i == ' ') && plusencode) {
          result = Curl_dyn_addn(&enc, "+", 1);
          if(result)
            return CURLUE_OUT_OF_MEMORY;
        }
        else if(ISUNRESERVED(*i) ||
                ((*i == '/') && urlskipslash) ||
                ((*i == '=') && equalsencode)) {
          if((*i == '=') && equalsencode)
            /* only skip the first equals sign */
            equalsencode = FALSE;
          result = Curl_dyn_addn(&enc, i, 1);
          if(result)
            return cc2cu(result);
        }
        else {
          char out[3]={'%'};
          out[1] = hexdigits[*i>>4];
          out[2] = hexdigits[*i & 0xf];
          result = Curl_dyn_addn(&enc, out, 3);
          if(result)
            return cc2cu(result);
        }
      }
    }
    else {
      char *p;
      CURLcode result = Curl_dyn_add(&enc, part);
      if(result)
        return cc2cu(result);
      p = Curl_dyn_ptr(&enc);
      while(*p) {
        /* make sure percent encoded are lower case */
        if((*p == '%') && ISXDIGIT(p[1]) && ISXDIGIT(p[2]) &&
           (ISUPPER(p[1]) || ISUPPER(p[2]))) {
          p[1] = Curl_raw_tolower(p[1]);
          p[2] = Curl_raw_tolower(p[2]);
          p += 3;
        }
        else
          p++;
      }
    }
    newp = Curl_dyn_ptr(&enc);

    if(appendquery && newp) {
      /* Append the 'newp' string onto the old query. Add a '&' separator if
         none is present at the end of the existing query already */

      size_t querylen = u->query ? strlen(u->query) : 0;
      bool addamperand = querylen && (u->query[querylen -1] != '&');
      if(querylen) {
        struct dynbuf qbuf;
        Curl_dyn_init(&qbuf, CURL_MAX_INPUT_LENGTH);

        if(Curl_dyn_addn(&qbuf, u->query, querylen)) /* add original query */
          goto nomem;

        if(addamperand) {
          if(Curl_dyn_addn(&qbuf, "&", 1))
            goto nomem;
        }
        if(Curl_dyn_add(&qbuf, newp))
          goto nomem;
        Curl_dyn_free(&enc);
        free(*storep);
        *storep = Curl_dyn_ptr(&qbuf);
        return CURLUE_OK;
nomem:
        Curl_dyn_free(&enc);
        return CURLUE_OUT_OF_MEMORY;
      }
    }

    else if(what == CURLUPART_HOST) {
      size_t n = Curl_dyn_len(&enc);
      if(!n && (flags & CURLU_NO_AUTHORITY)) {
        /* Skip hostname check, it is allowed to be empty. */
      }
      else {
        if(!n || hostname_check(u, (char *)newp, n)) {
          Curl_dyn_free(&enc);
          return CURLUE_BAD_HOSTNAME;
        }
      }
    }

    free(*storep);
    *storep = (char *)newp;
  }
  return CURLUE_OK;
}
