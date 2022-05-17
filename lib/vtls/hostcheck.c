/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(USE_OPENSSL)                                \
  || defined(USE_GSKIT)                                 \
  || defined(USE_SCHANNEL)
/* these backends use functions from this file */

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#include "curl_memrchr.h"

#include "hostcheck.h"
#include "strcase.h"
#include "hostip.h"

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* check the two input strings with given length, but do not
   assume they end in nul-bytes */
static bool pmatch(const char *hostname, size_t hostlen,
                   const char *pattern, size_t patternlen)
{
  if(hostlen != patternlen)
    return FALSE;
  return strncasecompare(hostname, pattern, hostlen);
}

/*
 * Match a hostname against a wildcard pattern.
 * E.g.
 *  "foo.host.com" matches "*.host.com".
 *
 * We use the matching rule described in RFC6125, section 6.4.3.
 * https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.3
 *
 * In addition: ignore trailing dots in the host names and wildcards, so that
 * the names are used normalized. This is what the browsers do.
 *
 * Do not allow wildcard matching on IP numbers. There are apparently
 * certificates being used with an IP address in the CN field, thus making no
 * apparent distinction between a name and an IP. We need to detect the use of
 * an IP address and not wildcard match on such names.
 *
 * Return TRUE on a match. FALSE if not.
 */

static bool hostmatch(const char *hostname,
                      size_t hostlen,
                      const char *pattern,
                      size_t patternlen)
{
  const char *pattern_label_end, *wildcard, *hostname_label_end;
  size_t prefixlen, suffixlen;

  /* normalize pattern and hostname by stripping off trailing dots */
  DEBUGASSERT(patternlen);
  if(hostname[hostlen-1]=='.')
    hostlen--;
  if(pattern[patternlen-1]=='.')
    patternlen--;

  wildcard = memchr(pattern, '*', patternlen);
  if(!wildcard)
    return pmatch(hostname, hostlen, pattern, patternlen);

  /* detect IP address as hostname and fail the match if so */
  if(Curl_host_is_ipnum(hostname))
    return FALSE;

  /* We require at least 2 dots in the pattern to avoid too wide wildcard
     match. */
  pattern_label_end = memchr(pattern, '.', patternlen);
  if(!pattern_label_end ||
     (memrchr(pattern, '.', patternlen) == pattern_label_end) ||
     strncasecompare(pattern, "xn--", 4))
    return pmatch(hostname, hostlen, pattern, patternlen);

  hostname_label_end = memchr(hostname, '.', hostlen);
  if(!hostname_label_end)
    return FALSE;
  else {
    size_t skiphost = hostname_label_end - hostname;
    size_t skiplen = pattern_label_end - pattern;
    if(!pmatch(hostname_label_end, hostlen - skiphost,
               pattern_label_end, patternlen - skiplen))
      return FALSE;
  }
  /* The wildcard must match at least one character, so the left-most
     label of the hostname is at least as large as the left-most label
     of the pattern. */
  if(hostname_label_end - hostname < pattern_label_end - pattern)
    return FALSE;

  prefixlen = wildcard - pattern;
  suffixlen = pattern_label_end - (wildcard + 1);
  return strncasecompare(pattern, hostname, prefixlen) &&
    strncasecompare(wildcard + 1, hostname_label_end - suffixlen,
                    suffixlen) ? TRUE : FALSE;
}

/*
 * Curl_cert_hostcheck() returns TRUE if a match and FALSE if not.
 */
bool Curl_cert_hostcheck(const char *match, size_t matchlen,
                         const char *hostname, size_t hostlen)
{
  if(match && *match && hostname && *hostname)
    return hostmatch(hostname, hostlen, match, matchlen);
  return FALSE;
}

#endif /* OPENSSL, GSKIT or schannel+wince */
