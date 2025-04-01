/* This is from the BIND 4.9.4 release, modified to compile by itself */

/* Copyright (c) Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 * SPDX-License-Identifier: ISC
 */

#include "curl_setup.h"
#include "curl_ctype.h"
#include "strparse.h"

#ifndef HAVE_INET_PTON

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "inet_pton.h"

#define IN6ADDRSZ       16
#define INADDRSZ         4
#define INT16SZ          2

/*
 * If USE_IPV6 is disabled, we still want to parse IPv6 addresses, so make
 * sure we have _some_ value for AF_INET6 without polluting our fake value
 * everywhere.
 */
#if !defined(USE_IPV6) && !defined(AF_INET6)
#define AF_INET6 (AF_INET + 1)
#endif

/*
 * WARNING: Do not even consider trying to compile this on a system where
 * sizeof(int) < 4. sizeof(int) > 4 is fine; all the world's not a VAX.
 */

static int      inet_pton4(const char *src, unsigned char *dst);
static int      inet_pton6(const char *src, unsigned char *dst);

/* int
 * inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address was not valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * notice:
 *      On Windows we store the error in the thread errno, not
 *      in the Winsock error code. This is to avoid losing the
 *      actual last Winsock error. When this function returns
 *      -1, check errno not SOCKERRNO.
 * author:
 *      Paul Vixie, 1996.
 */
int
curlx_inet_pton(int af, const char *src, void *dst)
{
  switch(af) {
  case AF_INET:
    return inet_pton4(src, (unsigned char *)dst);
  case AF_INET6:
    return inet_pton6(src, (unsigned char *)dst);
  default:
    CURL_SETERRNO(SOCKEAFNOSUPPORT);
    return -1;
  }
  /* NOTREACHED */
}

/* int
 * inet_pton4(src, dst)
 *      like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *      1 if `src' is a valid dotted quad, else 0.
 * notice:
 *      does not touch `dst' unless it is returning 1.
 * author:
 *      Paul Vixie, 1996.
 */
static int
inet_pton4(const char *src, unsigned char *dst)
{
  int saw_digit, octets, ch;
  unsigned char tmp[INADDRSZ], *tp;

  saw_digit = 0;
  octets = 0;
  tp = tmp;
  *tp = 0;
  while((ch = *src++) != '\0') {
    if(ISDIGIT(ch)) {
      unsigned int val = (*tp * 10) + (ch - '0');

      if(saw_digit && *tp == 0)
        return 0;
      if(val > 255)
        return 0;
      *tp = (unsigned char)val;
      if(!saw_digit) {
        if(++octets > 4)
          return 0;
        saw_digit = 1;
      }
    }
    else if(ch == '.' && saw_digit) {
      if(octets == 4)
        return 0;
      *++tp = 0;
      saw_digit = 0;
    }
    else
      return 0;
  }
  if(octets < 4)
    return 0;
  memcpy(dst, tmp, INADDRSZ);
  return 1;
}

/* int
 * inet_pton6(src, dst)
 *      convert presentation level address to network order binary form.
 * return:
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *      (1) does not touch `dst' unless it is returning 1.
 *      (2) :: in a full address is silently ignored.
 * credit:
 *      inspired by Mark Andrews.
 * author:
 *      Paul Vixie, 1996.
 */
static int
inet_pton6(const char *src, unsigned char *dst)
{
  unsigned char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
  const char *curtok;
  int ch, saw_xdigit;
  size_t val;

  memset((tp = tmp), 0, IN6ADDRSZ);
  endp = tp + IN6ADDRSZ;
  colonp = NULL;
  /* Leading :: requires some special handling. */
  if(*src == ':')
    if(*++src != ':')
      return 0;
  curtok = src;
  saw_xdigit = 0;
  val = 0;
  while((ch = *src++) != '\0') {
    if(ISXDIGIT(ch)) {
      val <<= 4;
      val |= Curl_hexval(ch);
      if(++saw_xdigit > 4)
        return 0;
      continue;
    }
    if(ch == ':') {
      curtok = src;
      if(!saw_xdigit) {
        if(colonp)
          return 0;
        colonp = tp;
        continue;
      }
      if(tp + INT16SZ > endp)
        return 0;
      *tp++ = (unsigned char) ((val >> 8) & 0xff);
      *tp++ = (unsigned char) (val & 0xff);
      saw_xdigit = 0;
      val = 0;
      continue;
    }
    if(ch == '.' && ((tp + INADDRSZ) <= endp) &&
        inet_pton4(curtok, tp) > 0) {
      tp += INADDRSZ;
      saw_xdigit = 0;
      break;    /* '\0' was seen by inet_pton4(). */
    }
    return 0;
  }
  if(saw_xdigit) {
    if(tp + INT16SZ > endp)
      return 0;
    *tp++ = (unsigned char) ((val >> 8) & 0xff);
    *tp++ = (unsigned char) (val & 0xff);
  }
  if(colonp) {
    /*
     * Since some memmove()'s erroneously fail to handle
     * overlapping regions, we will do the shift by hand.
     */
    const ssize_t n = tp - colonp;
    ssize_t i;

    if(tp == endp)
      return 0;
    for(i = 1; i <= n; i++) {
      *(endp - i) = *(colonp + n - i);
      *(colonp + n - i) = 0;
    }
    tp = endp;
  }
  if(tp != endp)
    return 0;
  memcpy(dst, tmp, IN6ADDRSZ);
  return 1;
}

#endif /* HAVE_INET_PTON */
