/*
 * Original code by Paul Vixie. "curlified" by Gisle Vanem.
 */

#include "setup.h"

#ifndef HAVE_INET_NTOP

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <string.h>
#include <errno.h>

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "inet_ntop.h"

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
/* this platform has a inet_ntoa_r() function, but no proto declared anywhere
   so we include our own proto to make compilers happy */
#include "inet_ntoa_r.h"
#endif

#define IN6ADDRSZ       16
#define INADDRSZ         4
#define INT16SZ          2

#ifdef WIN32
#define EAFNOSUPPORT    WSAEAFNOSUPPORT
#define SET_ERRNO(e)    WSASetLastError(errno = (e))
#else
#define SET_ERRNO(e)    errno = e
#endif

/*
 * Format an IPv4 address, more or less like inet_ntoa().
 *
 * Returns `dst' (as a const)
 * Note:
 *  - uses no statics
 *  - takes a u_char* not an in_addr as input
 */
static char *inet_ntop4 (const u_char *src, char *dst, size_t size)
{
#if defined(HAVE_INET_NTOA_R_2_ARGS)
  const char *ptr;
  curlassert(size >= 16);
  ptr = inet_ntoa_r(*(struct in_addr*)src, dst);
  return (char *)memmove(dst, ptr, strlen(ptr)+1);

#elif defined(HAVE_INET_NTOA_R)
  return inet_ntoa_r(*(struct in_addr*)src, dst, size);

#else
  const char *addr = inet_ntoa(*(struct in_addr*)src);

  if (strlen(addr) >= size)
  {
    SET_ERRNO(ENOSPC);
    return (NULL);
  }
  return strcpy(dst, addr);
#endif
}

#ifdef ENABLE_IPV6
/*
 * Convert IPv6 binary address into presentation (printable) format.
 */
static char *inet_ntop6 (const u_char *src, char *dst, size_t size)
{
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
  char  tmp [sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
  char *tp;
  struct {
    long base;
    long len;
  } best, cur;
  u_long words [IN6ADDRSZ / INT16SZ];
  int    i;

  /* Preprocess:
   *  Copy the input (bytewise) array into a wordwise array.
   *  Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset(words, 0, sizeof(words));
  for (i = 0; i < IN6ADDRSZ; i++)
      words[i/2] |= (src[i] << ((1 - (i % 2)) << 3));

  best.base = -1;
  cur.base  = -1;
  for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
  {
    if (words[i] == 0)
    {
      if (cur.base == -1)
        cur.base = i, cur.len = 1;
      else
        cur.len++;
    }
    else if (cur.base != -1)
    {
      if (best.base == -1 || cur.len > best.len)
         best = cur;
      cur.base = -1;
    }
  }
  if ((cur.base != -1) && (best.base == -1 || cur.len > best.len))
     best = cur;
  if (best.base != -1 && best.len < 2)
     best.base = -1;

  /* Format the result.
   */
  tp = tmp;
  for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
  {
    /* Are we inside the best run of 0x00's?
     */
    if (best.base != -1 && i >= best.base && i < (best.base + best.len))
    {
      if (i == best.base)
         *tp++ = ':';
      continue;
    }

    /* Are we following an initial run of 0x00s or any real hex?
     */
    if (i != 0)
       *tp++ = ':';

    /* Is this address an encapsulated IPv4?
     */
    if (i == 6 && best.base == 0 &&
        (best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
    {
      if (!inet_ntop4(src+12, tp, sizeof(tmp) - (tp - tmp)))
      {
        SET_ERRNO(ENOSPC);
        return (NULL);
      }
      tp += strlen(tp);
      break;
    }
    tp += snprintf(tp, 5, "%lx", words[i]);
  }

  /* Was it a trailing run of 0x00's?
   */
  if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
     *tp++ = ':';
  *tp++ = '\0';

  /* Check for overflow, copy, and we're done.
   */
  if ((size_t)(tp - tmp) > size)
  {
    SET_ERRNO(ENOSPC);
    return (NULL);
  }
  return strcpy (dst, tmp);
}
#endif  /* ENABLE_IPV6 */

/*
 * Convert a network format address to presentation format.
 *
 * Returns pointer to presentation format address (`buf'),
 * Returns NULL on error (see errno).
 */
char *Curl_inet_ntop(int af, const void *src, char *buf, size_t size)
{
  switch (af) {
  case AF_INET:
    return inet_ntop4((const u_char*)src, buf, size);
#ifdef ENABLE_IPV6
  case AF_INET6:
    return inet_ntop6((const u_char*)src, buf, size);
#endif
  default:
    SET_ERRNO(EAFNOSUPPORT);
    return NULL;
  }
}
#endif  /* HAVE_INET_NTOP */
