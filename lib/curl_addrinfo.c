/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 ***************************************************************************/

#include "setup.h"

#include <curl/curl.h>

#ifdef NEED_MALLOC_H
#  include <malloc.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#ifdef  VMS
#  include <in.h>
#  include <inet.h>
#  include <stdlib.h>
#endif

#if defined(NETWARE) && defined(__NOVELL_LIBC__)
#  undef  in_addr_t
#  define in_addr_t unsigned long
#endif

#include "curl_addrinfo.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "memory.h"
/* The last #include file should be: */
#include "memdebug.h"


/*
 * Curl_freeaddrinfo()
 *
 * This is used to free a linked list of Curl_addrinfo structs along
 * with all its associated allocated storage. This function should be
 * called once for each successful call to Curl_getaddrinfo_ex() or to
 * any function call which actually allocates a Curl_addrinfo struct.
 */

void
Curl_freeaddrinfo(Curl_addrinfo *cahead)
{
  Curl_addrinfo *ca, *canext;

  for(ca = cahead; ca != NULL; ca = canext) {

    if(ca->ai_addr)
      free(ca->ai_addr);

    if(ca->ai_canonname)
      free(ca->ai_canonname);

    canext = ca->ai_next;

    free(ca);
  }
}


#ifdef HAVE_GETADDRINFO
/*
 * Curl_getaddrinfo_ex()
 *
 * This is a warapper function around system's getaddrinfo(), with
 * the only difference that instead of returning a linked list of
 * addrinfo structs this one returns a linked list of Curl_addrinfo
 * ones. The memory allocated by this function *MUST* be free'd with
 * Curl_freeaddrinfo().  For each successful call to this function
 * there must be an associated call later to Curl_freeaddrinfo().
 *
 * There should be no single call to system's getaddrinfo() in the
 * whole library, any such call should be 'routed' through this one.
 */

int
Curl_getaddrinfo_ex(const char *nodename,
                    const char *servname,
                    const struct addrinfo *hints,
                    Curl_addrinfo **result)
{
  const struct addrinfo *ainext;
  const struct addrinfo *ai;
  struct addrinfo *aihead;
  Curl_addrinfo *cafirst = NULL;
  Curl_addrinfo *calast = NULL;
  Curl_addrinfo *ca;
  int error;

  *result = NULL; /* assume failure */

  error = getaddrinfo(nodename, servname, hints, &aihead);
  if(error)
    return error;

  for(ai = aihead; ai != NULL; ai = ainext) {

    if((ca = malloc(sizeof(Curl_addrinfo))) == NULL) {
      error = EAI_MEMORY;
      break;
    }

    /* copy each structure member individually, member ordering, */
    /* size, or padding might be different for each structure.   */

    ca->ai_flags     = ai->ai_flags;
    ca->ai_family    = ai->ai_family;
    ca->ai_socktype  = ai->ai_socktype;
    ca->ai_protocol  = ai->ai_protocol;
    ca->ai_addrlen   = 0;
    ca->ai_addr      = NULL;
    ca->ai_canonname = NULL;
    ca->ai_next      = NULL;

    if((ai->ai_addrlen > 0) && (ai->ai_addr != NULL)) {
      ca->ai_addrlen  = ai->ai_addrlen;
      if((ca->ai_addr = malloc(ca->ai_addrlen)) == NULL) {
        error = EAI_MEMORY;
        free(ca);
        break;
      }
      memcpy(ca->ai_addr, ai->ai_addr, ca->ai_addrlen);
    }

    if(ai->ai_canonname != NULL) {
      if((ca->ai_canonname = strdup(ai->ai_canonname)) == NULL) {
        error = EAI_MEMORY;
        if(ca->ai_addr)
          free(ca->ai_addr);
        free(ca);
        break;
      }
    }

    /* if the return list is empty, this becomes the first element */
    if(!cafirst)
      cafirst = ca;

    /* add this element last in the return list */
    if(calast)
      calast->ai_next = ca;
    calast = ca;

    /* fetch next element fom the addrinfo list */
    ainext = ai->ai_next;
  }

  /* destroy the addrinfo list */
  if(aihead)
    freeaddrinfo(aihead);

  /* if we failed, also destroy the Curl_addrinfo list */
  if(error) {
    Curl_freeaddrinfo(cafirst);
    cafirst = NULL;
  }

  *result = cafirst;

  return error; /* This is not a CURLcode */
}
#endif /* HAVE_GETADDRINFO */


/*
 * Curl_he2ai()
 *
 * This function returns a pointer to the first element of a newly allocated
 * Curl_addrinfo struct linked list filled with the data of a given hostent.
 * Curl_addrinfo is meant to work like the addrinfo struct does for a IPv6
 * stack, but usable also for IPv4, all hosts and environments.
 *
 * The memory allocated by this function *MUST* be free'd later on calling
 * Curl_freeaddrinfo().  For each successful call to this function there
 * must be an associated call later to Curl_freeaddrinfo().
 *
 *   Curl_addrinfo defined in "lib/curl_addrinfo.h"
 *
 *     struct Curl_addrinfo {
 *       int                   ai_flags;
 *       int                   ai_family;
 *       int                   ai_socktype;
 *       int                   ai_protocol;
 *       socklen_t             ai_addrlen;   * Follow rfc3493 struct addrinfo *
 *       char                 *ai_canonname;
 *       struct sockaddr      *ai_addr;
 *       struct Curl_addrinfo *ai_next;
 *     };
 *     typedef struct Curl_addrinfo Curl_addrinfo;
 *
 *   hostent defined in <netdb.h>
 *
 *     struct hostent {
 *       char    *h_name;
 *       char    **h_aliases;
 *       int     h_addrtype;
 *       int     h_length;
 *       char    **h_addr_list;
 *     };
 *
 *   for backward compatibility:
 *
 *     #define h_addr  h_addr_list[0]
 */

Curl_addrinfo *
Curl_he2ai(const struct hostent *he, int port)
{
  Curl_addrinfo *ai;
  Curl_addrinfo *prevai = NULL;
  Curl_addrinfo *firstai = NULL;
  struct sockaddr_in *addr;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *addr6;
#endif
  CURLcode result = CURLE_OK;
  int i;
  char *curr;

  if(!he)
    /* no input == no output! */
    return NULL;

  for(i=0; (curr = he->h_addr_list[i]) != NULL; i++) {

    int ss_size;
#ifdef ENABLE_IPV6
    if (he->h_addrtype == AF_INET6)
      ss_size = sizeof (struct sockaddr_in6);
    else
#endif
      ss_size = sizeof (struct sockaddr_in);

    if((ai = calloc(1, sizeof(Curl_addrinfo))) == NULL) {
      result = CURLE_OUT_OF_MEMORY;
      break;
    }
    if((ai->ai_canonname = strdup(he->h_name)) == NULL) {
      result = CURLE_OUT_OF_MEMORY;
      free(ai);
      break;
    }
    if((ai->ai_addr = calloc(1, ss_size)) == NULL) {
      result = CURLE_OUT_OF_MEMORY;
      free(ai->ai_canonname);
      free(ai);
      break;
    }

    if(!firstai)
      /* store the pointer we want to return from this function */
      firstai = ai;

    if(prevai)
      /* make the previous entry point to this */
      prevai->ai_next = ai;

    ai->ai_family = he->h_addrtype;

    /* we return all names as STREAM, so when using this address for TFTP
       the type must be ignored and conn->socktype be used instead! */
    ai->ai_socktype = SOCK_STREAM;

    ai->ai_addrlen = ss_size;

    /* leave the rest of the struct filled with zero */

    switch (ai->ai_family) {
    case AF_INET:
      addr = (struct sockaddr_in *)ai->ai_addr; /* storage area for this info */

      memcpy(&addr->sin_addr, curr, sizeof(struct in_addr));
      addr->sin_family = (unsigned short)(he->h_addrtype);
      addr->sin_port = htons((unsigned short)port);
      break;

#ifdef ENABLE_IPV6
    case AF_INET6:
      addr6 = (struct sockaddr_in6 *)ai->ai_addr; /* storage area for this info */

      memcpy(&addr6->sin6_addr, curr, sizeof(struct in6_addr));
      addr6->sin6_family = (unsigned short)(he->h_addrtype);
      addr6->sin6_port = htons((unsigned short)port);
      break;
#endif
    }

    prevai = ai;
  }

  if(result != CURLE_OK) {
    /* Use parenthesis to prevent memdebug from replacing this */
    Curl_freeaddrinfo(firstai);
    firstai = NULL;
  }

  return firstai;
}

