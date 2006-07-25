/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <string.h>

#ifdef NEED_MALLOC_H
#include <malloc.h>
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
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>     /* required for free() prototypes */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>     /* for the close() proto */
#endif
#ifdef  VMS
#include <in.h>
#include <inet.h>
#include <stdlib.h>
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#ifdef HAVE_PROCESS_H
#include <process.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "strerror.h"
#include "url.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

#include "memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/***********************************************************************
 * Only for builds using asynchronous name resolves
 **********************************************************************/
#ifdef CURLRES_ASYNCH
/*
 * addrinfo_callback() gets called by ares, gethostbyname_thread() or
 * getaddrinfo_thread() when we got the name resolved (or not!).
 *
 * If the status argument is CURL_ASYNC_SUCCESS, we might need to copy the
 * address field since it might be freed when this function returns. This
 * operation stores the resolved data in the DNS cache.
 *
 * NOTE: for IPv6 operations, Curl_addrinfo_copy() returns the same
 * pointer it is given as argument!
 *
 * The storage operation locks and unlocks the DNS cache.
 */
static CURLcode addrinfo_callback(void *arg, /* "struct connectdata *" */
                                  int status,
                                  void *addr)
{
  struct connectdata *conn = (struct connectdata *)arg;
  struct Curl_dns_entry *dns = NULL;
  CURLcode rc = CURLE_OK;

  conn->async.status = status;

  if(CURL_ASYNC_SUCCESS == status) {

    /*
     * IPv4/ares: Curl_addrinfo_copy() copies the address and returns an
     * allocated version.
     *
     * IPv6: Curl_addrinfo_copy() returns the input pointer!
     */
    Curl_addrinfo *ai = Curl_addrinfo_copy(addr, conn->async.port);
    if(ai) {
      struct SessionHandle *data = conn->data;

      if(data->share)
        Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);

      dns = Curl_cache_addr(data, ai,
                            conn->async.hostname,
                            conn->async.port);
      if(!dns) {
        /* failed to store, cleanup and return error */
        Curl_freeaddrinfo(ai);
        rc = CURLE_OUT_OF_MEMORY;
      }

      if(data->share)
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
    }
    else
      rc = CURLE_OUT_OF_MEMORY;
  }

  conn->async.dns = dns;

 /* Set async.done TRUE last in this function since it may be used multi-
    threaded and once this is TRUE the other thread may read fields from the
    async struct */
  conn->async.done = TRUE;

  /* ipv4: The input hostent struct will be freed by ares when we return from
     this function */
  return rc;
}

CURLcode Curl_addrinfo4_callback(void *arg, /* "struct connectdata *" */
                                 int status,
                                 struct hostent *hostent)
{
  return addrinfo_callback(arg, status, hostent);
}

#ifdef CURLRES_IPV6
CURLcode Curl_addrinfo6_callback(void *arg, /* "struct connectdata *" */
                                 int status,
                                 struct addrinfo *ai)
{
 /* NOTE: for CURLRES_ARES, the 'ai' argument is really a
  * 'struct hostent' pointer.
  */
  return addrinfo_callback(arg, status, ai);
}
#endif

#endif /* CURLRES_ASYNC */
