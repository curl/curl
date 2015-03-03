/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
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
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/***********************************************************************
 * Only for builds using asynchronous name resolves
 **********************************************************************/
#ifdef CURLRES_ASYNCH

/*
 * Curl_addrinfo_callback() gets called by ares, gethostbyname_thread()
 * or getaddrinfo_thread() when we got the name resolved (or not!).
 *
 * If the status argument is CURL_ASYNC_SUCCESS, this function takes
 * ownership of the Curl_addrinfo passed, storing the resolved data
 * in the DNS cache.
 *
 * The storage operation locks and unlocks the DNS cache.
 */
CURLcode Curl_addrinfo_callback(struct connectdata *conn,
                                int status,
                                struct Curl_addrinfo *ai)
{
  struct Curl_dns_entry *dns = NULL;
  CURLcode result = CURLE_OK;

  conn->async.status = status;

  if(CURL_ASYNC_SUCCESS == status) {
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
        result = CURLE_OUT_OF_MEMORY;
      }

      if(data->share)
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
    }
    else {
      result = CURLE_OUT_OF_MEMORY;
    }
  }

  conn->async.dns = dns;

 /* Set async.done TRUE last in this function since it may be used multi-
    threaded and once this is TRUE the other thread may read fields from the
    async struct */
  conn->async.done = TRUE;

  /* IPv4: The input hostent struct will be freed by ares when we return from
     this function */
  return result;
}

/* Call this function after Curl_connect() has returned async=TRUE and
   then a successful name resolve has been received.

   Note: this function disconnects and frees the conn data in case of
   resolve failure */
CURLcode Curl_async_resolved(struct connectdata *conn,
                             bool *protocol_done)
{
  CURLcode result;

  if(conn->async.dns) {
    conn->dns_entry = conn->async.dns;
    conn->async.dns = NULL;
  }

  result = Curl_setup_conn(conn, protocol_done);

  if(result)
    /* We're not allowed to return failure with memory left allocated
       in the connectdata struct, free those here */
    Curl_disconnect(conn, FALSE); /* close the connection */

  return result;
}

/*
 * Curl_getaddrinfo() is the generic low-level name resolve API within this
 * source file. There are several versions of this function - for different
 * name resolve layers (selected at build-time). They all take this same set
 * of arguments
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                const char *hostname,
                                int port,
                                int *waitp)
{
  return Curl_resolver_getaddrinfo(conn, hostname, port, waitp);
}

#endif /* CURLRES_ASYNCH */
