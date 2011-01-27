/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

#include <string.h>

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
#ifdef __VMS
#include <in.h>
#include <inet.h>
#include <stdlib.h>
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

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/***********************************************************************
 * Only for builds using asynchronous name resolves
 **********************************************************************/
#ifdef CURLRES_ASYNCH

/*
 * Cancel all possibly still on-going resolves for this connection.
 */
void Curl_async_cancel(struct connectdata *conn)
{
  /* If we have a "half" response already received, we first clear that off
     so that nothing is tempted to use it */
  if(conn->async.temp_ai) {
    Curl_freeaddrinfo(conn->async.temp_ai);
    conn->async.temp_ai = NULL;
  }
}


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
  CURLcode rc = CURLE_OK;

  conn->async.status = status;

  if(CURL_ASYNC_SUCCESS == status) {
    if(ai) {
      struct SessionHandle *data = conn->data;

#if defined(ENABLE_IPV6) && defined(CURLRES_ARES) /* CURLRES_IPV6 */
      Curl_addrinfo *ai_tail = ai;

      while (ai_tail->ai_next)
        ai_tail = ai_tail->ai_next;

      /* Add the new results to the list of old results. */
      ai_tail->ai_next = conn->async.temp_ai;
      conn->async.temp_ai = ai;

      if(--conn->async.num_pending > 0)
        /* We are not done yet. Just return. */
        return CURLE_OK;

      /* make sure the temp pointer is cleared and isn't pointing to something
         we take care of below */
      conn->async.temp_ai = NULL;
#endif
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
    else {
#if defined(ENABLE_IPV6) && defined(CURLRES_ARES) /* CURLRES_IPV6 */
      if(--conn->async.num_pending > 0) {
        /* We are not done yet. Clean up and return.
	   This function will be called again. */
        if(conn->async.temp_ai) {
          Curl_freeaddrinfo(conn->async.temp_ai);
          conn->async.temp_ai = NULL;
        }
        return CURLE_OUT_OF_MEMORY;
      }
#endif
      rc = CURLE_OUT_OF_MEMORY;
    }
  }
#if defined(ENABLE_IPV6) && defined(CURLRES_ARES) /* CURLRES_IPV6 */
  else
  {
      if(--conn->async.num_pending > 0)
        /* We are not done yet. Just return. */
        return CURLE_OK;

      if(conn->async.temp_ai) {
        /* We are done, and while this latest request
           failed, some previous results exist. */
        struct SessionHandle *data = conn->data;

        if(data->share)
          Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);

        dns = Curl_cache_addr(data, conn->async.temp_ai,
                              conn->async.hostname,
                              conn->async.port);
        if(!dns) {
          /* failed to store, cleanup and return error */
          Curl_freeaddrinfo(conn->async.temp_ai);
          rc = CURLE_OUT_OF_MEMORY;
        }
        if(data->share)
          Curl_share_unlock(data, CURL_LOCK_DATA_DNS);

        /* make sure the temp pointer is cleared and isn't pointing to
           something we've taken care of already */
        conn->async.temp_ai = NULL;
      }
  }
#endif

  conn->async.dns = dns;

 /* Set async.done TRUE last in this function since it may be used multi-
    threaded and once this is TRUE the other thread may read fields from the
    async struct */
  conn->async.done = TRUE;

  /* ipv4: The input hostent struct will be freed by ares when we return from
     this function */
  return rc;
}

#endif /* CURLRES_ASYNCH */
