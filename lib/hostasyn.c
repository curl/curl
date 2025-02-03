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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

/***********************************************************************
 * Only for builds using asynchronous name resolves
 **********************************************************************/
#ifdef FETCHRES_ASYNCH

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

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "url.h"
#include "fetch_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/*
 * Fetch_addrinfo_callback() gets called by ares, gethostbyname_thread()
 * or getaddrinfo_thread() when we got the name resolved (or not!).
 *
 * If the status argument is FETCH_ASYNC_SUCCESS, this function takes
 * ownership of the Fetch_addrinfo passed, storing the resolved data
 * in the DNS cache.
 *
 * The storage operation locks and unlocks the DNS cache.
 */
FETCHcode Fetch_addrinfo_callback(struct Fetch_easy *data,
                                 int status,
                                 struct Fetch_addrinfo *ai)
{
  struct Fetch_dns_entry *dns = NULL;
  FETCHcode result = FETCHE_OK;

  data->state.async.status = status;

  if (FETCH_ASYNC_SUCCESS == status)
  {
    if (ai)
    {
      if (data->share)
        Fetch_share_lock(data, FETCH_LOCK_DATA_DNS, FETCH_LOCK_ACCESS_SINGLE);

      dns = Fetch_cache_addr(data, ai,
                            data->state.async.hostname, 0,
                            data->state.async.port, FALSE);
      if (data->share)
        Fetch_share_unlock(data, FETCH_LOCK_DATA_DNS);

      if (!dns)
      {
        /* failed to store, cleanup and return error */
        Fetch_freeaddrinfo(ai);
        result = FETCHE_OUT_OF_MEMORY;
      }
    }
    else
    {
      result = FETCHE_OUT_OF_MEMORY;
    }
  }

  data->state.async.dns = dns;

  /* Set async.done TRUE last in this function since it may be used multi-
     threaded and once this is TRUE the other thread may read fields from the
     async struct */
  data->state.async.done = TRUE;

  /* IPv4: The input hostent struct will be freed by ares when we return from
     this function */
  return result;
}

/*
 * Fetch_getaddrinfo() is the generic low-level name resolve API within this
 * source file. There are several versions of this function - for different
 * name resolve layers (selected at build-time). They all take this same set
 * of arguments
 */
struct Fetch_addrinfo *Fetch_getaddrinfo(struct Fetch_easy *data,
                                       const char *hostname,
                                       int port,
                                       int *waitp)
{
  return Fetch_resolver_getaddrinfo(data, hostname, port, waitp);
}

#endif /* FETCHRES_ASYNCH */
