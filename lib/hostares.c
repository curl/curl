/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include <errno.h>

#define _REENTRANT

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <malloc.h>
#else
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
#include <stdlib.h>	/* required for free() prototypes */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>     /* for the close() proto */
#endif
#ifdef	VMS
#include <in.h>
#include <inet.h>
#include <stdlib.h>
#endif
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#ifdef WIN32
#include <process.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
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

/* The last #include file should be: */
#ifdef CURLDEBUG
#include "memdebug.h"
#endif

/***********************************************************************
 * Only for ares-enabled builds
 **********************************************************************/

#ifdef CURLRES_ARES

/*
 * Curl_fdset() is called when someone from the outside world (using
 * curl_multi_fdset()) wants to get our fd_set setup and we're talking with
 * ares. The caller must make sure that this function is only called when we
 * have a working ares channel.
 *
 * Returns: CURLE_OK always!
 */

CURLcode Curl_fdset(struct connectdata *conn,
                    fd_set *read_fd_set,
                    fd_set *write_fd_set,
                    int *max_fdp)

{
  int max = ares_fds(conn->data->state.areschannel,
                     read_fd_set, write_fd_set);
  *max_fdp = max;

  return CURLE_OK;
}

/*
 * Curl_is_resolved() is called repeatedly to check if a previous name resolve
 * request has completed. It should also make sure to time-out if the
 * operation seems to take too long.
 *
 * Returns normal CURLcode errors.
 */
CURLcode Curl_is_resolved(struct connectdata *conn,
                          struct Curl_dns_entry **dns)
{
  fd_set read_fds, write_fds;
  struct timeval tv={0,0};
  struct SessionHandle *data = conn->data;
  int nfds;

  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);

  nfds = ares_fds(data->state.areschannel, &read_fds, &write_fds);

  (void)select(nfds, &read_fds, &write_fds, NULL,
               (struct timeval *)&tv);

  /* Call ares_process() unconditonally here, even if we simply timed out
     above, as otherwise the ares name resolve won't timeout! */
  ares_process(data->state.areschannel, &read_fds, &write_fds);

  *dns = NULL;

  if(conn->async.done) {
    /* we're done, kill the ares handle */
    if(!conn->async.dns)
      return CURLE_COULDNT_RESOLVE_HOST;
    *dns = conn->async.dns;
  }

  return CURLE_OK;
}

/*
 * Curl_wait_for_resolv() waits for a resolve to finish. This function should
 * be avoided since using this risk getting the multi interface to "hang".
 *
 * If 'entry' is non-NULL, make it point to the resolved dns entry
 *
 * Returns CURLE_COULDNT_RESOLVE_HOST if the host was not resolved, and
 * CURLE_OPERATION_TIMEDOUT if a time-out occurred.
 */
CURLcode Curl_wait_for_resolv(struct connectdata *conn,
                              struct Curl_dns_entry **entry)
{
  CURLcode rc=CURLE_OK;
  struct SessionHandle *data = conn->data;
  long timeout = CURL_TIMEOUT_RESOLVE; /* default name resolve timeout */

  /* now, see if there's a connect timeout or a regular timeout to
     use instead of the default one */
  if(conn->data->set.connecttimeout)
    timeout = conn->data->set.connecttimeout;
  else if(conn->data->set.timeout)
    timeout = conn->data->set.timeout;

  /* We convert the number of seconds into number of milliseconds here: */
  if(timeout < 2147483)
    /* maximum amount of seconds that can be multiplied with 1000 and
       still fit within 31 bits */
    timeout *= 1000;
  else
    timeout = 0x7fffffff; /* ridiculous amount of time anyway */

  /* Wait for the name resolve query to complete. */
  while (1) {
    int nfds=0;
    fd_set read_fds, write_fds;
    struct timeval *tvp, tv, store;
    int count;
    struct timeval now = Curl_tvnow();
    long timediff;

    store.tv_sec = (int)timeout/1000;
    store.tv_usec = (timeout%1000)*1000;
    
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    nfds = ares_fds(data->state.areschannel, &read_fds, &write_fds);
    if (nfds == 0)
      /* no file descriptors means we're done waiting */
      break;
    tvp = ares_timeout(data->state.areschannel, &store, &tv);
    count = select(nfds, &read_fds, &write_fds, NULL, tvp);
    if (count < 0 && errno != EINVAL)
      break;

    ares_process(data->state.areschannel, &read_fds, &write_fds);

    timediff = Curl_tvdiff(Curl_tvnow(), now); /* spent time */
    timeout -= timediff?timediff:1; /* always deduct at least 1 */
    if (timeout < 0) {
      /* our timeout, so we cancel the ares operation */
      ares_cancel(data->state.areschannel);
      break;
    }
  }

  /* Operation complete, if the lookup was successful we now have the entry
     in the cache. */
    
  if(entry)
    *entry = conn->async.dns;

  if(!conn->async.dns) {
    /* a name was not resolved */
    if((timeout < 0) || (conn->async.status == ARES_ETIMEOUT)) {
      failf(data, "Resolving host timed out: %s", conn->hostname);
      rc = CURLE_OPERATION_TIMEDOUT;
    }
    else if(conn->async.done) {
      failf(data, "Could not resolve host: %s (%s)", conn->hostname,
            ares_strerror(conn->async.status));
      rc = CURLE_COULDNT_RESOLVE_HOST;
    }
    else
      rc = CURLE_OPERATION_TIMEDOUT;

    /* close the connection, since we can't return failure here without
       cleaning up this connection properly */
    Curl_disconnect(conn);
  }
  
  return rc;
}

/*
 * Curl_getaddrinfo() - when using ares
 *
 * Returns name information about the given hostname and port number. If
 * successful, the 'hostent' is returned and the forth argument will point to
 * memory we need to free after use. That memory *MUST* be freed with
 * Curl_freeaddrinfo(), nothing else.
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                char *hostname,
                                int port,
                                int *waitp)
{
  char *bufp;
  struct SessionHandle *data = conn->data;
  in_addr_t in = inet_addr(hostname);

  *waitp = FALSE;
  
  if (in != CURL_INADDR_NONE)
    /* This is a dotted IP address 123.123.123.123-style */
    return Curl_ip2addr(in, hostname);

  bufp = strdup(hostname);

  if(bufp) {
    Curl_safefree(conn->async.hostname);
    conn->async.hostname = bufp;
    conn->async.port = port;
    conn->async.done = FALSE; /* not done */
    conn->async.status = 0;   /* clear */
    conn->async.dns = NULL;   /* clear */

    /* areschannel is already setup in the Curl_open() function */
    ares_gethostbyname(data->state.areschannel, hostname, PF_INET,
                       Curl_addrinfo_callback, conn);
      
    *waitp = TRUE; /* please wait for the response */
  }
  return NULL; /* no struct yet */
}

#endif /* CURLRES_ARES */
