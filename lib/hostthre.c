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

#include "inet_ntop.h"

/* The last #include file should be: */
#ifdef CURLDEBUG
#include "memdebug.h"
#endif

/***********************************************************************
 * Only for Windows threaded name resolves builds
 **********************************************************************/
#ifdef CURLRES_THREADED

/* This function is used to init a threaded resolve */
static bool init_resolve_thread(struct connectdata *conn,
                                const char *hostname, int port,
                                const Curl_addrinfo *hints);

#ifdef CURLRES_IPV4
  #define THREAD_FUNC  gethostbyname_thread
  #define THREAD_NAME "gethostbyname_thread"
#else
  #define THREAD_FUNC  getaddrinfo_thread
  #define THREAD_NAME "getaddrinfo_thread"
#endif

#if defined(DEBUG_THREADING_GETHOSTBYNAME) || \
    defined(DEBUG_THREADING_GETADDRINFO)
/* If this is defined, provide tracing */
#define TRACE(args)  \
 do { trace_it("%u: ", __LINE__); trace_it args; } while (0)

static void trace_it (const char *fmt, ...)
{
  static int do_trace = -1;
  va_list args;

  if (do_trace == -1) {
    const char *env = getenv("CURL_TRACE");
    do_trace = (env && atoi(env) > 0);
  }
  if (!do_trace)
    return;
  va_start (args, fmt);
  vfprintf (stderr, fmt, args);
  fflush (stderr);
  va_end (args);
}
#else
#define TRACE(x)
#endif

#ifdef DEBUG_THREADING_GETADDRINFO
static void dump_addrinfo (struct connectdata *conn, const struct addrinfo *ai)
{
  TRACE(("dump_addrinfo:\n"));
  for ( ; ai; ai = ai->ai_next) {
    char  buf [INET6_ADDRSTRLEN];

    trace_it("    fam %2d, CNAME %s, ",
             ai->ai_family, ai->ai_canonname ? ai->ai_canonname : "<none>");
    if (Curl_printable_address(ai->ai_family, ai->ai_addr, buf, sizeof(buf)))
      trace_it("%s\n", buf);
    else
      trace_it("failed; %s\n", Curl_strerror(conn,WSAGetLastError()));
  }
}
#endif

struct thread_data {
  HANDLE thread_hnd;
  unsigned thread_id;
  DWORD  thread_status;
  curl_socket_t dummy_sock;   /* dummy for Curl_fdset() */
  FILE *stderr_file;
#ifdef CURLRES_IPV6
  struct addrinfo hints;
#endif
};

#if defined(CURLRES_IPV4)
/*
 * gethostbyname_thread() resolves a name, calls the Curl_addrinfo_callback
 * and then exits.
 *
 * For builds without ARES/ENABLE_IPV6, create a resolver thread and wait on
 * it.
 */
static unsigned __stdcall gethostbyname_thread (void *arg)
{
  struct connectdata *conn = (struct connectdata*) arg;
  struct thread_data *td = (struct thread_data*) conn->async.os_specific;
  struct hostent *he;
  int    rc;

  /* Sharing the same _iob[] element with our parent thread should
   * hopefully make printouts synchronised. I'm not sure it works
   * with a static runtime lib (MSVC's libc.lib).
   */
  *stderr = *td->stderr_file;

  WSASetLastError (conn->async.status = NO_DATA); /* pending status */
  he = gethostbyname (conn->async.hostname);
  if (he) {
    Curl_addrinfo_callback(conn, CURL_ASYNC_SUCCESS, he);
    rc = 1;
  }
  else {
    Curl_addrinfo_callback(conn, (int)WSAGetLastError(), NULL);
    rc = 0;
  }
  TRACE(("Winsock-error %d, addr %s\n", conn->async.status,
         he ? inet_ntoa(*(struct in_addr*)he->h_addr) : "unknown"));
  return (rc);
  /* An implicit _endthreadex() here */
}

#elif defined(CURLRES_IPV6)

/*
 * getaddrinfo_thread() resolves a name, calls Curl_addrinfo_callback and then
 * exits.
 *
 * For builds without ARES, but with ENABLE_IPV6, create a resolver thread
 * and wait on it.
 */
static unsigned __stdcall getaddrinfo_thread (void *arg)
{
  struct connectdata *conn = (struct connectdata*) arg;
  struct thread_data *td   = (struct thread_data*) conn->async.os_specific;
  struct addrinfo    *res;
  char   service [NI_MAXSERV];
  int    rc;

  *stderr = *td->stderr_file;

  itoa(conn->async.port, service, 10);

  WSASetLastError(conn->async.status = NO_DATA); /* pending status */

  rc = getaddrinfo(conn->async.hostname, service, &td->hints, &res);

  if (rc == 0) {
#ifdef DEBUG_THREADING_GETADDRINFO
    dump_addrinfo (conn, res);
#endif
    Curl_addrinfo_callback(conn, CURL_ASYNC_SUCCESS, res);
  }
  else {
    Curl_addrinfo_callback(conn, (int)WSAGetLastError(), NULL);
    TRACE(("Winsock-error %d, no address\n", conn->async.status));
  }
  return (rc);
  /* An implicit _endthreadex() here */
}
#endif

/*
 * destroy_thread_data() cleans up async resolver data.
 * Complementary of ares_destroy.
 */
static void destroy_thread_data (struct Curl_async *async)
{
  if (async->hostname)
    free(async->hostname);

  if (async->os_specific) {
    curl_socket_t sock = ((const struct thread_data*)async->os_specific)->dummy_sock;

    if (sock != CURL_SOCKET_BAD)
      sclose(sock);
    free(async->os_specific);
  }
  async->hostname = NULL;
  async->os_specific = NULL;
}

/*
 * init_resolve_thread() starts a new thread that performs the actual
 * resolve. This function returns before the resolve is done.
 *
 * Returns FALSE in case of failure, otherwise TRUE.
 */
static bool init_resolve_thread (struct connectdata *conn,
                                 const char *hostname, int port,
                                 const Curl_addrinfo *hints)
{
  struct thread_data *td = calloc(sizeof(*td), 1);

  if (!td) {
    SetLastError(ENOMEM);
    return FALSE;
  }

  Curl_safefree(conn->async.hostname);
  conn->async.hostname = strdup(hostname);
#ifdef USE_LIBIDN
  if (conn->ace_hostname)
    TRACE(("ACE name '%s'\n", conn->ace_hostname));
#endif
  if (!conn->async.hostname) {
    free(td);
    SetLastError(ENOMEM);
    return FALSE;
  }

  conn->async.port = port;
  conn->async.done = FALSE;
  conn->async.status = 0;
  conn->async.dns = NULL;
  conn->async.os_specific = (void*) td;

  td->dummy_sock = CURL_SOCKET_BAD;
  td->stderr_file = stderr;
  td->thread_hnd = (HANDLE) _beginthreadex(NULL, 0, THREAD_FUNC,
                                           conn, 0, &td->thread_id);
#ifdef CURLRES_IPV6
  curlassert(hints);
  td->hints = *hints;
#else
  (void) hints;
#endif

  if (!td->thread_hnd) {
     SetLastError(errno);
     TRACE(("_beginthreadex() failed; %s\n", Curl_strerror(conn,errno)));
     destroy_thread_data(&conn->async);
     return FALSE;
  }
  /* This socket is only to keep Curl_fdset() and select() happy; should never
   * become signalled for read/write since it's unbound but Windows needs
   * atleast 1 socket in select().
   */
  td->dummy_sock = socket(AF_INET, SOCK_DGRAM, 0);
  return TRUE;
}


/*
 * Curl_wait_for_resolv() waits for a resolve to finish. This function should
 * be avoided since using this risk getting the multi interface to "hang".
 *
 * If 'entry' is non-NULL, make it point to the resolved dns entry
 *
 * This is the version for resolves-in-a-thread.
 */
CURLcode Curl_wait_for_resolv(struct connectdata *conn,
                              struct Curl_dns_entry **entry)
{
  struct thread_data   *td = (struct thread_data*) conn->async.os_specific;
  struct SessionHandle *data = conn->data;
  long   timeout;
  DWORD  status, ticks;
  CURLcode rc;

  curlassert (conn && td);

  /* now, see if there's a connect timeout or a regular timeout to
     use instead of the default one */
  timeout =
    conn->data->set.connecttimeout ? conn->data->set.connecttimeout :
    conn->data->set.timeout ? conn->data->set.timeout :
    CURL_TIMEOUT_RESOLVE; /* default name resolve timeout */
  ticks = GetTickCount();

  status = WaitForSingleObject(td->thread_hnd, 1000UL*timeout);
  if (status == WAIT_OBJECT_0 || status == WAIT_ABANDONED) {
     /* Thread finished before timeout; propagate Winsock error to this thread.
      * 'conn->async.done = TRUE' is set in Curl_addrinfo_callback().
      */
     WSASetLastError(conn->async.status);
     GetExitCodeThread(td->thread_hnd, &td->thread_status);
     TRACE(("%s() status %lu, thread retval %lu, ",
            THREAD_NAME, status, td->thread_status));
  }
  else {
     conn->async.done = TRUE;
     td->thread_status = (DWORD)-1;
     TRACE(("%s() timeout, ", THREAD_NAME));
  }

  TRACE(("elapsed %lu ms\n", GetTickCount()-ticks));

  CloseHandle(td->thread_hnd);

  if(entry)
    *entry = conn->async.dns;

  rc = CURLE_OK;

  if (!conn->async.dns) {
    /* a name was not resolved */
    if (td->thread_status == (DWORD)-1 || conn->async.status == NO_DATA) {
      failf(data, "Resolving host timed out: %s", conn->hostname);
      rc = CURLE_OPERATION_TIMEDOUT;
    }
    else if(conn->async.done) {
      failf(data, "Could not resolve host: %s; %s",
            conn->hostname, Curl_strerror(conn,conn->async.status));
      rc = CURLE_COULDNT_RESOLVE_HOST;
    }
    else
      rc = CURLE_OPERATION_TIMEDOUT;
  }

  destroy_thread_data(&conn->async);

  if(CURLE_OK != rc)
    /* close the connection, since we must not return failure from here
       without cleaning up this connection properly */
    Curl_disconnect(conn);

  return (rc);
}

/*
 * Curl_is_resolved() is called repeatedly to check if a previous name resolve
 * request has completed. It should also make sure to time-out if the
 * operation seems to take too long.
 */
CURLcode Curl_is_resolved(struct connectdata *conn,
                          struct Curl_dns_entry **entry)
{
  *entry = NULL;

  if (conn->async.done) {
    /* we're done */
    destroy_thread_data(&conn->async);
    if (!conn->async.dns) {
      TRACE(("Curl_is_resolved(): CURLE_COULDNT_RESOLVE_HOST\n"));
      return CURLE_COULDNT_RESOLVE_HOST;
    }
    *entry = conn->async.dns;
    TRACE(("resolved okay, dns %p\n", *entry));
  }
  else
    TRACE(("not yet\n"));
  return CURLE_OK;
}

CURLcode Curl_fdset(struct connectdata *conn,
                    fd_set *read_fd_set,
                    fd_set *write_fd_set,
                    int *max_fdp)
{
  const struct thread_data *td =
    (const struct thread_data *) conn->async.os_specific;

  if (td && td->dummy_sock != CURL_SOCKET_BAD) {
    FD_SET(td->dummy_sock,write_fd_set);
    *max_fdp = td->dummy_sock;
  }
  (void) read_fd_set;
  return CURLE_OK;
}

#ifdef CURLRES_IPV4
/*
 * Curl_getaddrinfo() - for Windows threading without ENABLE_IPV6.
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                char *hostname,
                                int port,
                                int *waitp)
{
  struct hostent *h = NULL;
  struct SessionHandle *data = conn->data;
  in_addr_t in;

  *waitp = 0; /* don't wait, we act synchronously */

  in = inet_addr(hostname);
  if (in != CURL_INADDR_NONE)
    /* This is a dotted IP address 123.123.123.123-style */
    return Curl_ip2addr(in, hostname);

  /* fire up a new resolver thread! */
  if (init_resolve_thread(conn, hostname, port, NULL)) {
    *waitp = TRUE;  /* please wait for the response */
    return NULL;
  }

  /* fall-back to blocking version */
  infof(data, "init_resolve_thread() failed for %s; code %lu\n",
        hostname, GetLastError());

  h = gethostbyname(hostname);
  if (!h) {
    infof(data, "gethostbyname(2) failed for %s:%d; %s\n",
          hostname, port, Curl_strerror(conn,WSAGetLastError()));
    return NULL;
  }
  return h;
}
#endif /* CURLRES_IPV4 */

#ifdef CURLRES_IPV6
/*
 * Curl_getaddrinfo() - for Windows threading IPv6 enabled
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                char *hostname,
                                int port,
                                int *waitp)
{
  struct addrinfo hints, *res;
  int error;
  char sbuf[NI_MAXSERV];
  curl_socket_t s;
  int pf;
  struct SessionHandle *data = conn->data;

  *waitp = FALSE; /* default to synch response */

  /* see if we have an IPv6 stack */
  s = socket(PF_INET6, SOCK_DGRAM, 0);
  if (s == CURL_SOCKET_BAD) {
    /* Some non-IPv6 stacks have been found to make very slow name resolves
     * when PF_UNSPEC is used, so thus we switch to a mere PF_INET lookup if
     * the stack seems to be a non-ipv6 one. */

    pf = PF_INET;
  }
  else {
    /* This seems to be an IPv6-capable stack, use PF_UNSPEC for the widest
     * possible checks. And close the socket again.
     */
    sclose(s);

    /*
     * Check if a more limited name resolve has been requested.
     */
    switch(data->set.ip_version) {
    case CURL_IPRESOLVE_V4:
      pf = PF_INET;
      break;
    case CURL_IPRESOLVE_V6:
      pf = PF_INET6;
      break;
    default:
      pf = PF_UNSPEC;
      break;
    }
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  itoa(port, sbuf, 10);

  /* fire up a new resolver thread! */
  if (init_resolve_thread(conn, hostname, port, &hints)) {
    *waitp = TRUE;  /* please wait for the response */
    return NULL;
  }

  /* fall-back to blocking version */
  infof(data, "init_resolve_thread() failed for %s; code %lu\n",
        hostname, GetLastError());

  error = getaddrinfo(hostname, sbuf, &hints, &res);
  if (error) {
    infof(data, "getaddrinfo() failed for %s:%d; %s\n",
          hostname, port, Curl_strerror(conn,WSAGetLastError()));
    return NULL;
  }
  return res;
}
#endif /* CURLRES_IPV6 */
#endif /* CURLRES_THREADED */
