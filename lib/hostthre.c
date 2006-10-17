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
#include <errno.h>

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
#include "multiif.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "inet_ntop.h"

#include "memory.h"
/* The last #include file should be: */
#include "memdebug.h"

#if defined(_MSC_VER) && defined(CURL_NO__BEGINTHREADEX)
#pragma message ("No _beginthreadex() available in this RTL")
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
    if (Curl_printable_address(ai, buf, sizeof(buf)))
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
  curl_socket_t dummy_sock;   /* dummy for Curl_resolv_fdset() */
  HANDLE mutex_waiting;  /* marks that we are still waiting for a resolve */
  HANDLE event_resolved; /* marks that the thread obtained the information */
  HANDLE event_thread_started; /* marks that the thread has initialized and
                                  started */
  HANDLE mutex_terminate; /* serializes access to flag_terminate */
  HANDLE event_terminate; /* flag for thread to terminate instead of calling
                             callbacks */
#ifdef CURLRES_IPV6
  struct addrinfo hints;
#endif
};

/* Data for synchronization between resolver thread and its parent */
struct thread_sync_data {
  HANDLE mutex_waiting;   /* thread_data.mutex_waiting duplicate */
  HANDLE mutex_terminate; /* thread_data.mutex_terminate duplicate */
  HANDLE event_terminate; /* thread_data.event_terminate duplicate */
  char * hostname;        /* hostname to resolve, Curl_async.hostname
                             duplicate */
};

/* Destroy resolver thread synchronization data */
static
void destroy_thread_sync_data(struct thread_sync_data * tsd)
{
  if (tsd->hostname) {
    free(tsd->hostname);
    tsd->hostname = NULL;
  }
  if (tsd->event_terminate) {
    CloseHandle(tsd->event_terminate);
    tsd->event_terminate = NULL;
  }
  if (tsd->mutex_terminate) {
    CloseHandle(tsd->mutex_terminate);
    tsd->mutex_terminate = NULL;
  }
  if (tsd->mutex_waiting) {
    CloseHandle(tsd->mutex_waiting);
    tsd->mutex_waiting = NULL;
  }
}

/* Initialize resolver thread synchronization data */
static
BOOL init_thread_sync_data(struct thread_data * td,
                           char * hostname,
                           struct thread_sync_data * tsd)
{
  HANDLE curr_proc = GetCurrentProcess();

  memset(tsd, 0, sizeof(*tsd));
  if (!DuplicateHandle(curr_proc, td->mutex_waiting,
                       curr_proc, &tsd->mutex_waiting, 0, FALSE,
                       DUPLICATE_SAME_ACCESS)) {
    /* failed to duplicate the mutex, no point in continuing */
    destroy_thread_sync_data(tsd);
    return FALSE;
  }
  if (!DuplicateHandle(curr_proc, td->mutex_terminate,
                       curr_proc, &tsd->mutex_terminate, 0, FALSE,
                       DUPLICATE_SAME_ACCESS)) {
    /* failed to duplicate the mutex, no point in continuing */
    destroy_thread_sync_data(tsd);
    return FALSE;
  }
  if (!DuplicateHandle(curr_proc, td->event_terminate,
                       curr_proc, &tsd->event_terminate, 0, FALSE,
                       DUPLICATE_SAME_ACCESS)) {
    /* failed to duplicate the event, no point in continuing */
    destroy_thread_sync_data(tsd);
    return FALSE;
  }
  /* Copying hostname string because original can be destroyed by parent
   * thread during gethostbyname execution.
   */
  tsd->hostname = strdup(hostname);
  if (!tsd->hostname) {
    /* Memory allocation failed */
    destroy_thread_sync_data(tsd);
    return FALSE;
  }
  return TRUE;
}

/* acquire resolver thread synchronization */
static
BOOL acquire_thread_sync(struct thread_sync_data * tsd)
{
  /* is the thread initiator still waiting for us ? */
  if (WaitForSingleObject(tsd->mutex_waiting, 0) == WAIT_TIMEOUT) {
    /* yes, it is */

    /* Waiting access to event_terminate */
    if (WaitForSingleObject(tsd->mutex_terminate, INFINITE) != WAIT_OBJECT_0) {
      /* Something went wrong - now just ignoring */
    }
    else {
      if (WaitForSingleObject(tsd->event_terminate, 0) != WAIT_TIMEOUT) {
        /* Parent thread signaled us to terminate.
         * This means that all data in conn->async is now destroyed
         * and we cannot use it.
         */
      }
      else {
        return TRUE;
      }
    }
  }
  return FALSE;
}

/* release resolver thread synchronization */
static
void release_thread_sync(struct thread_sync_data * tsd)
{
  ReleaseMutex(tsd->mutex_terminate);
}

#if defined(CURLRES_IPV4)
/*
 * gethostbyname_thread() resolves a name, calls the Curl_addrinfo4_callback
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
  int    rc = 0;

  /* Duplicate the passed mutex and event handles.
   * This allows us to use it even after the container gets destroyed
   * due to a resolver timeout.
   */
  struct thread_sync_data tsd = { 0,0,0,NULL };
  if (!init_thread_sync_data(td, conn->async.hostname, &tsd)) {
    /* thread synchronization data initialization failed */
    return (unsigned)-1;
  }

  WSASetLastError (conn->async.status = NO_DATA); /* pending status */

  /* Signaling that we have initialized all copies of data and handles we
     need */
  SetEvent(td->event_thread_started);

  he = gethostbyname (tsd.hostname);

  /* is parent thread waiting for us and are we able to access conn members? */
  if (acquire_thread_sync(&tsd)) {
    /* Mark that we have obtained the information, and that we are calling
     * back with it. */
    SetEvent(td->event_resolved);
    if (he) {
      rc = Curl_addrinfo4_callback(conn, CURL_ASYNC_SUCCESS, he);
    }
    else {
      rc = Curl_addrinfo4_callback(conn, (int)WSAGetLastError(), NULL);
    }
    TRACE(("Winsock-error %d, addr %s\n", conn->async.status,
           he ? inet_ntoa(*(struct in_addr*)he->h_addr) : "unknown"));
    release_thread_sync(&tsd);
  }

  /* clean up */
  destroy_thread_sync_data(&tsd);

  return (rc);
  /* An implicit _endthreadex() here */
}

#elif defined(CURLRES_IPV6)

/*
 * getaddrinfo_thread() resolves a name, calls Curl_addrinfo6_callback and then
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
  struct addrinfo hints = td->hints;

  /* Duplicate the passed mutex handle.
   * This allows us to use it even after the container gets destroyed
   * due to a resolver timeout.
   */
  struct thread_sync_data tsd = { 0,0,0,NULL };
  if (!init_thread_sync_data(td, conn->async.hostname, &tsd)) {
    /* thread synchronization data initialization failed */
    return -1;
  }

  itoa(conn->async.port, service, 10);

  WSASetLastError(conn->async.status = NO_DATA); /* pending status */

  /* Signaling that we have initialized all copies of data and handles we
     need */
  SetEvent(td->event_thread_started);

  rc = getaddrinfo(tsd.hostname, service, &hints, &res);

  /* is parent thread waiting for us and are we able to access conn members? */
  if (acquire_thread_sync(&tsd)) {
    /* Mark that we have obtained the information, and that we are calling
       back with it. */
    SetEvent(td->event_resolved);

    if (rc == 0) {
#ifdef DEBUG_THREADING_GETADDRINFO
      dump_addrinfo (conn, res);
#endif
      rc = Curl_addrinfo6_callback(conn, CURL_ASYNC_SUCCESS, res);
    }
    else {
      rc = Curl_addrinfo6_callback(conn, (int)WSAGetLastError(), NULL);
      TRACE(("Winsock-error %d, no address\n", conn->async.status));
    }
    release_thread_sync(&tsd);
  }

  /* clean up */
  destroy_thread_sync_data(&tsd);

  return (rc);
  /* An implicit _endthreadex() here */
}
#endif

/*
 * Curl_destroy_thread_data() cleans up async resolver data and thread handle.
 * Complementary of ares_destroy.
 */
void Curl_destroy_thread_data (struct Curl_async *async)
{
  if (async->hostname)
    free(async->hostname);

  if (async->os_specific) {
    struct thread_data *td = (struct thread_data*) async->os_specific;
    curl_socket_t sock = td->dummy_sock;

    if (td->mutex_terminate && td->event_terminate) {
      /* Signaling resolver thread to terminate */
      if (WaitForSingleObject(td->mutex_terminate, INFINITE) == WAIT_OBJECT_0) {
        SetEvent(td->event_terminate);
        ReleaseMutex(td->mutex_terminate);
      }
      else {
        /* Something went wrong - just ignoring it */
      }
    }

    if (td->mutex_terminate)
      CloseHandle(td->mutex_terminate);
    if (td->event_terminate)
      CloseHandle(td->event_terminate);
    if (td->event_thread_started)
      CloseHandle(td->event_thread_started);

    if (sock != CURL_SOCKET_BAD)
      sclose(sock);

    /* destroy the synchronization objects */
    if (td->mutex_waiting)
      CloseHandle(td->mutex_waiting);
    td->mutex_waiting = NULL;
    if (td->event_resolved)
      CloseHandle(td->event_resolved);

    if (td->thread_hnd)
      CloseHandle(td->thread_hnd);

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
  HANDLE thread_and_event[2] = {0};

  if (!td) {
    SetLastError(ENOMEM);
    return FALSE;
  }

  Curl_safefree(conn->async.hostname);
  conn->async.hostname = strdup(hostname);
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

  /* Create the mutex used to inform the resolver thread that we're
   * still waiting, and take initial ownership.
   */
  td->mutex_waiting = CreateMutex(NULL, TRUE, NULL);
  if (td->mutex_waiting == NULL) {
    Curl_destroy_thread_data(&conn->async);
    SetLastError(EAGAIN);
    return FALSE;
  }

  /* Create the event that the thread uses to inform us that it's
   * done resolving. Do not signal it.
   */
  td->event_resolved = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (td->event_resolved == NULL) {
    Curl_destroy_thread_data(&conn->async);
    SetLastError(EAGAIN);
    return FALSE;
  }
  /* Create the mutex used to serialize access to event_terminated
   * between us and resolver thread.
   */
  td->mutex_terminate = CreateMutex(NULL, FALSE, NULL);
  if (td->mutex_terminate == NULL) {
    Curl_destroy_thread_data(&conn->async);
    SetLastError(EAGAIN);
    return FALSE;
  }
  /* Create the event used to signal thread that it should terminate.
   */
  td->event_terminate = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (td->event_terminate == NULL) {
    Curl_destroy_thread_data(&conn->async);
    SetLastError(EAGAIN);
    return FALSE;
  }
  /* Create the event used by thread to inform it has initialized its own data.
   */
  td->event_thread_started = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (td->event_thread_started == NULL) {
    Curl_destroy_thread_data(&conn->async);
    SetLastError(EAGAIN);
    return FALSE;
  }

#ifdef _WIN32_WCE
  td->thread_hnd = (HANDLE) CreateThread(NULL, 0,
                                         (LPTHREAD_START_ROUTINE) THREAD_FUNC,
                                         conn, 0, &td->thread_id);
#else
  td->thread_hnd = (HANDLE) _beginthreadex(NULL, 0, THREAD_FUNC,
                                           conn, 0, &td->thread_id);
#endif

#ifdef CURLRES_IPV6
  curlassert(hints);
  td->hints = *hints;
#else
  (void) hints;
#endif

  if (!td->thread_hnd) {
#ifdef _WIN32_WCE
     TRACE(("CreateThread() failed; %s\n", Curl_strerror(conn,GetLastError())));
#else
     SetLastError(errno);
     TRACE(("_beginthreadex() failed; %s\n", Curl_strerror(conn,errno)));
#endif
     Curl_destroy_thread_data(&conn->async);
     return FALSE;
  }
  /* Waiting until the thread will initialize its data or it will exit due errors.
   */
  thread_and_event[0] = td->thread_hnd;
  thread_and_event[1] = td->event_thread_started;
  if (WaitForMultipleObjects(sizeof(thread_and_event) /
                             sizeof(thread_and_event[0]),
                             (const HANDLE*)thread_and_event, FALSE,
                             INFINITE) == WAIT_FAILED) {
    /* The resolver thread has been created,
     * most probably it works now - ignoring this "minor" error
     */
  }
  /* This socket is only to keep Curl_resolv_fdset() and select() happy;
   * should never become signalled for read/write since it's unbound but
   * Windows needs atleast 1 socket in select().
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

  /* wait for the thread to resolve the name */
  status = WaitForSingleObject(td->event_resolved, 1000UL*timeout);

  /* mark that we are now done waiting */
  ReleaseMutex(td->mutex_waiting);

  /* close our handle to the mutex, no point in hanging on to it */
  CloseHandle(td->mutex_waiting);
  td->mutex_waiting = NULL;

  /* close the event handle, it's useless now */
  CloseHandle(td->event_resolved);
  td->event_resolved = NULL;

  /* has the resolver thread succeeded in resolving our query ? */
  if (status == WAIT_OBJECT_0) {
    /* wait for the thread to exit, it's in the callback sequence */
    if (WaitForSingleObject(td->thread_hnd, 5000) == WAIT_TIMEOUT) {
      TerminateThread(td->thread_hnd, 0);
      conn->async.done = TRUE;
      td->thread_status = (DWORD)-1;
      TRACE(("%s() thread stuck?!, ", THREAD_NAME));
    }
    else {
      /* Thread finished before timeout; propagate Winsock error to this
       * thread.  'conn->async.done = TRUE' is set in
       * Curl_addrinfo4/6_callback().
       */
      WSASetLastError(conn->async.status);
      GetExitCodeThread(td->thread_hnd, &td->thread_status);
      TRACE(("%s() status %lu, thread retval %lu, ",
             THREAD_NAME, status, td->thread_status));
    }
  }
  else {
    conn->async.done = TRUE;
    td->thread_status = (DWORD)-1;
    TRACE(("%s() timeout, ", THREAD_NAME));
  }

  TRACE(("elapsed %lu ms\n", GetTickCount()-ticks));

  if(entry)
    *entry = conn->async.dns;

  rc = CURLE_OK;

  if (!conn->async.dns) {
    /* a name was not resolved */
    if (td->thread_status == CURLE_OUT_OF_MEMORY) {
      rc = CURLE_OUT_OF_MEMORY;
      failf(data, "Could not resolve host: %s", curl_easy_strerror(rc));
    }
    else if(conn->async.done) {
      if(conn->bits.httpproxy) {
        failf(data, "Could not resolve proxy: %s; %s",
              conn->proxy.dispname, Curl_strerror(conn, conn->async.status));
        rc = CURLE_COULDNT_RESOLVE_PROXY;
      }
      else {
        failf(data, "Could not resolve host: %s; %s",
              conn->host.name, Curl_strerror(conn, conn->async.status));
        rc = CURLE_COULDNT_RESOLVE_HOST;
      }
    }
    else if (td->thread_status == (DWORD)-1 || conn->async.status == NO_DATA) {
      failf(data, "Resolving host timed out: %s", conn->host.name);
      rc = CURLE_OPERATION_TIMEDOUT;
    }
    else
      rc = CURLE_OPERATION_TIMEDOUT;
  }

  Curl_destroy_thread_data(&conn->async);

  if(!conn->async.dns)
    conn->bits.close = TRUE;

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
    Curl_destroy_thread_data(&conn->async);
    if (!conn->async.dns) {
      TRACE(("Curl_is_resolved(): CURLE_COULDNT_RESOLVE_HOST\n"));
      return CURLE_COULDNT_RESOLVE_HOST;
    }
    *entry = conn->async.dns;
    TRACE(("resolved okay, dns %p\n", *entry));
  }
  return CURLE_OK;
}

int Curl_resolv_getsock(struct connectdata *conn,
                        curl_socket_t *socks,
                        int numsocks)
{
  const struct thread_data *td =
    (const struct thread_data *) conn->async.os_specific;

  if (td && td->dummy_sock != CURL_SOCKET_BAD) {
    if(numsocks) {
      /* return one socket waiting for writable, even though this is just
         a dummy */
      socks[0] = td->dummy_sock;
      return GETSOCK_WRITESOCK(0);
    }
  }
  return 0;
}

#ifdef CURLRES_IPV4
/*
 * Curl_getaddrinfo() - for Windows threading without ENABLE_IPV6.
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                const char *hostname,
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
    return Curl_ip2addr(in, hostname, port);

  /* fire up a new resolver thread! */
  if (init_resolve_thread(conn, hostname, port, NULL)) {
    *waitp = TRUE;  /* please wait for the response */
    return NULL;
  }

  /* fall-back to blocking version */
  infof(data, "init_resolve_thread() failed for %s; %s\n",
        hostname, Curl_strerror(conn,GetLastError()));

  h = gethostbyname(hostname);
  if (!h) {
    infof(data, "gethostbyname(2) failed for %s:%d; %s\n",
          hostname, port, Curl_strerror(conn,WSAGetLastError()));
    return NULL;
  }
  return Curl_he2ai(h, port);
}
#endif /* CURLRES_IPV4 */

#ifdef CURLRES_IPV6
/*
 * Curl_getaddrinfo() - for Windows threading IPv6 enabled
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                const char *hostname,
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
  hints.ai_socktype = conn->socktype;
#if 0 /* removed nov 8 2005 before 7.15.1 */
  hints.ai_flags = AI_CANONNAME;
#endif
  itoa(port, sbuf, 10);

  /* fire up a new resolver thread! */
  if (init_resolve_thread(conn, hostname, port, &hints)) {
    *waitp = TRUE;  /* please wait for the response */
    return NULL;
  }

  /* fall-back to blocking version */
  infof(data, "init_resolve_thread() failed for %s; %s\n",
        hostname, Curl_strerror(conn,GetLastError()));

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
