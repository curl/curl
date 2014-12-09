/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
 * See comment in curl_memory.h for the explanation of this sanity check.
 */

#ifdef CURLX_NO_MEMORY_CALLBACKS
#error "libcurl shall not ever be built with CURLX_NO_MEMORY_CALLBACKS defined"
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
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "strequal.h"
#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "vtls/vtls.h"
#include "url.h"
#include "getinfo.h"
#include "hostip.h"
#include "share.h"
#include "strdup.h"
#include "curl_memory.h"
#include "progress.h"
#include "easyif.h"
#include "select.h"
#include "sendf.h" /* for failf function prototype */
#include "curl_ntlm.h"
#include "connect.h" /* for Curl_getconnectinfo */
#include "slist.h"
#include "amigaos.h"
#include "non-ascii.h"
#include "warnless.h"
#include "conncache.h"
#include "multiif.h"
#include "sigpipe.h"
#include "ssh.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/* win32_cleanup() is for win32 socket cleanup functionality, the opposite
   of win32_init() */
static void win32_cleanup(void)
{
#ifdef USE_WINSOCK
  WSACleanup();
#endif
#ifdef USE_WINDOWS_SSPI
  Curl_sspi_global_cleanup();
#endif
}

/* win32_init() performs win32 socket initialization to properly setup the
   stack to allow networking */
static CURLcode win32_init(void)
{
#ifdef USE_WINSOCK
  WORD wVersionRequested;
  WSADATA wsaData;
  int res;

#if defined(ENABLE_IPV6) && (USE_WINSOCK < 2)
  Error IPV6_requires_winsock2
#endif

  wVersionRequested = MAKEWORD(USE_WINSOCK, USE_WINSOCK);

  res = WSAStartup(wVersionRequested, &wsaData);

  if(res != 0)
    /* Tell the user that we couldn't find a useable */
    /* winsock.dll.     */
    return CURLE_FAILED_INIT;

  /* Confirm that the Windows Sockets DLL supports what we need.*/
  /* Note that if the DLL supports versions greater */
  /* than wVersionRequested, it will still return */
  /* wVersionRequested in wVersion. wHighVersion contains the */
  /* highest supported version. */

  if(LOBYTE( wsaData.wVersion ) != LOBYTE(wVersionRequested) ||
     HIBYTE( wsaData.wVersion ) != HIBYTE(wVersionRequested) ) {
    /* Tell the user that we couldn't find a useable */

    /* winsock.dll. */
    WSACleanup();
    return CURLE_FAILED_INIT;
  }
  /* The Windows Sockets DLL is acceptable. Proceed. */
#elif defined(USE_LWIPSOCK)
  lwip_init();
#endif

#ifdef USE_WINDOWS_SSPI
  {
    CURLcode result = Curl_sspi_global_init();
    if(result)
      return result;
  }
#endif

  return CURLE_OK;
}

#ifdef USE_LIBIDN
/*
 * Initialise use of IDNA library.
 * It falls back to ASCII if $CHARSET isn't defined. This doesn't work for
 * idna_to_ascii_lz().
 */
static void idna_init (void)
{
#ifdef WIN32
  char buf[60];
  UINT cp = GetACP();

  if(!getenv("CHARSET") && cp > 0) {
    snprintf(buf, sizeof(buf), "CHARSET=cp%u", cp);
    putenv(buf);
  }
#else
  /* to do? */
#endif
}
#endif  /* USE_LIBIDN */

/* true globals -- for curl_global_init() and curl_global_cleanup() */
static unsigned int  initialized;
static long          init_flags;

/*
 * strdup (and other memory functions) is redefined in complicated
 * ways, but at this point it must be defined as the system-supplied strdup
 * so the callback pointer is initialized correctly.
 */
#if defined(_WIN32_WCE)
#define system_strdup _strdup
#elif !defined(HAVE_STRDUP)
#define system_strdup curlx_strdup
#else
#define system_strdup strdup
#endif

#if defined(_MSC_VER) && defined(_DLL) && !defined(__POCC__)
#  pragma warning(disable:4232) /* MSVC extension, dllimport identity */
#endif

#ifndef __SYMBIAN32__
/*
 * If a memory-using function (like curl_getenv) is used before
 * curl_global_init() is called, we need to have these pointers set already.
 */
curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
curl_free_callback Curl_cfree = (curl_free_callback)free;
curl_realloc_callback Curl_crealloc = (curl_realloc_callback)realloc;
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)system_strdup;
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;
#if defined(WIN32) && defined(UNICODE)
curl_wcsdup_callback Curl_cwcsdup = (curl_wcsdup_callback)_wcsdup;
#endif
#else
/*
 * Symbian OS doesn't support initialization to code in writeable static data.
 * Initialization will occur in the curl_global_init() call.
 */
curl_malloc_callback Curl_cmalloc;
curl_free_callback Curl_cfree;
curl_realloc_callback Curl_crealloc;
curl_strdup_callback Curl_cstrdup;
curl_calloc_callback Curl_ccalloc;
#endif

#if defined(_MSC_VER) && defined(_DLL) && !defined(__POCC__)
#  pragma warning(default:4232) /* MSVC extension, dllimport identity */
#endif

/**
 * curl_global_init() globally initializes cURL given a bitwise set of the
 * different features of what to initialize.
 */
CURLcode curl_global_init(long flags)
{
  if(initialized++)
    return CURLE_OK;

  /* Setup the default memory functions here (again) */
  Curl_cmalloc = (curl_malloc_callback)malloc;
  Curl_cfree = (curl_free_callback)free;
  Curl_crealloc = (curl_realloc_callback)realloc;
  Curl_cstrdup = (curl_strdup_callback)system_strdup;
  Curl_ccalloc = (curl_calloc_callback)calloc;
#if defined(WIN32) && defined(UNICODE)
  Curl_cwcsdup = (curl_wcsdup_callback)_wcsdup;
#endif

  if(flags & CURL_GLOBAL_SSL)
    if(!Curl_ssl_init()) {
      DEBUGF(fprintf(stderr, "Error: Curl_ssl_init failed\n"));
      return CURLE_FAILED_INIT;
    }

  if(flags & CURL_GLOBAL_WIN32)
    if(win32_init()) {
      DEBUGF(fprintf(stderr, "Error: win32_init failed\n"));
      return CURLE_FAILED_INIT;
    }

#ifdef __AMIGA__
  if(!Curl_amiga_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_amiga_init failed\n"));
    return CURLE_FAILED_INIT;
  }
#endif

#ifdef NETWARE
  if(netware_init()) {
    DEBUGF(fprintf(stderr, "Warning: LONG namespace not available\n"));
  }
#endif

#ifdef USE_LIBIDN
  idna_init();
#endif

  if(Curl_resolver_global_init()) {
    DEBUGF(fprintf(stderr, "Error: resolver_global_init failed\n"));
    return CURLE_FAILED_INIT;
  }

#if defined(USE_LIBSSH2) && defined(HAVE_LIBSSH2_INIT)
  if(libssh2_init(0)) {
    DEBUGF(fprintf(stderr, "Error: libssh2_init failed\n"));
    return CURLE_FAILED_INIT;
  }
#endif

  if(flags & CURL_GLOBAL_ACK_EINTR)
    Curl_ack_eintr = 1;

  init_flags  = flags;

  return CURLE_OK;
}

/*
 * curl_global_init_mem() globally initializes cURL and also registers the
 * user provided callback routines.
 */
CURLcode curl_global_init_mem(long flags, curl_malloc_callback m,
                              curl_free_callback f, curl_realloc_callback r,
                              curl_strdup_callback s, curl_calloc_callback c)
{
  CURLcode result = CURLE_OK;

  /* Invalid input, return immediately */
  if(!m || !f || !r || !s || !c)
    return CURLE_FAILED_INIT;

  if(initialized) {
    /* Already initialized, don't do it again, but bump the variable anyway to
       work like curl_global_init() and require the same amount of cleanup
       calls. */
    initialized++;
    return CURLE_OK;
  }

  /* Call the actual init function first */
  result = curl_global_init(flags);
  if(!result) {
    Curl_cmalloc = m;
    Curl_cfree = f;
    Curl_cstrdup = s;
    Curl_crealloc = r;
    Curl_ccalloc = c;
  }

  return result;
}

/**
 * curl_global_cleanup() globally cleanups cURL, uses the value of
 * "init_flags" to determine what needs to be cleaned up and what doesn't.
 */
void curl_global_cleanup(void)
{
  if(!initialized)
    return;

  if(--initialized)
    return;

  Curl_global_host_cache_dtor();

  if(init_flags & CURL_GLOBAL_SSL)
    Curl_ssl_cleanup();

  Curl_resolver_global_cleanup();

  if(init_flags & CURL_GLOBAL_WIN32)
    win32_cleanup();

  Curl_amiga_cleanup();

#if defined(USE_LIBSSH2) && defined(HAVE_LIBSSH2_EXIT)
  (void)libssh2_exit();
#endif

  init_flags  = 0;
}

/*
 * curl_easy_init() is the external interface to alloc, setup and init an
 * easy handle that is returned. If anything goes wrong, NULL is returned.
 */
CURL *curl_easy_init(void)
{
  CURLcode result;
  struct SessionHandle *data;

  /* Make sure we inited the global SSL stuff */
  if(!initialized) {
    result = curl_global_init(CURL_GLOBAL_DEFAULT);
    if(result) {
      /* something in the global init failed, return nothing */
      DEBUGF(fprintf(stderr, "Error: curl_global_init failed\n"));
      return NULL;
    }
  }

  /* We use curl_open() with undefined URL so far */
  result = Curl_open(&data);
  if(result) {
    DEBUGF(fprintf(stderr, "Error: Curl_open failed\n"));
    return NULL;
  }

  return data;
}

/*
 * curl_easy_setopt() is the external interface for setting options on an
 * easy handle.
 */

#undef curl_easy_setopt
CURLcode curl_easy_setopt(CURL *curl, CURLoption tag, ...)
{
  va_list arg;
  struct SessionHandle *data = curl;
  CURLcode result;

  if(!curl)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  va_start(arg, tag);

  result = Curl_setopt(data, tag, arg);

  va_end(arg);
  return result;
}

#ifdef CURLDEBUG

struct socketmonitor {
  struct socketmonitor *next; /* the next node in the list or NULL */
  struct pollfd socket; /* socket info of what to monitor */
};

struct events {
  long ms;              /* timeout, run the timeout function when reached */
  bool msbump;          /* set TRUE when timeout is set by callback */
  int num_sockets;      /* number of nodes in the monitor list */
  struct socketmonitor *list; /* list of sockets to monitor */
  int running_handles;  /* store the returned number */
};

/* events_timer
 *
 * Callback that gets called with a new value when the timeout should be
 * updated.
 */

static int events_timer(CURLM *multi,    /* multi handle */
                        long timeout_ms, /* see above */
                        void *userp)    /* private callback pointer */
{
  struct events *ev = userp;
  (void)multi;
  if(timeout_ms == -1)
    /* timeout removed */
    timeout_ms = 0;
  else if(timeout_ms == 0)
    /* timeout is already reached! */
    timeout_ms = 1; /* trigger asap */

  ev->ms = timeout_ms;
  ev->msbump = TRUE;
  return 0;
}


/* poll2cselect
 *
 * convert from poll() bit definitions to libcurl's CURL_CSELECT_* ones
 */
static int poll2cselect(int pollmask)
{
  int omask=0;
  if(pollmask & POLLIN)
    omask |= CURL_CSELECT_IN;
  if(pollmask & POLLOUT)
    omask |= CURL_CSELECT_OUT;
  if(pollmask & POLLERR)
    omask |= CURL_CSELECT_ERR;
  return omask;
}


/* socketcb2poll
 *
 * convert from libcurl' CURL_POLL_* bit definitions to poll()'s
 */
static short socketcb2poll(int pollmask)
{
  short omask=0;
  if(pollmask & CURL_POLL_IN)
    omask |= POLLIN;
  if(pollmask & CURL_POLL_OUT)
    omask |= POLLOUT;
  return omask;
}

/* events_socket
 *
 * Callback that gets called with information about socket activity to
 * monitor.
 */
static int events_socket(CURL *easy,      /* easy handle */
                         curl_socket_t s, /* socket */
                         int what,        /* see above */
                         void *userp,     /* private callback
                                             pointer */
                         void *socketp)   /* private socket
                                             pointer */
{
  struct events *ev = userp;
  struct socketmonitor *m;
  struct socketmonitor *prev=NULL;

#if defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void) easy;
#endif
  (void)socketp;

  m = ev->list;
  while(m) {
    if(m->socket.fd == s) {

      if(what == CURL_POLL_REMOVE) {
        struct socketmonitor *nxt = m->next;
        /* remove this node from the list of monitored sockets */
        if(prev)
          prev->next = nxt;
        else
          ev->list = nxt;
        free(m);
        m = nxt;
        infof(easy, "socket cb: socket %d REMOVED\n", s);
      }
      else {
        /* The socket 's' is already being monitored, update the activity
           mask. Convert from libcurl bitmask to the poll one. */
        m->socket.events = socketcb2poll(what);
        infof(easy, "socket cb: socket %d UPDATED as %s%s\n", s,
              what&CURL_POLL_IN?"IN":"",
              what&CURL_POLL_OUT?"OUT":"");
      }
      break;
    }
    prev = m;
    m = m->next; /* move to next node */
  }
  if(!m) {
    if(what == CURL_POLL_REMOVE) {
      /* this happens a bit too often, libcurl fix perhaps? */
      /* fprintf(stderr,
         "%s: socket %d asked to be REMOVED but not present!\n",
                 __func__, s); */
    }
    else {
      m = malloc(sizeof(struct socketmonitor));
      m->next = ev->list;
      m->socket.fd = s;
      m->socket.events = socketcb2poll(what);
      m->socket.revents = 0;
      ev->list = m;
      infof(easy, "socket cb: socket %d ADDED as %s%s\n", s,
            what&CURL_POLL_IN?"IN":"",
            what&CURL_POLL_OUT?"OUT":"");
    }
  }

  return 0;
}


/*
 * events_setup()
 *
 * Do the multi handle setups that only event-based transfers need.
 */
static void events_setup(CURLM *multi, struct events *ev)
{
  /* timer callback */
  curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, events_timer);
  curl_multi_setopt(multi, CURLMOPT_TIMERDATA, ev);

  /* socket callback */
  curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, events_socket);
  curl_multi_setopt(multi, CURLMOPT_SOCKETDATA, ev);
}


/* wait_or_timeout()
 *
 * waits for activity on any of the given sockets, or the timeout to trigger.
 */

static CURLcode wait_or_timeout(struct Curl_multi *multi, struct events *ev)
{
  bool done = FALSE;
  CURLMcode mcode;
  CURLcode result = CURLE_OK;

  while(!done) {
    CURLMsg *msg;
    struct socketmonitor *m;
    struct pollfd *f;
    struct pollfd fds[4];
    int numfds=0;
    int pollrc;
    int i;
    struct timeval before;
    struct timeval after;

    /* populate the fds[] array */
    for(m = ev->list, f=&fds[0]; m; m = m->next) {
      f->fd = m->socket.fd;
      f->events = m->socket.events;
      f->revents = 0;
      /* fprintf(stderr, "poll() %d check socket %d\n", numfds, f->fd); */
      f++;
      numfds++;
    }

    /* get the time stamp to use to figure out how long poll takes */
    before = curlx_tvnow();

    /* wait for activity or timeout */
    pollrc = Curl_poll(fds, numfds, (int)ev->ms);

    after = curlx_tvnow();

    ev->msbump = FALSE; /* reset here */

    if(0 == pollrc) {
      /* timeout! */
      ev->ms = 0;
      /* fprintf(stderr, "call curl_multi_socket_action( TIMEOUT )\n"); */
      mcode = curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0,
                                       &ev->running_handles);
    }
    else if(pollrc > 0) {
      /* loop over the monitored sockets to see which ones had activity */
      for(i = 0; i< numfds; i++) {
        if(fds[i].revents) {
          /* socket activity, tell libcurl */
          int act = poll2cselect(fds[i].revents); /* convert */
          infof(multi->easyp, "call curl_multi_socket_action( socket %d )\n",
                fds[i].fd);
          mcode = curl_multi_socket_action(multi, fds[i].fd, act,
                                           &ev->running_handles);
        }
      }

      if(!ev->msbump)
        /* If nothing updated the timeout, we decrease it by the spent time.
         * If it was updated, it has the new timeout time stored already.
         */
        ev->ms += curlx_tvdiff(after, before);

    }
    else
      return CURLE_RECV_ERROR;

    if(mcode)
      return CURLE_URL_MALFORMAT; /* TODO: return a proper error! */

    /* we don't really care about the "msgs_in_queue" value returned in the
       second argument */
    msg = curl_multi_info_read(multi, &pollrc);
    if(msg) {
      result = msg->data.result;
      done = TRUE;
    }
  }

  return result;
}


/* easy_events()
 *
 * Runs a transfer in a blocking manner using the events-based API
 */
static CURLcode easy_events(CURLM *multi)
{
  struct events evs= {2, FALSE, 0, NULL, 0};

  /* if running event-based, do some further multi inits */
  events_setup(multi, &evs);

  return wait_or_timeout(multi, &evs);
}
#else /* CURLDEBUG */
/* when not built with debug, this function doesn't exist */
#define easy_events(x) CURLE_NOT_BUILT_IN
#endif

static CURLcode easy_transfer(CURLM *multi)
{
  bool done = FALSE;
  CURLMcode mcode = CURLM_OK;
  CURLcode result = CURLE_OK;
  struct timeval before;
  int without_fds = 0;  /* count number of consecutive returns from
                           curl_multi_wait() without any filedescriptors */

  while(!done && !mcode) {
    int still_running = 0;
    int ret;

    before = curlx_tvnow();
    mcode = curl_multi_wait(multi, NULL, 0, 1000, &ret);

    if(mcode == CURLM_OK) {
      if(ret == -1) {
        /* poll() failed not on EINTR, indicate a network problem */
        result = CURLE_RECV_ERROR;
        break;
      }
      else if(ret == 0) {
        struct timeval after = curlx_tvnow();
        /* If it returns without any filedescriptor instantly, we need to
           avoid busy-looping during periods where it has nothing particular
           to wait for */
        if(curlx_tvdiff(after, before) <= 10) {
          without_fds++;
          if(without_fds > 2) {
            int sleep_ms = without_fds < 10 ? (1 << (without_fds-1)): 1000;
            Curl_wait_ms(sleep_ms);
          }
        }
        else
          /* it wasn't "instant", restart counter */
          without_fds = 0;
      }
      else
        /* got file descriptor, restart counter */
        without_fds = 0;

      mcode = curl_multi_perform(multi, &still_running);
    }

    /* only read 'still_running' if curl_multi_perform() return OK */
    if((mcode == CURLM_OK) && !still_running) {
      int rc;
      CURLMsg *msg = curl_multi_info_read(multi, &rc);
      if(msg) {
        result = msg->data.result;
        done = TRUE;
      }
    }
  }

  /* Make sure to return some kind of error if there was a multi problem */
  if(mcode) {
    return (mcode == CURLM_OUT_OF_MEMORY) ? CURLE_OUT_OF_MEMORY :
            /* The other multi errors should never happen, so return
               something suitably generic */
            CURLE_BAD_FUNCTION_ARGUMENT;
  }

  return result;
}


/*
 * easy_perform() is the external interface that performs a blocking
 * transfer as previously setup.
 *
 * CONCEPT: This function creates a multi handle, adds the easy handle to it,
 * runs curl_multi_perform() until the transfer is done, then detaches the
 * easy handle, destroys the multi handle and returns the easy handle's return
 * code.
 *
 * REALITY: it can't just create and destroy the multi handle that easily. It
 * needs to keep it around since if this easy handle is used again by this
 * function, the same multi handle must be re-used so that the same pools and
 * caches can be used.
 *
 * DEBUG: if 'events' is set TRUE, this function will use a replacement engine
 * instead of curl_multi_perform() and use curl_multi_socket_action().
 */
static CURLcode easy_perform(struct SessionHandle *data, bool events)
{
  CURLM *multi;
  CURLMcode mcode;
  CURLcode result = CURLE_OK;
  SIGPIPE_VARIABLE(pipe_st);

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(data->multi) {
    failf(data, "easy handle already used in multi handle");
    return CURLE_FAILED_INIT;
  }

  if(data->multi_easy)
    multi = data->multi_easy;
  else {
    /* this multi handle will only ever have a single easy handled attached
       to it, so make it use minimal hashes */
    multi = Curl_multi_handle(1, 3);
    if(!multi)
      return CURLE_OUT_OF_MEMORY;
    data->multi_easy = multi;
  }

  /* Copy the MAXCONNECTS option to the multi handle */
  curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, data->set.maxconnects);

  mcode = curl_multi_add_handle(multi, data);
  if(mcode) {
    curl_multi_cleanup(multi);
    if(mcode == CURLM_OUT_OF_MEMORY)
      return CURLE_OUT_OF_MEMORY;
    else
      return CURLE_FAILED_INIT;
  }

  sigpipe_ignore(data, &pipe_st);

  /* assign this after curl_multi_add_handle() since that function checks for
     it and rejects this handle otherwise */
  data->multi = multi;

  /* run the transfer */
  result = events ? easy_events(multi) : easy_transfer(multi);

  /* ignoring the return code isn't nice, but atm we can't really handle
     a failure here, room for future improvement! */
  (void)curl_multi_remove_handle(multi, data);

  sigpipe_restore(&pipe_st);

  /* The multi handle is kept alive, owned by the easy handle */
  return result;
}


/*
 * curl_easy_perform() is the external interface that performs a blocking
 * transfer as previously setup.
 */
CURLcode curl_easy_perform(CURL *easy)
{
  return easy_perform(easy, FALSE);
}

#ifdef CURLDEBUG
/*
 * curl_easy_perform_ev() is the external interface that performs a blocking
 * transfer using the event-based API internally.
 */
CURLcode curl_easy_perform_ev(CURL *easy)
{
  return easy_perform(easy, TRUE);
}

#endif

/*
 * curl_easy_cleanup() is the external interface to cleaning/freeing the given
 * easy handle.
 */
void curl_easy_cleanup(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;
  SIGPIPE_VARIABLE(pipe_st);

  if(!data)
    return;

  sigpipe_ignore(data, &pipe_st);
  Curl_close(data);
  sigpipe_restore(&pipe_st);
}

/*
 * curl_easy_getinfo() is an external interface that allows an app to retrieve
 * information from a performed transfer and similar.
 */
#undef curl_easy_getinfo
CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...)
{
  va_list arg;
  void *paramp;
  CURLcode result;
  struct SessionHandle *data = (struct SessionHandle *)curl;

  va_start(arg, info);
  paramp = va_arg(arg, void *);

  result = Curl_getinfo(data, info, paramp);

  va_end(arg);
  return result;
}

/*
 * curl_easy_duphandle() is an external interface to allow duplication of a
 * given input easy handle. The returned handle will be a new working handle
 * with all options set exactly as the input source handle.
 */
CURL *curl_easy_duphandle(CURL *incurl)
{
  struct SessionHandle *data=(struct SessionHandle *)incurl;

  struct SessionHandle *outcurl = calloc(1, sizeof(struct SessionHandle));
  if(NULL == outcurl)
    goto fail;

  /*
   * We setup a few buffers we need. We should probably make them
   * get setup on-demand in the code, as that would probably decrease
   * the likeliness of us forgetting to init a buffer here in the future.
   */
  outcurl->state.headerbuff = malloc(HEADERSIZE);
  if(!outcurl->state.headerbuff)
    goto fail;
  outcurl->state.headersize = HEADERSIZE;

  /* copy all userdefined values */
  if(Curl_dupset(outcurl, data))
    goto fail;

  /* the connection cache is setup on demand */
  outcurl->state.conn_cache = NULL;

  outcurl->state.lastconnect = NULL;

  outcurl->progress.flags    = data->progress.flags;
  outcurl->progress.callback = data->progress.callback;

  if(data->cookies) {
    /* If cookies are enabled in the parent handle, we enable them
       in the clone as well! */
    outcurl->cookies = Curl_cookie_init(data,
                                        data->cookies->filename,
                                        outcurl->cookies,
                                        data->set.cookiesession);
    if(!outcurl->cookies)
      goto fail;
  }

  /* duplicate all values in 'change' */
  if(data->change.cookielist) {
    outcurl->change.cookielist =
      Curl_slist_duplicate(data->change.cookielist);
    if(!outcurl->change.cookielist)
      goto fail;
  }

  if(data->change.url) {
    outcurl->change.url = strdup(data->change.url);
    if(!outcurl->change.url)
      goto fail;
    outcurl->change.url_alloc = TRUE;
  }

  if(data->change.referer) {
    outcurl->change.referer = strdup(data->change.referer);
    if(!outcurl->change.referer)
      goto fail;
    outcurl->change.referer_alloc = TRUE;
  }

  /* Clone the resolver handle, if present, for the new handle */
  if(Curl_resolver_duphandle(&outcurl->state.resolver,
                             data->state.resolver))
    goto fail;

  Curl_convert_setup(outcurl);

  outcurl->magic = CURLEASY_MAGIC_NUMBER;

  /* we reach this point and thus we are OK */

  return outcurl;

  fail:

  if(outcurl) {
    curl_slist_free_all(outcurl->change.cookielist);
    outcurl->change.cookielist = NULL;
    Curl_safefree(outcurl->state.headerbuff);
    Curl_safefree(outcurl->change.url);
    Curl_safefree(outcurl->change.referer);
    Curl_freeset(outcurl);
    free(outcurl);
  }

  return NULL;
}

/*
 * curl_easy_reset() is an external interface that allows an app to re-
 * initialize a session handle to the default values.
 */
void curl_easy_reset(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;

  Curl_safefree(data->state.pathbuffer);

  data->state.path = NULL;

  Curl_free_request_state(data);

  /* zero out UserDefined data: */
  Curl_freeset(data);
  memset(&data->set, 0, sizeof(struct UserDefined));
  (void)Curl_init_userdefined(&data->set);

  /* zero out Progress data: */
  memset(&data->progress, 0, sizeof(struct Progress));

  data->progress.flags |= PGRS_HIDE;
  data->state.current_speed = -1; /* init to negative == impossible */
}

/*
 * curl_easy_pause() allows an application to pause or unpause a specific
 * transfer and direction. This function sets the full new state for the
 * current connection this easy handle operates on.
 *
 * NOTE: if you have the receiving paused and you call this function to remove
 * the pausing, you may get your write callback called at this point.
 *
 * Action is a bitmask consisting of CURLPAUSE_* bits in curl/curl.h
 */
CURLcode curl_easy_pause(CURL *curl, int action)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;
  struct SingleRequest *k = &data->req;
  CURLcode result = CURLE_OK;

  /* first switch off both pause bits */
  int newstate = k->keepon &~ (KEEP_RECV_PAUSE| KEEP_SEND_PAUSE);

  /* set the new desired pause bits */
  newstate |= ((action & CURLPAUSE_RECV)?KEEP_RECV_PAUSE:0) |
    ((action & CURLPAUSE_SEND)?KEEP_SEND_PAUSE:0);

  /* put it back in the keepon */
  k->keepon = newstate;

  if(!(newstate & KEEP_RECV_PAUSE) && data->state.tempwrite) {
    /* we have a buffer for sending that we now seem to be able to deliver
       since the receive pausing is lifted! */

    /* get the pointer in local copy since the function may return PAUSE
       again and then we'll get a new copy allocted and stored in
       the tempwrite variables */
    char *tempwrite = data->state.tempwrite;

    data->state.tempwrite = NULL;
    result = Curl_client_chop_write(data->easy_conn, data->state.tempwritetype,
                                    tempwrite, data->state.tempwritesize);
    free(tempwrite);
  }

  /* if there's no error and we're not pausing both directions, we want
     to have this handle checked soon */
  if(!result &&
     ((newstate&(KEEP_RECV_PAUSE|KEEP_SEND_PAUSE)) !=
      (KEEP_RECV_PAUSE|KEEP_SEND_PAUSE)) )
    Curl_expire(data, 1); /* get this handle going again */

  return result;
}


static CURLcode easy_connection(struct SessionHandle *data,
                                curl_socket_t *sfd,
                                struct connectdata **connp)
{
  if(data == NULL)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* only allow these to be called on handles with CURLOPT_CONNECT_ONLY */
  if(!data->set.connect_only) {
    failf(data, "CONNECT_ONLY is required!");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  *sfd = Curl_getconnectinfo(data, connp);

  if(*sfd == CURL_SOCKET_BAD) {
    failf(data, "Failed to get recent socket");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  return CURLE_OK;
}

/*
 * Receives data from the connected socket. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 * Returns CURLE_OK on success, error code on error.
 */
CURLcode curl_easy_recv(CURL *curl, void *buffer, size_t buflen, size_t *n)
{
  curl_socket_t sfd;
  CURLcode result;
  ssize_t n1;
  struct connectdata *c;
  struct SessionHandle *data = (struct SessionHandle *)curl;

  result = easy_connection(data, &sfd, &c);
  if(result)
    return result;

  *n = 0;
  result = Curl_read(c, sfd, buffer, buflen, &n1);

  if(result)
    return result;

  *n = (size_t)n1;

  return CURLE_OK;
}

/*
 * Sends data over the connected socket. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 */
CURLcode curl_easy_send(CURL *curl, const void *buffer, size_t buflen,
                        size_t *n)
{
  curl_socket_t sfd;
  CURLcode result;
  ssize_t n1;
  struct connectdata *c = NULL;
  struct SessionHandle *data = (struct SessionHandle *)curl;

  result = easy_connection(data, &sfd, &c);
  if(result)
    return result;

  *n = 0;
  result = Curl_write(c, sfd, buffer, buflen, &n1);

  if(n1 == -1)
    return CURLE_SEND_ERROR;

  /* detect EAGAIN */
  if(!result && !n1)
    return CURLE_AGAIN;

  *n = (size_t)n1;

  return result;
}
