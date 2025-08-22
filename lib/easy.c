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
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
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
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "vquic/vquic.h"
#include "url.h"
#include "getinfo.h"
#include "hostip.h"
#include "share.h"
#include "strdup.h"
#include "progress.h"
#include "easyif.h"
#include "multiif.h"
#include "select.h"
#include "cfilters.h"
#include "sendf.h" /* for failf function prototype */
#include "connect.h" /* for Curl_getconnectinfo */
#include "slist.h"
#include "mime.h"
#include "amigaos.h"
#include "macos.h"
#include "curlx/warnless.h"
#include "curlx/wait.h"
#include "sigpipe.h"
#include "vssh/ssh.h"
#include "setopt.h"
#include "http_digest.h"
#include "system_win32.h"
#include "http2.h"
#include "curlx/dynbuf.h"
#include "altsvc.h"
#include "hsts.h"

#include "easy_lock.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* true globals -- for curl_global_init() and curl_global_cleanup() */
static unsigned int  initialized;
static long          easy_init_flags;

#ifdef GLOBAL_INIT_IS_THREADSAFE

static curl_simple_lock s_lock = CURL_SIMPLE_LOCK_INIT;
#define global_init_lock() curl_simple_lock_lock(&s_lock)
#define global_init_unlock() curl_simple_lock_unlock(&s_lock)

#else

#define global_init_lock()
#define global_init_unlock()

#endif

/*
 * strdup (and other memory functions) is redefined in complicated
 * ways, but at this point it must be defined as the system-supplied strdup
 * so the callback pointer is initialized correctly.
 */
#ifdef UNDER_CE
#define system_strdup _strdup
#elif !defined(HAVE_STRDUP)
#define system_strdup Curl_strdup
#else
#define system_strdup strdup
#endif

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(push)
#  pragma warning(disable:4232) /* MSVC extension, dllimport identity */
#endif

/*
 * If a memory-using function (like curl_getenv) is used before
 * curl_global_init() is called, we need to have these pointers set already.
 */
curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
curl_free_callback Curl_cfree = (curl_free_callback)free;
curl_realloc_callback Curl_crealloc = (curl_realloc_callback)realloc;
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)system_strdup;
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(pop)
#endif

#ifdef DEBUGBUILD
static char *leakpointer;
#endif

/**
 * curl_global_init() globally initializes curl given a bitwise set of the
 * different features of what to initialize.
 */
static CURLcode global_init(long flags, bool memoryfuncs)
{
  if(initialized++)
    return CURLE_OK;

  if(memoryfuncs) {
    /* Setup the default memory functions here (again) */
    Curl_cmalloc = (curl_malloc_callback)malloc;
    Curl_cfree = (curl_free_callback)free;
    Curl_crealloc = (curl_realloc_callback)realloc;
    Curl_cstrdup = (curl_strdup_callback)system_strdup;
    Curl_ccalloc = (curl_calloc_callback)calloc;
  }

  if(Curl_trc_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_trc_init failed\n"));
    goto fail;
  }

  if(!Curl_ssl_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_ssl_init failed\n"));
    goto fail;
  }

  if(!Curl_vquic_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_vquic_init failed\n"));
    goto fail;
  }

  if(Curl_win32_init(flags)) {
    DEBUGF(fprintf(stderr, "Error: win32_init failed\n"));
    goto fail;
  }

  if(Curl_amiga_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_amiga_init failed\n"));
    goto fail;
  }

  if(Curl_macos_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_macos_init failed\n"));
    goto fail;
  }

  if(Curl_async_global_init()) {
    DEBUGF(fprintf(stderr, "Error: resolver_global_init failed\n"));
    goto fail;
  }

  if(Curl_ssh_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_ssh_init failed\n"));
    goto fail;
  }

  easy_init_flags = flags;

#ifdef DEBUGBUILD
  if(getenv("CURL_GLOBAL_INIT"))
    /* alloc data that will leak if *cleanup() is not called! */
    leakpointer = malloc(1);
#endif

  return CURLE_OK;

fail:
  initialized--; /* undo the increase */
  return CURLE_FAILED_INIT;
}


/**
 * curl_global_init() globally initializes curl given a bitwise set of the
 * different features of what to initialize.
 */
CURLcode curl_global_init(long flags)
{
  CURLcode result;
  global_init_lock();

  result = global_init(flags, TRUE);

  global_init_unlock();

  return result;
}

/*
 * curl_global_init_mem() globally initializes curl and also registers the
 * user provided callback routines.
 */
CURLcode curl_global_init_mem(long flags, curl_malloc_callback m,
                              curl_free_callback f, curl_realloc_callback r,
                              curl_strdup_callback s, curl_calloc_callback c)
{
  CURLcode result;

  /* Invalid input, return immediately */
  if(!m || !f || !r || !s || !c)
    return CURLE_FAILED_INIT;

  global_init_lock();

  if(initialized) {
    /* Already initialized, do not do it again, but bump the variable anyway to
       work like curl_global_init() and require the same amount of cleanup
       calls. */
    initialized++;
    global_init_unlock();
    return CURLE_OK;
  }

  /* set memory functions before global_init() in case it wants memory
     functions */
  Curl_cmalloc = m;
  Curl_cfree = f;
  Curl_cstrdup = s;
  Curl_crealloc = r;
  Curl_ccalloc = c;

  /* Call the actual init function, but without setting */
  result = global_init(flags, FALSE);

  global_init_unlock();

  return result;
}

/**
 * curl_global_cleanup() globally cleanups curl, uses the value of
 * "easy_init_flags" to determine what needs to be cleaned up and what does
 * not.
 */
void curl_global_cleanup(void)
{
  global_init_lock();

  if(!initialized) {
    global_init_unlock();
    return;
  }

  if(--initialized) {
    global_init_unlock();
    return;
  }

  Curl_ssl_cleanup();
  Curl_async_global_cleanup();

#ifdef _WIN32
  Curl_win32_cleanup(easy_init_flags);
#endif

  Curl_amiga_cleanup();

  Curl_ssh_cleanup();

#ifdef DEBUGBUILD
  free(leakpointer);
#endif

  easy_init_flags = 0;

  global_init_unlock();
}

/**
 * curl_global_trace() globally initializes curl logging.
 */
CURLcode curl_global_trace(const char *config)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  CURLcode result;
  global_init_lock();

  result = Curl_trc_opt(config);

  global_init_unlock();

  return result;
#else
  (void)config;
  return CURLE_OK;
#endif
}

/*
 * curl_global_sslset() globally initializes the SSL backend to use.
 */
CURLsslset curl_global_sslset(curl_sslbackend id, const char *name,
                              const curl_ssl_backend ***avail)
{
  CURLsslset rc;

  global_init_lock();

  rc = Curl_init_sslset_nolock(id, name, avail);

  global_init_unlock();

  return rc;
}

/*
 * curl_easy_init() is the external interface to alloc, setup and init an
 * easy handle that is returned. If anything goes wrong, NULL is returned.
 */
CURL *curl_easy_init(void)
{
  CURLcode result;
  struct Curl_easy *data;

  /* Make sure we inited the global SSL stuff */
  global_init_lock();

  if(!initialized) {
    result = global_init(CURL_GLOBAL_DEFAULT, TRUE);
    if(result) {
      /* something in the global init failed, return nothing */
      DEBUGF(fprintf(stderr, "Error: curl_global_init failed\n"));
      global_init_unlock();
      return NULL;
    }
  }
  global_init_unlock();

  /* We use curl_open() with undefined URL so far */
  result = Curl_open(&data);
  if(result) {
    DEBUGF(fprintf(stderr, "Error: Curl_open failed\n"));
    return NULL;
  }

  return data;
}

#ifdef DEBUGBUILD

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

#define DEBUG_EV_POLL   0

/* events_timer
 *
 * Callback that gets called with a new value when the timeout should be
 * updated.
 */
static int events_timer(CURLM *multi,    /* multi handle */
                        long timeout_ms, /* see above */
                        void *userp)     /* private callback pointer */
{
  struct events *ev = userp;
  (void)multi;
#if DEBUG_EV_POLL
  fprintf(stderr, "events_timer: set timeout %ldms\n", timeout_ms);
#endif
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
  int omask = 0;
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
  short omask = 0;
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
  struct socketmonitor *prev = NULL;
  bool found = FALSE;
  struct Curl_easy *data = easy;

#ifdef CURL_DISABLE_VERBOSE_STRINGS
  (void)easy;
#endif
  (void)socketp;

  m = ev->list;
  while(m) {
    if(m->socket.fd == s) {
      found = TRUE;
      if(what == CURL_POLL_REMOVE) {
        struct socketmonitor *nxt = m->next;
        /* remove this node from the list of monitored sockets */
        if(prev)
          prev->next = nxt;
        else
          ev->list = nxt;
        free(m);
        infof(data, "socket cb: socket %" FMT_SOCKET_T " REMOVED", s);
      }
      else {
        /* The socket 's' is already being monitored, update the activity
           mask. Convert from libcurl bitmask to the poll one. */
        m->socket.events = socketcb2poll(what);
        infof(data, "socket cb: socket %" FMT_SOCKET_T
              " UPDATED as %s%s", s,
              (what&CURL_POLL_IN) ? "IN" : "",
              (what&CURL_POLL_OUT) ? "OUT" : "");
      }
      break;
    }
    prev = m;
    m = m->next; /* move to next node */
  }

  if(!found) {
    if(what == CURL_POLL_REMOVE) {
      /* should not happen if our logic is correct, but is no drama. */
      DEBUGF(infof(data, "socket cb: asked to REMOVE socket %"
                   FMT_SOCKET_T "but not present!", s));
      DEBUGASSERT(0);
    }
    else {
      m = malloc(sizeof(struct socketmonitor));
      if(m) {
        m->next = ev->list;
        m->socket.fd = s;
        m->socket.events = socketcb2poll(what);
        m->socket.revents = 0;
        ev->list = m;
        infof(data, "socket cb: socket %" FMT_SOCKET_T " ADDED as %s%s", s,
              (what&CURL_POLL_IN) ? "IN" : "",
              (what&CURL_POLL_OUT) ? "OUT" : "");
      }
      else
        return CURLE_OUT_OF_MEMORY;
    }
  }

  return 0;
}


/*
 * events_setup()
 *
 * Do the multi handle setups that only event-based transfers need.
 */
static void events_setup(struct Curl_multi *multi, struct events *ev)
{
  /* timer callback */
  curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, events_timer);
  curl_multi_setopt(multi, CURLMOPT_TIMERDATA, ev);

  /* socket callback */
  curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, events_socket);
  curl_multi_setopt(multi, CURLMOPT_SOCKETDATA, ev);
}

/* populate_fds()
 *
 * populate the fds[] array
 */
static unsigned int populate_fds(struct pollfd *fds, struct events *ev)
{
  unsigned int numfds = 0;
  struct pollfd *f;
  struct socketmonitor *m;

  f = &fds[0];
  for(m = ev->list; m; m = m->next) {
    f->fd = m->socket.fd;
    f->events = m->socket.events;
    f->revents = 0;
#if DEBUG_EV_POLL
    fprintf(stderr, "poll() %d check socket %d\n", numfds, f->fd);
#endif
    f++;
    numfds++;
  }
  return numfds;
}

/* poll_fds()
 *
 * poll the fds[] array
 */
static CURLcode poll_fds(struct events *ev,
                         struct pollfd *fds,
                         const unsigned int numfds,
                         int *pollrc)
{
  if(numfds) {
    /* wait for activity or timeout */
#if DEBUG_EV_POLL
    fprintf(stderr, "poll(numfds=%u, timeout=%ldms)\n", numfds, ev->ms);
#endif
    *pollrc = Curl_poll(fds, numfds, ev->ms);
#if DEBUG_EV_POLL
    fprintf(stderr, "poll(numfds=%u, timeout=%ldms) -> %d\n",
            numfds, ev->ms, *pollrc);
#endif
    if(*pollrc < 0)
      return CURLE_UNRECOVERABLE_POLL;
  }
  else {
#if DEBUG_EV_POLL
    fprintf(stderr, "poll, but no fds, wait timeout=%ldms\n", ev->ms);
#endif
    *pollrc = 0;
    if(ev->ms > 0)
      curlx_wait_ms(ev->ms);
  }
  return CURLE_OK;
}

/* wait_or_timeout()
 *
 * waits for activity on any of the given sockets, or the timeout to trigger.
 */
static CURLcode wait_or_timeout(struct Curl_multi *multi, struct events *ev)
{
  bool done = FALSE;
  CURLMcode mcode = CURLM_OK;
  CURLcode result = CURLE_OK;

  while(!done) {
    CURLMsg *msg;
    struct pollfd fds[4];
    int pollrc;
    struct curltime before;
    const unsigned int numfds = populate_fds(fds, ev);

    /* get the time stamp to use to figure out how long poll takes */
    before = curlx_now();

    result = poll_fds(ev, fds, numfds, &pollrc);
    if(result)
      return result;

    ev->msbump = FALSE; /* reset here */

    if(!pollrc) {
      /* timeout! */
      ev->ms = 0;
      /* fprintf(stderr, "call curl_multi_socket_action(TIMEOUT)\n"); */
      mcode = curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0,
                                       &ev->running_handles);
    }
    else {
      /* here pollrc is > 0 */
      /* loop over the monitored sockets to see which ones had activity */
      unsigned int i;
      for(i = 0; i < numfds; i++) {
        if(fds[i].revents) {
          /* socket activity, tell libcurl */
          int act = poll2cselect(fds[i].revents); /* convert */

          /* sending infof "randomly" to the first easy handle */
          infof(multi->admin, "call curl_multi_socket_action(socket "
                "%" FMT_SOCKET_T ")", (curl_socket_t)fds[i].fd);
          mcode = curl_multi_socket_action(multi, fds[i].fd, act,
                                           &ev->running_handles);
        }
      }


      if(!ev->msbump && ev->ms >= 0) {
        /* If nothing updated the timeout, we decrease it by the spent time.
         * If it was updated, it has the new timeout time stored already.
         */
        timediff_t timediff = curlx_timediff(curlx_now(), before);
        if(timediff > 0) {
#if DEBUG_EV_POLL
        fprintf(stderr, "poll timeout %ldms not updated, decrease by "
                "time spent %ldms\n", ev->ms, (long)timediff);
#endif
          if(timediff > ev->ms)
            ev->ms = 0;
          else
            ev->ms -= (long)timediff;
        }
      }
    }

    if(mcode)
      return CURLE_URL_MALFORMAT;

    /* we do not really care about the "msgs_in_queue" value returned in the
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
static CURLcode easy_events(struct Curl_multi *multi)
{
  /* this struct is made static to allow it to be used after this function
     returns and curl_multi_remove_handle() is called */
  static struct events evs = {-1, FALSE, 0, NULL, 0};

  /* if running event-based, do some further multi inits */
  events_setup(multi, &evs);

  return wait_or_timeout(multi, &evs);
}
#else /* DEBUGBUILD */
/* when not built with debug, this function does not exist */
#define easy_events(x) CURLE_NOT_BUILT_IN
#endif

static CURLcode easy_transfer(struct Curl_multi *multi)
{
  bool done = FALSE;
  CURLMcode mcode = CURLM_OK;
  CURLcode result = CURLE_OK;

  while(!done && !mcode) {
    int still_running = 0;

    mcode = curl_multi_poll(multi, NULL, 0, 1000, NULL);

    if(!mcode)
      mcode = curl_multi_perform(multi, &still_running);

    /* only read 'still_running' if curl_multi_perform() return OK */
    if(!mcode && !still_running) {
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
    result = (mcode == CURLM_OUT_OF_MEMORY) ? CURLE_OUT_OF_MEMORY :
      /* The other multi errors should never happen, so return
         something suitably generic */
      CURLE_BAD_FUNCTION_ARGUMENT;
  }

  return result;
}


/*
 * easy_perform() is the internal interface that performs a blocking
 * transfer as previously setup.
 *
 * CONCEPT: This function creates a multi handle, adds the easy handle to it,
 * runs curl_multi_perform() until the transfer is done, then detaches the
 * easy handle, destroys the multi handle and returns the easy handle's return
 * code.
 *
 * REALITY: it cannot just create and destroy the multi handle that easily. It
 * needs to keep it around since if this easy handle is used again by this
 * function, the same multi handle must be reused so that the same pools and
 * caches can be used.
 *
 * DEBUG: if 'events' is set TRUE, this function will use a replacement engine
 * instead of curl_multi_perform() and use curl_multi_socket_action().
 */
static CURLcode easy_perform(struct Curl_easy *data, bool events)
{
  struct Curl_multi *multi;
  CURLMcode mcode;
  CURLcode result = CURLE_OK;
  SIGPIPE_VARIABLE(pipe_st);

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(data->set.errorbuffer)
    /* clear this as early as possible */
    data->set.errorbuffer[0] = 0;

  data->state.os_errno = 0;

  if(data->multi) {
    failf(data, "easy handle already used in multi handle");
    return CURLE_FAILED_INIT;
  }

  /* if the handle has a connection still attached (it is/was a connect-only
     handle) then disconnect before performing */
  if(data->conn) {
    struct connectdata *c;
    curl_socket_t s;
    Curl_detach_connection(data);
    s = Curl_getconnectinfo(data, &c);
    if((s != CURL_SOCKET_BAD) && c) {
      Curl_conn_terminate(data, c, TRUE);
    }
    DEBUGASSERT(!data->conn);
  }

  if(data->multi_easy)
    multi = data->multi_easy;
  else {
    /* this multi handle will only ever have a single easy handle attached to
       it, so make it use minimal hash sizes */
    multi = Curl_multi_handle(16, 1, 3, 7, 3);
    if(!multi)
      return CURLE_OUT_OF_MEMORY;
  }

  if(multi->in_callback)
    return CURLE_RECURSIVE_API_CALL;

  /* Copy the MAXCONNECTS option to the multi handle */
  curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, (long)data->set.maxconnects);

  data->multi_easy = NULL; /* pretend it does not exist */
  mcode = curl_multi_add_handle(multi, data);
  if(mcode) {
    curl_multi_cleanup(multi);
    if(mcode == CURLM_OUT_OF_MEMORY)
      return CURLE_OUT_OF_MEMORY;
    return CURLE_FAILED_INIT;
  }

  /* assign this after curl_multi_add_handle() */
  data->multi_easy = multi;

  sigpipe_init(&pipe_st);
  sigpipe_apply(data, &pipe_st);

  /* run the transfer */
  result = events ? easy_events(multi) : easy_transfer(multi);

  /* ignoring the return code is not nice, but atm we cannot really handle
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
CURLcode curl_easy_perform(CURL *data)
{
  return easy_perform(data, FALSE);
}

#ifdef DEBUGBUILD
/*
 * curl_easy_perform_ev() is the external interface that performs a blocking
 * transfer using the event-based API internally.
 */
CURLcode curl_easy_perform_ev(struct Curl_easy *data)
{
  return easy_perform(data, TRUE);
}
#endif

/*
 * curl_easy_cleanup() is the external interface to cleaning/freeing the given
 * easy handle.
 */
void curl_easy_cleanup(CURL *ptr)
{
  struct Curl_easy *data = ptr;
  if(GOOD_EASY_HANDLE(data)) {
    SIGPIPE_VARIABLE(pipe_st);
    sigpipe_ignore(data, &pipe_st);
    Curl_close(&data);
    sigpipe_restore(&pipe_st);
  }
}

/*
 * curl_easy_getinfo() is an external interface that allows an app to retrieve
 * information from a performed transfer and similar.
 */
#undef curl_easy_getinfo
CURLcode curl_easy_getinfo(CURL *data, CURLINFO info, ...)
{
  va_list arg;
  void *paramp;
  CURLcode result;

  va_start(arg, info);
  paramp = va_arg(arg, void *);

  result = Curl_getinfo(data, info, paramp);

  va_end(arg);
  return result;
}

static CURLcode dupset(struct Curl_easy *dst, struct Curl_easy *src)
{
  CURLcode result = CURLE_OK;
  enum dupstring i;
  enum dupblob j;

  /* Copy src->set into dst->set first, then deal with the strings
     afterwards */
  dst->set = src->set;
  Curl_mime_initpart(&dst->set.mimepost);

  /* clear all dest string and blob pointers first, in case we error out
     mid-function */
  memset(dst->set.str, 0, STRING_LAST * sizeof(char *));
  memset(dst->set.blobs, 0, BLOB_LAST * sizeof(struct curl_blob *));

  /* duplicate all strings */
  for(i = (enum dupstring)0; i < STRING_LASTZEROTERMINATED; i++) {
    result = Curl_setstropt(&dst->set.str[i], src->set.str[i]);
    if(result)
      return result;
  }

  /* duplicate all blobs */
  for(j = (enum dupblob)0; j < BLOB_LAST; j++) {
    result = Curl_setblobopt(&dst->set.blobs[j], src->set.blobs[j]);
    if(result)
      return result;
  }

  /* duplicate memory areas pointed to */
  i = STRING_COPYPOSTFIELDS;
  if(src->set.str[i]) {
    if(src->set.postfieldsize == -1)
      dst->set.str[i] = strdup(src->set.str[i]);
    else
      /* postfieldsize is curl_off_t, Curl_memdup() takes a size_t ... */
      dst->set.str[i] = Curl_memdup(src->set.str[i],
                                    curlx_sotouz(src->set.postfieldsize));
    if(!dst->set.str[i])
      return CURLE_OUT_OF_MEMORY;
    /* point to the new copy */
    dst->set.postfields = dst->set.str[i];
  }

  /* Duplicate mime data. */
  result = Curl_mime_duppart(dst, &dst->set.mimepost, &src->set.mimepost);

  if(src->set.resolve)
    dst->state.resolve = dst->set.resolve;

  return result;
}

static void dupeasy_meta_freeentry(void *p)
{
  (void)p;
  /* Will always be FALSE. Cannot use a 0 assert here since compilers
   * are not in agreement if they then want a NORETURN attribute or
   * not. *sigh* */
  DEBUGASSERT(p == NULL);
}

/*
 * curl_easy_duphandle() is an external interface to allow duplication of a
 * given input easy handle. The returned handle will be a new working handle
 * with all options set exactly as the input source handle.
 */
CURL *curl_easy_duphandle(CURL *d)
{
  struct Curl_easy *data = d;
  struct Curl_easy *outcurl = NULL;

  if(!GOOD_EASY_HANDLE(data))
    goto fail;
  outcurl = calloc(1, sizeof(struct Curl_easy));
  if(!outcurl)
    goto fail;

  /*
   * We setup a few buffers we need. We should probably make them
   * get setup on-demand in the code, as that would probably decrease
   * the likeliness of us forgetting to init a buffer here in the future.
   */
  outcurl->set.buffer_size = data->set.buffer_size;

  Curl_hash_init(&outcurl->meta_hash, 23,
                 Curl_hash_str, curlx_str_key_compare, dupeasy_meta_freeentry);
  curlx_dyn_init(&outcurl->state.headerb, CURL_MAX_HTTP_HEADER);
  Curl_netrc_init(&outcurl->state.netrc);

  /* the connection pool is setup on demand */
  outcurl->state.lastconnect_id = -1;
  outcurl->state.recent_conn_id = -1;
  outcurl->id = -1;
  outcurl->mid = UINT_MAX;
  outcurl->master_mid = UINT_MAX;

#ifndef CURL_DISABLE_HTTP
  Curl_llist_init(&outcurl->state.httphdrs, NULL);
#endif
  Curl_initinfo(outcurl);

  /* copy all userdefined values */
  if(dupset(outcurl, data))
    goto fail;

  outcurl->progress.hide     = data->progress.hide;
  outcurl->progress.callback = data->progress.callback;

#ifndef CURL_DISABLE_COOKIES
  outcurl->state.cookielist = NULL;
  if(data->cookies && data->state.cookie_engine) {
    /* If cookies are enabled in the parent handle, we enable them
       in the clone as well! */
    outcurl->cookies = Curl_cookie_init(outcurl, NULL, outcurl->cookies,
                                        data->set.cookiesession);
    if(!outcurl->cookies)
      goto fail;
  }

  if(data->state.cookielist) {
    outcurl->state.cookielist = Curl_slist_duplicate(data->state.cookielist);
    if(!outcurl->state.cookielist)
      goto fail;
  }
#endif

  if(data->state.url) {
    outcurl->state.url = strdup(data->state.url);
    if(!outcurl->state.url)
      goto fail;
    outcurl->state.url_alloc = TRUE;
  }

  if(data->state.referer) {
    outcurl->state.referer = strdup(data->state.referer);
    if(!outcurl->state.referer)
      goto fail;
    outcurl->state.referer_alloc = TRUE;
  }

  /* Reinitialize an SSL engine for the new handle
   * note: the engine name has already been copied by dupset */
  if(outcurl->set.str[STRING_SSL_ENGINE]) {
    if(Curl_ssl_set_engine(outcurl, outcurl->set.str[STRING_SSL_ENGINE]))
      goto fail;
  }

#ifndef CURL_DISABLE_ALTSVC
  if(data->asi) {
    outcurl->asi = Curl_altsvc_init();
    if(!outcurl->asi)
      goto fail;
    if(outcurl->set.str[STRING_ALTSVC])
      (void)Curl_altsvc_load(outcurl->asi, outcurl->set.str[STRING_ALTSVC]);
  }
#endif
#ifndef CURL_DISABLE_HSTS
  if(data->hsts) {
    outcurl->hsts = Curl_hsts_init();
    if(!outcurl->hsts)
      goto fail;
    if(outcurl->set.str[STRING_HSTS])
      (void)Curl_hsts_loadfile(outcurl,
                               outcurl->hsts, outcurl->set.str[STRING_HSTS]);
    (void)Curl_hsts_loadcb(outcurl, outcurl->hsts);
  }
#endif

  outcurl->magic = CURLEASY_MAGIC_NUMBER;

  /* we reach this point and thus we are OK */

  return outcurl;

fail:

  if(outcurl) {
#ifndef CURL_DISABLE_COOKIES
    free(outcurl->cookies);
#endif
    curlx_dyn_free(&outcurl->state.headerb);
    Curl_altsvc_cleanup(&outcurl->asi);
    Curl_hsts_cleanup(&outcurl->hsts);
    Curl_freeset(outcurl);
    free(outcurl);
  }

  return NULL;
}

/*
 * curl_easy_reset() is an external interface that allows an app to re-
 * initialize a session handle to the default values.
 */
void curl_easy_reset(CURL *d)
{
  struct Curl_easy *data = d;
  if(!GOOD_EASY_HANDLE(data))
    return;

  Curl_req_hard_reset(&data->req, data);
  Curl_hash_clean(&data->meta_hash);

  /* clear all meta data */
  Curl_meta_reset(data);
  /* clear any resolve data */
  Curl_async_shutdown(data);
  Curl_resolv_unlink(data, &data->state.dns[0]);
  Curl_resolv_unlink(data, &data->state.dns[1]);
  /* zero out UserDefined data: */
  Curl_freeset(data);
  memset(&data->set, 0, sizeof(struct UserDefined));
  (void)Curl_init_userdefined(data);

  /* zero out Progress data: */
  memset(&data->progress, 0, sizeof(struct Progress));

  /* zero out PureInfo data: */
  Curl_initinfo(data);

  data->progress.hide = TRUE;
  data->state.current_speed = -1; /* init to negative == impossible */
  data->state.retrycount = 0;     /* reset the retry counter */
  data->state.recent_conn_id = -1; /* clear remembered connection id */

  /* zero out authentication data: */
  memset(&data->state.authhost, 0, sizeof(struct auth));
  memset(&data->state.authproxy, 0, sizeof(struct auth));

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_DIGEST_AUTH)
  Curl_http_auth_cleanup_digest(data);
#endif
  data->master_mid = UINT_MAX;
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
 *
 * NOTE: This is one of few API functions that are allowed to be called from
 * within a callback.
 */
CURLcode curl_easy_pause(CURL *d, int action)
{
  CURLcode result = CURLE_OK;
  bool recursive = FALSE;
  bool changed = FALSE;
  struct Curl_easy *data = d;
  bool recv_paused, recv_paused_new;
  bool send_paused, send_paused_new;

  if(!GOOD_EASY_HANDLE(data) || !data->conn)
    /* crazy input, do not continue */
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(Curl_is_in_callback(data))
    recursive = TRUE;

  recv_paused = Curl_xfer_recv_is_paused(data);
  recv_paused_new = (action & CURLPAUSE_RECV);
  send_paused = Curl_xfer_send_is_paused(data);
  send_paused_new = (action & CURLPAUSE_SEND);

  if(send_paused != send_paused_new) {
    changed = TRUE;
    result = Curl_1st_err(result, Curl_xfer_pause_send(data, send_paused_new));
  }

  if(recv_paused != recv_paused_new) {
    changed = TRUE;
    result = Curl_1st_err(result, Curl_xfer_pause_recv(data, recv_paused_new));
  }

  /* If not completely pausing both directions now, run again in any case. */
  if(!Curl_xfer_is_blocked(data)) {
    /* reset the too-slow time keeper */
    data->state.keeps_speed.tv_sec = 0;
    if(data->multi) {
      Curl_multi_mark_dirty(data); /* make it run */
      /* On changes, tell application to update its timers. */
      if(changed) {
        if(Curl_update_timer(data->multi) && !result)
          result = CURLE_ABORTED_BY_CALLBACK;
      }
    }
  }

  if(!result && changed && !data->state.done && data->multi)
    /* pause/unpausing may result in multi event changes */
    if(Curl_multi_ev_assess_xfer(data->multi, data) && !result)
      result = CURLE_ABORTED_BY_CALLBACK;

  if(recursive)
    /* this might have called a callback recursively which might have set this
       to false again on exit */
    Curl_set_in_callback(data, TRUE);

  return result;
}


static CURLcode easy_connection(struct Curl_easy *data,
                                struct connectdata **connp)
{
  curl_socket_t sfd;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* only allow these to be called on handles with CURLOPT_CONNECT_ONLY */
  if(!data->set.connect_only) {
    failf(data, "CONNECT_ONLY is required");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  sfd = Curl_getconnectinfo(data, connp);

  if(sfd == CURL_SOCKET_BAD) {
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
CURLcode curl_easy_recv(CURL *d, void *buffer, size_t buflen, size_t *n)
{
  CURLcode result;
  struct connectdata *c;
  struct Curl_easy *data = d;

  if(!GOOD_EASY_HANDLE(data))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(Curl_is_in_callback(data))
    return CURLE_RECURSIVE_API_CALL;

  result = easy_connection(data, &c);
  if(result)
    return result;

  if(!data->conn)
    /* on first invoke, the transfer has been detached from the connection and
       needs to be reattached */
    Curl_attach_connection(data, c);

  *n = 0;
  return Curl_conn_recv(data, FIRSTSOCKET, buffer, buflen, n);
}

#ifndef CURL_DISABLE_WEBSOCKETS
CURLcode Curl_connect_only_attach(struct Curl_easy *data)
{
  CURLcode result;
  struct connectdata *c = NULL;

  result = easy_connection(data, &c);
  if(result)
    return result;

  if(!data->conn)
    /* on first invoke, the transfer has been detached from the connection and
       needs to be reattached */
    Curl_attach_connection(data, c);

  return CURLE_OK;
}
#endif /* !CURL_DISABLE_WEBSOCKETS */

/*
 * Sends data over the connected socket.
 *
 * This is the private internal version of curl_easy_send()
 */
CURLcode Curl_senddata(struct Curl_easy *data, const void *buffer,
                       size_t buflen, size_t *n)
{
  CURLcode result;
  struct connectdata *c = NULL;
  SIGPIPE_VARIABLE(pipe_st);

  *n = 0;
  result = easy_connection(data, &c);
  if(result)
    return result;

  if(!data->conn)
    /* on first invoke, the transfer has been detached from the connection and
       needs to be reattached */
    Curl_attach_connection(data, c);

  sigpipe_ignore(data, &pipe_st);
  result = Curl_conn_send(data, FIRSTSOCKET, buffer, buflen, FALSE, n);
  sigpipe_restore(&pipe_st);

  if(result && result != CURLE_AGAIN)
    return CURLE_SEND_ERROR;
  return result;
}

/*
 * Sends data over the connected socket. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 */
CURLcode curl_easy_send(CURL *d, const void *buffer, size_t buflen, size_t *n)
{
  size_t written = 0;
  CURLcode result;
  struct Curl_easy *data = d;
  if(!GOOD_EASY_HANDLE(data))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(Curl_is_in_callback(data))
    return CURLE_RECURSIVE_API_CALL;

  result = Curl_senddata(data, buffer, buflen, &written);
  *n = written;
  return result;
}

/*
 * Performs connection upkeep for the given session handle.
 */
CURLcode curl_easy_upkeep(CURL *d)
{
  struct Curl_easy *data = d;
  /* Verify that we got an easy handle we can work with. */
  if(!GOOD_EASY_HANDLE(data))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(Curl_is_in_callback(data))
    return CURLE_RECURSIVE_API_CALL;

  /* Use the common function to keep connections alive. */
  return Curl_cpool_upkeep(data);
}

CURLcode curl_easy_ssls_import(CURL *d, const char *session_key,
                               const unsigned char *shmac, size_t shmac_len,
                               const unsigned char *sdata, size_t sdata_len)
{
#if defined(USE_SSL) && defined(USE_SSLS_EXPORT)
  struct Curl_easy *data = d;
  if(!GOOD_EASY_HANDLE(data))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return Curl_ssl_session_import(data, session_key,
                                 shmac, shmac_len, sdata, sdata_len);
#else
  (void)d;
  (void)session_key;
  (void)shmac;
  (void)shmac_len;
  (void)sdata;
  (void)sdata_len;
  return CURLE_NOT_BUILT_IN;
#endif
}

CURLcode curl_easy_ssls_export(CURL *d,
                               curl_ssls_export_cb *export_fn,
                               void *userptr)
{
#if defined(USE_SSL) && defined(USE_SSLS_EXPORT)
  struct Curl_easy *data = d;
  if(!GOOD_EASY_HANDLE(data))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return Curl_ssl_session_export(data, export_fn, userptr);
#else
  (void)d;
  (void)export_fn;
  (void)userptr;
  return CURLE_NOT_BUILT_IN;
#endif
}

CURLcode Curl_meta_set(struct Curl_easy *data, const char *key,
                       void *meta_data, Curl_meta_dtor *meta_dtor)
{
  DEBUGASSERT(meta_data); /* never set to NULL */
  if(!Curl_hash_add2(&data->meta_hash, CURL_UNCONST(key), strlen(key) + 1,
                     meta_data, meta_dtor)) {
    meta_dtor(CURL_UNCONST(key), strlen(key) + 1, meta_data);
    return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}

void Curl_meta_remove(struct Curl_easy *data, const char *key)
{
  Curl_hash_delete(&data->meta_hash, CURL_UNCONST(key), strlen(key) + 1);
}

void *Curl_meta_get(struct Curl_easy *data, const char *key)
{
  return Curl_hash_pick(&data->meta_hash, CURL_UNCONST(key), strlen(key) + 1);
}

void Curl_meta_reset(struct Curl_easy *data)
{
  Curl_hash_clean(&data->meta_hash);
}
