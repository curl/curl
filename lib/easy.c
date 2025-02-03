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
#include <fetch/fetch.h>
#include "transfer.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
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
#include "warnless.h"
#include "sigpipe.h"
#include "vssh/ssh.h"
#include "setopt.h"
#include "http_digest.h"
#include "system_win32.h"
#include "http2.h"
#include "dynbuf.h"
#include "altsvc.h"
#include "hsts.h"

#include "easy_lock.h"

/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

/* true globals -- for fetch_global_init() and fetch_global_cleanup() */
static unsigned int  initialized;
static long          easy_init_flags;

#ifdef GLOBAL_INIT_IS_THREADSAFE

static fetch_simple_lock s_lock = FETCH_SIMPLE_LOCK_INIT;
#define global_init_lock() fetch_simple_lock_lock(&s_lock)
#define global_init_unlock() fetch_simple_lock_unlock(&s_lock)

#else

#define global_init_lock()
#define global_init_unlock()

#endif

/*
 * strdup (and other memory functions) is redefined in complicated
 * ways, but at this point it must be defined as the system-supplied strdup
 * so the callback pointer is initialized correctly.
 */
#if defined(_WIN32_WCE)
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
 * If a memory-using function (like fetch_getenv) is used before
 * fetch_global_init() is called, we need to have these pointers set already.
 */
fetch_malloc_callback Curl_cmalloc = (fetch_malloc_callback)malloc;
fetch_free_callback Curl_cfree = (fetch_free_callback)free;
fetch_realloc_callback Curl_crealloc = (fetch_realloc_callback)realloc;
fetch_strdup_callback Curl_cstrdup = (fetch_strdup_callback)system_strdup;
fetch_calloc_callback Curl_ccalloc = (fetch_calloc_callback)calloc;
#if defined(_WIN32) && defined(UNICODE)
fetch_wcsdup_callback Curl_cwcsdup = Curl_wcsdup;
#endif

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(pop)
#endif

#ifdef DEBUGBUILD
static char *leakpointer;
#endif

/**
 * fetch_global_init() globally initializes fetch given a bitwise set of the
 * different features of what to initialize.
 */
static FETCHcode global_init(long flags, bool memoryfuncs)
{
  if(initialized++)
    return FETCHE_OK;

  if(memoryfuncs) {
    /* Setup the default memory functions here (again) */
    Curl_cmalloc = (fetch_malloc_callback)malloc;
    Curl_cfree = (fetch_free_callback)free;
    Curl_crealloc = (fetch_realloc_callback)realloc;
    Curl_cstrdup = (fetch_strdup_callback)system_strdup;
    Curl_ccalloc = (fetch_calloc_callback)calloc;
#if defined(_WIN32) && defined(UNICODE)
    Curl_cwcsdup = (fetch_wcsdup_callback)_wcsdup;
#endif
  }

  if(Curl_trc_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_trc_init failed\n"));
    goto fail;
  }

  if(!Curl_ssl_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_ssl_init failed\n"));
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

  if(Curl_resolver_global_init()) {
    DEBUGF(fprintf(stderr, "Error: resolver_global_init failed\n"));
    goto fail;
  }

  if(Curl_ssh_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_ssh_init failed\n"));
    goto fail;
  }

  easy_init_flags = flags;

#ifdef DEBUGBUILD
  if(getenv("FETCH_GLOBAL_INIT"))
    /* alloc data that will leak if *cleanup() is not called! */
    leakpointer = malloc(1);
#endif

  return FETCHE_OK;

fail:
  initialized--; /* undo the increase */
  return FETCHE_FAILED_INIT;
}


/**
 * fetch_global_init() globally initializes fetch given a bitwise set of the
 * different features of what to initialize.
 */
FETCHcode fetch_global_init(long flags)
{
  FETCHcode result;
  global_init_lock();

  result = global_init(flags, TRUE);

  global_init_unlock();

  return result;
}

/*
 * fetch_global_init_mem() globally initializes fetch and also registers the
 * user provided callback routines.
 */
FETCHcode fetch_global_init_mem(long flags, fetch_malloc_callback m,
                              fetch_free_callback f, fetch_realloc_callback r,
                              fetch_strdup_callback s, fetch_calloc_callback c)
{
  FETCHcode result;

  /* Invalid input, return immediately */
  if(!m || !f || !r || !s || !c)
    return FETCHE_FAILED_INIT;

  global_init_lock();

  if(initialized) {
    /* Already initialized, do not do it again, but bump the variable anyway to
       work like fetch_global_init() and require the same amount of cleanup
       calls. */
    initialized++;
    global_init_unlock();
    return FETCHE_OK;
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
 * fetch_global_cleanup() globally cleanups fetch, uses the value of
 * "easy_init_flags" to determine what needs to be cleaned up and what does
 * not.
 */
void fetch_global_cleanup(void)
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
  Curl_resolver_global_cleanup();

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
 * fetch_global_trace() globally initializes fetch logging.
 */
FETCHcode fetch_global_trace(const char *config)
{
#ifndef FETCH_DISABLE_VERBOSE_STRINGS
  FETCHcode result;
  global_init_lock();

  result = Curl_trc_opt(config);

  global_init_unlock();

  return result;
#else
  (void)config;
  return FETCHE_OK;
#endif
}

/*
 * fetch_global_sslset() globally initializes the SSL backend to use.
 */
FETCHsslset fetch_global_sslset(fetch_sslbackend id, const char *name,
                              const fetch_ssl_backend ***avail)
{
  FETCHsslset rc;

  global_init_lock();

  rc = Curl_init_sslset_nolock(id, name, avail);

  global_init_unlock();

  return rc;
}

/*
 * fetch_easy_init() is the external interface to alloc, setup and init an
 * easy handle that is returned. If anything goes wrong, NULL is returned.
 */
FETCH *fetch_easy_init(void)
{
  FETCHcode result;
  struct Curl_easy *data;

  /* Make sure we inited the global SSL stuff */
  global_init_lock();

  if(!initialized) {
    result = global_init(FETCH_GLOBAL_DEFAULT, TRUE);
    if(result) {
      /* something in the global init failed, return nothing */
      DEBUGF(fprintf(stderr, "Error: fetch_global_init failed\n"));
      global_init_unlock();
      return NULL;
    }
  }
  global_init_unlock();

  /* We use fetch_open() with undefined URL so far */
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
static int events_timer(FETCHM *multi,    /* multi handle */
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
 * convert from poll() bit definitions to libfetch's FETCH_CSELECT_* ones
 */
static int poll2cselect(int pollmask)
{
  int omask = 0;
  if(pollmask & POLLIN)
    omask |= FETCH_CSELECT_IN;
  if(pollmask & POLLOUT)
    omask |= FETCH_CSELECT_OUT;
  if(pollmask & POLLERR)
    omask |= FETCH_CSELECT_ERR;
  return omask;
}


/* socketcb2poll
 *
 * convert from libfetch' FETCH_POLL_* bit definitions to poll()'s
 */
static short socketcb2poll(int pollmask)
{
  short omask = 0;
  if(pollmask & FETCH_POLL_IN)
    omask |= POLLIN;
  if(pollmask & FETCH_POLL_OUT)
    omask |= POLLOUT;
  return omask;
}

/* events_socket
 *
 * Callback that gets called with information about socket activity to
 * monitor.
 */
static int events_socket(FETCH *easy,      /* easy handle */
                         fetch_socket_t s, /* socket */
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

#if defined(FETCH_DISABLE_VERBOSE_STRINGS)
  (void) easy;
#endif
  (void)socketp;

  m = ev->list;
  while(m) {
    if(m->socket.fd == s) {
      found = TRUE;
      if(what == FETCH_POLL_REMOVE) {
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
           mask. Convert from libfetch bitmask to the poll one. */
        m->socket.events = socketcb2poll(what);
        infof(data, "socket cb: socket %" FMT_SOCKET_T
              " UPDATED as %s%s", s,
              (what&FETCH_POLL_IN) ? "IN" : "",
              (what&FETCH_POLL_OUT) ? "OUT" : "");
      }
      break;
    }
    prev = m;
    m = m->next; /* move to next node */
  }

  if(!found) {
    if(what == FETCH_POLL_REMOVE) {
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
              (what&FETCH_POLL_IN) ? "IN" : "",
              (what&FETCH_POLL_OUT) ? "OUT" : "");
      }
      else
        return FETCHE_OUT_OF_MEMORY;
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
  fetch_multi_setopt(multi, FETCHMOPT_TIMERFUNCTION, events_timer);
  fetch_multi_setopt(multi, FETCHMOPT_TIMERDATA, ev);

  /* socket callback */
  fetch_multi_setopt(multi, FETCHMOPT_SOCKETFUNCTION, events_socket);
  fetch_multi_setopt(multi, FETCHMOPT_SOCKETDATA, ev);
}


/* wait_or_timeout()
 *
 * waits for activity on any of the given sockets, or the timeout to trigger.
 */

static FETCHcode wait_or_timeout(struct Curl_multi *multi, struct events *ev)
{
  bool done = FALSE;
  FETCHMcode mcode = FETCHM_OK;
  FETCHcode result = FETCHE_OK;

  while(!done) {
    FETCHMsg *msg;
    struct socketmonitor *m;
    struct pollfd *f;
    struct pollfd fds[4];
    int numfds = 0;
    int pollrc;
    int i;
    struct fetchtime before;

    /* populate the fds[] array */
    for(m = ev->list, f = &fds[0]; m; m = m->next) {
      f->fd = m->socket.fd;
      f->events = m->socket.events;
      f->revents = 0;
#if DEBUG_EV_POLL
      fprintf(stderr, "poll() %d check socket %d\n", numfds, f->fd);
#endif
      f++;
      numfds++;
    }

    /* get the time stamp to use to figure out how long poll takes */
    before = Curl_now();

    if(numfds) {
      /* wait for activity or timeout */
#if DEBUG_EV_POLL
      fprintf(stderr, "poll(numfds=%d, timeout=%ldms)\n", numfds, ev->ms);
#endif
      pollrc = Curl_poll(fds, (unsigned int)numfds, ev->ms);
#if DEBUG_EV_POLL
      fprintf(stderr, "poll(numfds=%d, timeout=%ldms) -> %d\n",
              numfds, ev->ms, pollrc);
#endif
      if(pollrc < 0)
        return FETCHE_UNRECOVERABLE_POLL;
    }
    else {
#if DEBUG_EV_POLL
      fprintf(stderr, "poll, but no fds, wait timeout=%ldms\n", ev->ms);
#endif
      pollrc = 0;
      if(ev->ms > 0)
        Curl_wait_ms(ev->ms);
    }

    ev->msbump = FALSE; /* reset here */

    if(!pollrc) {
      /* timeout! */
      ev->ms = 0;
      /* fprintf(stderr, "call fetch_multi_socket_action(TIMEOUT)\n"); */
      mcode = fetch_multi_socket_action(multi, FETCH_SOCKET_TIMEOUT, 0,
                                       &ev->running_handles);
    }
    else {
      /* here pollrc is > 0 */
      struct Curl_llist_node *e = Curl_llist_head(&multi->process);
      struct Curl_easy *data;
      DEBUGASSERT(e);
      data = Curl_node_elem(e);
      DEBUGASSERT(data);

      /* loop over the monitored sockets to see which ones had activity */
      for(i = 0; i < numfds; i++) {
        if(fds[i].revents) {
          /* socket activity, tell libfetch */
          int act = poll2cselect(fds[i].revents); /* convert */

          /* sending infof "randomly" to the first easy handle */
          infof(data, "call fetch_multi_socket_action(socket "
                "%" FMT_SOCKET_T ")", (fetch_socket_t)fds[i].fd);
          mcode = fetch_multi_socket_action(multi, fds[i].fd, act,
                                           &ev->running_handles);
        }
      }


      if(!ev->msbump && ev->ms >= 0) {
        /* If nothing updated the timeout, we decrease it by the spent time.
         * If it was updated, it has the new timeout time stored already.
         */
        timediff_t timediff = Curl_timediff(Curl_now(), before);
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
      return FETCHE_URL_MALFORMAT;

    /* we do not really care about the "msgs_in_queue" value returned in the
       second argument */
    msg = fetch_multi_info_read(multi, &pollrc);
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
static FETCHcode easy_events(struct Curl_multi *multi)
{
  /* this struct is made static to allow it to be used after this function
     returns and fetch_multi_remove_handle() is called */
  static struct events evs = {-1, FALSE, 0, NULL, 0};

  /* if running event-based, do some further multi inits */
  events_setup(multi, &evs);

  return wait_or_timeout(multi, &evs);
}
#else /* DEBUGBUILD */
/* when not built with debug, this function does not exist */
#define easy_events(x) FETCHE_NOT_BUILT_IN
#endif

static FETCHcode easy_transfer(struct Curl_multi *multi)
{
  bool done = FALSE;
  FETCHMcode mcode = FETCHM_OK;
  FETCHcode result = FETCHE_OK;

  while(!done && !mcode) {
    int still_running = 0;

    mcode = fetch_multi_poll(multi, NULL, 0, 1000, NULL);

    if(!mcode)
      mcode = fetch_multi_perform(multi, &still_running);

    /* only read 'still_running' if fetch_multi_perform() return OK */
    if(!mcode && !still_running) {
      int rc;
      FETCHMsg *msg = fetch_multi_info_read(multi, &rc);
      if(msg) {
        result = msg->data.result;
        done = TRUE;
      }
    }
  }

  /* Make sure to return some kind of error if there was a multi problem */
  if(mcode) {
    result = (mcode == FETCHM_OUT_OF_MEMORY) ? FETCHE_OUT_OF_MEMORY :
      /* The other multi errors should never happen, so return
         something suitably generic */
      FETCHE_BAD_FUNCTION_ARGUMENT;
  }

  return result;
}


/*
 * easy_perform() is the external interface that performs a blocking
 * transfer as previously setup.
 *
 * CONCEPT: This function creates a multi handle, adds the easy handle to it,
 * runs fetch_multi_perform() until the transfer is done, then detaches the
 * easy handle, destroys the multi handle and returns the easy handle's return
 * code.
 *
 * REALITY: it cannot just create and destroy the multi handle that easily. It
 * needs to keep it around since if this easy handle is used again by this
 * function, the same multi handle must be reused so that the same pools and
 * caches can be used.
 *
 * DEBUG: if 'events' is set TRUE, this function will use a replacement engine
 * instead of fetch_multi_perform() and use fetch_multi_socket_action().
 */
static FETCHcode easy_perform(struct Curl_easy *data, bool events)
{
  struct Curl_multi *multi;
  FETCHMcode mcode;
  FETCHcode result = FETCHE_OK;
  SIGPIPE_VARIABLE(pipe_st);

  if(!data)
    return FETCHE_BAD_FUNCTION_ARGUMENT;

  if(data->set.errorbuffer)
    /* clear this as early as possible */
    data->set.errorbuffer[0] = 0;

  data->state.os_errno = 0;

  if(data->multi) {
    failf(data, "easy handle already used in multi handle");
    return FETCHE_FAILED_INIT;
  }

  /* if the handle has a connection still attached (it is/was a connect-only
     handle) then disconnect before performing */
  if(data->conn) {
    struct connectdata *c;
    fetch_socket_t s;
    Curl_detach_connection(data);
    s = Curl_getconnectinfo(data, &c);
    if((s != FETCH_SOCKET_BAD) && c) {
      Curl_cpool_disconnect(data, c, TRUE);
    }
    DEBUGASSERT(!data->conn);
  }

  if(data->multi_easy)
    multi = data->multi_easy;
  else {
    /* this multi handle will only ever have a single easy handle attached to
       it, so make it use minimal hash sizes */
    multi = Curl_multi_handle(1, 3, 7, 3);
    if(!multi)
      return FETCHE_OUT_OF_MEMORY;
  }

  if(multi->in_callback)
    return FETCHE_RECURSIVE_API_CALL;

  /* Copy the MAXCONNECTS option to the multi handle */
  fetch_multi_setopt(multi, FETCHMOPT_MAXCONNECTS, (long)data->set.maxconnects);

  data->multi_easy = NULL; /* pretend it does not exist */
  mcode = fetch_multi_add_handle(multi, data);
  if(mcode) {
    fetch_multi_cleanup(multi);
    if(mcode == FETCHM_OUT_OF_MEMORY)
      return FETCHE_OUT_OF_MEMORY;
    return FETCHE_FAILED_INIT;
  }

  /* assign this after fetch_multi_add_handle() */
  data->multi_easy = multi;

  sigpipe_init(&pipe_st);
  sigpipe_apply(data, &pipe_st);

  /* run the transfer */
  result = events ? easy_events(multi) : easy_transfer(multi);

  /* ignoring the return code is not nice, but atm we cannot really handle
     a failure here, room for future improvement! */
  (void)fetch_multi_remove_handle(multi, data);

  sigpipe_restore(&pipe_st);

  /* The multi handle is kept alive, owned by the easy handle */
  return result;
}


/*
 * fetch_easy_perform() is the external interface that performs a blocking
 * transfer as previously setup.
 */
FETCHcode fetch_easy_perform(FETCH *data)
{
  return easy_perform(data, FALSE);
}

#ifdef DEBUGBUILD
/*
 * fetch_easy_perform_ev() is the external interface that performs a blocking
 * transfer using the event-based API internally.
 */
FETCHcode fetch_easy_perform_ev(struct Curl_easy *data)
{
  return easy_perform(data, TRUE);
}

#endif

/*
 * fetch_easy_cleanup() is the external interface to cleaning/freeing the given
 * easy handle.
 */
void fetch_easy_cleanup(FETCH *ptr)
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
 * fetch_easy_getinfo() is an external interface that allows an app to retrieve
 * information from a performed transfer and similar.
 */
#undef fetch_easy_getinfo
FETCHcode fetch_easy_getinfo(FETCH *data, FETCHINFO info, ...)
{
  va_list arg;
  void *paramp;
  FETCHcode result;

  va_start(arg, info);
  paramp = va_arg(arg, void *);

  result = Curl_getinfo(data, info, paramp);

  va_end(arg);
  return result;
}

static FETCHcode dupset(struct Curl_easy *dst, struct Curl_easy *src)
{
  FETCHcode result = FETCHE_OK;
  enum dupstring i;
  enum dupblob j;

  /* Copy src->set into dst->set first, then deal with the strings
     afterwards */
  dst->set = src->set;
  Curl_mime_initpart(&dst->set.mimepost);

  /* clear all dest string and blob pointers first, in case we error out
     mid-function */
  memset(dst->set.str, 0, STRING_LAST * sizeof(char *));
  memset(dst->set.blobs, 0, BLOB_LAST * sizeof(struct fetch_blob *));

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
      /* postfieldsize is fetch_off_t, Curl_memdup() takes a size_t ... */
      dst->set.str[i] = Curl_memdup(src->set.str[i],
                                    fetchx_sotouz(src->set.postfieldsize));
    if(!dst->set.str[i])
      return FETCHE_OUT_OF_MEMORY;
    /* point to the new copy */
    dst->set.postfields = dst->set.str[i];
  }

  /* Duplicate mime data. */
  result = Curl_mime_duppart(dst, &dst->set.mimepost, &src->set.mimepost);

  if(src->set.resolve)
    dst->state.resolve = dst->set.resolve;

  return result;
}

/*
 * fetch_easy_duphandle() is an external interface to allow duplication of a
 * given input easy handle. The returned handle will be a new working handle
 * with all options set exactly as the input source handle.
 */
FETCH *fetch_easy_duphandle(FETCH *d)
{
  struct Curl_easy *data = d;
  struct Curl_easy *outfetch = calloc(1, sizeof(struct Curl_easy));
  if(!outfetch)
    goto fail;

  /*
   * We setup a few buffers we need. We should probably make them
   * get setup on-demand in the code, as that would probably decrease
   * the likeliness of us forgetting to init a buffer here in the future.
   */
  outfetch->set.buffer_size = data->set.buffer_size;

  /* copy all userdefined values */
  if(dupset(outfetch, data))
    goto fail;

  Curl_dyn_init(&outfetch->state.headerb, FETCH_MAX_HTTP_HEADER);
  Curl_netrc_init(&outfetch->state.netrc);

  /* the connection pool is setup on demand */
  outfetch->state.lastconnect_id = -1;
  outfetch->state.recent_conn_id = -1;
  outfetch->id = -1;

  outfetch->progress.flags    = data->progress.flags;
  outfetch->progress.callback = data->progress.callback;

#ifndef FETCH_DISABLE_COOKIES
  outfetch->state.cookielist = NULL;
  if(data->cookies && data->state.cookie_engine) {
    /* If cookies are enabled in the parent handle, we enable them
       in the clone as well! */
    outfetch->cookies = Curl_cookie_init(outfetch, NULL, outfetch->cookies,
                                        data->set.cookiesession);
    if(!outfetch->cookies)
      goto fail;
  }

  if(data->state.cookielist) {
    outfetch->state.cookielist = Curl_slist_duplicate(data->state.cookielist);
    if(!outfetch->state.cookielist)
      goto fail;
  }
#endif

  if(data->state.url) {
    outfetch->state.url = strdup(data->state.url);
    if(!outfetch->state.url)
      goto fail;
    outfetch->state.url_alloc = TRUE;
  }

  if(data->state.referer) {
    outfetch->state.referer = strdup(data->state.referer);
    if(!outfetch->state.referer)
      goto fail;
    outfetch->state.referer_alloc = TRUE;
  }

  /* Reinitialize an SSL engine for the new handle
   * note: the engine name has already been copied by dupset */
  if(outfetch->set.str[STRING_SSL_ENGINE]) {
    if(Curl_ssl_set_engine(outfetch, outfetch->set.str[STRING_SSL_ENGINE]))
      goto fail;
  }

#ifndef FETCH_DISABLE_ALTSVC
  if(data->asi) {
    outfetch->asi = Curl_altsvc_init();
    if(!outfetch->asi)
      goto fail;
    if(outfetch->set.str[STRING_ALTSVC])
      (void)Curl_altsvc_load(outfetch->asi, outfetch->set.str[STRING_ALTSVC]);
  }
#endif
#ifndef FETCH_DISABLE_HSTS
  if(data->hsts) {
    outfetch->hsts = Curl_hsts_init();
    if(!outfetch->hsts)
      goto fail;
    if(outfetch->set.str[STRING_HSTS])
      (void)Curl_hsts_loadfile(outfetch,
                               outfetch->hsts, outfetch->set.str[STRING_HSTS]);
    (void)Curl_hsts_loadcb(outfetch, outfetch->hsts);
  }
#endif

#ifdef FETCHRES_ASYNCH
  /* Clone the resolver handle, if present, for the new handle */
  if(Curl_resolver_duphandle(outfetch,
                             &outfetch->state.async.resolver,
                             data->state.async.resolver))
    goto fail;
#endif

#ifdef USE_ARES
  {
    FETCHcode rc;

    rc = Curl_set_dns_servers(outfetch, data->set.str[STRING_DNS_SERVERS]);
    if(rc && rc != FETCHE_NOT_BUILT_IN)
      goto fail;

    rc = Curl_set_dns_interface(outfetch, data->set.str[STRING_DNS_INTERFACE]);
    if(rc && rc != FETCHE_NOT_BUILT_IN)
      goto fail;

    rc = Curl_set_dns_local_ip4(outfetch, data->set.str[STRING_DNS_LOCAL_IP4]);
    if(rc && rc != FETCHE_NOT_BUILT_IN)
      goto fail;

    rc = Curl_set_dns_local_ip6(outfetch, data->set.str[STRING_DNS_LOCAL_IP6]);
    if(rc && rc != FETCHE_NOT_BUILT_IN)
      goto fail;
  }
#endif /* USE_ARES */
#ifndef FETCH_DISABLE_HTTP
  Curl_llist_init(&outfetch->state.httphdrs, NULL);
#endif
  Curl_initinfo(outfetch);

  outfetch->magic = FETCHEASY_MAGIC_NUMBER;

  /* we reach this point and thus we are OK */

  return outfetch;

fail:

  if(outfetch) {
#ifndef FETCH_DISABLE_COOKIES
    free(outfetch->cookies);
#endif
    Curl_dyn_free(&outfetch->state.headerb);
    Curl_altsvc_cleanup(&outfetch->asi);
    Curl_hsts_cleanup(&outfetch->hsts);
    Curl_freeset(outfetch);
    free(outfetch);
  }

  return NULL;
}

/*
 * fetch_easy_reset() is an external interface that allows an app to re-
 * initialize a session handle to the default values.
 */
void fetch_easy_reset(FETCH *d)
{
  struct Curl_easy *data = d;
  Curl_req_hard_reset(&data->req, data);

  /* zero out UserDefined data: */
  Curl_freeset(data);
  memset(&data->set, 0, sizeof(struct UserDefined));
  (void)Curl_init_userdefined(data);

  /* zero out Progress data: */
  memset(&data->progress, 0, sizeof(struct Progress));

  /* zero out PureInfo data: */
  Curl_initinfo(data);

  data->progress.flags |= PGRS_HIDE;
  data->state.current_speed = -1; /* init to negative == impossible */
  data->state.retrycount = 0;     /* reset the retry counter */

  /* zero out authentication data: */
  memset(&data->state.authhost, 0, sizeof(struct auth));
  memset(&data->state.authproxy, 0, sizeof(struct auth));

#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_DIGEST_AUTH)
  Curl_http_auth_cleanup_digest(data);
#endif
}

/*
 * fetch_easy_pause() allows an application to pause or unpause a specific
 * transfer and direction. This function sets the full new state for the
 * current connection this easy handle operates on.
 *
 * NOTE: if you have the receiving paused and you call this function to remove
 * the pausing, you may get your write callback called at this point.
 *
 * Action is a bitmask consisting of FETCHPAUSE_* bits in fetch/fetch.h
 *
 * NOTE: This is one of few API functions that are allowed to be called from
 * within a callback.
 */
FETCHcode fetch_easy_pause(FETCH *d, int action)
{
  struct SingleRequest *k;
  FETCHcode result = FETCHE_OK;
  int oldstate;
  int newstate;
  bool recursive = FALSE;
  bool keep_changed, unpause_read, not_all_paused;
  struct Curl_easy *data = d;

  if(!GOOD_EASY_HANDLE(data) || !data->conn)
    /* crazy input, do not continue */
    return FETCHE_BAD_FUNCTION_ARGUMENT;

  if(Curl_is_in_callback(data))
    recursive = TRUE;
  k = &data->req;
  oldstate = k->keepon & (KEEP_RECV_PAUSE| KEEP_SEND_PAUSE);

  /* first switch off both pause bits then set the new pause bits */
  newstate = (k->keepon &~ (KEEP_RECV_PAUSE| KEEP_SEND_PAUSE)) |
    ((action & FETCHPAUSE_RECV) ? KEEP_RECV_PAUSE : 0) |
    ((action & FETCHPAUSE_SEND) ? KEEP_SEND_PAUSE : 0);

  keep_changed = ((newstate & (KEEP_RECV_PAUSE| KEEP_SEND_PAUSE)) != oldstate);
  not_all_paused = (newstate & (KEEP_RECV_PAUSE|KEEP_SEND_PAUSE)) !=
                   (KEEP_RECV_PAUSE|KEEP_SEND_PAUSE);
  unpause_read = ((k->keepon & ~newstate & KEEP_SEND_PAUSE) &&
                  (data->mstate == MSTATE_PERFORMING ||
                   data->mstate == MSTATE_RATELIMITING));
  /* Unpausing writes is detected on the next run in
   * transfer.c:Curl_sendrecv(). This is because this may result
   * in a transfer error if the application's callbacks fail */

  /* Set the new keepon state, so it takes effect no matter what error
   * may happen afterwards. */
  k->keepon = newstate;

  /* If not completely pausing both directions now, run again in any case. */
  if(not_all_paused) {
    Curl_expire(data, 0, EXPIRE_RUN_NOW);
    /* reset the too-slow time keeper */
    data->state.keeps_speed.tv_sec = 0;
    /* Simulate socket events on next run for unpaused directions */
    if(!(newstate & KEEP_SEND_PAUSE))
      data->state.select_bits |= FETCH_CSELECT_OUT;
    if(!(newstate & KEEP_RECV_PAUSE))
      data->state.select_bits |= FETCH_CSELECT_IN;
    /* On changes, tell application to update its timers. */
    if(keep_changed && data->multi) {
      if(Curl_update_timer(data->multi)) {
        result = FETCHE_ABORTED_BY_CALLBACK;
        goto out;
      }
    }
  }

  if(unpause_read) {
    result = Curl_creader_unpause(data);
    if(result)
      goto out;
  }

  if(!(k->keepon & KEEP_RECV_PAUSE) && Curl_cwriter_is_paused(data)) {
    Curl_conn_ev_data_pause(data, FALSE);
    result = Curl_cwriter_unpause(data);
  }

out:
  if(!result && !data->state.done && keep_changed)
    /* This transfer may have been moved in or out of the bundle, update the
       corresponding socket callback, if used */
    result = Curl_updatesocket(data);

  if(recursive)
    /* this might have called a callback recursively which might have set this
       to false again on exit */
    Curl_set_in_callback(data, TRUE);

  return result;
}


static FETCHcode easy_connection(struct Curl_easy *data,
                                struct connectdata **connp)
{
  fetch_socket_t sfd;

  if(!data)
    return FETCHE_BAD_FUNCTION_ARGUMENT;

  /* only allow these to be called on handles with FETCHOPT_CONNECT_ONLY */
  if(!data->set.connect_only) {
    failf(data, "CONNECT_ONLY is required");
    return FETCHE_UNSUPPORTED_PROTOCOL;
  }

  sfd = Curl_getconnectinfo(data, connp);

  if(sfd == FETCH_SOCKET_BAD) {
    failf(data, "Failed to get recent socket");
    return FETCHE_UNSUPPORTED_PROTOCOL;
  }

  return FETCHE_OK;
}

/*
 * Receives data from the connected socket. Use after successful
 * fetch_easy_perform() with FETCHOPT_CONNECT_ONLY option.
 * Returns FETCHE_OK on success, error code on error.
 */
FETCHcode fetch_easy_recv(FETCH *d, void *buffer, size_t buflen, size_t *n)
{
  FETCHcode result;
  ssize_t n1;
  struct connectdata *c;
  struct Curl_easy *data = d;

  if(Curl_is_in_callback(data))
    return FETCHE_RECURSIVE_API_CALL;

  result = easy_connection(data, &c);
  if(result)
    return result;

  if(!data->conn)
    /* on first invoke, the transfer has been detached from the connection and
       needs to be reattached */
    Curl_attach_connection(data, c);

  *n = 0;
  result = Curl_conn_recv(data, FIRSTSOCKET, buffer, buflen, &n1);

  if(result)
    return result;

  *n = (size_t)n1;
  return FETCHE_OK;
}

#ifndef FETCH_DISABLE_WEBSOCKETS
FETCHcode Curl_connect_only_attach(struct Curl_easy *data)
{
  FETCHcode result;
  struct connectdata *c = NULL;

  result = easy_connection(data, &c);
  if(result)
    return result;

  if(!data->conn)
    /* on first invoke, the transfer has been detached from the connection and
       needs to be reattached */
    Curl_attach_connection(data, c);

  return FETCHE_OK;
}
#endif /* !FETCH_DISABLE_WEBSOCKETS */

/*
 * Sends data over the connected socket.
 *
 * This is the private internal version of fetch_easy_send()
 */
FETCHcode Curl_senddata(struct Curl_easy *data, const void *buffer,
                       size_t buflen, size_t *n)
{
  FETCHcode result;
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

  if(result && result != FETCHE_AGAIN)
    return FETCHE_SEND_ERROR;
  return result;
}

/*
 * Sends data over the connected socket. Use after successful
 * fetch_easy_perform() with FETCHOPT_CONNECT_ONLY option.
 */
FETCHcode fetch_easy_send(FETCH *d, const void *buffer, size_t buflen, size_t *n)
{
  size_t written = 0;
  FETCHcode result;
  struct Curl_easy *data = d;
  if(Curl_is_in_callback(data))
    return FETCHE_RECURSIVE_API_CALL;

  result = Curl_senddata(data, buffer, buflen, &written);
  *n = written;
  return result;
}

/*
 * Performs connection upkeep for the given session handle.
 */
FETCHcode fetch_easy_upkeep(FETCH *d)
{
  struct Curl_easy *data = d;
  /* Verify that we got an easy handle we can work with. */
  if(!GOOD_EASY_HANDLE(data))
    return FETCHE_BAD_FUNCTION_ARGUMENT;

  if(Curl_is_in_callback(data))
    return FETCHE_RECURSIVE_API_CALL;

  /* Use the common function to keep connections alive. */
  return Curl_cpool_upkeep(data);
}

FETCHcode fetch_easy_ssls_import(FETCH *d, const char *session_key,
                               const unsigned char *shmac, size_t shmac_len,
                               const unsigned char *sdata, size_t sdata_len)
{
#ifdef USE_SSLS_EXPORT
  struct Curl_easy *data = d;
  if(!GOOD_EASY_HANDLE(data))
    return FETCHE_BAD_FUNCTION_ARGUMENT;
  return Curl_ssl_session_import(data, session_key,
                                 shmac, shmac_len, sdata, sdata_len);
#else
  (void)d;
  (void)session_key;
  (void)shmac;
  (void)shmac_len;
  (void)sdata;
  (void)sdata_len;
  return FETCHE_NOT_BUILT_IN;
#endif
}

FETCHcode fetch_easy_ssls_export(FETCH *d,
                               fetch_ssls_export_cb *export_fn,
                               void *userptr)
{
#ifdef USE_SSLS_EXPORT
  struct Curl_easy *data = d;
  if(!GOOD_EASY_HANDLE(data))
    return FETCHE_BAD_FUNCTION_ARGUMENT;
  return Curl_ssl_session_export(data, export_fn, userptr);
#else
  (void)d;
  (void)export_fn;
  (void)userptr;
  return FETCHE_NOT_BUILT_IN;
#endif
}
