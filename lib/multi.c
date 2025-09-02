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

#include <curl/curl.h>

#include "urldata.h"
#include "transfer.h"
#include "url.h"
#include "cfilters.h"
#include "connect.h"
#include "progress.h"
#include "easyif.h"
#include "share.h"
#include "psl.h"
#include "multiif.h"
#include "multi_ev.h"
#include "sendf.h"
#include "curlx/timeval.h"
#include "http.h"
#include "select.h"
#include "curlx/warnless.h"
#include "curlx/wait.h"
#include "speedcheck.h"
#include "conncache.h"
#include "multihandle.h"
#include "sigpipe.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "http_proxy.h"
#include "http2.h"
#include "socketpair.h"
#include "socks.h"
#include "urlapi-int.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* initial multi->xfers table size for a full multi */
#define CURL_XFER_TABLE_SIZE    512

/*
  CURL_SOCKET_HASH_TABLE_SIZE should be a prime number. Increasing it from 97
  to 911 takes on a 32-bit machine 4 x 804 = 3211 more bytes. Still, every
  curl handle takes 6K memory, therefore this 3K are not significant.
*/
#ifndef CURL_SOCKET_HASH_TABLE_SIZE
#define CURL_SOCKET_HASH_TABLE_SIZE 911
#endif

#ifndef CURL_CONNECTION_HASH_SIZE
#define CURL_CONNECTION_HASH_SIZE 97
#endif

#ifndef CURL_DNS_HASH_SIZE
#define CURL_DNS_HASH_SIZE 71
#endif

#ifndef CURL_TLS_SESSION_SIZE
#define CURL_TLS_SESSION_SIZE 25
#endif

#define CURL_MULTI_HANDLE 0x000bab1e

#ifdef DEBUGBUILD
/* On a debug build, we want to fail hard on multi handles that
 * are not NULL, but no longer have the MAGIC touch. This gives
 * us early warning on things only discovered by valgrind otherwise. */
#define GOOD_MULTI_HANDLE(x) \
  (((x) && (x)->magic == CURL_MULTI_HANDLE)? TRUE:      \
  (DEBUGASSERT(!(x)), FALSE))
#else
#define GOOD_MULTI_HANDLE(x) \
  ((x) && (x)->magic == CURL_MULTI_HANDLE)
#endif

static void move_pending_to_connect(struct Curl_multi *multi,
                                    struct Curl_easy *data);
static CURLMcode add_next_timeout(struct curltime now,
                                  struct Curl_multi *multi,
                                  struct Curl_easy *d);
static CURLMcode multi_timeout(struct Curl_multi *multi,
                               struct curltime *expire_time,
                               long *timeout_ms);
static void process_pending_handles(struct Curl_multi *multi);
static void multi_xfer_bufs_free(struct Curl_multi *multi);
#ifdef DEBUGBUILD
static void multi_xfer_tbl_dump(struct Curl_multi *multi);
#endif

/* function pointer called once when switching TO a state */
typedef void (*init_multistate_func)(struct Curl_easy *data);

/* called in DID state, before PERFORMING state */
static void before_perform(struct Curl_easy *data)
{
  data->req.chunk = FALSE;
  Curl_pgrsTime(data, TIMER_PRETRANSFER);
}

static void init_completed(struct Curl_easy *data)
{
  /* this is a completed transfer */

  /* Important: reset the conn pointer so that we do not point to memory
     that could be freed anytime */
  Curl_detach_connection(data);
  Curl_expire_clear(data); /* stop all timers */
}

/* always use this function to change state, to make debugging easier */
static void mstate(struct Curl_easy *data, CURLMstate state
#ifdef DEBUGBUILD
                   , int lineno
#endif
)
{
  CURLMstate oldstate = data->mstate;
  static const init_multistate_func finit[MSTATE_LAST] = {
    NULL,              /* INIT */
    NULL,              /* PENDING */
    NULL,              /* SETUP */
    Curl_init_CONNECT, /* CONNECT */
    NULL,              /* RESOLVING */
    NULL,              /* CONNECTING */
    NULL,              /* TUNNELING */
    NULL,              /* PROTOCONNECT */
    NULL,              /* PROTOCONNECTING */
    NULL,              /* DO */
    NULL,              /* DOING */
    NULL,              /* DOING_MORE */
    before_perform,    /* DID */
    NULL,              /* PERFORMING */
    NULL,              /* RATELIMITING */
    NULL,              /* DONE */
    init_completed,    /* COMPLETED */
    NULL               /* MSGSENT */
  };

  if(oldstate == state)
    /* do not bother when the new state is the same as the old state */
    return;

#ifdef DEBUGBUILD
  CURL_TRC_M(data, "-> [%s] (line %d)", CURL_MSTATE_NAME(state), lineno);
#else
  CURL_TRC_M(data, "-> [%s]", CURL_MSTATE_NAME(state));
#endif

  data->mstate = state;

  if(state == MSTATE_COMPLETED) {
    /* changing to COMPLETED means it is in process and needs to go */
    DEBUGASSERT(Curl_uint_bset_contains(&data->multi->process, data->mid));
    Curl_uint_bset_remove(&data->multi->process, data->mid);
    Curl_uint_bset_remove(&data->multi->pending, data->mid); /* to be sure */

    if(Curl_uint_bset_empty(&data->multi->process)) {
      /* free the transfer buffer when we have no more active transfers */
      multi_xfer_bufs_free(data->multi);
    }
  }

  /* if this state has an init-function, run it */
  if(finit[state])
    finit[state](data);
}

#ifndef DEBUGBUILD
#define multistate(x,y) mstate(x,y)
#else
#define multistate(x,y) mstate(x,y, __LINE__)
#endif


/* multi->proto_hash destructor. Should never be called as elements
 * MUST be added with their own destructor */
static void ph_freeentry(void *p)
{
  (void)p;
  /* Will always be FALSE. Cannot use a 0 assert here since compilers
   * are not in agreement if they then want a NORETURN attribute or
   * not. *sigh* */
  DEBUGASSERT(p == NULL);
}

/*
 * multi_addmsg()
 *
 * Called when a transfer is completed. Adds the given msg pointer to
 * the list kept in the multi handle.
 */
static void multi_addmsg(struct Curl_multi *multi, struct Curl_message *msg)
{
  Curl_llist_append(&multi->msglist, msg, &msg->list);
}

struct Curl_multi *Curl_multi_handle(unsigned int xfer_table_size,
                                     size_t ev_hashsize,  /* event hash */
                                     size_t chashsize, /* connection hash */
                                     size_t dnssize,   /* dns hash */
                                     size_t sesssize)  /* TLS session cache */
{
  struct Curl_multi *multi = calloc(1, sizeof(struct Curl_multi));

  if(!multi)
    return NULL;

  multi->magic = CURL_MULTI_HANDLE;

  Curl_dnscache_init(&multi->dnscache, dnssize);
  Curl_multi_ev_init(multi, ev_hashsize);
  Curl_uint_tbl_init(&multi->xfers, NULL);
  Curl_uint_bset_init(&multi->process);
  Curl_uint_bset_init(&multi->dirty);
  Curl_uint_bset_init(&multi->pending);
  Curl_uint_bset_init(&multi->msgsent);
  Curl_hash_init(&multi->proto_hash, 23,
                 Curl_hash_str, curlx_str_key_compare, ph_freeentry);
  Curl_llist_init(&multi->msglist, NULL);

  multi->multiplexing = TRUE;
  multi->max_concurrent_streams = 100;
  multi->last_timeout_ms = -1;

  if(Curl_uint_bset_resize(&multi->process, xfer_table_size) ||
     Curl_uint_bset_resize(&multi->pending, xfer_table_size) ||
     Curl_uint_bset_resize(&multi->dirty, xfer_table_size) ||
     Curl_uint_bset_resize(&multi->msgsent, xfer_table_size) ||
     Curl_uint_tbl_resize(&multi->xfers, xfer_table_size))
    goto error;

  multi->admin = curl_easy_init();
  if(!multi->admin)
    goto error;
  /* Initialize admin handle to operate inside this multi */
  multi->admin->multi = multi;
  multi->admin->state.internal = TRUE;
  Curl_llist_init(&multi->admin->state.timeoutlist, NULL);
#ifdef DEBUGBUILD
  if(getenv("CURL_DEBUG"))
    multi->admin->set.verbose = TRUE;
#endif
  Curl_uint_tbl_add(&multi->xfers, multi->admin, &multi->admin->mid);

  if(Curl_cshutdn_init(&multi->cshutdn, multi))
    goto error;

  Curl_cpool_init(&multi->cpool, multi->admin, NULL, chashsize);

#ifdef USE_SSL
  if(Curl_ssl_scache_create(sesssize, 2, &multi->ssl_scache))
    goto error;
#else
  (void)sesssize;
#endif

#ifdef USE_WINSOCK
  multi->wsa_event = WSACreateEvent();
  if(multi->wsa_event == WSA_INVALID_EVENT)
    goto error;
#elif defined(ENABLE_WAKEUP)
  if(wakeup_create(multi->wakeup_pair, TRUE) < 0) {
    multi->wakeup_pair[0] = CURL_SOCKET_BAD;
    multi->wakeup_pair[1] = CURL_SOCKET_BAD;
  }
#endif

  return multi;

error:

  Curl_multi_ev_cleanup(multi);
  Curl_hash_destroy(&multi->proto_hash);
  Curl_dnscache_destroy(&multi->dnscache);
  Curl_cpool_destroy(&multi->cpool);
  Curl_cshutdn_destroy(&multi->cshutdn, multi->admin);
#ifdef USE_SSL
  Curl_ssl_scache_destroy(multi->ssl_scache);
#endif
  if(multi->admin) {
    multi->admin->multi = NULL;
    Curl_close(&multi->admin);
  }

  Curl_uint_bset_destroy(&multi->process);
  Curl_uint_bset_destroy(&multi->dirty);
  Curl_uint_bset_destroy(&multi->pending);
  Curl_uint_bset_destroy(&multi->msgsent);
  Curl_uint_tbl_destroy(&multi->xfers);

  free(multi);
  return NULL;
}

CURLM *curl_multi_init(void)
{
  return Curl_multi_handle(CURL_XFER_TABLE_SIZE,
                           CURL_SOCKET_HASH_TABLE_SIZE,
                           CURL_CONNECTION_HASH_SIZE,
                           CURL_DNS_HASH_SIZE,
                           CURL_TLS_SESSION_SIZE);
}

#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
static void multi_warn_debug(struct Curl_multi *multi, struct Curl_easy *data)
{
  if(!multi->warned) {
    infof(data, "!!! WARNING !!!");
    infof(data, "This is a debug build of libcurl, "
          "do not use in production.");
    multi->warned = TRUE;
  }
}
#else
#define multi_warn_debug(x,y) Curl_nop_stmt
#endif


static CURLMcode multi_xfers_add(struct Curl_multi *multi,
                                 struct Curl_easy *data)
{
  unsigned int capacity = Curl_uint_tbl_capacity(&multi->xfers);
  unsigned int new_size = 0;
  /* Prepare to make this into a CURLMOPT_MAX_TRANSFERS, because some
   * applications may want to prevent a run-away of their memory use. */
  /* UINT_MAX is our "invalid" id, do not let the table grow up to that. */
  const unsigned int max_capacity = UINT_MAX - 1;

  if(capacity < max_capacity) {
    /* We want `multi->xfers` to have "sufficient" free rows, so that we do
     * have to reuse the `mid` from a just removed easy right away.
     * Since uint_tbl and uint_bset are quite memory efficient,
     * regard less than 25% free as insufficient.
     * (for low capacities, e.g. multi_easy, 4 or less). */
    unsigned int used = Curl_uint_tbl_count(&multi->xfers);
    unsigned int unused = capacity - used;
    unsigned int min_unused = CURLMAX(capacity >> 2, 4);
    if(unused <= min_unused) {
      /* Make sure the uint arithmetic here works on the corner
       * cases where we are close to max_capacity or UINT_MAX */
      if((min_unused >= max_capacity) ||
         ((max_capacity - min_unused) <= capacity) ||
         ((UINT_MAX - min_unused - 63) <= capacity)) {
        new_size = max_capacity; /* can not be larger than this */
      }
      else {
         /* make it a 64 multiple, since our bitsets frow by that and
          * small (easy_multi) grows to at least 64 on first resize. */
        new_size = (((used + min_unused) + 63) / 64) * 64;
      }
    }
  }

  if(new_size > capacity) {
    /* Grow the bitsets first. Should one fail, we do not need
     * to downsize the already resized ones. The sets continue
     * to work properly when larger than the table, but not
     * the other way around. */
    CURL_TRC_M(data, "increasing xfer table size to %u", new_size);
    if(Curl_uint_bset_resize(&multi->process, new_size) ||
       Curl_uint_bset_resize(&multi->dirty, new_size) ||
       Curl_uint_bset_resize(&multi->pending, new_size) ||
       Curl_uint_bset_resize(&multi->msgsent, new_size) ||
       Curl_uint_tbl_resize(&multi->xfers, new_size))
      return CURLM_OUT_OF_MEMORY;
  }

  /* Insert the easy into the table now */
  if(!Curl_uint_tbl_add(&multi->xfers, data, &data->mid)) {
    /* MUST only happen when table is full */
    DEBUGASSERT(Curl_uint_tbl_capacity(&multi->xfers) <=
                Curl_uint_tbl_count(&multi->xfers));
    return CURLM_OUT_OF_MEMORY;
  }
  return CURLM_OK;
}


CURLMcode curl_multi_add_handle(CURLM *m, CURL *d)
{
  CURLMcode rc;
  struct Curl_multi *multi = m;
  struct Curl_easy *data = d;
  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  /* Verify that we got a somewhat good easy handle too */
  if(!GOOD_EASY_HANDLE(data))
    return CURLM_BAD_EASY_HANDLE;

  /* Prevent users from adding same easy handle more than once and prevent
     adding to more than one multi stack */
  if(data->multi)
    return CURLM_ADDED_ALREADY;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  if(multi->dead) {
    /* a "dead" handle cannot get added transfers while any existing easy
       handles are still alive - but if there are none alive anymore, it is
       fine to start over and unmark the "deadness" of this handle.
       This means only the admin handle MUST be present. */
    if((Curl_uint_tbl_count(&multi->xfers) != 1) ||
       !Curl_uint_tbl_contains(&multi->xfers, 0))
      return CURLM_ABORTED_BY_CALLBACK;
    multi->dead = FALSE;
    Curl_uint_bset_clear(&multi->process);
    Curl_uint_bset_clear(&multi->dirty);
    Curl_uint_bset_clear(&multi->pending);
    Curl_uint_bset_clear(&multi->msgsent);
  }

  if(data->multi_easy) {
    /* if this easy handle was previously used for curl_easy_perform(), there
       is a private multi handle here that we can kill */
    curl_multi_cleanup(data->multi_easy);
    data->multi_easy = NULL;
  }

  /* Insert the easy into the multi->xfers table, assigning it a `mid`. */
  if(multi_xfers_add(multi, data))
    return CURLM_OUT_OF_MEMORY;

  /* Initialize timeout list for this handle */
  Curl_llist_init(&data->state.timeoutlist, NULL);

  /*
   * No failure allowed in this function beyond this point. No modification of
   * easy nor multi handle allowed before this except for potential multi's
   * connection pool growing which will not be undone in this function no
   * matter what.
   */
  if(data->set.errorbuffer)
    data->set.errorbuffer[0] = 0;

  data->state.os_errno = 0;

  /* make the Curl_easy refer back to this multi handle - before Curl_expire()
     is called. */
  data->multi = multi;

  /* set the easy handle */
  multistate(data, MSTATE_INIT);

#ifdef USE_LIBPSL
  /* Do the same for PSL. */
  if(data->share && (data->share->specifier & (1 << CURL_LOCK_DATA_PSL)))
    data->psl = &data->share->psl;
  else
    data->psl = &multi->psl;
#endif

  /* add the easy handle to the process set */
  Curl_uint_bset_add(&multi->process, data->mid);
  ++multi->xfers_alive;
  ++multi->xfers_total_ever;

  Curl_cpool_xfer_init(data);
  multi_warn_debug(multi, data);

  /* Make sure the new handle will run */
  Curl_multi_mark_dirty(data);
  /* Necessary in event based processing, where dirty handles trigger
   * a timeout callback invocation. */
  rc = Curl_update_timer(multi);
  if(rc) {
    data->multi = NULL; /* not anymore */
    Curl_uint_tbl_remove(&multi->xfers, data->mid);
    data->mid = UINT_MAX;
    return rc;
  }

  /* The admin handle only ever has default timeouts set. To improve the
     state somewhat we clone the timeouts from each added handle so that the
     admin handle always has the same timeouts as the most recently added
     easy handle. */
  multi->admin->set.timeout = data->set.timeout;
  multi->admin->set.server_response_timeout =
    data->set.server_response_timeout;
  multi->admin->set.no_signal = data->set.no_signal;

  CURL_TRC_M(data, "added to multi, mid=%u, running=%u, total=%u",
             data->mid, Curl_multi_xfers_running(multi),
             Curl_uint_tbl_count(&multi->xfers));
  return CURLM_OK;
}

#if 0
/* Debug-function, used like this:
 *
 * Curl_hash_print(&multi->sockhash, debug_print_sock_hash);
 *
 * Enable the hash print function first by editing hash.c
 */
static void debug_print_sock_hash(void *p)
{
  struct Curl_sh_entry *sh = (struct Curl_sh_entry *)p;

  fprintf(stderr, " [readers %u][writers %u]",
          sh->readers, sh->writers);
}
#endif

struct multi_done_ctx {
  BIT(premature);
};

static void multi_done_locked(struct connectdata *conn,
                              struct Curl_easy *data,
                              void *userdata)
{
  struct multi_done_ctx *mdctx = userdata;
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  const char *host =
#ifndef CURL_DISABLE_PROXY
        conn->bits.socksproxy ?
        conn->socks_proxy.host.dispname :
        conn->bits.httpproxy ? conn->http_proxy.host.dispname :
#endif
        conn->bits.conn_to_host ? conn->conn_to_host.dispname :
        conn->host.dispname;
  int port =
#ifndef CURL_DISABLE_PROXY
        conn->bits.httpproxy ? conn->http_proxy.port :
#endif
        conn->bits.conn_to_port ? conn->conn_to_port :
        conn->remote_port;
#endif

  Curl_detach_connection(data);

  CURL_TRC_M(data, "multi_done_locked, in use=%u",
             Curl_uint_spbset_count(&conn->xfers_attached));
  if(CONN_INUSE(conn)) {
    /* Stop if still used. */
    CURL_TRC_M(data, "Connection still in use %u, no more multi_done now!",
               Curl_uint_spbset_count(&conn->xfers_attached));
    return;
  }

  data->state.done = TRUE; /* called just now! */
  data->state.recent_conn_id = conn->connection_id;

  Curl_resolv_unlink(data, &data->state.dns[0]); /* done with this */
  Curl_resolv_unlink(data, &data->state.dns[1]);
  Curl_dnscache_prune(data);

  /* if data->set.reuse_forbid is TRUE, it means the libcurl client has
     forced us to close this connection. This is ignored for requests taking
     place in a NTLM/NEGOTIATE authentication handshake

     if conn->bits.close is TRUE, it means that the connection should be
     closed in spite of all our efforts to be nice, due to protocol
     restrictions in our or the server's end

     if premature is TRUE, it means this connection was said to be DONE before
     the entire request operation is complete and thus we cannot know in what
     state it is for reusing, so we are forced to close it. In a perfect world
     we can add code that keep track of if we really must close it here or not,
     but currently we have no such detail knowledge.
  */

  if((data->set.reuse_forbid
#ifdef USE_NTLM
      && !(conn->http_ntlm_state == NTLMSTATE_TYPE2 ||
           conn->proxy_ntlm_state == NTLMSTATE_TYPE2)
#endif
#ifdef USE_SPNEGO
      && !(conn->http_negotiate_state == GSS_AUTHRECV ||
           conn->proxy_negotiate_state == GSS_AUTHRECV)
#endif
     ) || conn->bits.close
       || (mdctx->premature && !Curl_conn_is_multiplex(conn, FIRSTSOCKET))) {
#ifndef CURL_DISABLE_VERBOSE_STRINGS
    CURL_TRC_M(data, "multi_done, terminating conn #%" FMT_OFF_T " to %s:%d, "
               "forbid=%d, close=%d, premature=%d, conn_multiplex=%d",
               conn->connection_id, host, port, data->set.reuse_forbid,
               conn->bits.close, mdctx->premature,
               Curl_conn_is_multiplex(conn, FIRSTSOCKET));
#endif
    connclose(conn, "disconnecting");
    Curl_conn_terminate(data, conn, mdctx->premature);
  }
  else if(!Curl_conn_get_max_concurrent(data, conn, FIRSTSOCKET)) {
#ifndef CURL_DISABLE_VERBOSE_STRINGS
    CURL_TRC_M(data, "multi_done, conn #%" FMT_OFF_T " to %s:%d was shutdown"
               " by server, not reusing", conn->connection_id, host, port);
#endif
    connclose(conn, "server shutdown");
    Curl_conn_terminate(data, conn, mdctx->premature);
  }
  else {
    /* the connection is no longer in use by any transfer */
    if(Curl_cpool_conn_now_idle(data, conn)) {
      /* connection kept in the cpool */
      data->state.lastconnect_id = conn->connection_id;
#ifndef CURL_DISABLE_VERBOSE_STRINGS
      infof(data, "Connection #%" FMT_OFF_T " to host %s:%d left intact",
            conn->connection_id, host, port);
#endif
    }
    else {
      /* connection was removed from the cpool and destroyed. */
      data->state.lastconnect_id = -1;
    }
  }
}

static CURLcode multi_done(struct Curl_easy *data,
                           CURLcode status,  /* an error if this is called
                                                after an error was detected */
                           bool premature)
{
  CURLcode result;
  struct connectdata *conn = data->conn;
  struct multi_done_ctx mdctx;

  memset(&mdctx, 0, sizeof(mdctx));

  CURL_TRC_M(data, "multi_done: status: %d prem: %d done: %d",
             (int)status, (int)premature, data->state.done);

  if(data->state.done)
    /* Stop if multi_done() has already been called */
    return CURLE_OK;

  /* Shut down any ongoing async resolver operation. */
  Curl_async_shutdown(data);

  /* Cleanup possible redirect junk */
  Curl_safefree(data->req.newurl);
  Curl_safefree(data->req.location);

  switch(status) {
  case CURLE_ABORTED_BY_CALLBACK:
  case CURLE_READ_ERROR:
  case CURLE_WRITE_ERROR:
    /* When we are aborted due to a callback return code it basically have to
       be counted as premature as there is trouble ahead if we do not. We have
       many callbacks and protocols work differently, we could potentially do
       this more fine-grained in the future. */
    premature = TRUE;
    FALLTHROUGH();
  default:
    break;
  }

  /* this calls the protocol-specific function pointer previously set */
  if(conn->handler->done && (data->mstate >= MSTATE_PROTOCONNECT))
    result = conn->handler->done(data, status, premature);
  else
    result = status;

  if(CURLE_ABORTED_BY_CALLBACK != result) {
    /* avoid this if we already aborted by callback to avoid this calling
       another callback */
    int rc = Curl_pgrsDone(data);
    if(!result && rc)
      result = CURLE_ABORTED_BY_CALLBACK;
  }

  /* Make sure that transfer client writes are really done now. */
  result = Curl_1st_err(result, Curl_xfer_write_done(data, premature));

  /* Inform connection filters that this transfer is done */
  Curl_conn_ev_data_done(data, premature);

  process_pending_handles(data->multi); /* connection / multiplex */

  if(!result)
    result = Curl_req_done(&data->req, data, premature);

  /* Under the potential connection pool's share lock, decide what to
   * do with the transfer's connection. */
  mdctx.premature = premature;
  Curl_cpool_do_locked(data, data->conn, multi_done_locked, &mdctx);

  /* flush the netrc cache */
  Curl_netrc_cleanup(&data->state.netrc);
  return result;
}

static void close_connect_only(struct connectdata *conn,
                               struct Curl_easy *data,
                               void *userdata)
{
  (void)userdata;
  (void)data;
  if(conn->connect_only)
    connclose(conn, "Removing connect-only easy handle");
}

CURLMcode curl_multi_remove_handle(CURLM *m, CURL *d)
{
  struct Curl_multi *multi = m;
  struct Curl_easy *data = d;
  bool premature;
  struct Curl_llist_node *e;
  CURLMcode rc;
  bool removed_timer = FALSE;
  unsigned int mid;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  /* Verify that we got a somewhat good easy handle too */
  if(!GOOD_EASY_HANDLE(data))
    return CURLM_BAD_EASY_HANDLE;

  /* Prevent users from trying to remove same easy handle more than once */
  if(!data->multi)
    return CURLM_OK; /* it is already removed so let's say it is fine! */

  /* Prevent users from trying to remove an easy handle from the wrong multi */
  if(data->multi != multi)
    return CURLM_BAD_EASY_HANDLE;

  if(data->mid == UINT_MAX) {
    DEBUGASSERT(0);
    return CURLM_INTERNAL_ERROR;
  }
  if(Curl_uint_tbl_get(&multi->xfers, data->mid) != data) {
    DEBUGASSERT(0);
    return CURLM_INTERNAL_ERROR;
  }

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  premature = (data->mstate < MSTATE_COMPLETED);

  /* If the 'state' is not INIT or COMPLETED, we might need to do something
     nice to put the easy_handle in a good known state when this returns. */
  if(data->conn &&
     data->mstate > MSTATE_DO &&
     data->mstate < MSTATE_COMPLETED) {
    /* Set connection owner so that the DONE function closes it. We can
       safely do this here since connection is killed. */
    streamclose(data->conn, "Removed with partial response");
  }

  if(data->conn) {
    /* multi_done() clears the association between the easy handle and the
       connection.

       Note that this ignores the return code simply because there is
       nothing really useful to do with it anyway! */
    (void)multi_done(data, data->result, premature);
  }

  /* The timer must be shut down before data->multi is set to NULL, else the
     timenode will remain in the splay tree after curl_easy_cleanup is
     called. Do it after multi_done() in case that sets another time! */
  removed_timer = Curl_expire_clear(data);

  /* If in `msgsent`, it was deducted from `multi->xfers_alive` already. */
  if(!Curl_uint_bset_contains(&multi->msgsent, data->mid))
    --multi->xfers_alive;

  Curl_wildcard_dtor(&data->wildcard);

  data->mstate = MSTATE_COMPLETED;

  /* Remove the association between the connection and the handle */
  Curl_detach_connection(data);

  /* Tell event handling that this transfer is definitely going away */
  Curl_multi_ev_xfer_done(multi, data);

  if(data->set.connect_only && !data->multi_easy) {
    /* This removes a handle that was part the multi interface that used
       CONNECT_ONLY, that connection is now left alive but since this handle
       has bits.close set nothing can use that transfer anymore and it is
       forbidden from reuse. This easy handle cannot find the connection
       anymore once removed from the multi handle

       Better close the connection here, at once.
    */
    struct connectdata *c;
    curl_socket_t s;
    s = Curl_getconnectinfo(data, &c);
    if((s != CURL_SOCKET_BAD) && c) {
      Curl_conn_terminate(data, c, TRUE);
    }
  }

  if(data->state.lastconnect_id != -1) {
    /* Mark any connect-only connection for closure */
    Curl_cpool_do_by_id(data, data->state.lastconnect_id,
                            close_connect_only, NULL);
  }

#ifdef USE_LIBPSL
  /* Remove the PSL association. */
  if(data->psl == &multi->psl)
    data->psl = NULL;
#endif

  /* make sure there is no pending message in the queue sent from this easy
     handle */
  for(e = Curl_llist_head(&multi->msglist); e; e = Curl_node_next(e)) {
    struct Curl_message *msg = Curl_node_elem(e);

    if(msg->extmsg.easy_handle == data) {
      Curl_node_remove(e);
      /* there can only be one from this specific handle */
      break;
    }
  }

  /* clear the association to this multi handle */
  mid = data->mid;
  DEBUGASSERT(Curl_uint_tbl_contains(&multi->xfers, mid));
  Curl_uint_tbl_remove(&multi->xfers, mid);
  Curl_uint_bset_remove(&multi->process, mid);
  Curl_uint_bset_remove(&multi->dirty, mid);
  Curl_uint_bset_remove(&multi->pending, mid);
  Curl_uint_bset_remove(&multi->msgsent, mid);
  data->multi = NULL;
  data->mid = UINT_MAX;
  data->master_mid = UINT_MAX;

  /* NOTE NOTE NOTE
     We do not touch the easy handle here! */
  process_pending_handles(multi);

  if(removed_timer) {
    rc = Curl_update_timer(multi);
    if(rc)
      return rc;
  }

  CURL_TRC_M(data, "removed from multi, mid=%u, running=%u, total=%u",
             mid, Curl_multi_xfers_running(multi),
             Curl_uint_tbl_count(&multi->xfers));
  return CURLM_OK;
}

/* Return TRUE if the application asked for multiplexing */
bool Curl_multiplex_wanted(const struct Curl_multi *multi)
{
  return multi && multi->multiplexing;
}

/*
 * Curl_detach_connection() removes the given transfer from the connection.
 *
 * This is the only function that should clear data->conn. This will
 * occasionally be called with the data->conn pointer already cleared.
 */
void Curl_detach_connection(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  if(conn) {
    Curl_uint_spbset_remove(&conn->xfers_attached, data->mid);
    if(Curl_uint_spbset_empty(&conn->xfers_attached))
      conn->attached_multi = NULL;
  }
  data->conn = NULL;
}

/*
 * Curl_attach_connection() attaches this transfer to this connection.
 *
 * This is the only function that should assign data->conn
 */
void Curl_attach_connection(struct Curl_easy *data,
                            struct connectdata *conn)
{
  DEBUGASSERT(data);
  DEBUGASSERT(!data->conn);
  DEBUGASSERT(conn);
  data->conn = conn;
  Curl_uint_spbset_add(&conn->xfers_attached, data->mid);
  /* all attached transfers must be from the same multi */
  if(!conn->attached_multi)
    conn->attached_multi = data->multi;
  DEBUGASSERT(conn->attached_multi == data->multi);

  if(conn->handler && conn->handler->attach)
    conn->handler->attach(data, conn);
}

static CURLcode mstate_connecting_pollset(struct Curl_easy *data,
                                          struct easy_pollset *ps)
{
  if(data->conn) {
    curl_socket_t sockfd = Curl_conn_get_first_socket(data);
    if(sockfd != CURL_SOCKET_BAD) {
      /* Default is to wait to something from the server */
      return Curl_pollset_change(data, ps, sockfd, CURL_POLL_IN, 0);
    }
  }
  return CURLE_OK;
}

static CURLcode mstate_protocol_pollset(struct Curl_easy *data,
                                        struct easy_pollset *ps)
{
  if(data->conn) {
    curl_socket_t sockfd;
    if(data->conn->handler->proto_pollset)
      return data->conn->handler->proto_pollset(data, ps);
    sockfd = data->conn->sock[FIRSTSOCKET];
    if(sockfd != CURL_SOCKET_BAD) {
      /* Default is to wait to something from the server */
      return Curl_pollset_change(data, ps, sockfd, CURL_POLL_IN, 0);
    }
  }
  return CURLE_OK;
}

static CURLcode mstate_do_pollset(struct Curl_easy *data,
                                  struct easy_pollset *ps)
{
  if(data->conn) {
    if(data->conn->handler->doing_pollset)
      return data->conn->handler->doing_pollset(data, ps);
    else if(CONN_SOCK_IDX_VALID(data->conn->send_idx)) {
      /* Default is that we want to send something to the server */
      return Curl_pollset_add_out(
        data, ps, data->conn->sock[data->conn->send_idx]);
    }
  }
  return CURLE_OK;
}

static CURLcode mstate_domore_pollset(struct Curl_easy *data,
                                      struct easy_pollset *ps)
{
  if(data->conn) {
    if(data->conn->handler->domore_pollset)
      return data->conn->handler->domore_pollset(data, ps);
    else if(CONN_SOCK_IDX_VALID(data->conn->send_idx)) {
      /* Default is that we want to send something to the server */
      return Curl_pollset_add_out(
        data, ps, data->conn->sock[data->conn->send_idx]);
    }
  }
  return CURLE_OK;
}

static CURLcode mstate_perform_pollset(struct Curl_easy *data,
                                       struct easy_pollset *ps)
{
  if(!data->conn)
    return CURLE_OK;
  else if(data->conn->handler->perform_pollset)
    return data->conn->handler->perform_pollset(data, ps);
  else {
    /* Default is to obey the data->req.keepon flags for send/recv */
    CURLcode result = CURLE_OK;
    if(CURL_WANT_RECV(data) && CONN_SOCK_IDX_VALID(data->conn->recv_idx)) {
      result = Curl_pollset_add_in(
        data, ps, data->conn->sock[data->conn->recv_idx]);
    }

    if(!result && Curl_req_want_send(data) &&
       CONN_SOCK_IDX_VALID(data->conn->send_idx)) {
      result = Curl_pollset_add_out(
        data, ps, data->conn->sock[data->conn->send_idx]);
    }
    return result;
  }
}

/* Initializes `poll_set` with the current socket poll actions needed
 * for transfer `data`. */
CURLMcode Curl_multi_pollset(struct Curl_easy *data,
                             struct easy_pollset *ps,
                             const char *caller)
{
  CURLMcode mresult = CURLM_OK;
  CURLcode result = CURLE_OK;
  bool expect_sockets = TRUE;

  /* If the transfer has no connection, this is fine. Happens when
     called via curl_multi_remove_handle() => Curl_multi_ev_assess() =>
     Curl_multi_pollset(). */
  Curl_pollset_reset(ps);
  if(!data->conn)
    return CURLM_OK;

  switch(data->mstate) {
  case MSTATE_INIT:
  case MSTATE_PENDING:
  case MSTATE_SETUP:
  case MSTATE_CONNECT:
    /* nothing to poll for yet */
    expect_sockets = FALSE;
    break;

  case MSTATE_RESOLVING:
    result = Curl_resolv_pollset(data, ps);
    /* connection filters are not involved in this phase. It's ok if we get no
     * sockets to wait for. Resolving can wake up from other sources. */
    expect_sockets = FALSE;
    break;

  case MSTATE_CONNECTING:
  case MSTATE_TUNNELING:
    if(!Curl_xfer_recv_is_paused(data)) {
      result = mstate_connecting_pollset(data, ps);
      if(!result)
        result = Curl_conn_adjust_pollset(data, data->conn, ps);
    }
    else
      expect_sockets = FALSE;
    break;

  case MSTATE_PROTOCONNECT:
  case MSTATE_PROTOCONNECTING:
    result = mstate_protocol_pollset(data, ps);
    if(!result)
      result = Curl_conn_adjust_pollset(data, data->conn, ps);
    break;

  case MSTATE_DO:
  case MSTATE_DOING:
    result = mstate_do_pollset(data, ps);
    if(!result)
      result = Curl_conn_adjust_pollset(data, data->conn, ps);
    break;

  case MSTATE_DOING_MORE:
    result = mstate_domore_pollset(data, ps);
    if(!result)
      result = Curl_conn_adjust_pollset(data, data->conn, ps);
    break;

  case MSTATE_DID: /* same as PERFORMING in regard to polling */
  case MSTATE_PERFORMING:
    result = mstate_perform_pollset(data, ps);
    if(!result)
      result = Curl_conn_adjust_pollset(data, data->conn, ps);
    break;

  case MSTATE_RATELIMITING:
    /* we need to let time pass, ignore socket(s) */
    expect_sockets = FALSE;
    break;

  case MSTATE_DONE:
  case MSTATE_COMPLETED:
  case MSTATE_MSGSENT:
    /* nothing more to poll for */
    expect_sockets = FALSE;
    break;

  default:
    failf(data, "multi_getsock: unexpected multi state %d", data->mstate);
    DEBUGASSERT(0);
    expect_sockets = FALSE;
    break;
  }

  if(result) {
    if(result == CURLE_OUT_OF_MEMORY)
      mresult = CURLM_OUT_OF_MEMORY;
    else {
      failf(data, "error determining pollset: %d", result);
      mresult = CURLM_INTERNAL_ERROR;
    }
    goto out;
  }

  /* Unblocked and waiting to receive with buffered input.
   * Make transfer run again at next opportunity. */
  if(!Curl_xfer_is_blocked(data) && !Curl_xfer_is_too_fast(data) &&
     ((Curl_pollset_want_read(data, ps, data->conn->sock[FIRSTSOCKET]) &&
       Curl_conn_data_pending(data, FIRSTSOCKET)) ||
      (Curl_pollset_want_read(data, ps, data->conn->sock[SECONDARYSOCKET]) &&
       Curl_conn_data_pending(data, SECONDARYSOCKET)))) {
    CURL_TRC_M(data, "%s pollset[] has POLLIN, but there is still "
               "buffered input to consume -> mark as dirty", caller);
    Curl_multi_mark_dirty(data);
  }

  if(CURL_TRC_M_is_verbose(data)) {
    size_t timeout_count = Curl_llist_count(&data->state.timeoutlist);
    switch(ps->n) {
      case 0:
        CURL_TRC_M(data, "%s pollset[], timeouts=%zu, paused %d/%d (r/w)",
                   caller, timeout_count,
                   Curl_xfer_send_is_paused(data),
                   Curl_xfer_recv_is_paused(data));
        break;
      case 1:
        CURL_TRC_M(data, "%s pollset[fd=%" FMT_SOCKET_T " %s%s], timeouts=%zu",
                   caller, ps->sockets[0],
                   (ps->actions[0] & CURL_POLL_IN) ? "IN" : "",
                   (ps->actions[0] & CURL_POLL_OUT) ? "OUT" : "",
                   timeout_count);
        break;
      case 2:
        CURL_TRC_M(data, "%s pollset[fd=%" FMT_SOCKET_T " %s%s, "
                   "fd=%" FMT_SOCKET_T " %s%s], timeouts=%zu",
                   caller, ps->sockets[0],
                   (ps->actions[0] & CURL_POLL_IN) ? "IN" : "",
                   (ps->actions[0] & CURL_POLL_OUT) ? "OUT" : "",
                   ps->sockets[1],
                   (ps->actions[1] & CURL_POLL_IN) ? "IN" : "",
                   (ps->actions[1] & CURL_POLL_OUT) ? "OUT" : "",
                   timeout_count);
        break;
      default:
        CURL_TRC_M(data, "%s pollset[fds=%u], timeouts=%zu",
                   caller, ps->n, timeout_count);
        break;
    }
    CURL_TRC_M_TIMEOUTS(data);
  }

  if(expect_sockets && !ps->n && data->multi &&
     !Curl_uint_bset_contains(&data->multi->dirty, data->mid) &&
     !Curl_llist_count(&data->state.timeoutlist) &&
     !Curl_cwriter_is_paused(data) && !Curl_creader_is_paused(data) &&
     Curl_conn_is_ip_connected(data, FIRSTSOCKET)) {
    /* We expected sockets for POLL monitoring, but none are set.
     * We are not dirty (and run anyway).
     * We are not waiting on any timer.
     * None of the READ/WRITE directions are paused.
     * We are connected to the server on IP level, at least. */
    infof(data, "WARNING: no socket in pollset or timer, transfer may stall!");
    DEBUGASSERT(0);
  }
out:
  return mresult;
}

CURLMcode curl_multi_fdset(CURLM *m,
                           fd_set *read_fd_set, fd_set *write_fd_set,
                           fd_set *exc_fd_set, int *max_fd)
{
  /* Scan through all the easy handles to get the file descriptors set.
     Some easy handles may not have connected to the remote host yet,
     and then we must make sure that is done. */
  int this_max_fd = -1;
  struct Curl_multi *multi = m;
  struct easy_pollset ps;
  unsigned int i, mid;
  (void)exc_fd_set;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  Curl_pollset_init(&ps);
  if(Curl_uint_bset_first(&multi->process, &mid)) {
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);

      if(!data) {
        DEBUGASSERT(0);
        continue;
      }

      Curl_multi_pollset(data, &ps, "curl_multi_fdset");
      for(i = 0; i < ps.n; i++) {
        if(!FDSET_SOCK(ps.sockets[i]))
          /* pretend it does not exist */
          continue;
#ifdef __DJGPP__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
        if(ps.actions[i] & CURL_POLL_IN)
          FD_SET(ps.sockets[i], read_fd_set);
        if(ps.actions[i] & CURL_POLL_OUT)
          FD_SET(ps.sockets[i], write_fd_set);
#ifdef __DJGPP__
#pragma GCC diagnostic pop
#endif
        if((int)ps.sockets[i] > this_max_fd)
          this_max_fd = (int)ps.sockets[i];
      }
    }
    while(Curl_uint_bset_next(&multi->process, mid, &mid));
  }

  Curl_cshutdn_setfds(&multi->cshutdn, multi->admin,
                      read_fd_set, write_fd_set, &this_max_fd);

  *max_fd = this_max_fd;
  Curl_pollset_cleanup(&ps);

  return CURLM_OK;
}

CURLMcode curl_multi_waitfds(CURLM *m,
                             struct curl_waitfd *ufds,
                             unsigned int size,
                             unsigned int *fd_count)
{
  struct Curl_waitfds cwfds;
  CURLMcode result = CURLM_OK;
  struct Curl_multi *multi = m;
  struct easy_pollset ps;
  unsigned int need = 0, mid;

  if(!ufds && (size || !fd_count))
    return CURLM_BAD_FUNCTION_ARGUMENT;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  Curl_pollset_init(&ps);
  Curl_waitfds_init(&cwfds, ufds, size);
  if(Curl_uint_bset_first(&multi->process, &mid)) {
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(!data) {
        DEBUGASSERT(0);
        Curl_uint_bset_remove(&multi->process, mid);
        Curl_uint_bset_remove(&multi->dirty, mid);
        continue;
      }
      Curl_multi_pollset(data, &ps, "curl_multi_waitfds");
      need += Curl_waitfds_add_ps(&cwfds, &ps);
    }
    while(Curl_uint_bset_next(&multi->process, mid, &mid));
  }

  need += Curl_cshutdn_add_waitfds(&multi->cshutdn, multi->admin, &cwfds);

  if(need != cwfds.n && ufds) {
    result = CURLM_OUT_OF_MEMORY;
  }

  if(fd_count)
    *fd_count = need;
  Curl_pollset_cleanup(&ps);
  return result;
}

#ifdef USE_WINSOCK
/* Reset FD_WRITE for TCP sockets. Nothing is actually sent. UDP sockets cannot
 * be reset this way because an empty datagram would be sent. #9203
 *
 * "On Windows the internal state of FD_WRITE as returned from
 * WSAEnumNetworkEvents is only reset after successful send()."
 */
static void reset_socket_fdwrite(curl_socket_t s)
{
  int t;
  int l = (int)sizeof(t);
  if(!getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&t, &l) && t == SOCK_STREAM)
    send(s, NULL, 0, 0);
}
#endif

#define NUM_POLLS_ON_STACK 10

static CURLMcode multi_wait(struct Curl_multi *multi,
                            struct curl_waitfd extra_fds[],
                            unsigned int extra_nfds,
                            int timeout_ms,
                            int *ret,
                            bool extrawait, /* when no socket, wait */
                            bool use_wakeup)
{
  size_t i;
  struct curltime expire_time;
  long timeout_internal;
  int retcode = 0;
  struct easy_pollset ps;
  struct pollfd a_few_on_stack[NUM_POLLS_ON_STACK];
  struct curl_pollfds cpfds;
  unsigned int curl_nfds = 0; /* how many pfds are for curl transfers */
  struct Curl_easy *data = NULL;
  CURLMcode result = CURLM_OK;
  unsigned int mid;

#ifdef USE_WINSOCK
  WSANETWORKEVENTS wsa_events;
  DEBUGASSERT(multi->wsa_event != WSA_INVALID_EVENT);
#endif
#ifndef ENABLE_WAKEUP
  (void)use_wakeup;
#endif

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  if(timeout_ms < 0)
    return CURLM_BAD_FUNCTION_ARGUMENT;

  Curl_pollset_init(&ps);
  Curl_pollfds_init(&cpfds, a_few_on_stack, NUM_POLLS_ON_STACK);

  /* Add the curl handles to our pollfds first */
  if(Curl_uint_bset_first(&multi->process, &mid)) {
    do {
      data = Curl_multi_get_easy(multi, mid);
      if(!data) {
        DEBUGASSERT(0);
        Curl_uint_bset_remove(&multi->process, mid);
        Curl_uint_bset_remove(&multi->dirty, mid);
        continue;
      }
      Curl_multi_pollset(data, &ps, "multi_wait");
      if(Curl_pollfds_add_ps(&cpfds, &ps)) {
        result = CURLM_OUT_OF_MEMORY;
        goto out;
      }
    }
    while(Curl_uint_bset_next(&multi->process, mid, &mid));
  }

  if(Curl_cshutdn_add_pollfds(&multi->cshutdn, multi->admin, &cpfds)) {
    result = CURLM_OUT_OF_MEMORY;
    goto out;
  }

  curl_nfds = cpfds.n; /* what curl internally uses in cpfds */
  /* Add external file descriptions from poll-like struct curl_waitfd */
  for(i = 0; i < extra_nfds; i++) {
    unsigned short events = 0;
    if(extra_fds[i].events & CURL_WAIT_POLLIN)
      events |= POLLIN;
    if(extra_fds[i].events & CURL_WAIT_POLLPRI)
      events |= POLLPRI;
    if(extra_fds[i].events & CURL_WAIT_POLLOUT)
      events |= POLLOUT;
    if(Curl_pollfds_add_sock(&cpfds, extra_fds[i].fd, events)) {
      result = CURLM_OUT_OF_MEMORY;
      goto out;
    }
  }

#ifdef USE_WINSOCK
  /* Set the WSA events based on the collected pollds */
  for(i = 0; i < cpfds.n; i++) {
    long mask = 0;
    if(cpfds.pfds[i].events & POLLIN)
      mask |= FD_READ|FD_ACCEPT|FD_CLOSE;
    if(cpfds.pfds[i].events & POLLPRI)
      mask |= FD_OOB;
    if(cpfds.pfds[i].events & POLLOUT) {
      mask |= FD_WRITE|FD_CONNECT|FD_CLOSE;
      reset_socket_fdwrite(cpfds.pfds[i].fd);
    }
    if(mask) {
      if(WSAEventSelect(cpfds.pfds[i].fd, multi->wsa_event, mask) != 0) {
        result = CURLM_OUT_OF_MEMORY;
        goto out;
      }
    }
  }
#endif

#ifdef ENABLE_WAKEUP
#ifndef USE_WINSOCK
  if(use_wakeup && multi->wakeup_pair[0] != CURL_SOCKET_BAD) {
    if(Curl_pollfds_add_sock(&cpfds, multi->wakeup_pair[0], POLLIN)) {
      result = CURLM_OUT_OF_MEMORY;
      goto out;
    }
  }
#endif
#endif

  /* We check the internal timeout *AFTER* we collected all sockets to
   * poll. Collecting the sockets may install new timers by protocols
   * and connection filters.
   * Use the shorter one of the internal and the caller requested timeout. */
  (void)multi_timeout(multi, &expire_time, &timeout_internal);
  if((timeout_internal >= 0) && (timeout_internal < (long)timeout_ms))
    timeout_ms = (int)timeout_internal;

  if(data)
    CURL_TRC_M(data, "multi_wait(fds=%d, timeout=%d) tinternal=%ld",
               cpfds.n, timeout_ms, timeout_internal);
#if defined(ENABLE_WAKEUP) && defined(USE_WINSOCK)
  if(cpfds.n || use_wakeup) {
#else
  if(cpfds.n) {
#endif
    int pollrc;
#ifdef USE_WINSOCK
    if(cpfds.n)         /* just pre-check with Winsock */
      pollrc = Curl_poll(cpfds.pfds, cpfds.n, 0);
    else
      pollrc = 0;
#else
    pollrc = Curl_poll(cpfds.pfds, cpfds.n, timeout_ms); /* wait... */
#endif
    if(pollrc < 0) {
      result = CURLM_UNRECOVERABLE_POLL;
      goto out;
    }

    if(pollrc > 0) {
      retcode = pollrc;
#ifdef USE_WINSOCK
    }
    else { /* now wait... if not ready during the pre-check (pollrc == 0) */
      WSAWaitForMultipleEvents(1, &multi->wsa_event, FALSE, (DWORD)timeout_ms,
                               FALSE);
    }
    /* With Winsock, we have to run the following section unconditionally
       to call WSAEventSelect(fd, event, 0) on all the sockets */
    {
#endif
      /* copy revents results from the poll to the curl_multi_wait poll
         struct, the bit values of the actual underlying poll() implementation
         may not be the same as the ones in the public libcurl API! */
      for(i = 0; i < extra_nfds; i++) {
        unsigned r = (unsigned)cpfds.pfds[curl_nfds + i].revents;
        unsigned short mask = 0;
#ifdef USE_WINSOCK
        curl_socket_t s = extra_fds[i].fd;
        wsa_events.lNetworkEvents = 0;
        if(WSAEnumNetworkEvents(s, NULL, &wsa_events) == 0) {
          if(wsa_events.lNetworkEvents & (FD_READ|FD_ACCEPT|FD_CLOSE))
            mask |= CURL_WAIT_POLLIN;
          if(wsa_events.lNetworkEvents & (FD_WRITE|FD_CONNECT|FD_CLOSE))
            mask |= CURL_WAIT_POLLOUT;
          if(wsa_events.lNetworkEvents & FD_OOB)
            mask |= CURL_WAIT_POLLPRI;
          if(ret && !pollrc && wsa_events.lNetworkEvents)
            retcode++;
        }
        WSAEventSelect(s, multi->wsa_event, 0);
        if(!pollrc) {
          extra_fds[i].revents = (short)mask;
          continue;
        }
#endif
        if(r & POLLIN)
          mask |= CURL_WAIT_POLLIN;
        if(r & POLLOUT)
          mask |= CURL_WAIT_POLLOUT;
        if(r & POLLPRI)
          mask |= CURL_WAIT_POLLPRI;
        extra_fds[i].revents = (short)mask;
      }

#ifdef USE_WINSOCK
      /* Count up all our own sockets that had activity,
         and remove them from the event. */
      for(i = 0; i < curl_nfds; ++i) {
        wsa_events.lNetworkEvents = 0;
        if(WSAEnumNetworkEvents(cpfds.pfds[i].fd, NULL, &wsa_events) == 0) {
          if(ret && !pollrc && wsa_events.lNetworkEvents)
            retcode++;
        }
        WSAEventSelect(cpfds.pfds[i].fd, multi->wsa_event, 0);
      }
      WSAResetEvent(multi->wsa_event);
#else
#ifdef ENABLE_WAKEUP
      if(use_wakeup && multi->wakeup_pair[0] != CURL_SOCKET_BAD) {
        if(cpfds.pfds[curl_nfds + extra_nfds].revents & POLLIN) {
          char buf[64];
          ssize_t nread;
          while(1) {
            /* the reading socket is non-blocking, try to read
               data from it until it receives an error (except EINTR).
               In normal cases it will get EAGAIN or EWOULDBLOCK
               when there is no more data, breaking the loop. */
            nread = wakeup_read(multi->wakeup_pair[0], buf, sizeof(buf));
            if(nread <= 0) {
              if(nread < 0 && SOCKEINTR == SOCKERRNO)
                continue;
              break;
            }
          }
          /* do not count the wakeup socket into the returned value */
          retcode--;
        }
      }
#endif
#endif
    }
  }

  if(ret)
    *ret = retcode;
#if defined(ENABLE_WAKEUP) && defined(USE_WINSOCK)
  if(extrawait && !cpfds.n && !use_wakeup) {
#else
  if(extrawait && !cpfds.n) {
#endif
    long sleep_ms = 0;

    /* Avoid busy-looping when there is nothing particular to wait for */
    if(!curl_multi_timeout(multi, &sleep_ms) && sleep_ms) {
      if(sleep_ms > timeout_ms)
        sleep_ms = timeout_ms;
      /* when there are no easy handles in the multi, this holds a -1
         timeout */
      else if(sleep_ms < 0)
        sleep_ms = timeout_ms;
      curlx_wait_ms(sleep_ms);
    }
  }

out:
  Curl_pollset_cleanup(&ps);
  Curl_pollfds_cleanup(&cpfds);
  return result;
}

CURLMcode curl_multi_wait(CURLM *multi,
                          struct curl_waitfd extra_fds[],
                          unsigned int extra_nfds,
                          int timeout_ms,
                          int *ret)
{
  return multi_wait(multi, extra_fds, extra_nfds, timeout_ms, ret, FALSE,
                    FALSE);
}

CURLMcode curl_multi_poll(CURLM *multi,
                          struct curl_waitfd extra_fds[],
                          unsigned int extra_nfds,
                          int timeout_ms,
                          int *ret)
{
  return multi_wait(multi, extra_fds, extra_nfds, timeout_ms, ret, TRUE,
                    TRUE);
}

CURLMcode curl_multi_wakeup(CURLM *m)
{
  /* this function is usually called from another thread,
     it has to be careful only to access parts of the
     Curl_multi struct that are constant */
  struct Curl_multi *multi = m;

  /* GOOD_MULTI_HANDLE can be safely called */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

#ifdef ENABLE_WAKEUP
#ifdef USE_WINSOCK
  if(WSASetEvent(multi->wsa_event))
    return CURLM_OK;
#else
  /* the wakeup_pair variable is only written during init and cleanup,
     making it safe to access from another thread after the init part
     and before cleanup */
  if(multi->wakeup_pair[1] != CURL_SOCKET_BAD) {
    while(1) {
#ifdef USE_EVENTFD
      /* eventfd has a stringent rule of requiring the 8-byte buffer when
         calling write(2) on it */
      const uint64_t buf[1] = { 1 };
#else
      const char buf[1] = { 1 };
#endif
      /* swrite() is not thread-safe in general, because concurrent calls
         can have their messages interleaved, but in this case the content
         of the messages does not matter, which makes it ok to call.

         The write socket is set to non-blocking, this way this function
         cannot block, making it safe to call even from the same thread
         that will call curl_multi_wait(). If swrite() returns that it
         would block, it is considered successful because it means that
         previous calls to this function will wake up the poll(). */
      if(wakeup_write(multi->wakeup_pair[1], buf, sizeof(buf)) < 0) {
        int err = SOCKERRNO;
        int return_success;
#ifdef USE_WINSOCK
        return_success = SOCKEWOULDBLOCK == err;
#else
        if(SOCKEINTR == err)
          continue;
        return_success = SOCKEWOULDBLOCK == err || EAGAIN == err;
#endif
        if(!return_success)
          return CURLM_WAKEUP_FAILURE;
      }
      return CURLM_OK;
    }
  }
#endif
#endif
  return CURLM_WAKEUP_FAILURE;
}

/*
 * multi_ischanged() is called
 *
 * Returns TRUE/FALSE whether the state is changed to trigger a CONNECT_PEND
 * => CONNECT action.
 *
 * Set 'clear' to TRUE to have it also clear the state variable.
 */
static bool multi_ischanged(struct Curl_multi *multi, bool clear)
{
  bool retval = multi->recheckstate;
  if(clear)
    multi->recheckstate = FALSE;
  return retval;
}

/*
 * Curl_multi_connchanged() is called to tell that there is a connection in
 * this multi handle that has changed state (multiplexing become possible, the
 * number of allowed streams changed or similar), and a subsequent use of this
 * multi handle should move CONNECT_PEND handles back to CONNECT to have them
 * retry.
 */
void Curl_multi_connchanged(struct Curl_multi *multi)
{
  multi->recheckstate = TRUE;
}

CURLMcode Curl_multi_add_perform(struct Curl_multi *multi,
                                 struct Curl_easy *data,
                                 struct connectdata *conn)
{
  CURLMcode rc;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  rc = curl_multi_add_handle(multi, data);
  if(!rc) {
    struct SingleRequest *k = &data->req;
    CURLcode result;

    /* pass in NULL for 'conn' here since we do not want to init the
       connection, only this transfer */
    result = Curl_init_do(data, NULL);
    if(result) {
      curl_multi_remove_handle(multi, data);
      return CURLM_INTERNAL_ERROR;
    }

    /* take this handle to the perform state right away */
    multistate(data, MSTATE_PERFORMING);
    Curl_attach_connection(data, conn);
    k->keepon |= KEEP_RECV; /* setup to receive! */
  }
  return rc;
}

static CURLcode multi_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->handler);

  if(conn->handler->do_it)
    result = conn->handler->do_it(data, done);

  return result;
}

/*
 * multi_do_more() is called during the DO_MORE multi state. It is basically a
 * second stage DO state which (wrongly) was introduced to support FTP's
 * second connection.
 *
 * 'complete' can return 0 for incomplete, 1 for done and -1 for go back to
 * DOING state there is more work to do!
 */

static CURLcode multi_do_more(struct Curl_easy *data, int *complete)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  *complete = 0;

  if(conn->handler->do_more)
    result = conn->handler->do_more(data, complete);

  return result;
}

/*
 * Check whether a timeout occurred, and handle it if it did
 */
static bool multi_handle_timeout(struct Curl_easy *data,
                                 struct curltime *now,
                                 bool *stream_error,
                                 CURLcode *result)
{
  bool connect_timeout = data->mstate < MSTATE_DO;
  timediff_t timeout_ms = Curl_timeleft(data, now, connect_timeout);
  if(timeout_ms < 0) {
    /* Handle timed out */
    struct curltime since;
    if(connect_timeout)
      since = data->progress.t_startsingle;
    else
      since = data->progress.t_startop;
    if(data->mstate == MSTATE_RESOLVING)
      failf(data, "Resolving timed out after %" FMT_TIMEDIFF_T
            " milliseconds", curlx_timediff(*now, since));
    else if(data->mstate == MSTATE_CONNECTING)
      failf(data, "Connection timed out after %" FMT_TIMEDIFF_T
            " milliseconds", curlx_timediff(*now, since));
    else {
      struct SingleRequest *k = &data->req;
      if(k->size != -1) {
        failf(data, "Operation timed out after %" FMT_TIMEDIFF_T
              " milliseconds with %" FMT_OFF_T " out of %"
              FMT_OFF_T " bytes received",
              curlx_timediff(*now, since), k->bytecount, k->size);
      }
      else {
        failf(data, "Operation timed out after %" FMT_TIMEDIFF_T
              " milliseconds with %" FMT_OFF_T " bytes received",
              curlx_timediff(*now, since), k->bytecount);
      }
    }
    *result = CURLE_OPERATION_TIMEDOUT;
    if(data->conn) {
      /* Force connection closed if the connection has indeed been used */
      if(data->mstate > MSTATE_DO) {
        streamclose(data->conn, "Disconnect due to timeout");
        *stream_error = TRUE;
      }
      (void)multi_done(data, *result, TRUE);
    }
    return TRUE;
  }

  return FALSE;
}

/*
 * We are doing protocol-specific connecting and this is being called over and
 * over from the multi interface until the connection phase is done on
 * protocol layer.
 */

static CURLcode protocol_connecting(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  if(conn && conn->handler->connecting) {
    *done = FALSE;
    result = conn->handler->connecting(data, done);
  }
  else
    *done = TRUE;

  return result;
}

/*
 * We are DOING this is being called over and over from the multi interface
 * until the DOING phase is done on protocol layer.
 */

static CURLcode protocol_doing(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  if(conn && conn->handler->doing) {
    *done = FALSE;
    result = conn->handler->doing(data, done);
  }
  else
    *done = TRUE;

  return result;
}

/*
 * We have discovered that the TCP connection has been successful, we can now
 * proceed with some action.
 *
 */
static CURLcode protocol_connect(struct Curl_easy *data,
                                 bool *protocol_done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  DEBUGASSERT(conn);
  DEBUGASSERT(protocol_done);

  *protocol_done = FALSE;

  if(Curl_conn_is_connected(conn, FIRSTSOCKET)
     && conn->bits.protoconnstart) {
    /* We already are connected, get back. This may happen when the connect
       worked fine in the first call, like when we connect to a local server
       or proxy. Note that we do not know if the protocol is actually done.

       Unless this protocol does not have any protocol-connect callback, as
       then we know we are done. */
    if(!conn->handler->connecting)
      *protocol_done = TRUE;

    return CURLE_OK;
  }

  if(!conn->bits.protoconnstart) {
    if(conn->handler->connect_it) {
      /* is there a protocol-specific connect() procedure? */

      /* Call the protocol-specific connect function */
      result = conn->handler->connect_it(data, protocol_done);
    }
    else
      *protocol_done = TRUE;

    /* it has started, possibly even completed but that knowledge is not stored
       in this bit! */
    if(!result)
      conn->bits.protoconnstart = TRUE;
  }

  return result; /* pass back status */
}

static void set_in_callback(struct Curl_multi *multi, bool value)
{
  multi->in_callback = value;
}

/*
 * posttransfer() is called immediately after a transfer ends
 */
static void multi_posttransfer(struct Curl_easy *data)
{
#if defined(HAVE_SIGNAL) && defined(SIGPIPE) && !defined(HAVE_MSG_NOSIGNAL)
  /* restore the signal handler for SIGPIPE before we get back */
  if(!data->set.no_signal)
    signal(SIGPIPE, data->state.prev_signal);
#else
  (void)data;
#endif
}

/*
 * multi_follow() handles the URL redirect magic. Pass in the 'newurl' string
 * as given by the remote server and set up the new URL to request.
 *
 * This function DOES NOT FREE the given url.
 */
static CURLcode multi_follow(struct Curl_easy *data,
                             const struct Curl_handler *handler,
                             const char *newurl, /* the Location: string */
                             followtype type) /* see transfer.h */
{
  if(handler && handler->follow)
    return handler->follow(data, newurl, type);
  return CURLE_TOO_MANY_REDIRECTS;
}

static CURLcode mspeed_check(struct Curl_easy *data,
                             struct curltime *nowp)
{
  timediff_t recv_wait_ms = 0;
  timediff_t send_wait_ms = 0;

  /* check if over send speed */
  if(data->set.max_send_speed)
    send_wait_ms = Curl_pgrsLimitWaitTime(&data->progress.ul,
                                          data->set.max_send_speed,
                                          *nowp);

  /* check if over recv speed */
  if(data->set.max_recv_speed)
    recv_wait_ms = Curl_pgrsLimitWaitTime(&data->progress.dl,
                                          data->set.max_recv_speed,
                                          *nowp);

  if(send_wait_ms || recv_wait_ms) {
    if(data->mstate != MSTATE_RATELIMITING) {
      Curl_ratelimit(data, *nowp);
      multistate(data, MSTATE_RATELIMITING);
    }
    Curl_expire(data, CURLMAX(send_wait_ms, recv_wait_ms), EXPIRE_TOOFAST);
    Curl_multi_clear_dirty(data);
    return CURLE_AGAIN;
  }
  else if(data->mstate != MSTATE_PERFORMING) {
    multistate(data, MSTATE_PERFORMING);
    Curl_ratelimit(data, *nowp);
  }
  return CURLE_OK;
}

static CURLMcode state_performing(struct Curl_easy *data,
                                  struct curltime *nowp,
                                  bool *stream_errorp,
                                  CURLcode *resultp)
{
  char *newurl = NULL;
  bool retry = FALSE;
  CURLMcode rc = CURLM_OK;
  CURLcode result = *resultp = CURLE_OK;
  *stream_errorp = FALSE;

  if(mspeed_check(data, nowp) == CURLE_AGAIN)
    return CURLM_OK;

  /* read/write data if it is ready to do so */
  result = Curl_sendrecv(data, nowp);

  if(data->req.done || (result == CURLE_RECV_ERROR)) {
    /* If CURLE_RECV_ERROR happens early enough, we assume it was a race
     * condition and the server closed the reused connection exactly when we
     * wanted to use it, so figure out if that is indeed the case.
     */
    CURLcode ret = Curl_retry_request(data, &newurl);
    if(!ret)
      retry = !!newurl;
    else if(!result)
      result = ret;

    if(retry) {
      /* if we are to retry, set the result to OK and consider the
         request as done */
      result = CURLE_OK;
      data->req.done = TRUE;
    }
  }
#ifndef CURL_DISABLE_HTTP
  else if((CURLE_HTTP2_STREAM == result) &&
          Curl_h2_http_1_1_error(data)) {
    CURLcode ret = Curl_retry_request(data, &newurl);

    if(!ret) {
      infof(data, "Downgrades to HTTP/1.1");
      streamclose(data->conn, "Disconnect HTTP/2 for HTTP/1");
      data->state.http_neg.wanted = CURL_HTTP_V1x;
      data->state.http_neg.allowed = CURL_HTTP_V1x;
      /* clear the error message bit too as we ignore the one we got */
      data->state.errorbuf = FALSE;
      if(!newurl)
        /* typically for HTTP_1_1_REQUIRED error on first flight */
        newurl = strdup(data->state.url);
      /* if we are to retry, set the result to OK and consider the request
         as done */
      retry = TRUE;
      result = CURLE_OK;
      data->req.done = TRUE;
    }
    else
      result = ret;
  }
#endif

  if(result) {
    /*
     * The transfer phase returned error, we mark the connection to get closed
     * to prevent being reused. This is because we cannot possibly know if the
     * connection is in a good shape or not now. Unless it is a protocol which
     * uses two "channels" like FTP, as then the error happened in the data
     * connection.
     */

    if(!(data->conn->handler->flags & PROTOPT_DUAL) &&
       result != CURLE_HTTP2_STREAM)
      streamclose(data->conn, "Transfer returned error");

    multi_posttransfer(data);
    multi_done(data, result, TRUE);
  }
  else if(data->req.done && !Curl_cwriter_is_paused(data)) {
    const struct Curl_handler *handler = data->conn->handler;

    /* call this even if the readwrite function returned error */
    multi_posttransfer(data);

    /* When we follow redirects or is set to retry the connection, we must to
       go back to the CONNECT state */
    if(data->req.newurl || retry) {
      followtype follow = FOLLOW_NONE;
      if(!retry) {
        /* if the URL is a follow-location and not just a retried request then
           figure out the URL here */
        free(newurl);
        newurl = data->req.newurl;
        data->req.newurl = NULL;
        follow = FOLLOW_REDIR;
      }
      else
        follow = FOLLOW_RETRY;
      (void)multi_done(data, CURLE_OK, FALSE);
      /* multi_done() might return CURLE_GOT_NOTHING */
      result = multi_follow(data, handler, newurl, follow);
      if(!result) {
        multistate(data, MSTATE_SETUP);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
    }
    else {
      /* after the transfer is done, go DONE */

      /* but first check to see if we got a location info even though we are
         not following redirects */
      if(data->req.location) {
        free(newurl);
        newurl = data->req.location;
        data->req.location = NULL;
        result = multi_follow(data, handler, newurl, FOLLOW_FAKE);
        if(result) {
          *stream_errorp = TRUE;
          result = multi_done(data, result, TRUE);
        }
      }

      if(!result) {
        multistate(data, MSTATE_DONE);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
    }
  }
  else { /* not errored, not done */
    mspeed_check(data, nowp);
  }
  free(newurl);
  *resultp = result;
  return rc;
}

static CURLMcode state_do(struct Curl_easy *data,
                          bool *stream_errorp,
                          CURLcode *resultp)
{
  CURLMcode rc = CURLM_OK;
  CURLcode result = CURLE_OK;
  if(data->set.fprereq) {
    int prereq_rc;

    /* call the prerequest callback function */
    Curl_set_in_callback(data, TRUE);
    prereq_rc = data->set.fprereq(data->set.prereq_userp,
                                  data->info.primary.remote_ip,
                                  data->info.primary.local_ip,
                                  data->info.primary.remote_port,
                                  data->info.primary.local_port);
    Curl_set_in_callback(data, FALSE);
    if(prereq_rc != CURL_PREREQFUNC_OK) {
      failf(data, "operation aborted by pre-request callback");
      /* failure in pre-request callback - do not do any other processing */
      result = CURLE_ABORTED_BY_CALLBACK;
      multi_posttransfer(data);
      multi_done(data, result, FALSE);
      *stream_errorp = TRUE;
      goto end;
    }
  }

  if(data->set.connect_only && !data->set.connect_only_ws) {
    /* keep connection open for application to use the socket */
    connkeep(data->conn, "CONNECT_ONLY");
    multistate(data, MSTATE_DONE);
    rc = CURLM_CALL_MULTI_PERFORM;
  }
  else {
    bool dophase_done = FALSE;
    /* Perform the protocol's DO action */
    result = multi_do(data, &dophase_done);

    /* When multi_do() returns failure, data->conn might be NULL! */

    if(!result) {
      if(!dophase_done) {
#ifndef CURL_DISABLE_FTP
        /* some steps needed for wildcard matching */
        if(data->state.wildcardmatch) {
          struct WildcardData *wc = data->wildcard;
          if(wc->state == CURLWC_DONE || wc->state == CURLWC_SKIP) {
            /* skip some states if it is important */
            multi_done(data, CURLE_OK, FALSE);

            /* if there is no connection left, skip the DONE state */
            multistate(data, data->conn ?
                       MSTATE_DONE : MSTATE_COMPLETED);
            rc = CURLM_CALL_MULTI_PERFORM;
            goto end;
          }
        }
#endif
        /* DO was not completed in one function call, we must continue
           DOING... */
        multistate(data, MSTATE_DOING);
        rc = CURLM_CALL_MULTI_PERFORM;
      }

      /* after DO, go DO_DONE... or DO_MORE */
      else if(data->conn->bits.do_more) {
        /* we are supposed to do more, but we need to sit down, relax and wait
           a little while first */
        multistate(data, MSTATE_DOING_MORE);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else {
        /* we are done with the DO, now DID */
        multistate(data, MSTATE_DID);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
    }
    else if((CURLE_SEND_ERROR == result) &&
            data->conn->bits.reuse) {
      /*
       * In this situation, a connection that we were trying to use may have
       * unexpectedly died. If possible, send the connection back to the
       * CONNECT phase so we can try again.
       */
      const struct Curl_handler *handler = data->conn->handler;
      char *newurl = NULL;
      followtype follow = FOLLOW_NONE;
      CURLcode drc;

      drc = Curl_retry_request(data, &newurl);
      if(drc) {
        /* a failure here pretty much implies an out of memory */
        result = drc;
        *stream_errorp = TRUE;
      }

      multi_posttransfer(data);
      drc = multi_done(data, result, FALSE);

      /* When set to retry the connection, we must go back to the CONNECT
       * state */
      if(newurl) {
        if(!drc || (drc == CURLE_SEND_ERROR)) {
          follow = FOLLOW_RETRY;
          drc = multi_follow(data, handler, newurl, follow);
          if(!drc) {
            multistate(data, MSTATE_SETUP);
            rc = CURLM_CALL_MULTI_PERFORM;
            result = CURLE_OK;
          }
          else {
            /* Follow failed */
            result = drc;
          }
        }
        else {
          /* done did not return OK or SEND_ERROR */
          result = drc;
        }
      }
      else {
        /* Have error handler disconnect conn if we cannot retry */
        *stream_errorp = TRUE;
      }
      free(newurl);
    }
    else {
      /* failure detected */
      multi_posttransfer(data);
      if(data->conn)
        multi_done(data, result, FALSE);
      *stream_errorp = TRUE;
    }
  }
end:
  *resultp = result;
  return rc;
}

static CURLMcode state_ratelimiting(struct Curl_easy *data,
                                    struct curltime *nowp,
                                    CURLcode *resultp)
{
  CURLcode result = CURLE_OK;
  CURLMcode rc = CURLM_OK;
  DEBUGASSERT(data->conn);
  /* if both rates are within spec, resume transfer */
  if(Curl_pgrsUpdate(data))
    result = CURLE_ABORTED_BY_CALLBACK;
  else
    result = Curl_speedcheck(data, *nowp);

  if(result) {
    if(!(data->conn->handler->flags & PROTOPT_DUAL) &&
       result != CURLE_HTTP2_STREAM)
      streamclose(data->conn, "Transfer returned error");

    multi_posttransfer(data);
    multi_done(data, result, TRUE);
  }
  else {
    if(!mspeed_check(data, nowp))
      rc = CURLM_CALL_MULTI_PERFORM;
  }
  *resultp = result;
  return rc;
}

static CURLMcode state_resolving(struct Curl_multi *multi,
                                 struct Curl_easy *data,
                                 bool *stream_errorp,
                                 CURLcode *resultp)
{
  struct Curl_dns_entry *dns = NULL;
  CURLcode result;
  CURLMcode rc = CURLM_OK;

  result = Curl_resolv_check(data, &dns);
  CURL_TRC_DNS(data, "Curl_resolv_check() -> %d, %s",
               result, dns ? "found" : "missing");
  /* Update sockets here, because the socket(s) may have been closed and the
     application thus needs to be told, even if it is likely that the same
     socket(s) will again be used further down. If the name has not yet been
     resolved, it is likely that new sockets have been opened in an attempt to
     contact another resolver. */
  rc = Curl_multi_ev_assess_xfer(multi, data);
  if(rc)
    return rc;

  if(dns) {
    bool connected;
    /* Perform the next step in the connection phase, and then move on to the
       WAITCONNECT state */
    result = Curl_once_resolved(data, dns, &connected);

    if(result)
      /* if Curl_once_resolved() returns failure, the connection struct is
         already freed and gone */
      data->conn = NULL; /* no more connection */
    else {
      /* call again please so that we get the next socket setup */
      rc = CURLM_CALL_MULTI_PERFORM;
      if(connected)
        multistate(data, MSTATE_PROTOCONNECT);
      else {
        multistate(data, MSTATE_CONNECTING);
      }
    }
  }

  if(result)
    /* failure detected */
    *stream_errorp = TRUE;

  *resultp = result;
  return rc;
}

static CURLMcode state_connect(struct Curl_multi *multi,
                               struct Curl_easy *data,
                               struct curltime *nowp,
                               CURLcode *resultp)
{
  /* Connect. We want to get a connection identifier filled in. This state can
     be entered from SETUP and from PENDING. */
  bool connected;
  bool async;
  CURLMcode rc = CURLM_OK;
  CURLcode result = Curl_connect(data, &async, &connected);
  if(CURLE_NO_CONNECTION_AVAILABLE == result) {
    /* There was no connection available. We will go to the pending state and
       wait for an available connection. */
    multistate(data, MSTATE_PENDING);
    /* move from process to pending set */
    Curl_uint_bset_remove(&multi->process, data->mid);
    Curl_uint_bset_remove(&multi->dirty, data->mid);
    Curl_uint_bset_add(&multi->pending, data->mid);
    *resultp = CURLE_OK;
    return rc;
  }
  else
    process_pending_handles(data->multi);

  if(!result) {
    *nowp = Curl_pgrsTime(data, TIMER_POSTQUEUE);
    if(async)
      /* We are now waiting for an asynchronous name lookup */
      multistate(data, MSTATE_RESOLVING);
    else {
      /* after the connect has been sent off, go WAITCONNECT unless the
         protocol connect is already done and we can go directly to WAITDO or
         DO! */
      rc = CURLM_CALL_MULTI_PERFORM;

      if(connected) {
        if(!data->conn->bits.reuse &&
           Curl_conn_is_multiplex(data->conn, FIRSTSOCKET)) {
          /* new connection, can multiplex, wake pending handles */
          process_pending_handles(data->multi);
        }
        multistate(data, MSTATE_PROTOCONNECT);
      }
      else {
        multistate(data, MSTATE_CONNECTING);
      }
    }
  }
  *resultp = result;
  return rc;
}

static CURLMcode multi_runsingle(struct Curl_multi *multi,
                                 struct curltime *nowp,
                                 struct Curl_easy *data)
{
  struct Curl_message *msg = NULL;
  bool connected;
  bool protocol_connected = FALSE;
  bool dophase_done = FALSE;
  CURLMcode rc;
  CURLcode result = CURLE_OK;
  int control;

  if(!GOOD_EASY_HANDLE(data))
    return CURLM_BAD_EASY_HANDLE;

  if(multi->dead) {
    /* a multi-level callback returned error before, meaning every individual
     transfer now has failed */
    result = CURLE_ABORTED_BY_CALLBACK;
    multi_posttransfer(data);
    multi_done(data, result, FALSE);
    multistate(data, MSTATE_COMPLETED);
  }

  multi_warn_debug(multi, data);

  /* transfer runs now, clear the dirty bit. This may be set
   * again during processing, triggering a re-run later. */
  Curl_uint_bset_remove(&multi->dirty, data->mid);

  do {
    /* A "stream" here is a logical stream if the protocol can handle that
       (HTTP/2), or the full connection for older protocols */
    bool stream_error = FALSE;
    rc = CURLM_OK;

    if(multi_ischanged(multi, TRUE)) {
      CURL_TRC_M(data, "multi changed, check CONNECT_PEND queue");
      process_pending_handles(multi); /* multiplexed */
    }

    if(data->mstate > MSTATE_CONNECT &&
       data->mstate < MSTATE_COMPLETED) {
      /* Make sure we set the connection's current owner */
      DEBUGASSERT(data->conn);
      if(!data->conn)
        return CURLM_INTERNAL_ERROR;
    }

    /* Wait for the connect state as only then is the start time stored, but
       we must not check already completed handles */
    if((data->mstate >= MSTATE_CONNECT) && (data->mstate < MSTATE_COMPLETED) &&
       multi_handle_timeout(data, nowp, &stream_error, &result))
      /* Skip the statemachine and go directly to error handling section. */
      goto statemachine_end;

    switch(data->mstate) {
    case MSTATE_INIT:
      /* Transitional state. init this transfer. A handle never comes back to
         this state. */
      result = Curl_pretransfer(data);
      if(result)
        break;

      /* after init, go SETUP */
      multistate(data, MSTATE_SETUP);
      (void)Curl_pgrsTime(data, TIMER_STARTOP);
      FALLTHROUGH();

    case MSTATE_SETUP:
      /* Transitional state. Setup things for a new transfer. The handle
         can come back to this state on a redirect. */
      *nowp = Curl_pgrsTime(data, TIMER_STARTSINGLE);
      if(data->set.timeout)
        Curl_expire(data, data->set.timeout, EXPIRE_TIMEOUT);
      if(data->set.connecttimeout)
        /* Since a connection might go to pending and back to CONNECT several
           times before it actually takes off, we need to set the timeout once
           in SETUP before we enter CONNECT the first time. */
        Curl_expire(data, data->set.connecttimeout, EXPIRE_CONNECTTIMEOUT);

      multistate(data, MSTATE_CONNECT);
      FALLTHROUGH();

    case MSTATE_CONNECT:
      rc = state_connect(multi, data, nowp, &result);
      break;

    case MSTATE_RESOLVING:
      /* awaiting an asynch name resolve to complete */
      rc = state_resolving(multi, data, &stream_error, &result);
      break;

#ifndef CURL_DISABLE_HTTP
    case MSTATE_TUNNELING:
      /* this is HTTP-specific, but sending CONNECT to a proxy is HTTP... */
      DEBUGASSERT(data->conn);
      result = Curl_http_connect(data, &protocol_connected);
      if(!result) {
        rc = CURLM_CALL_MULTI_PERFORM;
        /* initiate protocol connect phase */
        multistate(data, MSTATE_PROTOCONNECT);
      }
      else
        stream_error = TRUE;
      break;
#endif

    case MSTATE_CONNECTING:
      /* awaiting a completion of an asynch TCP connect */
      DEBUGASSERT(data->conn);
      if(!Curl_xfer_recv_is_paused(data)) {
        result = Curl_conn_connect(data, FIRSTSOCKET, FALSE, &connected);
        if(connected && !result) {
          if(!data->conn->bits.reuse &&
             Curl_conn_is_multiplex(data->conn, FIRSTSOCKET)) {
            /* new connection, can multiplex, wake pending handles */
            process_pending_handles(data->multi);
          }
          rc = CURLM_CALL_MULTI_PERFORM;
          multistate(data, MSTATE_PROTOCONNECT);
        }
        else if(result) {
          /* failure detected */
          multi_posttransfer(data);
          multi_done(data, result, TRUE);
          stream_error = TRUE;
          break;
        }
      }
      break;

    case MSTATE_PROTOCONNECT:
      if(!result && data->conn->bits.reuse) {
        /* ftp seems to hang when protoconnect on reused connection since we
         * handle PROTOCONNECT in general inside the filers, it seems wrong to
         * restart this on a reused connection.
         */
        multistate(data, MSTATE_DO);
        rc = CURLM_CALL_MULTI_PERFORM;
        break;
      }
      if(!result)
        result = protocol_connect(data, &protocol_connected);
      if(!result && !protocol_connected) {
        /* switch to waiting state */
        multistate(data, MSTATE_PROTOCONNECTING);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else if(!result) {
        /* protocol connect has completed, go WAITDO or DO */
        multistate(data, MSTATE_DO);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else {
        /* failure detected */
        multi_posttransfer(data);
        multi_done(data, result, TRUE);
        stream_error = TRUE;
      }
      break;

    case MSTATE_PROTOCONNECTING:
      /* protocol-specific connect phase */
      result = protocol_connecting(data, &protocol_connected);
      if(!result && protocol_connected) {
        /* after the connect has completed, go WAITDO or DO */
        multistate(data, MSTATE_DO);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else if(result) {
        /* failure detected */
        multi_posttransfer(data);
        multi_done(data, result, TRUE);
        stream_error = TRUE;
      }
      break;

    case MSTATE_DO:
      rc = state_do(data, &stream_error, &result);
      break;

    case MSTATE_DOING:
      /* we continue DOING until the DO phase is complete */
      DEBUGASSERT(data->conn);
      result = protocol_doing(data, &dophase_done);
      if(!result) {
        if(dophase_done) {
          /* after DO, go DO_DONE or DO_MORE */
          multistate(data, data->conn->bits.do_more ?
                     MSTATE_DOING_MORE : MSTATE_DID);
          rc = CURLM_CALL_MULTI_PERFORM;
        } /* dophase_done */
      }
      else {
        /* failure detected */
        multi_posttransfer(data);
        multi_done(data, result, FALSE);
        stream_error = TRUE;
      }
      break;

    case MSTATE_DOING_MORE:
      /*
       * When we are connected, DOING MORE and then go DID
       */
      DEBUGASSERT(data->conn);
      result = multi_do_more(data, &control);

      if(!result) {
        if(control) {
          /* if positive, advance to DO_DONE
             if negative, go back to DOING */
          multistate(data, control == 1 ?
                     MSTATE_DID : MSTATE_DOING);
          rc = CURLM_CALL_MULTI_PERFORM;
        }
        /* else
           stay in DO_MORE */
      }
      else {
        /* failure detected */
        multi_posttransfer(data);
        multi_done(data, result, FALSE);
        stream_error = TRUE;
      }
      break;

    case MSTATE_DID:
      DEBUGASSERT(data->conn);
      if(data->conn->bits.multiplex)
        /* Check if we can move pending requests to send pipe */
        process_pending_handles(multi); /*  multiplexed */

      /* Only perform the transfer if there is a good socket to work with.
         Having both BAD is a signal to skip immediately to DONE */
      if(CONN_SOCK_IDX_VALID(data->conn->recv_idx) ||
         CONN_SOCK_IDX_VALID(data->conn->send_idx))
        multistate(data, MSTATE_PERFORMING);
      else {
#ifndef CURL_DISABLE_FTP
        if(data->state.wildcardmatch &&
           ((data->conn->handler->flags & PROTOPT_WILDCARD) == 0)) {
          data->wildcard->state = CURLWC_DONE;
        }
#endif
        multistate(data, MSTATE_DONE);
      }
      rc = CURLM_CALL_MULTI_PERFORM;
      break;

    case MSTATE_RATELIMITING: /* limit-rate exceeded in either direction */
      rc = state_ratelimiting(data, nowp, &result);
      break;

    case MSTATE_PERFORMING:
      rc = state_performing(data, nowp, &stream_error, &result);
      break;

    case MSTATE_DONE:
      /* this state is highly transient, so run another loop after this */
      rc = CURLM_CALL_MULTI_PERFORM;

      if(data->conn) {
        CURLcode res;

        /* post-transfer command */
        res = multi_done(data, result, FALSE);

        /* allow a previously set error code take precedence */
        if(!result)
          result = res;
      }

#ifndef CURL_DISABLE_FTP
      if(data->state.wildcardmatch) {
        if(data->wildcard->state != CURLWC_DONE) {
          /* if a wildcard is set and we are not ending -> lets start again
             with MSTATE_INIT */
          multistate(data, MSTATE_INIT);
          break;
        }
      }
#endif
      /* after we have DONE what we are supposed to do, go COMPLETED, and
         it does not matter what the multi_done() returned! */
      multistate(data, MSTATE_COMPLETED);
      break;

    case MSTATE_COMPLETED:
      break;

    case MSTATE_PENDING:
    case MSTATE_MSGSENT:
      /* handles in these states should NOT be in this list */
      break;

    default:
      return CURLM_INTERNAL_ERROR;
    }

    if(data->mstate >= MSTATE_CONNECT &&
       data->mstate < MSTATE_DO &&
       rc != CURLM_CALL_MULTI_PERFORM &&
       !multi_ischanged(multi, FALSE)) {
      /* We now handle stream timeouts if and only if this will be the last
       * loop iteration. We only check this on the last iteration to ensure
       * that if we know we have additional work to do immediately
       * (i.e. CURLM_CALL_MULTI_PERFORM == TRUE) then we should do that before
       * declaring the connection timed out as we may almost have a completed
       * connection. */
      multi_handle_timeout(data, nowp, &stream_error, &result);
    }

statemachine_end:

    if(data->mstate < MSTATE_COMPLETED) {
      if(result) {
        /*
         * If an error was returned, and we are not in completed state now,
         * then we go to completed and consider this transfer aborted.
         */

        /* NOTE: no attempt to disconnect connections must be made
           in the case blocks above - cleanup happens only here */

        /* Check if we can move pending requests to send pipe */
        process_pending_handles(multi); /* connection */

        if(data->conn) {
          if(stream_error) {
            /* Do not attempt to send data over a connection that timed out */
            bool dead_connection = result == CURLE_OPERATION_TIMEDOUT;
            struct connectdata *conn = data->conn;

            /* This is where we make sure that the conn pointer is reset.
               We do not have to do this in every case block above where a
               failure is detected */
            Curl_detach_connection(data);
            Curl_conn_terminate(data, conn, dead_connection);
          }
        }
        else if(data->mstate == MSTATE_CONNECT) {
          /* Curl_connect() failed */
          multi_posttransfer(data);
          Curl_pgrsUpdate_nometer(data);
        }

        multistate(data, MSTATE_COMPLETED);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      /* if there is still a connection to use, call the progress function */
      else if(data->conn && Curl_pgrsUpdate(data)) {
        /* aborted due to progress callback return code must close the
           connection */
        result = CURLE_ABORTED_BY_CALLBACK;
        streamclose(data->conn, "Aborted by callback");

        /* if not yet in DONE state, go there, otherwise COMPLETED */
        multistate(data, (data->mstate < MSTATE_DONE) ?
                   MSTATE_DONE : MSTATE_COMPLETED);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
    }

    if(MSTATE_COMPLETED == data->mstate) {
      if(data->master_mid != UINT_MAX) {
        /* A sub transfer, not for msgsent to application */
        struct Curl_easy *mdata;

        CURL_TRC_M(data, "sub xfer done for master %u", data->master_mid);
        mdata = Curl_multi_get_easy(multi, data->master_mid);
        if(mdata) {
          if(mdata->sub_xfer_done)
            mdata->sub_xfer_done(mdata, data, result);
          else
            CURL_TRC_M(data, "master easy %u without sub_xfer_done callback.",
                       data->master_mid);
        }
        else {
          CURL_TRC_M(data, "master easy %u already gone.", data->master_mid);
        }
      }
      else {
        /* now fill in the Curl_message with this info */
        msg = &data->msg;

        msg->extmsg.msg = CURLMSG_DONE;
        msg->extmsg.easy_handle = data;
        msg->extmsg.data.result = result;

        multi_addmsg(multi, msg);
        DEBUGASSERT(!data->conn);
      }
      multistate(data, MSTATE_MSGSENT);

      /* remove from the other sets, add to msgsent */
      Curl_uint_bset_remove(&multi->process, data->mid);
      Curl_uint_bset_remove(&multi->dirty, data->mid);
      Curl_uint_bset_remove(&multi->pending, data->mid);
      Curl_uint_bset_add(&multi->msgsent, data->mid);
      --multi->xfers_alive;
      return CURLM_OK;
    }
  } while((rc == CURLM_CALL_MULTI_PERFORM) || multi_ischanged(multi, FALSE));

  data->result = result;
  return rc;
}


CURLMcode curl_multi_perform(CURLM *m, int *running_handles)
{
  CURLMcode returncode = CURLM_OK;
  struct Curl_tree *t = NULL;
  struct curltime now = curlx_now();
  struct Curl_multi *multi = m;
  unsigned int mid;
  SIGPIPE_VARIABLE(pipe_st);

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  sigpipe_init(&pipe_st);
  if(Curl_uint_bset_first(&multi->process, &mid)) {
    CURL_TRC_M(multi->admin, "multi_perform(running=%u)",
               Curl_multi_xfers_running(multi));
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      CURLMcode result;
      if(!data) {
        DEBUGASSERT(0);
        Curl_uint_bset_remove(&multi->process, mid);
        Curl_uint_bset_remove(&multi->dirty, mid);
        continue;
      }
      if(data != multi->admin) {
        /* admin handle is processed below */
        sigpipe_apply(data, &pipe_st);
        result = multi_runsingle(multi, &now, data);
        if(result)
          returncode = result;
      }
    }
    while(Curl_uint_bset_next(&multi->process, mid, &mid));
  }

  sigpipe_apply(multi->admin, &pipe_st);
  Curl_cshutdn_perform(&multi->cshutdn, multi->admin, CURL_SOCKET_TIMEOUT);
  sigpipe_restore(&pipe_st);

  if(multi_ischanged(m, TRUE))
    process_pending_handles(m);

  /*
   * Simply remove all expired timers from the splay since handles are dealt
   * with unconditionally by this function and curl_multi_timeout() requires
   * that already passed/handled expire times are removed from the splay.
   *
   * It is important that the 'now' value is set at the entry of this function
   * and not for the current time as it may have ticked a little while since
   * then and then we risk this loop to remove timers that actually have not
   * been handled!
   */
  do {
    multi->timetree = Curl_splaygetbest(now, multi->timetree, &t);
    if(t) {
      /* the removed may have another timeout in queue */
      struct Curl_easy *data = Curl_splayget(t);
      (void)add_next_timeout(now, multi, data);
      if(data->mstate == MSTATE_PENDING) {
        bool stream_unused;
        CURLcode result_unused;
        if(multi_handle_timeout(data, &now, &stream_unused, &result_unused)) {
          infof(data, "PENDING handle timeout");
          move_pending_to_connect(multi, data);
        }
      }
    }
  } while(t);

  if(running_handles) {
    unsigned int running = Curl_multi_xfers_running(multi);
    *running_handles = (running < INT_MAX) ? (int)running : INT_MAX;
  }

  if(CURLM_OK >= returncode)
    returncode = Curl_update_timer(multi);

  return returncode;
}

CURLMcode curl_multi_cleanup(CURLM *m)
{
  struct Curl_multi *multi = m;
  if(GOOD_MULTI_HANDLE(multi)) {
    void *entry;
    unsigned int mid;
    if(multi->in_callback)
      return CURLM_RECURSIVE_API_CALL;

    /* First remove all remaining easy handles,
     * close internal ones. admin handle is special */
    if(Curl_uint_tbl_first(&multi->xfers, &mid, &entry)) {
      do {
        struct Curl_easy *data = entry;
        if(!GOOD_EASY_HANDLE(data))
          return CURLM_BAD_HANDLE;

#ifdef DEBUGBUILD
        if(mid != data->mid) {
          CURL_TRC_M(data, "multi_cleanup: still present with mid=%u, "
                     "but unexpected data->mid=%u\n", mid, data->mid);
          DEBUGASSERT(0);
        }
#endif

        if(data == multi->admin)
          continue;

        if(!data->state.done && data->conn)
          /* if DONE was never called for this handle */
          (void)multi_done(data, CURLE_OK, TRUE);

        data->multi = NULL; /* clear the association */
        Curl_uint_tbl_remove(&multi->xfers, mid);
        data->mid = UINT_MAX;

#ifdef USE_LIBPSL
        if(data->psl == &multi->psl)
          data->psl = NULL;
#endif
        if(data->state.internal)
          Curl_close(&data);
      }
      while(Curl_uint_tbl_next(&multi->xfers, mid, &mid, &entry));
    }

    Curl_cpool_destroy(&multi->cpool);
    Curl_cshutdn_destroy(&multi->cshutdn, multi->admin);
    if(multi->admin) {
      CURL_TRC_M(multi->admin, "multi_cleanup, closing admin handle, done");
      multi->admin->multi = NULL;
      Curl_uint_tbl_remove(&multi->xfers, multi->admin->mid);
      Curl_close(&multi->admin);
    }

    multi->magic = 0; /* not good anymore */

    Curl_multi_ev_cleanup(multi);
    Curl_hash_destroy(&multi->proto_hash);
    Curl_dnscache_destroy(&multi->dnscache);
    Curl_psl_destroy(&multi->psl);
#ifdef USE_SSL
    Curl_ssl_scache_destroy(multi->ssl_scache);
#endif

#ifdef USE_WINSOCK
    WSACloseEvent(multi->wsa_event);
#else
#ifdef ENABLE_WAKEUP
    wakeup_close(multi->wakeup_pair[0]);
#ifndef USE_EVENTFD
    wakeup_close(multi->wakeup_pair[1]);
#endif
#endif
#endif

    multi_xfer_bufs_free(multi);
#ifdef DEBUGBUILD
    if(Curl_uint_tbl_count(&multi->xfers)) {
      multi_xfer_tbl_dump(multi);
      DEBUGASSERT(0);
    }
#endif
    Curl_uint_bset_destroy(&multi->process);
    Curl_uint_bset_destroy(&multi->dirty);
    Curl_uint_bset_destroy(&multi->pending);
    Curl_uint_bset_destroy(&multi->msgsent);
    Curl_uint_tbl_destroy(&multi->xfers);
    free(multi);

    return CURLM_OK;
  }
  return CURLM_BAD_HANDLE;
}

/*
 * curl_multi_info_read()
 *
 * This function is the primary way for a multi/multi_socket application to
 * figure out if a transfer has ended. We MUST make this function as fast as
 * possible as it will be polled frequently and we MUST NOT scan any lists in
 * here to figure out things. We must scale fine to thousands of handles and
 * beyond. The current design is fully O(1).
 */

CURLMsg *curl_multi_info_read(CURLM *m, int *msgs_in_queue)
{
  struct Curl_message *msg;
  struct Curl_multi *multi = m;

  *msgs_in_queue = 0; /* default to none */

  if(GOOD_MULTI_HANDLE(multi) &&
     !multi->in_callback &&
     Curl_llist_count(&multi->msglist)) {
    /* there is one or more messages in the list */
    struct Curl_llist_node *e;

    /* extract the head of the list to return */
    e = Curl_llist_head(&multi->msglist);

    msg = Curl_node_elem(e);

    /* remove the extracted entry */
    Curl_node_remove(e);

    *msgs_in_queue = curlx_uztosi(Curl_llist_count(&multi->msglist));

    return &msg->extmsg;
  }
  return NULL;
}


void Curl_multi_will_close(struct Curl_easy *data, curl_socket_t s)
{
  if(data) {
    struct Curl_multi *multi = data->multi;
    if(multi) {
      CURL_TRC_M(data, "Curl_multi_will_close fd=%" FMT_SOCKET_T, s);
      Curl_multi_ev_socket_done(multi, data, s);
    }
  }
}

/*
 * add_next_timeout()
 *
 * Each Curl_easy has a list of timeouts. The add_next_timeout() is called
 * when it has just been removed from the splay tree because the timeout has
 * expired. This function is then to advance in the list to pick the next
 * timeout to use (skip the already expired ones) and add this node back to
 * the splay tree again.
 *
 * The splay tree only has each sessionhandle as a single node and the nearest
 * timeout is used to sort it on.
 */
static CURLMcode add_next_timeout(struct curltime now,
                                  struct Curl_multi *multi,
                                  struct Curl_easy *d)
{
  struct curltime *tv = &d->state.expiretime;
  struct Curl_llist *list = &d->state.timeoutlist;
  struct Curl_llist_node *e;

  /* move over the timeout list for this specific handle and remove all
     timeouts that are now passed tense and store the next pending
     timeout in *tv */
  for(e = Curl_llist_head(list); e;) {
    struct Curl_llist_node *n = Curl_node_next(e);
    struct time_node *node = Curl_node_elem(e);
    timediff_t diff = curlx_timediff_us(node->time, now);
    if(diff <= 0)
      /* remove outdated entry */
      Curl_node_remove(e);
    else
      /* the list is sorted so get out on the first mismatch */
      break;
    e = n;
  }
  e = Curl_llist_head(list);
  if(!e) {
    /* clear the expire times within the handles that we remove from the
       splay tree */
    tv->tv_sec = 0;
    tv->tv_usec = 0;
  }
  else {
    struct time_node *node = Curl_node_elem(e);
    /* copy the first entry to 'tv' */
    memcpy(tv, &node->time, sizeof(*tv));

    /* Insert this node again into the splay. Keep the timer in the list in
       case we need to recompute future timers. */
    multi->timetree = Curl_splayinsert(*tv, multi->timetree,
                                       &d->state.timenode);
  }
  return CURLM_OK;
}

struct multi_run_ctx {
  struct Curl_multi *multi;
  struct curltime now;
  size_t run_xfers;
  SIGPIPE_MEMBER(pipe_st);
  bool run_cpool;
};

static void multi_mark_expired_as_dirty(struct multi_run_ctx *mrc)
{
  struct Curl_multi *multi = mrc->multi;
  struct Curl_easy *data = NULL;
  struct Curl_tree *t = NULL;

  /*
   * The loop following here will go on as long as there are expire-times left
   * to process (compared to mrc->now) in the splay and 'data' will be
   * re-assigned for every expired handle we deal with.
   */
  while(1) {
    /* Check if there is one (more) expired timer to deal with! This function
       extracts a matching node if there is one */
    multi->timetree = Curl_splaygetbest(mrc->now, multi->timetree, &t);
    if(!t)
      return;

    data = Curl_splayget(t); /* assign this for next loop */
    if(!data)
      continue;

    (void)add_next_timeout(mrc->now, multi, data);
    Curl_multi_mark_dirty(data);
  }
}

static CURLMcode multi_run_dirty(struct multi_run_ctx *mrc)
{
  struct Curl_multi *multi = mrc->multi;
  CURLMcode result = CURLM_OK;
  unsigned int mid;

  if(Curl_uint_bset_first(&multi->dirty, &mid)) {
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(data) {
        CURL_TRC_M(data, "multi_run_dirty");

        if(data == multi->admin) {
          Curl_uint_bset_remove(&multi->dirty, mid);
          mrc->run_cpool = TRUE;
          continue;
        }
        else if(!Curl_uint_bset_contains(&multi->process, mid)) {
          /* We are no longer processing this transfer */
          Curl_uint_bset_remove(&multi->dirty, mid);
          continue;
        }

        mrc->run_xfers++;
        sigpipe_apply(data, &mrc->pipe_st);
        /* runsingle() clears the dirty mid */
        result = multi_runsingle(multi, &mrc->now, data);

        if(CURLM_OK >= result) {
          /* reassess event handling of data */
          result = Curl_multi_ev_assess_xfer(multi, data);
          if(result)
            goto out;
        }
      }
      else {
        CURL_TRC_M(multi->admin, "multi_run_dirty, %u no longer found", mid);
        Curl_uint_bset_remove(&multi->dirty, mid);
      }
    }
    while(Curl_uint_bset_next(&multi->dirty, mid, &mid));
  }

out:
  return result;
}

static CURLMcode multi_socket(struct Curl_multi *multi,
                              bool checkall,
                              curl_socket_t s,
                              int ev_bitmask,
                              int *running_handles)
{
  CURLMcode result = CURLM_OK;
  struct multi_run_ctx mrc;

  (void)ev_bitmask;
  memset(&mrc, 0, sizeof(mrc));
  mrc.multi = multi;
  mrc.now = curlx_now();
  sigpipe_init(&mrc.pipe_st);

  if(checkall) {
    /* *perform() deals with running_handles on its own */
    result = curl_multi_perform(multi, running_handles);

    if(result != CURLM_BAD_HANDLE) {
      /* Reassess event status of all active transfers */
      result = Curl_multi_ev_assess_xfer_bset(multi, &multi->process);
    }
    mrc.run_cpool = TRUE;
    goto out;
  }

  if(s != CURL_SOCKET_TIMEOUT) {
    /* Mark all transfers of that socket as dirty */
    Curl_multi_ev_dirty_xfers(multi, s, &mrc.run_cpool);
  }
  else {
    /* Asked to run due to time-out. Clear the 'last_expire_ts' variable to
       force Curl_update_timer() to trigger a callback to the app again even
       if the same timeout is still the one to run after this call. That
       handles the case when the application asks libcurl to run the timeout
       prematurely. */
    memset(&multi->last_expire_ts, 0, sizeof(multi->last_expire_ts));
    mrc.run_cpool = TRUE;
  }

  multi_mark_expired_as_dirty(&mrc);
  result = multi_run_dirty(&mrc);
  if(result)
    goto out;

  if(mrc.run_xfers) {
    /* Running transfers takes time. With a new timestamp, we might catch
     * other expires which are due now. Instead of telling the application
     * to set a 0 timeout and call us again, we run them here.
     * Do that only once or it might be unfair to transfers on other
     * sockets. */
    mrc.now = curlx_now();
    multi_mark_expired_as_dirty(&mrc);
    result = multi_run_dirty(&mrc);
  }

out:
  if(mrc.run_cpool) {
    sigpipe_apply(multi->admin, &mrc.pipe_st);
    Curl_cshutdn_perform(&multi->cshutdn, multi->admin, s);
  }
  sigpipe_restore(&mrc.pipe_st);

  if(multi_ischanged(multi, TRUE))
    process_pending_handles(multi);

  if(running_handles) {
    unsigned int running = Curl_multi_xfers_running(multi);
    *running_handles = (running < INT_MAX) ? (int)running : INT_MAX;
  }

  if(CURLM_OK >= result)
    result = Curl_update_timer(multi);
  return result;
}

#undef curl_multi_setopt
CURLMcode curl_multi_setopt(CURLM *m,
                            CURLMoption option, ...)
{
  CURLMcode res = CURLM_OK;
  va_list param;
  unsigned long uarg;
  struct Curl_multi *multi = m;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  va_start(param, option);

  switch(option) {
  case CURLMOPT_SOCKETFUNCTION:
    multi->socket_cb = va_arg(param, curl_socket_callback);
    break;
  case CURLMOPT_SOCKETDATA:
    multi->socket_userp = va_arg(param, void *);
    break;
  case CURLMOPT_PUSHFUNCTION:
    multi->push_cb = va_arg(param, curl_push_callback);
    break;
  case CURLMOPT_PUSHDATA:
    multi->push_userp = va_arg(param, void *);
    break;
  case CURLMOPT_PIPELINING:
    multi->multiplexing = va_arg(param, long) & CURLPIPE_MULTIPLEX ? 1 : 0;
    break;
  case CURLMOPT_TIMERFUNCTION:
    multi->timer_cb = va_arg(param, curl_multi_timer_callback);
    break;
  case CURLMOPT_TIMERDATA:
    multi->timer_userp = va_arg(param, void *);
    break;
  case CURLMOPT_MAXCONNECTS:
    uarg = va_arg(param, unsigned long);
    if(uarg <= UINT_MAX)
      multi->maxconnects = (unsigned int)uarg;
    break;
  case CURLMOPT_MAX_HOST_CONNECTIONS:
    multi->max_host_connections = va_arg(param, long);
    break;
  case CURLMOPT_MAX_TOTAL_CONNECTIONS:
    multi->max_total_connections = va_arg(param, long);
    break;
    /* options formerly used for pipelining */
  case CURLMOPT_MAX_PIPELINE_LENGTH:
    break;
  case CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE:
    break;
  case CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE:
    break;
  case CURLMOPT_PIPELINING_SITE_BL:
    break;
  case CURLMOPT_PIPELINING_SERVER_BL:
    break;
  case CURLMOPT_MAX_CONCURRENT_STREAMS:
    {
      long streams = va_arg(param, long);
      if((streams < 1) || (streams > INT_MAX))
        streams = 100;
      multi->max_concurrent_streams = (unsigned int)streams;
    }
    break;
  case CURLMOPT_NETWORK_CHANGED: {
    long val = va_arg(param, long);
    if(val & CURLMNWC_CLEAR_DNS) {
      Curl_dnscache_clear(multi->admin);
    }
    if(val & CURLMNWC_CLEAR_CONNS) {
      Curl_cpool_nw_changed(multi->admin);
    }
    break;
  }
  default:
    res = CURLM_UNKNOWN_OPTION;
    break;
  }
  va_end(param);
  return res;
}

/* we define curl_multi_socket() in the public multi.h header */
#undef curl_multi_socket

CURLMcode curl_multi_socket(CURLM *m, curl_socket_t s, int *running_handles)
{
  struct Curl_multi *multi = m;
  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;
  return multi_socket(multi, FALSE, s, 0, running_handles);
}

CURLMcode curl_multi_socket_action(CURLM *m, curl_socket_t s,
                                   int ev_bitmask, int *running_handles)
{
  struct Curl_multi *multi = m;
  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;
  return multi_socket(multi, FALSE, s, ev_bitmask, running_handles);
}

CURLMcode curl_multi_socket_all(CURLM *m, int *running_handles)
{
  struct Curl_multi *multi = m;
  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;
  return multi_socket(multi, TRUE, CURL_SOCKET_BAD, 0, running_handles);
}


static bool multi_has_dirties(struct Curl_multi *multi)
{
  unsigned int mid;
  if(Curl_uint_bset_first(&multi->dirty, &mid)) {
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(data) {
        if(Curl_uint_bset_contains(&multi->process, mid))
          return TRUE;
        /* We are no longer processing this transfer */
        Curl_uint_bset_remove(&multi->dirty, mid);
      }
      else {
        CURL_TRC_M(multi->admin, "dirty transfer %u no longer found", mid);
        Curl_uint_bset_remove(&multi->dirty, mid);
      }
    }
    while(Curl_uint_bset_next(&multi->dirty, mid, &mid));
  }
  return FALSE;
}

static CURLMcode multi_timeout(struct Curl_multi *multi,
                               struct curltime *expire_time,
                               long *timeout_ms)
{
  static const struct curltime tv_zero = {0, 0};

  if(multi->dead) {
    *timeout_ms = 0;
    return CURLM_OK;
  }

  if(multi_has_dirties(multi)) {
    *expire_time = curlx_now();
    *timeout_ms = 0;
    return CURLM_OK;
  }
  else if(multi->timetree) {
    /* we have a tree of expire times */
    struct curltime now = curlx_now();

    /* splay the lowest to the bottom */
    multi->timetree = Curl_splay(tv_zero, multi->timetree);
    /* this will not return NULL from a non-empty tree, but some compilers
     * are not convinced of that. Analyzers are hard. */
    *expire_time = multi->timetree ? multi->timetree->key : tv_zero;

    /* 'multi->timetree' will be non-NULL here but the compilers sometimes
       yell at us if we assume so */
    if(multi->timetree &&
       curlx_timediff_us(multi->timetree->key, now) > 0) {
      /* some time left before expiration */
      timediff_t diff = curlx_timediff_ceil(multi->timetree->key, now);
      /* this should be safe even on 32-bit archs, as we do not use that
         overly long timeouts */
      *timeout_ms = (long)diff;
    }
    else {
      if(multi->timetree) {
        struct Curl_easy *data = Curl_splayget(multi->timetree);
        CURL_TRC_M(data, "multi_timeout() says this has expired");
      }
      /* 0 means immediately */
      *timeout_ms = 0;
    }
  }
  else {
    *expire_time = tv_zero;
    *timeout_ms = -1;
  }

  return CURLM_OK;
}

CURLMcode curl_multi_timeout(CURLM *m,
                             long *timeout_ms)
{
  struct curltime expire_time;
  struct Curl_multi *multi = m;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  return multi_timeout(multi, &expire_time, timeout_ms);
}

#define DEBUG_UPDATE_TIMER    0

/*
 * Tell the application it should update its timers, if it subscribes to the
 * update timer callback.
 */
CURLMcode Curl_update_timer(struct Curl_multi *multi)
{
  struct curltime expire_ts;
  long timeout_ms;
  int rc;
  bool set_value = FALSE;

  if(!multi->timer_cb || multi->dead)
    return CURLM_OK;
  if(multi_timeout(multi, &expire_ts, &timeout_ms)) {
    return CURLM_OK;
  }

  if(timeout_ms < 0 && multi->last_timeout_ms < 0) {
#if DEBUG_UPDATE_TIMER
    fprintf(stderr, "Curl_update_timer(), still no timeout, no change\n");
#endif
  }
  else if(timeout_ms < 0) {
    /* there is no timeout now but there was one previously */
#if DEBUG_UPDATE_TIMER
    fprintf(stderr, "Curl_update_timer(), remove timeout, "
        " last_timeout=%ldms\n", multi->last_timeout_ms);
#endif
    timeout_ms = -1; /* normalize */
    set_value = TRUE;
  }
  else if(multi->last_timeout_ms < 0) {
#if DEBUG_UPDATE_TIMER
    fprintf(stderr, "Curl_update_timer(), had no timeout, set now\n");
#endif
    set_value = TRUE;
  }
  else if(curlx_timediff_us(multi->last_expire_ts, expire_ts)) {
    /* We had a timeout before and have one now, the absolute timestamp
     * differs. The relative timeout_ms may be the same, but the starting
     * point differs. Let the application restart its timer. */
#if DEBUG_UPDATE_TIMER
    fprintf(stderr, "Curl_update_timer(), expire timestamp changed\n");
#endif
    set_value = TRUE;
  }
  else {
    /* We have same expire time as previously. Our relative 'timeout_ms'
     * may be different now, but the application has the timer running
     * and we do not to tell it to start this again. */
#if DEBUG_UPDATE_TIMER
    fprintf(stderr, "Curl_update_timer(), same expire timestamp, no change\n");
#endif
  }

  if(set_value) {
#if DEBUG_UPDATE_TIMER
    fprintf(stderr, "Curl_update_timer(), set timeout %ldms\n", timeout_ms);
#endif
    multi->last_expire_ts = expire_ts;
    multi->last_timeout_ms = timeout_ms;
    set_in_callback(multi, TRUE);
    rc = multi->timer_cb(multi, timeout_ms, multi->timer_userp);
    set_in_callback(multi, FALSE);
    if(rc == -1) {
      multi->dead = TRUE;
      return CURLM_ABORTED_BY_CALLBACK;
    }
  }
  return CURLM_OK;
}

/*
 * multi_deltimeout()
 *
 * Remove a given timestamp from the list of timeouts.
 */
static void
multi_deltimeout(struct Curl_easy *data, expire_id eid)
{
  struct Curl_llist_node *e;
  struct Curl_llist *timeoutlist = &data->state.timeoutlist;
  /* find and remove the specific node from the list */
  for(e = Curl_llist_head(timeoutlist); e; e = Curl_node_next(e)) {
    struct time_node *n = Curl_node_elem(e);
    if(n->eid == eid) {
      Curl_node_remove(e);
      return;
    }
  }
}

/*
 * multi_addtimeout()
 *
 * Add a timestamp to the list of timeouts. Keep the list sorted so that head
 * of list is always the timeout nearest in time.
 *
 */
static CURLMcode
multi_addtimeout(struct Curl_easy *data,
                 struct curltime *stamp,
                 expire_id eid)
{
  struct Curl_llist_node *e;
  struct time_node *node;
  struct Curl_llist_node *prev = NULL;
  size_t n;
  struct Curl_llist *timeoutlist = &data->state.timeoutlist;

  node = &data->state.expires[eid];

  /* copy the timestamp and id */
  memcpy(&node->time, stamp, sizeof(*stamp));
  node->eid = eid; /* also marks it as in use */

  n = Curl_llist_count(timeoutlist);
  if(n) {
    /* find the correct spot in the list */
    for(e = Curl_llist_head(timeoutlist); e; e = Curl_node_next(e)) {
      struct time_node *check = Curl_node_elem(e);
      timediff_t diff = curlx_timediff(check->time, node->time);
      if(diff > 0)
        break;
      prev = e;
    }

  }
  /* else
     this is the first timeout on the list */

  Curl_llist_insert_next(timeoutlist, prev, node, &node->list);
  return CURLM_OK;
}

void Curl_expire_ex(struct Curl_easy *data,
                    const struct curltime *nowp,
                    timediff_t milli, expire_id id)
{
  struct Curl_multi *multi = data->multi;
  struct curltime *curr_expire = &data->state.expiretime;
  struct curltime set;

  /* this is only interesting while there is still an associated multi struct
     remaining! */
  if(!multi)
    return;

  DEBUGASSERT(id < EXPIRE_LAST);

  set = *nowp;
  set.tv_sec += (time_t)(milli/1000); /* might be a 64 to 32 bits conversion */
  set.tv_usec += (int)(milli%1000)*1000;

  if(set.tv_usec >= 1000000) {
    set.tv_sec++;
    set.tv_usec -= 1000000;
  }

  /* Remove any timer with the same id just in case. */
  multi_deltimeout(data, id);

  /* Add it to the timer list. It must stay in the list until it has expired
     in case we need to recompute the minimum timer later. */
  multi_addtimeout(data, &set, id);

  if(curr_expire->tv_sec || curr_expire->tv_usec) {
    /* This means that the struct is added as a node in the splay tree.
       Compare if the new time is earlier, and only remove-old/add-new if it
       is. */
    timediff_t diff = curlx_timediff(set, *curr_expire);
    int rc;

    if(diff > 0) {
      /* The current splay tree entry is sooner than this new expiry time.
         We do not need to update our splay tree entry. */
      return;
    }

    /* Since this is an updated time, we must remove the previous entry from
       the splay tree first and then re-add the new value */
    rc = Curl_splayremove(multi->timetree, &data->state.timenode,
                          &multi->timetree);
    if(rc)
      infof(data, "Internal error removing splay node = %d", rc);
  }

  /* Indicate that we are in the splay tree and insert the new timer expiry
     value since it is our local minimum. */
  *curr_expire = set;
  Curl_splayset(&data->state.timenode, data);
  multi->timetree = Curl_splayinsert(*curr_expire, multi->timetree,
                                     &data->state.timenode);
  if(data->id >= 0)
    CURL_TRC_M(data, "[TIMEOUT] set %s to expire in %" FMT_TIMEDIFF_T "ns",
               CURL_TIMER_NAME(id), curlx_timediff_us(set, *nowp));
}

/*
 * Curl_expire()
 *
 * given a number of milliseconds from now to use to set the 'act before
 * this'-time for the transfer, to be extracted by curl_multi_timeout()
 *
 * The timeout will be added to a queue of timeouts if it defines a moment in
 * time that is later than the current head of queue.
 *
 * Expire replaces a former timeout using the same id if already set.
 */
void Curl_expire(struct Curl_easy *data, timediff_t milli, expire_id id)
{
  struct curltime now = curlx_now();
  Curl_expire_ex(data, &now, milli, id);
}

/*
 * Curl_expire_done()
 *
 * Removes the expire timer. Marks it as done.
 *
 */
void Curl_expire_done(struct Curl_easy *data, expire_id id)
{
  /* remove the timer, if there */
  multi_deltimeout(data, id);
  if(data->id >= 0)
    CURL_TRC_M(data, "[TIMEOUT] cleared %s", CURL_TIMER_NAME(id));
}

/*
 * Curl_expire_clear()
 *
 * Clear ALL timeout values for this handle.
 */
bool Curl_expire_clear(struct Curl_easy *data)
{
  struct Curl_multi *multi = data->multi;
  struct curltime *nowp = &data->state.expiretime;

  /* this is only interesting while there is still an associated multi struct
     remaining! */
  if(!multi)
    return FALSE;

  if(nowp->tv_sec || nowp->tv_usec) {
    /* Since this is an cleared time, we must remove the previous entry from
       the splay tree */
    struct Curl_llist *list = &data->state.timeoutlist;
    int rc;

    rc = Curl_splayremove(multi->timetree, &data->state.timenode,
                          &multi->timetree);
    if(rc)
      infof(data, "Internal error clearing splay node = %d", rc);

    /* clear the timeout list too */
    Curl_llist_destroy(list, NULL);

    if(data->id >= 0)
      CURL_TRC_M(data, "[TIMEOUT] all cleared");
    nowp->tv_sec = 0;
    nowp->tv_usec = 0;
    return TRUE;
  }
  return FALSE;
}

CURLMcode curl_multi_assign(CURLM *m, curl_socket_t s,
                            void *hashp)
{
  struct Curl_multi *multi = m;
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  return Curl_multi_ev_assign(multi, s, hashp);
}

static void move_pending_to_connect(struct Curl_multi *multi,
                                    struct Curl_easy *data)
{
  DEBUGASSERT(data->mstate == MSTATE_PENDING);

  /* Remove this node from the pending set, add into process set */
  Curl_uint_bset_remove(&multi->pending, data->mid);
  Curl_uint_bset_add(&multi->process, data->mid);

  multistate(data, MSTATE_CONNECT);
  Curl_multi_mark_dirty(data); /* make it run */
}

/* process_pending_handles() moves a handle from PENDING back into the process
   list and change state to CONNECT.

   We do not move all transfers because that can be a significant amount.
   Since this is tried every now and then doing too many too often becomes a
   performance problem.

   When there is a change for connection limits like max host connections etc,
   this likely only allows one new transfer. When there is a pipewait change,
   it can potentially allow hundreds of new transfers.

   We could consider an improvement where we store the queue reason and allow
   more pipewait rechecks than others.
*/
static void process_pending_handles(struct Curl_multi *multi)
{
  unsigned int mid;
  if(Curl_uint_bset_first(&multi->pending, &mid)) {
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(data) {
        move_pending_to_connect(multi, data);
        break;
      }
      /* transfer no longer known, should not happen */
      Curl_uint_bset_remove(&multi->pending, mid);
      DEBUGASSERT(0);
    }
    while(Curl_uint_bset_next(&multi->pending, mid, &mid));
  }
}

void Curl_set_in_callback(struct Curl_easy *data, bool value)
{
  if(data && data->multi)
    data->multi->in_callback = value;
}

bool Curl_is_in_callback(struct Curl_easy *data)
{
  return data && data->multi && data->multi->in_callback;
}

unsigned int Curl_multi_max_concurrent_streams(struct Curl_multi *multi)
{
  DEBUGASSERT(multi);
  return multi->max_concurrent_streams;
}

CURL **curl_multi_get_handles(CURLM *m)
{
  struct Curl_multi *multi = m;
  void *entry;
  unsigned int count = Curl_uint_tbl_count(&multi->xfers);
  CURL **a = malloc(sizeof(struct Curl_easy *) * (count + 1));
  if(a) {
    unsigned int i = 0, mid;

    if(Curl_uint_tbl_first(&multi->xfers, &mid, &entry)) {
      do {
        struct Curl_easy *data = entry;
        DEBUGASSERT(i < count);
        if(!data->state.internal)
          a[i++] = data;
      }
      while(Curl_uint_tbl_next(&multi->xfers, mid, &mid, &entry));
    }
    a[i] = NULL; /* last entry is a NULL */
  }
  return a;
}

CURLMcode curl_multi_get_offt(CURLM *m,
                              CURLMinfo_offt info,
                              curl_off_t *pvalue)
{
  struct Curl_multi *multi = m;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;
  if(!pvalue)
    return CURLM_BAD_FUNCTION_ARGUMENT;

  switch(info) {
  case CURLMINFO_XFERS_CURRENT: {
    unsigned int n = Curl_uint_tbl_count(&multi->xfers);
    if(n && multi->admin)
      --n;
    *pvalue = (curl_off_t)n;
    return CURLM_OK;
  }
  case CURLMINFO_XFERS_RUNNING:
    *pvalue = (curl_off_t)Curl_uint_bset_count(&multi->process);
    return CURLM_OK;
  case CURLMINFO_XFERS_PENDING:
    *pvalue = (curl_off_t)Curl_uint_bset_count(&multi->pending);
    return CURLM_OK;
  case CURLMINFO_XFERS_DONE:
    *pvalue = (curl_off_t)Curl_uint_bset_count(&multi->msgsent);
    return CURLM_OK;
  case CURLMINFO_XFERS_ADDED:
    *pvalue = multi->xfers_total_ever;
    return CURLM_OK;
  default:
    *pvalue = -1;
    return CURLM_UNKNOWN_OPTION;
  }
}

CURLcode Curl_multi_xfer_buf_borrow(struct Curl_easy *data,
                                    char **pbuf, size_t *pbuflen)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  *pbuf = NULL;
  *pbuflen = 0;
  if(!data->multi) {
    failf(data, "transfer has no multi handle");
    return CURLE_FAILED_INIT;
  }
  if(!data->set.buffer_size) {
    failf(data, "transfer buffer size is 0");
    return CURLE_FAILED_INIT;
  }
  if(data->multi->xfer_buf_borrowed) {
    failf(data, "attempt to borrow xfer_buf when already borrowed");
    return CURLE_AGAIN;
  }

  if(data->multi->xfer_buf &&
     data->set.buffer_size > data->multi->xfer_buf_len) {
    /* not large enough, get a new one */
    free(data->multi->xfer_buf);
    data->multi->xfer_buf = NULL;
    data->multi->xfer_buf_len = 0;
  }

  if(!data->multi->xfer_buf) {
    data->multi->xfer_buf = malloc((size_t)data->set.buffer_size);
    if(!data->multi->xfer_buf) {
      failf(data, "could not allocate xfer_buf of %zu bytes",
            (size_t)data->set.buffer_size);
      return CURLE_OUT_OF_MEMORY;
    }
    data->multi->xfer_buf_len = data->set.buffer_size;
  }

  data->multi->xfer_buf_borrowed = TRUE;
  *pbuf = data->multi->xfer_buf;
  *pbuflen = data->multi->xfer_buf_len;
  return CURLE_OK;
}

void Curl_multi_xfer_buf_release(struct Curl_easy *data, char *buf)
{
  (void)buf;
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  DEBUGASSERT(!buf || data->multi->xfer_buf == buf);
  data->multi->xfer_buf_borrowed = FALSE;
}

CURLcode Curl_multi_xfer_ulbuf_borrow(struct Curl_easy *data,
                                      char **pbuf, size_t *pbuflen)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  *pbuf = NULL;
  *pbuflen = 0;
  if(!data->multi) {
    failf(data, "transfer has no multi handle");
    return CURLE_FAILED_INIT;
  }
  if(!data->set.upload_buffer_size) {
    failf(data, "transfer upload buffer size is 0");
    return CURLE_FAILED_INIT;
  }
  if(data->multi->xfer_ulbuf_borrowed) {
    failf(data, "attempt to borrow xfer_ulbuf when already borrowed");
    return CURLE_AGAIN;
  }

  if(data->multi->xfer_ulbuf &&
     data->set.upload_buffer_size > data->multi->xfer_ulbuf_len) {
    /* not large enough, get a new one */
    free(data->multi->xfer_ulbuf);
    data->multi->xfer_ulbuf = NULL;
    data->multi->xfer_ulbuf_len = 0;
  }

  if(!data->multi->xfer_ulbuf) {
    data->multi->xfer_ulbuf = malloc((size_t)data->set.upload_buffer_size);
    if(!data->multi->xfer_ulbuf) {
      failf(data, "could not allocate xfer_ulbuf of %zu bytes",
            (size_t)data->set.upload_buffer_size);
      return CURLE_OUT_OF_MEMORY;
    }
    data->multi->xfer_ulbuf_len = data->set.upload_buffer_size;
  }

  data->multi->xfer_ulbuf_borrowed = TRUE;
  *pbuf = data->multi->xfer_ulbuf;
  *pbuflen = data->multi->xfer_ulbuf_len;
  return CURLE_OK;
}

void Curl_multi_xfer_ulbuf_release(struct Curl_easy *data, char *buf)
{
  (void)buf;
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  DEBUGASSERT(!buf || data->multi->xfer_ulbuf == buf);
  data->multi->xfer_ulbuf_borrowed = FALSE;
}

CURLcode Curl_multi_xfer_sockbuf_borrow(struct Curl_easy *data,
                                        size_t blen, char **pbuf)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  *pbuf = NULL;
  if(!data->multi) {
    failf(data, "transfer has no multi handle");
    return CURLE_FAILED_INIT;
  }
  if(data->multi->xfer_sockbuf_borrowed) {
    failf(data, "attempt to borrow xfer_sockbuf when already borrowed");
    return CURLE_AGAIN;
  }

  if(data->multi->xfer_sockbuf && blen > data->multi->xfer_sockbuf_len) {
    /* not large enough, get a new one */
    free(data->multi->xfer_sockbuf);
    data->multi->xfer_sockbuf = NULL;
    data->multi->xfer_sockbuf_len = 0;
  }

  if(!data->multi->xfer_sockbuf) {
    data->multi->xfer_sockbuf = malloc(blen);
    if(!data->multi->xfer_sockbuf) {
      failf(data, "could not allocate xfer_sockbuf of %zu bytes", blen);
      return CURLE_OUT_OF_MEMORY;
    }
    data->multi->xfer_sockbuf_len = blen;
  }

  data->multi->xfer_sockbuf_borrowed = TRUE;
  *pbuf = data->multi->xfer_sockbuf;
  return CURLE_OK;
}

void Curl_multi_xfer_sockbuf_release(struct Curl_easy *data, char *buf)
{
  (void)buf;
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  DEBUGASSERT(!buf || data->multi->xfer_sockbuf == buf);
  data->multi->xfer_sockbuf_borrowed = FALSE;
}

static void multi_xfer_bufs_free(struct Curl_multi *multi)
{
  DEBUGASSERT(multi);
  Curl_safefree(multi->xfer_buf);
  multi->xfer_buf_len = 0;
  multi->xfer_buf_borrowed = FALSE;
  Curl_safefree(multi->xfer_ulbuf);
  multi->xfer_ulbuf_len = 0;
  multi->xfer_ulbuf_borrowed = FALSE;
  Curl_safefree(multi->xfer_sockbuf);
  multi->xfer_sockbuf_len = 0;
  multi->xfer_sockbuf_borrowed = FALSE;
}

struct Curl_easy *Curl_multi_get_easy(struct Curl_multi *multi,
                                      unsigned int mid)
{
  struct Curl_easy *data = mid ? Curl_uint_tbl_get(&multi->xfers, mid) : NULL;
  if(data && GOOD_EASY_HANDLE(data))
    return data;
  CURL_TRC_M(multi->admin, "invalid easy handle in xfer table for mid=%u",
             mid);
  Curl_uint_tbl_remove(&multi->xfers, mid);
  return NULL;
}

unsigned int Curl_multi_xfers_running(struct Curl_multi *multi)
{
  return multi->xfers_alive;
}

void Curl_multi_mark_dirty(struct Curl_easy *data)
{
  if(data->multi && data->mid != UINT_MAX)
    Curl_uint_bset_add(&data->multi->dirty, data->mid);
}

void Curl_multi_clear_dirty(struct Curl_easy *data)
{
  if(data->multi && data->mid != UINT_MAX)
    Curl_uint_bset_remove(&data->multi->dirty, data->mid);
}

#ifdef DEBUGBUILD
static void multi_xfer_dump(struct Curl_multi *multi, unsigned int mid,
                            void *entry)
{
  struct Curl_easy *data = entry;

  (void)multi;
  if(!data) {
    fprintf(stderr, "mid=%u, entry=NULL, bug in xfer table?\n", mid);
  }
  else {
    fprintf(stderr, "mid=%u, magic=%s, p=%p, id=%" FMT_OFF_T ", url=%s\n",
            mid, (data->magic == CURLEASY_MAGIC_NUMBER) ? "GOOD" : "BAD!",
            (void *)data, data->id, data->state.url);
  }
}

static void multi_xfer_tbl_dump(struct Curl_multi *multi)
{
  unsigned int mid;
  void *entry;
  fprintf(stderr, "=== multi xfer table (count=%u, capacity=%u\n",
          Curl_uint_tbl_count(&multi->xfers),
          Curl_uint_tbl_capacity(&multi->xfers));
  if(Curl_uint_tbl_first(&multi->xfers, &mid, &entry)) {
    multi_xfer_dump(multi, mid, entry);
    while(Curl_uint_tbl_next(&multi->xfers, mid, &mid, &entry))
      multi_xfer_dump(multi, mid, entry);
  }
  fprintf(stderr, "===\n");
  fflush(stderr);
}
#endif /* DEBUGBUILD */
