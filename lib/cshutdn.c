/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing, <linus@haxx.se>
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
#include "url.h"
#include "cfilters.h"
#include "progress.h"
#include "multiif.h"
#include "multi_ev.h"
#include "sendf.h"
#include "cshutdn.h"
#include "http_negotiate.h"
#include "http_ntlm.h"
#include "sigpipe.h"
#include "connect.h"
#include "select.h"
#include "strcase.h"
#include "strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


static void cshutdn_run_conn_handler(struct Curl_easy *data,
                                     struct connectdata *conn)
{
  if(!conn->bits.shutdown_handler) {
    if(conn->dns_entry)
      Curl_resolv_unlink(data, &conn->dns_entry);

    /* Cleanup NTLM connection-related data */
    Curl_http_auth_cleanup_ntlm(conn);

    /* Cleanup NEGOTIATE connection-related data */
    Curl_http_auth_cleanup_negotiate(conn);

    if(conn->handler && conn->handler->disconnect) {
      /* Some disconnect handlers do a blocking wait on server responses.
       * FTP/IMAP/SMTP and SFTP are among them. When using the internal
       * handle, set an overall short timeout so we do not hang for the
       * default 120 seconds. */
      if(data->state.internal) {
        data->set.timeout = DEFAULT_SHUTDOWN_TIMEOUT_MS;
        (void)Curl_pgrsTime(data, TIMER_STARTOP);
      }

      /* This is set if protocol-specific cleanups should be made */
      DEBUGF(infof(data, "connection #%" FMT_OFF_T
                   ", shutdown protocol handler (aborted=%d)",
                   conn->connection_id, conn->bits.aborted));
      /* There are protocol handlers that block on retrieving
       * server responses here (FTP). Set a short timeout. */
      conn->handler->disconnect(data, conn, conn->bits.aborted);
    }

    /* possible left-overs from the async name resolvers */
    Curl_resolver_cancel(data);

    conn->bits.shutdown_handler = TRUE;
  }
}

static void cshutdn_run_once(struct Curl_easy *data,
                             struct connectdata *conn,
                             bool *done)
{
  CURLcode r1, r2;
  bool done1, done2;

  /* We expect to be attached when called */
  DEBUGASSERT(data->conn == conn);

  cshutdn_run_conn_handler(data, conn);

  if(conn->bits.shutdown_filters) {
    *done = TRUE;
    return;
  }

  if(!conn->connect_only && Curl_conn_is_connected(conn, FIRSTSOCKET))
    r1 = Curl_conn_shutdown(data, FIRSTSOCKET, &done1);
  else {
    r1 = CURLE_OK;
    done1 = TRUE;
  }

  if(!conn->connect_only && Curl_conn_is_connected(conn, SECONDARYSOCKET))
    r2 = Curl_conn_shutdown(data, SECONDARYSOCKET, &done2);
  else {
    r2 = CURLE_OK;
    done2 = TRUE;
  }

  /* we are done when any failed or both report success */
  *done = (r1 || r2 || (done1 && done2));
  if(*done)
    conn->bits.shutdown_filters = TRUE;
}

void Curl_cshutdn_run_once(struct Curl_easy *data,
                      struct connectdata *conn,
                      bool *done)
{
  DEBUGASSERT(!data->conn);
  Curl_attach_connection(data, conn);
  cshutdn_run_once(data, conn, done);
  CURL_TRC_M(data, "[SHUTDOWN] shutdown, done=%d", *done);
  Curl_detach_connection(data);
}


void Curl_cshutdn_terminate(struct Curl_easy *data,
                            struct connectdata *conn,
                            bool do_shutdown)
{
  struct Curl_easy *admin = data;
  bool done;

  /* there must be a connection to close */
  DEBUGASSERT(conn);
  /* it must be removed from the connection pool */
  DEBUGASSERT(!conn->bits.in_cpool);
  /* the transfer must be detached from the connection */
  DEBUGASSERT(data && !data->conn);

  /* If we can obtain an internal admin handle, use that to attach
   * and terminate the connection. Some protocol will try to mess with
   * `data` during shutdown and we do not want that with a `data` from
   * the application. */
  if(data->multi && data->multi->admin)
    admin = data->multi->admin;

  Curl_attach_connection(admin, conn);

  cshutdn_run_conn_handler(admin, conn);
  if(do_shutdown) {
    /* Make a last attempt to shutdown handlers and filters, if
     * not done so already. */
    cshutdn_run_once(admin, conn, &done);
  }
  CURL_TRC_M(admin, "[SHUTDOWN] closing connection");
  Curl_conn_close(admin, SECONDARYSOCKET);
  Curl_conn_close(admin, FIRSTSOCKET);
  Curl_detach_connection(admin);

  if(data->multi)
    Curl_multi_ev_conn_done(data->multi, data, conn);
  Curl_conn_free(admin, conn);

  if(data->multi) {
    CURL_TRC_M(data, "[SHUTDOWN] trigger multi connchanged");
    Curl_multi_connchanged(data->multi);
  }
}

static void cshutdn_destroy_oldest(struct cshutdn *cshutdn,
                                     struct Curl_easy *data)
{
  struct Curl_llist_node *e;
  struct connectdata *conn;

  e = Curl_llist_head(&cshutdn->list);
  if(e) {
    SIGPIPE_VARIABLE(pipe_st);
    conn = Curl_node_elem(e);
    Curl_node_remove(e);
    sigpipe_init(&pipe_st);
    sigpipe_apply(data, &pipe_st);
    Curl_cshutdn_terminate(data, conn, FALSE);
    sigpipe_restore(&pipe_st);
  }
}

#define NUM_POLLS_ON_STACK 10

static CURLcode cshutdn_wait(struct cshutdn *cshutdn,
                               struct Curl_easy *data,
                               int timeout_ms)
{
  struct pollfd a_few_on_stack[NUM_POLLS_ON_STACK];
  struct curl_pollfds cpfds;
  CURLcode result;

  Curl_pollfds_init(&cpfds, a_few_on_stack, NUM_POLLS_ON_STACK);

  result = Curl_cshutdn_add_pollfds(cshutdn, data, &cpfds);
  if(result)
    goto out;

  Curl_poll(cpfds.pfds, cpfds.n, CURLMIN(timeout_ms, 1000));

out:
  Curl_pollfds_cleanup(&cpfds);
  return result;
}


static void cshutdn_perform(struct cshutdn *cshutdn,
                              struct Curl_easy *data)
{
  struct Curl_llist_node *e = Curl_llist_head(&cshutdn->list);
  struct Curl_llist_node *enext;
  struct connectdata *conn;
  struct curltime *nowp = NULL;
  struct curltime now;
  timediff_t next_expire_ms = 0, ms;
  bool done;

  if(!e)
    return;

  CURL_TRC_M(data, "[SHUTDOWN] perform on %zu connections",
             Curl_llist_count(&cshutdn->list));
  while(e) {
    enext = Curl_node_next(e);
    conn = Curl_node_elem(e);
    Curl_cshutdn_run_once(data, conn, &done);
    if(done) {
      Curl_node_remove(e);
      Curl_cshutdn_terminate(data, conn, FALSE);
    }
    else {
      /* idata has one timer list, but maybe more than one connection.
       * Set EXPIRE_SHUTDOWN to the smallest time left for all. */
      if(!nowp) {
        now = Curl_now();
        nowp = &now;
      }
      ms = Curl_conn_shutdown_timeleft(conn, nowp);
      if(ms && ms < next_expire_ms)
        next_expire_ms = ms;
    }
    e = enext;
  }

  if(next_expire_ms)
    Curl_expire_ex(data, nowp, next_expire_ms, EXPIRE_SHUTDOWN);
}


static void cshutdn_terminate_all(struct cshutdn *cshutdn,
                                  struct Curl_easy *data,
                                  int timeout_ms)
{
  struct curltime started = Curl_now();
  struct Curl_llist_node *e;
  SIGPIPE_VARIABLE(pipe_st);

  DEBUGASSERT(cshutdn);
  DEBUGASSERT(data);

  CURL_TRC_M(data, "[SHUTDOWN] shutdown all");
  sigpipe_init(&pipe_st);
  sigpipe_apply(data, &pipe_st);

  while(Curl_llist_head(&cshutdn->list)) {
    timediff_t timespent;
    int remain_ms;

    cshutdn_perform(cshutdn, data);

    if(!Curl_llist_head(&cshutdn->list)) {
      CURL_TRC_M(data, "[SHUTDOWN] shutdown finished cleanly");
      break;
    }

    /* wait for activity, timeout or "nothing" */
    timespent = Curl_timediff(Curl_now(), started);
    if(timespent >= (timediff_t)timeout_ms) {
      CURL_TRC_M(data, "[SHUTDOWN] shutdown finished, %s",
                (timeout_ms > 0) ? "timeout" : "best effort done");
      break;
    }

    remain_ms = timeout_ms - (int)timespent;
    if(cshutdn_wait(cshutdn, data, remain_ms)) {
      CURL_TRC_M(data, "[SHUTDOWN] shutdown finished, aborted");
      break;
    }
  }

  /* Terminate any remaining. */
  e = Curl_llist_head(&cshutdn->list);
  while(e) {
    struct connectdata *conn = Curl_node_elem(e);
    Curl_node_remove(e);
    Curl_cshutdn_terminate(data, conn, FALSE);
    e = Curl_llist_head(&cshutdn->list);
  }
  DEBUGASSERT(!Curl_llist_count(&cshutdn->list));

  Curl_hostcache_clean(data, data->dns.hostcache);

  sigpipe_restore(&pipe_st);
}


int Curl_cshutdn_init(struct cshutdn *cshutdn,
                      struct Curl_multi *multi)
{
  DEBUGASSERT(multi);
  cshutdn->multi = multi;
  Curl_llist_init(&cshutdn->list, NULL);
  cshutdn->initialised = TRUE;
  return 0; /* good */
}


void Curl_cshutdn_destroy(struct cshutdn *cshutdn,
                          struct Curl_easy *data)
{
  if(cshutdn->initialised && data) {
    int timeout_ms = 0;
    /* Just for testing, run graceful shutdown */
#ifdef DEBUGBUILD
    {
      const char *p = getenv("CURL_GRACEFUL_SHUTDOWN");
      if(p) {
        curl_off_t l;
        if(!Curl_str_number(&p, &l, INT_MAX))
          timeout_ms = (int)l;
      }
    }
#endif

    CURL_TRC_M(data, "[SHUTDOWN] destroy, %zu connections, timeout=%dms",
               Curl_llist_count(&cshutdn->list), timeout_ms);
    cshutdn_terminate_all(cshutdn, data, timeout_ms);
  }
  cshutdn->multi = NULL;
}

size_t Curl_cshutdn_count(struct Curl_easy *data)
{
  if(data && data->multi) {
    struct cshutdn *csd = &data->multi->cshutdn;
    return Curl_llist_count(&csd->list);
  }
  return 0;
}

size_t Curl_cshutdn_dest_count(struct Curl_easy *data,
                               const char *destination)
{
  if(data && data->multi) {
    struct cshutdn *csd = &data->multi->cshutdn;
    size_t n = 0;
    struct Curl_llist_node *e = Curl_llist_head(&csd->list);
    while(e) {
      struct connectdata *conn = Curl_node_elem(e);
      if(!strcmp(destination, conn->destination))
        ++n;
      e = Curl_node_next(e);
    }
    return n;
  }
  return 0;
}


static CURLMcode cshutdn_update_ev(struct cshutdn *cshutdn,
                                     struct Curl_easy *data,
                                     struct connectdata *conn)
{
  CURLMcode mresult;

  DEBUGASSERT(cshutdn);
  DEBUGASSERT(cshutdn->multi->socket_cb);

  Curl_attach_connection(data, conn);
  mresult = Curl_multi_ev_assess_conn(cshutdn->multi, data, conn);
  Curl_detach_connection(data);
  return mresult;
}


void Curl_cshutdn_add(struct cshutdn *cshutdn,
                        struct connectdata *conn,
                        size_t conns_in_pool)
{
  struct Curl_easy *data = cshutdn->multi->admin;
  size_t max_total = (cshutdn->multi->max_total_connections > 0) ?
                     (size_t)cshutdn->multi->max_total_connections : 0;

  /* Add the connection to our shutdown list for non-blocking shutdown
   * during multi processing. */
  if(max_total > 0 && (max_total <=
        (conns_in_pool + Curl_llist_count(&cshutdn->list)))) {
    CURL_TRC_M(data, "[SHUTDOWN] discarding oldest shutdown connection "
               "due to connection limit of %zu", max_total);
    cshutdn_destroy_oldest(cshutdn, data);
  }

  if(cshutdn->multi->socket_cb) {
    if(cshutdn_update_ev(cshutdn, data, conn)) {
      CURL_TRC_M(data, "[SHUTDOWN] update events failed, discarding #%"
                 FMT_OFF_T, conn->connection_id);
      Curl_cshutdn_terminate(data, conn, FALSE);
      return;
    }
  }

  Curl_llist_append(&cshutdn->list, conn, &conn->cshutdn_node);
  CURL_TRC_M(data, "[SHUTDOWN] added #%" FMT_OFF_T
             " to shutdowns, now %zu conns in shutdown",
             conn->connection_id, Curl_llist_count(&cshutdn->list));
}


static void cshutdn_multi_socket(struct cshutdn *cshutdn,
                                   struct Curl_easy *data,
                                   curl_socket_t s)
{
  struct Curl_llist_node *e;
  struct connectdata *conn;
  bool done;

  DEBUGASSERT(cshutdn->multi->socket_cb);
  e = Curl_llist_head(&cshutdn->list);
  while(e) {
    conn = Curl_node_elem(e);
    if(s == conn->sock[FIRSTSOCKET] || s == conn->sock[SECONDARYSOCKET]) {
      Curl_cshutdn_run_once(data, conn, &done);
      if(done || cshutdn_update_ev(cshutdn, data, conn)) {
        Curl_node_remove(e);
        Curl_cshutdn_terminate(data, conn, FALSE);
      }
      break;
    }
    e = Curl_node_next(e);
  }
}


void Curl_cshutdn_perform(struct cshutdn *cshutdn,
                          struct Curl_easy *data,
                          curl_socket_t s)
{
  if((s == CURL_SOCKET_TIMEOUT) || (!cshutdn->multi->socket_cb))
    cshutdn_perform(cshutdn, data);
  else
    cshutdn_multi_socket(cshutdn, data, s);
}

/* return fd_set info about the shutdown connections */
void Curl_cshutdn_setfds(struct cshutdn *cshutdn,
                         struct Curl_easy *data,
                         fd_set *read_fd_set, fd_set *write_fd_set,
                         int *maxfd)
{
  if(Curl_llist_head(&cshutdn->list)) {
    struct Curl_llist_node *e;

    for(e = Curl_llist_head(&cshutdn->list); e;
        e = Curl_node_next(e)) {
      struct easy_pollset ps;
      unsigned int i;
      struct connectdata *conn = Curl_node_elem(e);
      memset(&ps, 0, sizeof(ps));
      Curl_attach_connection(data, conn);
      Curl_conn_adjust_pollset(data, conn, &ps);
      Curl_detach_connection(data);

      for(i = 0; i < ps.num; i++) {
#if defined(__DJGPP__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
        if(ps.actions[i] & CURL_POLL_IN)
          FD_SET(ps.sockets[i], read_fd_set);
        if(ps.actions[i] & CURL_POLL_OUT)
          FD_SET(ps.sockets[i], write_fd_set);
#if defined(__DJGPP__)
#pragma GCC diagnostic pop
#endif
        if((ps.actions[i] & (CURL_POLL_OUT | CURL_POLL_IN)) &&
           ((int)ps.sockets[i] > *maxfd))
          *maxfd = (int)ps.sockets[i];
      }
    }
  }
}

/* return information about the shutdown connections */
unsigned int Curl_cshutdn_add_waitfds(struct cshutdn *cshutdn,
                                      struct Curl_easy *data,
                                      struct Curl_waitfds *cwfds)
{
  unsigned int need = 0;

  if(Curl_llist_head(&cshutdn->list)) {
    struct Curl_llist_node *e;
    struct easy_pollset ps;
    struct connectdata *conn;

    for(e = Curl_llist_head(&cshutdn->list); e;
        e = Curl_node_next(e)) {
      conn = Curl_node_elem(e);
      memset(&ps, 0, sizeof(ps));
      Curl_attach_connection(data, conn);
      Curl_conn_adjust_pollset(data, conn, &ps);
      Curl_detach_connection(data);

      need += Curl_waitfds_add_ps(cwfds, &ps);
    }
  }
  return need;
}

CURLcode Curl_cshutdn_add_pollfds(struct cshutdn *cshutdn,
                                  struct Curl_easy *data,
                                  struct curl_pollfds *cpfds)
{
  CURLcode result = CURLE_OK;

  if(Curl_llist_head(&cshutdn->list)) {
    struct Curl_llist_node *e;
    struct easy_pollset ps;
    struct connectdata *conn;

    for(e = Curl_llist_head(&cshutdn->list); e;
        e = Curl_node_next(e)) {
      conn = Curl_node_elem(e);
      memset(&ps, 0, sizeof(ps));
      Curl_attach_connection(data, conn);
      Curl_conn_adjust_pollset(data, conn, &ps);
      Curl_detach_connection(data);

      result = Curl_pollfds_add_ps(cpfds, &ps);
      if(result) {
        Curl_pollfds_cleanup(cpfds);
        goto out;
      }
    }
  }
out:
  return result;
}
