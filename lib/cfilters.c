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

#include "urldata.h"
#include "strerror.h"
#include "cfilters.h"
#include "connect.h"
#include "url.h" /* for Curl_safefree() */
#include "sendf.h"
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "multiif.h"
#include "progress.h"
#include "warnless.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif


void Curl_cf_def_destroy_this(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  (void)cf;
  (void)data;
}

void Curl_cf_def_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  cf->connected = FALSE;
  if(cf->next)
    cf->next->cft->close(cf->next, data);
}

CURLcode Curl_cf_def_connect(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             bool blocking, bool *done)
{
  CURLcode result;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }
  if(cf->next) {
    result = cf->next->cft->connect(cf->next, data, blocking, done);
    if(!result && *done) {
      cf->connected = TRUE;
    }
    return result;
  }
  *done = FALSE;
  return CURLE_FAILED_INIT;
}

void Curl_cf_def_get_host(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const char **phost, const char **pdisplay_host,
                          int *pport)
{
  if(cf->next)
    cf->next->cft->get_host(cf->next, data, phost, pdisplay_host, pport);
  else {
    *phost = cf->conn->host.name;
    *pdisplay_host = cf->conn->host.dispname;
    *pport = cf->conn->port;
  }
}

int Curl_cf_def_get_select_socks(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 curl_socket_t *socks)
{
  return cf->next?
    cf->next->cft->get_select_socks(cf->next, data, socks) : 0;
}

bool Curl_cf_def_data_pending(struct Curl_cfilter *cf,
                              const struct Curl_easy *data)
{
  return cf->next?
    cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

ssize_t  Curl_cf_def_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err)
{
  return cf->next?
    cf->next->cft->do_send(cf->next, data, buf, len, err) :
    CURLE_RECV_ERROR;
}

ssize_t  Curl_cf_def_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err)
{
  return cf->next?
    cf->next->cft->do_recv(cf->next, data, buf, len, err) :
    CURLE_SEND_ERROR;
}

bool Curl_cf_def_conn_is_alive(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool *input_pending)
{
  return cf->next?
    cf->next->cft->is_alive(cf->next, data, input_pending) :
    FALSE; /* pessimistic in absence of data */
}

CURLcode Curl_cf_def_conn_keep_alive(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  return cf->next?
    cf->next->cft->keep_alive(cf->next, data) :
    CURLE_OK;
}

CURLcode Curl_cf_def_query(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           int query, int *pres1, void *pres2)
{
  return cf->next?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

void Curl_conn_cf_discard_chain(struct Curl_cfilter **pcf,
                                struct Curl_easy *data)
{
  struct Curl_cfilter *cfn, *cf = *pcf;

  if(cf) {
    *pcf = NULL;
    while(cf) {
      cfn = cf->next;
      /* prevent destroying filter to mess with its sub-chain, since
       * we have the reference now and will call destroy on it.
       */
      cf->next = NULL;
      cf->cft->destroy(cf, data);
      free(cf);
      cf = cfn;
    }
  }
}

void Curl_conn_cf_discard_all(struct Curl_easy *data,
                              struct connectdata *conn, int index)
{
  Curl_conn_cf_discard_chain(&conn->cfilter[index], data);
}

void Curl_conn_close(struct Curl_easy *data, int index)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data->conn);
  /* it is valid to call that without filters being present */
  cf = data->conn->cfilter[index];
  if(cf) {
    cf->cft->close(cf, data);
  }
}

ssize_t Curl_conn_recv(struct Curl_easy *data, int num, char *buf,
                       size_t len, CURLcode *code)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[num];
  while(cf && !cf->connected) {
    cf = cf->next;
  }
  if(cf) {
    return cf->cft->do_recv(cf, data, buf, len, code);
  }
  failf(data, CMSGI(data->conn, num, "recv: no filter connected"));
  *code = CURLE_FAILED_INIT;
  return -1;
}

ssize_t Curl_conn_send(struct Curl_easy *data, int num,
                       const void *mem, size_t len, CURLcode *code)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[num];
  while(cf && !cf->connected) {
    cf = cf->next;
  }
  if(cf) {
    return cf->cft->do_send(cf, data, mem, len, code);
  }
  failf(data, CMSGI(data->conn, num, "send: no filter connected"));
  DEBUGASSERT(0);
  *code = CURLE_FAILED_INIT;
  return -1;
}

CURLcode Curl_cf_create(struct Curl_cfilter **pcf,
                        const struct Curl_cftype *cft,
                        void *ctx)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(cft);
  cf = calloc(sizeof(*cf), 1);
  if(!cf)
    goto out;

  cf->cft = cft;
  cf->ctx = ctx;
  result = CURLE_OK;
out:
  *pcf = cf;
  return result;
}

void Curl_conn_cf_add(struct Curl_easy *data,
                      struct connectdata *conn,
                      int index,
                      struct Curl_cfilter *cf)
{
  (void)data;
  DEBUGASSERT(conn);
  DEBUGASSERT(!cf->conn);
  DEBUGASSERT(!cf->next);

  cf->next = conn->cfilter[index];
  cf->conn = conn;
  cf->sockindex = index;
  conn->cfilter[index] = cf;
  DEBUGF(LOG_CF(data, cf, "added"));
}

void Curl_conn_cf_insert_after(struct Curl_cfilter *cf_at,
                               struct Curl_cfilter *cf_new)
{
  struct Curl_cfilter *tail, **pnext;

  DEBUGASSERT(cf_at);
  DEBUGASSERT(cf_new);
  DEBUGASSERT(!cf_new->conn);

  tail = cf_at->next;
  cf_at->next = cf_new;
  do {
    cf_new->conn = cf_at->conn;
    cf_new->sockindex = cf_at->sockindex;
    pnext = &cf_new->next;
    cf_new = cf_new->next;
  } while(cf_new);
  *pnext = tail;
}

void Curl_conn_cf_discard(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct Curl_cfilter **pprev = &cf->conn->cfilter[cf->sockindex];

  /* remove from chain if still in there */
  DEBUGASSERT(cf);
  while (*pprev) {
    if (*pprev == cf) {
      *pprev = cf->next;
      break;
    }
    pprev = &((*pprev)->next);
  }
  cf->cft->destroy(cf, data);
  free(cf);
}

CURLcode Curl_conn_cf_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool blocking, bool *done)
{
  if(cf)
    return cf->cft->connect(cf, data, blocking, done);
  return CURLE_FAILED_INIT;
}

void Curl_conn_cf_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  if(cf)
    cf->cft->close(cf, data);
}

int Curl_conn_cf_get_select_socks(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  curl_socket_t *socks)
{
  if(cf)
    return cf->cft->get_select_socks(cf, data, socks);
  return 0;
}

bool Curl_conn_cf_data_pending(struct Curl_cfilter *cf,
                               const struct Curl_easy *data)
{
  if(cf)
    return cf->cft->has_data_pending(cf, data);
  return FALSE;
}

ssize_t Curl_conn_cf_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err)
{
  if(cf)
    return cf->cft->do_send(cf, data, buf, len, err);
  *err = CURLE_SEND_ERROR;
  return -1;
}

ssize_t Curl_conn_cf_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err)
{
  if(cf)
    return cf->cft->do_recv(cf, data, buf, len, err);
  *err = CURLE_RECV_ERROR;
  return -1;
}

CURLcode Curl_conn_connect(struct Curl_easy *data,
                           int sockindex,
                           bool blocking,
                           bool *done)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);

  cf = data->conn->cfilter[sockindex];
  DEBUGASSERT(cf);
  if(!cf)
    return CURLE_FAILED_INIT;

  *done = cf->connected;
  if(!*done) {
    result = cf->cft->connect(cf, data, blocking, done);
    if(!result && *done) {
      Curl_conn_ev_update_info(data, data->conn);
      Curl_conn_report_connect_stats(data, data->conn);
      data->conn->keepalive = Curl_now();
    }
    else if(result) {
      Curl_conn_report_connect_stats(data, data->conn);
    }
  }

  return result;
}

bool Curl_conn_is_connected(struct connectdata *conn, int sockindex)
{
  struct Curl_cfilter *cf;

  cf = conn->cfilter[sockindex];
  return cf && cf->connected;
}

bool Curl_conn_is_ip_connected(struct Curl_easy *data, int sockindex)
{
  struct Curl_cfilter *cf;

  cf = data->conn->cfilter[sockindex];
  while(cf) {
    if(cf->connected)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
    cf = cf->next;
  }
  return FALSE;
}

bool Curl_conn_is_ssl(struct connectdata *conn, int sockindex)
{
  struct Curl_cfilter *cf = conn? conn->cfilter[sockindex] : NULL;

  for(; cf; cf = cf->next) {
    if(cf->cft->flags & CF_TYPE_SSL)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

bool Curl_conn_is_multiplex(struct connectdata *conn, int sockindex)
{
  struct Curl_cfilter *cf = conn? conn->cfilter[sockindex] : NULL;

  for(; cf; cf = cf->next) {
    if(cf->cft->flags & CF_TYPE_MULTIPLEX)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT
       || cf->cft->flags & CF_TYPE_SSL)
      return FALSE;
  }
  return FALSE;
}

bool Curl_conn_data_pending(struct Curl_easy *data, int sockindex)
{
  struct Curl_cfilter *cf;

  (void)data;
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);

  cf = data->conn->cfilter[sockindex];
  while(cf && !cf->connected) {
    cf = cf->next;
  }
  if(cf) {
    return cf->cft->has_data_pending(cf, data);
  }
  return FALSE;
}

int Curl_conn_get_select_socks(struct Curl_easy *data, int sockindex,
                               curl_socket_t *socks)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[sockindex];

  /* if the next one is not yet connected, that's the one we want */
  while(cf && cf->next && !cf->next->connected)
    cf = cf->next;
  if(cf) {
    return cf->cft->get_select_socks(cf, data, socks);
  }
  return GETSOCK_BLANK;
}

void Curl_conn_get_host(struct Curl_easy *data, int sockindex,
                        const char **phost, const char **pdisplay_host,
                        int *pport)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[sockindex];
  if(cf) {
    cf->cft->get_host(cf, data, phost, pdisplay_host, pport);
  }
  else {
    /* Some filter ask during shutdown for this, mainly for debugging
     * purposes. We hand out the defaults, however this is not always
     * accurate, as the connection might be tunneled, etc. But all that
     * state is already gone here. */
    *phost = data->conn->host.name;
    *pdisplay_host = data->conn->host.dispname;
    *pport = data->conn->remote_port;
  }
}

CURLcode Curl_cf_def_cntrl(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int event, int arg1, void *arg2)
{
  (void)cf;
  (void)data;
  (void)event;
  (void)arg1;
  (void)arg2;
  return CURLE_OK;
}

CURLcode Curl_conn_cf_cntrl(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            bool ignore_result,
                            int event, int arg1, void *arg2)
{
  CURLcode result = CURLE_OK;

  for(; cf; cf = cf->next) {
    if(Curl_cf_def_cntrl == cf->cft->cntrl)
      continue;
    result = cf->cft->cntrl(cf, data, event, arg1, arg2);
    if(!ignore_result && result)
      break;
  }
  return result;
}

curl_socket_t Curl_conn_cf_get_socket(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  curl_socket_t sock;
  if(cf && !cf->cft->query(cf, data, CF_QUERY_SOCKET, NULL, &sock))
    return sock;
  return CURL_SOCKET_BAD;
}

curl_socket_t Curl_conn_get_socket(struct Curl_easy *data, int sockindex)
{
  struct Curl_cfilter *cf;

  cf = data->conn? data->conn->cfilter[sockindex] : NULL;
  /* if the top filter has not connected, ask it (and its sub-filters)
   * for the socket. Otherwise conn->sock[sockindex] should have it.
   */
  if(cf && !cf->connected)
    return Curl_conn_cf_get_socket(cf, data);
  return data->conn? data->conn->sock[sockindex] : CURL_SOCKET_BAD;
}

static CURLcode cf_cntrl_all(struct connectdata *conn,
                             struct Curl_easy *data,
                             bool ignore_result,
                             int event, int arg1, void *arg2)
{
  CURLcode result = CURLE_OK;
  size_t i;

  for(i = 0; i < ARRAYSIZE(conn->cfilter); ++i) {
    result = Curl_conn_cf_cntrl(conn->cfilter[i], data, ignore_result,
                                event, arg1, arg2);
    if(!ignore_result && result)
      break;
  }
  return result;
}

void Curl_conn_ev_data_attach(struct connectdata *conn,
                              struct Curl_easy *data)
{
  cf_cntrl_all(conn, data, TRUE, CF_CTRL_DATA_ATTACH, 0, NULL);
}

void Curl_conn_ev_data_detach(struct connectdata *conn,
                              struct Curl_easy *data)
{
  cf_cntrl_all(conn, data, TRUE, CF_CTRL_DATA_DETACH, 0, NULL);
}

CURLcode Curl_conn_ev_data_setup(struct Curl_easy *data)
{
  return cf_cntrl_all(data->conn, data, FALSE,
                      CF_CTRL_DATA_SETUP, 0, NULL);
}

CURLcode Curl_conn_ev_data_idle(struct Curl_easy *data)
{
  return cf_cntrl_all(data->conn, data, FALSE,
                      CF_CTRL_DATA_IDLE, 0, NULL);
}

/**
 * Notify connection filters that the transfer represented by `data`
 * is donw with sending data (e.g. has uploaded everything).
 */
void Curl_conn_ev_data_done_send(struct Curl_easy *data)
{
  cf_cntrl_all(data->conn, data, TRUE, CF_CTRL_DATA_DONE_SEND, 0, NULL);
}

/**
 * Notify connection filters that the transfer represented by `data`
 * is finished - eventually premature, e.g. before being complete.
 */
void Curl_conn_ev_data_done(struct Curl_easy *data, bool premature)
{
  cf_cntrl_all(data->conn, data, TRUE, CF_CTRL_DATA_DONE, premature, NULL);
}

CURLcode Curl_conn_ev_data_pause(struct Curl_easy *data, bool do_pause)
{
  return cf_cntrl_all(data->conn, data, FALSE,
                      CF_CTRL_DATA_PAUSE, do_pause, NULL);
}

void Curl_conn_ev_update_info(struct Curl_easy *data,
                              struct connectdata *conn)
{
  cf_cntrl_all(conn, data, TRUE, CF_CTRL_CONN_INFO_UPDATE, 0, NULL);
}

void Curl_conn_report_connect_stats(struct Curl_easy *data,
                                    struct connectdata *conn)
{
  struct Curl_cfilter *cf = conn->cfilter[FIRSTSOCKET];
  if(cf) {
    struct curltime connected;
    struct curltime appconnected;

    memset(&connected, 0, sizeof(connected));
    cf->cft->query(cf, data, CF_QUERY_TIMER_CONNECT, NULL, &connected);
    if(connected.tv_sec || connected.tv_usec)
      Curl_pgrsTimeWas(data, TIMER_CONNECT, connected);

    memset(&appconnected, 0, sizeof(appconnected));
    cf->cft->query(cf, data, CF_QUERY_TIMER_APPCONNECT, NULL, &appconnected);
    if(appconnected.tv_sec || appconnected.tv_usec)
      Curl_pgrsTimeWas(data, TIMER_APPCONNECT, appconnected);
  }
}

bool Curl_conn_is_alive(struct Curl_easy *data, struct connectdata *conn,
                        bool *input_pending)
{
  struct Curl_cfilter *cf = conn->cfilter[FIRSTSOCKET];
  return cf && !cf->conn->bits.close &&
         cf->cft->is_alive(cf, data, input_pending);
}

CURLcode Curl_conn_keep_alive(struct Curl_easy *data,
                              struct connectdata *conn,
                              int sockindex)
{
  struct Curl_cfilter *cf = conn->cfilter[sockindex];
  return cf? cf->cft->keep_alive(cf, data) : CURLE_OK;
}

size_t Curl_conn_get_max_concurrent(struct Curl_easy *data,
                                     struct connectdata *conn,
                                     int sockindex)
{
  CURLcode result;
  int n = 0;

  struct Curl_cfilter *cf = conn->cfilter[sockindex];
  result = cf? cf->cft->query(cf, data, CF_QUERY_MAX_CONCURRENT,
                              &n, NULL) : CURLE_UNKNOWN_OPTION;
  return (result || n <= 0)? 1 : (size_t)n;
}

