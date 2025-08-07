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
#include "url.h"
#include "sendf.h"
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "multiif.h"
#include "progress.h"
#include "select.h"
#include "curlx/warnless.h"
#include "curlx/strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static void cf_cntrl_update_info(struct Curl_easy *data,
                                 struct connectdata *conn);

#ifdef UNITTESTS
/* used by unit2600.c */
void Curl_cf_def_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  cf->connected = FALSE;
  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
}
#endif

CURLcode Curl_cf_def_shutdown(struct Curl_cfilter *cf,
                              struct Curl_easy *data, bool *done)
{
  (void)cf;
  (void)data;
  *done = TRUE;
  return CURLE_OK;
}

static void conn_report_connect_stats(struct Curl_easy *data,
                                      struct connectdata *conn);

CURLcode Curl_cf_def_adjust_pollset(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct easy_pollset *ps)
{
  /* NOP */
  (void)cf;
  (void)data;
  (void)ps;
  return CURLE_OK;
}

bool Curl_cf_def_data_pending(struct Curl_cfilter *cf,
                              const struct Curl_easy *data)
{
  return cf->next ?
    cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

CURLcode Curl_cf_def_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, bool eos,
                          size_t *pnwritten)
{
  if(cf->next)
    return cf->next->cft->do_send(cf->next, data, buf, len, eos, pnwritten);
  *pnwritten = 0;
  return CURLE_RECV_ERROR;
}

CURLcode Curl_cf_def_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, size_t *pnread)
{
  if(cf->next)
    return cf->next->cft->do_recv(cf->next, data, buf, len, pnread);
  *pnread = 0;
  return CURLE_SEND_ERROR;
}

bool Curl_cf_def_conn_is_alive(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool *input_pending)
{
  return cf->next ?
    cf->next->cft->is_alive(cf->next, data, input_pending) :
    FALSE; /* pessimistic in absence of data */
}

CURLcode Curl_cf_def_conn_keep_alive(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  return cf->next ?
    cf->next->cft->keep_alive(cf->next, data) :
    CURLE_OK;
}

CURLcode Curl_cf_def_query(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           int query, int *pres1, void *pres2)
{
  return cf->next ?
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
    cf->cft->do_close(cf, data);
  }
  Curl_shutdown_clear(data, index);
}

CURLcode Curl_conn_shutdown(struct Curl_easy *data, int sockindex, bool *done)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;
  timediff_t timeout_ms;
  struct curltime now;

  DEBUGASSERT(data->conn);

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* Get the first connected filter that is not shut down already. */
  cf = data->conn->cfilter[sockindex];
  while(cf && (!cf->connected || cf->shutdown))
    cf = cf->next;

  if(!cf) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  now = curlx_now();
  if(!Curl_shutdown_started(data, sockindex)) {
    CURL_TRC_M(data, "shutdown start on%s connection",
               sockindex ? " secondary" : "");
    Curl_shutdown_start(data, sockindex, 0, &now);
  }
  else {
    timeout_ms = Curl_shutdown_timeleft(data->conn, sockindex, &now);
    if(timeout_ms < 0) {
      /* info message, since this might be regarded as acceptable */
      infof(data, "shutdown timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
  }

  while(cf) {
    if(!cf->shutdown) {
      bool cfdone = FALSE;
      result = cf->cft->do_shutdown(cf, data, &cfdone);
      if(result) {
        CURL_TRC_CF(data, cf, "shut down failed with %d", result);
        return result;
      }
      else if(!cfdone) {
        CURL_TRC_CF(data, cf, "shut down not done yet");
        return CURLE_OK;
      }
      CURL_TRC_CF(data, cf, "shut down successfully");
      cf->shutdown = TRUE;
    }
    cf = cf->next;
  }
  *done = (!result);
  return result;
}

CURLcode Curl_cf_recv(struct Curl_easy *data, int num, char *buf,
                      size_t len, size_t *pnread)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[num];
  while(cf && !cf->connected)
    cf = cf->next;
  if(cf)
    return cf->cft->do_recv(cf, data, buf, len, pnread);
  failf(data, "recv: no filter connected");
  DEBUGASSERT(0);
  *pnread = 0;
  return CURLE_FAILED_INIT;
}

CURLcode Curl_cf_send(struct Curl_easy *data, int num,
                      const void *mem, size_t len, bool eos,
                      size_t *pnwritten)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[num];
  while(cf && !cf->connected)
    cf = cf->next;
  if(cf) {
    return cf->cft->do_send(cf, data, mem, len, eos, pnwritten);
  }
  failf(data, "send: no filter connected");
  DEBUGASSERT(0);
  *pnwritten = 0;
  return CURLE_FAILED_INIT;
}

struct cf_io_ctx {
  struct Curl_easy *data;
  struct Curl_cfilter *cf;
};

static CURLcode cf_bufq_reader(void *writer_ctx,
                               unsigned char *buf, size_t blen,
                               size_t *pnread)
{
  struct cf_io_ctx *io = writer_ctx;
  return Curl_conn_cf_recv(io->cf, io->data, (char *)buf, blen, pnread);
}

CURLcode Curl_cf_recv_bufq(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct bufq *bufq,
                           size_t maxlen,
                           size_t *pnread)
{
  struct cf_io_ctx io;

  if(!cf || !data) {
    *pnread = 0;
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  io.data = data;
  io.cf = cf;
  return Curl_bufq_sipn(bufq, maxlen, cf_bufq_reader, &io, pnread);
}

static CURLcode cf_bufq_writer(void *writer_ctx,
                               const unsigned char *buf, size_t buflen,
                               size_t *pnwritten)
{
  struct cf_io_ctx *io = writer_ctx;
  return Curl_conn_cf_send(io->cf, io->data, (const char *)buf,
                           buflen, FALSE, pnwritten);
}

CURLcode Curl_cf_send_bufq(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct bufq *bufq,
                           const unsigned char *buf, size_t blen,
                           size_t *pnwritten)
{
  struct cf_io_ctx io;

  if(!cf || !data) {
    *pnwritten = 0;
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  io.data = data;
  io.cf = cf;
  if(buf && blen)
    return Curl_bufq_write_pass(bufq, buf, blen, cf_bufq_writer, &io,
                                pnwritten);
  else
    return Curl_bufq_pass(bufq, cf_bufq_writer, &io, pnwritten);
}

CURLcode Curl_cf_create(struct Curl_cfilter **pcf,
                        const struct Curl_cftype *cft,
                        void *ctx)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(cft);
  cf = calloc(1, sizeof(*cf));
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
  CURL_TRC_CF(data, cf, "added");
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

bool Curl_conn_cf_discard_sub(struct Curl_cfilter *cf,
                              struct Curl_cfilter *discard,
                              struct Curl_easy *data,
                              bool destroy_always)
{
  struct Curl_cfilter **pprev = &cf->next;
  bool found = FALSE;

  /* remove from sub-chain and destroy */
  DEBUGASSERT(cf);
  while(*pprev) {
    if(*pprev == cf) {
      *pprev = discard->next;
      discard->next = NULL;
      found = TRUE;
      break;
    }
    pprev = &((*pprev)->next);
  }
  if(found || destroy_always) {
    discard->next = NULL;
    discard->cft->destroy(discard, data);
    free(discard);
  }
  return found;
}

CURLcode Curl_conn_cf_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool *done)
{
  if(cf)
    return cf->cft->do_connect(cf, data, done);
  return CURLE_FAILED_INIT;
}

void Curl_conn_cf_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  if(cf)
    cf->cft->do_close(cf, data);
}

CURLcode Curl_conn_cf_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                           const void *buf, size_t len, bool eos,
                           size_t *pnwritten)
{
  if(cf)
    return cf->cft->do_send(cf, data, buf, len, eos, pnwritten);
  *pnwritten = 0;
  return CURLE_SEND_ERROR;
}

CURLcode Curl_conn_cf_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           char *buf, size_t len, size_t *pnread)
{
  if(cf)
    return cf->cft->do_recv(cf, data, buf, len, pnread);
  *pnread = 0;
  return CURLE_RECV_ERROR;
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static CURLcode cf_verboseconnect(struct Curl_easy *data,
                                  struct Curl_cfilter *cf)
{
  if(Curl_trc_is_verbose(data)) {
    struct ip_quadruple ipquad;
    bool is_ipv6;
    CURLcode result;

    result = Curl_conn_cf_get_ip_info(cf, data, &is_ipv6, &ipquad);
    if(result)
      return result;

    infof(data, "Established %sconnection to %s (%s port %u) from %s port %u ",
          (cf->sockindex == SECONDARYSOCKET) ? "2nd " : "",
          CURL_CONN_HOST_DISPNAME(data->conn),
          ipquad.remote_ip, ipquad.remote_port,
          ipquad.local_ip, ipquad.local_port);
  }
  return CURLE_OK;
}
#endif

CURLcode Curl_conn_connect(struct Curl_easy *data,
                           int sockindex,
                           bool blocking,
                           bool *done)
{
#define CF_CONN_NUM_POLLS_ON_STACK 5
  struct pollfd a_few_on_stack[CF_CONN_NUM_POLLS_ON_STACK];
  struct easy_pollset ps;
  struct curl_pollfds cpfds;
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  cf = data->conn->cfilter[sockindex];
  if(!cf) {
    *done = FALSE;
    return CURLE_FAILED_INIT;
  }

  *done = cf->connected;
  if(*done)
    return CURLE_OK;

  Curl_pollset_init(&ps);
  Curl_pollfds_init(&cpfds, a_few_on_stack, CF_CONN_NUM_POLLS_ON_STACK);
  while(!*done) {
    if(Curl_conn_needs_flush(data, sockindex)) {
      DEBUGF(infof(data, "Curl_conn_connect(index=%d), flush", sockindex));
      result = Curl_conn_flush(data, sockindex);
      if(result && (result != CURLE_AGAIN))
        return result;
    }

    result = cf->cft->do_connect(cf, data, done);
    CURL_TRC_CF(data, cf, "Curl_conn_connect(block=%d) -> %d, done=%d",
                blocking, result, *done);
    if(!result && *done) {
      /* Now that the complete filter chain is connected, let all filters
       * persist information at the connection. E.g. cf-socket sets the
       * socket and ip related information. */
      cf_cntrl_update_info(data, data->conn);
      conn_report_connect_stats(data, data->conn);
      data->conn->keepalive = curlx_now();
#ifndef CURL_DISABLE_VERBOSE_STRINGS
      result = cf_verboseconnect(data, cf);
#endif
      goto out;
    }
    else if(result) {
      CURL_TRC_CF(data, cf, "Curl_conn_connect(), filter returned %d",
                  result);
      conn_report_connect_stats(data, data->conn);
      goto out;
    }

    if(!blocking)
      goto out;
    else {
      /* check allowed time left */
      const timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);
      curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);
      int rc;

      if(timeout_ms < 0) {
        /* no need to continue if time already is up */
        failf(data, "connect timeout");
        result = CURLE_OPERATION_TIMEDOUT;
        goto out;
      }

      CURL_TRC_CF(data, cf, "Curl_conn_connect(block=1), do poll");
      Curl_pollset_reset(&ps);
      Curl_pollfds_reset(&cpfds);
      /* In general, we want to send after connect, wait on that. */
      if(sockfd != CURL_SOCKET_BAD)
        Curl_pollset_set_out_only(data, &ps, sockfd);
      result = Curl_conn_adjust_pollset(data, data->conn, &ps);
      if(result)
        goto out;
      result = Curl_pollfds_add_ps(&cpfds, &ps);
      if(result)
        goto out;

      rc = Curl_poll(cpfds.pfds, cpfds.n,
                     CURLMIN(timeout_ms, (cpfds.n ? 1000 : 10)));
      CURL_TRC_CF(data, cf, "Curl_conn_connect(block=1), Curl_poll() -> %d",
                  rc);
      if(rc < 0) {
        result = CURLE_COULDNT_CONNECT;
        goto out;
      }
      /* continue iterating */
    }
  }

out:
  Curl_pollset_cleanup(&ps);
  Curl_pollfds_cleanup(&cpfds);
  return result;
}

bool Curl_conn_is_setup(struct connectdata *conn, int sockindex)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  return (conn->cfilter[sockindex] != NULL);
}

bool Curl_conn_is_connected(struct connectdata *conn, int sockindex)
{
  struct Curl_cfilter *cf;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  cf = conn->cfilter[sockindex];
  return cf && cf->connected;
}

bool Curl_conn_is_ip_connected(struct Curl_easy *data, int sockindex)
{
  struct Curl_cfilter *cf;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
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

static bool cf_is_ssl(struct Curl_cfilter *cf)
{
  for(; cf; cf = cf->next) {
    if(cf->cft->flags & CF_TYPE_SSL)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

bool Curl_conn_is_ssl(struct connectdata *conn, int sockindex)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  return conn ? cf_is_ssl(conn->cfilter[sockindex]) : FALSE;
}

bool Curl_conn_get_ssl_info(struct Curl_easy *data,
                            struct connectdata *conn, int sockindex,
                            struct curl_tlssessioninfo *info)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  if(Curl_conn_is_ssl(conn, sockindex)) {
    struct Curl_cfilter *cf = conn->cfilter[sockindex];
    CURLcode result = cf ? cf->cft->query(cf, data, CF_QUERY_SSL_INFO,
                               NULL, (void *)info) : CURLE_UNKNOWN_OPTION;
    return !result;
  }
  return FALSE;
}

CURLcode Curl_conn_get_ip_info(struct Curl_easy *data,
                               struct connectdata *conn, int sockindex,
                               bool *is_ipv6, struct ip_quadruple *ipquad)
{
  struct Curl_cfilter *cf;
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  cf = conn ? conn->cfilter[sockindex] : NULL;
  return Curl_conn_cf_get_ip_info(cf, data, is_ipv6, ipquad);
}

bool Curl_conn_is_multiplex(struct connectdata *conn, int sockindex)
{
  struct Curl_cfilter *cf;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  cf = conn ? conn->cfilter[sockindex] : NULL;

  for(; cf; cf = cf->next) {
    if(cf->cft->flags & CF_TYPE_MULTIPLEX)
      return TRUE;
    if(cf->cft->flags & (CF_TYPE_IP_CONNECT|CF_TYPE_SSL))
      return FALSE;
  }
  return FALSE;
}

unsigned char Curl_conn_get_transport(struct Curl_easy *data,
                                      struct connectdata *conn)
{
  struct Curl_cfilter *cf = conn->cfilter[FIRSTSOCKET];
  return Curl_conn_cf_get_transport(cf, data);
}

const char *Curl_conn_get_alpn_negotiated(struct Curl_easy *data,
                                          struct connectdata *conn)
{
  struct Curl_cfilter *cf = conn->cfilter[FIRSTSOCKET];
  return Curl_conn_cf_get_alpn_negotiated(cf, data);
}

unsigned char Curl_conn_http_version(struct Curl_easy *data,
                                     struct connectdata *conn)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_UNKNOWN_OPTION;
  unsigned char v = 0;

  cf = conn->cfilter[FIRSTSOCKET];
  for(; cf; cf = cf->next) {
    if(cf->cft->flags & CF_TYPE_HTTP) {
      int value = 0;
      result = cf->cft->query(cf, data, CF_QUERY_HTTP_VERSION, &value, NULL);
      if(!result && ((value < 0) || (value > 255)))
        result = CURLE_FAILED_INIT;
      else
        v = (unsigned char)value;
      break;
    }
    if(cf->cft->flags & (CF_TYPE_IP_CONNECT|CF_TYPE_SSL))
      break;
  }
  return (unsigned char)(result ? 0 : v);
}

bool Curl_conn_data_pending(struct Curl_easy *data, int sockindex)
{
  struct Curl_cfilter *cf;

  (void)data;
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;

  cf = data->conn->cfilter[sockindex];
  while(cf && !cf->connected) {
    cf = cf->next;
  }
  if(cf) {
    return cf->cft->has_data_pending(cf, data);
  }
  return FALSE;
}

bool Curl_conn_cf_needs_flush(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  CURLcode result;
  int pending = 0;
  result = cf ? cf->cft->query(cf, data, CF_QUERY_NEED_FLUSH,
                               &pending, NULL) : CURLE_UNKNOWN_OPTION;
  return (result || !pending) ? FALSE : TRUE;
}

bool Curl_conn_needs_flush(struct Curl_easy *data, int sockindex)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  return Curl_conn_cf_needs_flush(data->conn->cfilter[sockindex], data);
}

CURLcode Curl_conn_cf_adjust_pollset(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct easy_pollset *ps)
{
  CURLcode result = CURLE_OK;
  /* Get the lowest not-connected filter, if there are any */
  while(cf && !cf->connected && cf->next && !cf->next->connected)
    cf = cf->next;
  /* Skip all filters that have already shut down */
  while(cf && cf->shutdown)
    cf = cf->next;
  /* From there on, give all filters a chance to adjust the pollset.
   * Lower filters are called later, so they may override */
  while(cf && !result) {
    result = cf->cft->adjust_pollset(cf, data, ps);
    cf = cf->next;
  }
  return result;
}

CURLcode Curl_conn_adjust_pollset(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  struct easy_pollset *ps)
{
  CURLcode result = CURLE_OK;
  int i;

  DEBUGASSERT(data);
  DEBUGASSERT(conn);
  for(i = 0; (i < 2) && !result; ++i) {
    result = Curl_conn_cf_adjust_pollset(conn->cfilter[i], data, ps);
  }
  return result;
}

int Curl_conn_cf_poll(struct Curl_cfilter *cf,
                      struct Curl_easy *data,
                      timediff_t timeout_ms)
{
  struct easy_pollset ps;
  int result;

  DEBUGASSERT(cf);
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  Curl_pollset_init(&ps);

  result = Curl_conn_cf_adjust_pollset(cf, data, &ps);
  if(!result)
    result = Curl_pollset_poll(data, &ps, timeout_ms);
  Curl_pollset_cleanup(&ps);
  return result;
}

void Curl_conn_get_current_host(struct Curl_easy *data, int sockindex,
                                const char **phost, int *pport)
{
  struct Curl_cfilter *cf, *cf_proxy = NULL;

  if(!data->conn) {
    DEBUGASSERT(0);
    *phost = "";
    *pport = -1;
    return;
  }

  cf = CONN_SOCK_IDX_VALID(sockindex) ? data->conn->cfilter[sockindex] : NULL;
  /* Find the "lowest" tunneling proxy filter that has not connected yet. */
  while(cf && !cf->connected) {
    if((cf->cft->flags & (CF_TYPE_IP_CONNECT|CF_TYPE_PROXY)) ==
       (CF_TYPE_IP_CONNECT|CF_TYPE_PROXY))
       cf_proxy = cf;
    cf = cf->next;
  }
  /* cf_proxy (!= NULL) is not connected yet. It is talking
   * to an interim host and any authentication or other things apply
   * to this interim host and port. */
  if(!cf_proxy || cf_proxy->cft->query(cf_proxy, data, CF_QUERY_HOST_PORT,
                                       pport, CURL_UNCONST(phost))) {
    /* Everything connected or query unsuccessful, the overall
     * connection's destination is the answer */
    *phost = data->conn->host.name;
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

unsigned char Curl_conn_cf_get_transport(struct Curl_cfilter *cf,
                                         struct Curl_easy *data)
{
  int transport = 0;
  if(cf && !cf->cft->query(cf, data, CF_QUERY_TRANSPORT, &transport, NULL))
    return (unsigned char)transport;
  return (unsigned char)(data->conn ? data->conn->transport_wanted : 0);
}

const char *Curl_conn_cf_get_alpn_negotiated(struct Curl_cfilter *cf,
                                             struct Curl_easy *data)
{
  const char *alpn = NULL;
  CURL_TRC_CF(data, cf, "query ALPN");
  if(cf && !cf->cft->query(cf, data, CF_QUERY_ALPN_NEGOTIATED, NULL,
                           CURL_UNCONST(&alpn)))
    return alpn;
  return NULL;
}

static const struct Curl_sockaddr_ex *
cf_get_remote_addr(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  const struct Curl_sockaddr_ex *remote_addr = NULL;
  if(cf &&
     !cf->cft->query(cf, data, CF_QUERY_REMOTE_ADDR, NULL,
                     CURL_UNCONST(&remote_addr)))
    return remote_addr;
  return NULL;
}

CURLcode Curl_conn_cf_get_ip_info(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *is_ipv6, struct ip_quadruple *ipquad)
{
  CURLcode result = CURLE_UNKNOWN_OPTION;
  if(cf) {
    int ipv6 = 0;
    result = cf->cft->query(cf, data, CF_QUERY_IP_INFO, &ipv6, ipquad);
    *is_ipv6 = !!ipv6;
  }
  return result;
}

curl_socket_t Curl_conn_get_first_socket(struct Curl_easy *data)
{
  struct Curl_cfilter *cf;

  if(!data->conn)
    return CURL_SOCKET_BAD;

  cf = data->conn->cfilter[FIRSTSOCKET];
  /* if the top filter has not connected, ask it (and its sub-filters)
   * for the socket. Otherwise conn->sock[sockindex] should have it. */
  if(cf && !cf->connected)
    return Curl_conn_cf_get_socket(cf, data);
  return data->conn->sock[FIRSTSOCKET];
}

const struct Curl_sockaddr_ex *
Curl_conn_get_remote_addr(struct Curl_easy *data, int sockindex)
{
  struct Curl_cfilter *cf =
    (data->conn && CONN_SOCK_IDX_VALID(sockindex)) ?
    data->conn->cfilter[sockindex] : NULL;
  return cf ? cf_get_remote_addr(cf, data) : NULL;
}

void Curl_conn_forget_socket(struct Curl_easy *data, int sockindex)
{
  if(data->conn && CONN_SOCK_IDX_VALID(sockindex)) {
    struct Curl_cfilter *cf = data->conn->cfilter[sockindex];
    if(cf)
      (void)Curl_conn_cf_cntrl(cf, data, TRUE,
                               CF_CTRL_FORGET_SOCKET, 0, NULL);
    fake_sclose(data->conn->sock[sockindex]);
    data->conn->sock[sockindex] = CURL_SOCKET_BAD;
  }
}

static CURLcode cf_cntrl_all(struct connectdata *conn,
                             struct Curl_easy *data,
                             bool ignore_result,
                             int event, int arg1, void *arg2)
{
  CURLcode result = CURLE_OK;
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(conn->cfilter); ++i) {
    result = Curl_conn_cf_cntrl(conn->cfilter[i], data, ignore_result,
                                event, arg1, arg2);
    if(!ignore_result && result)
      break;
  }
  return result;
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


CURLcode Curl_conn_flush(struct Curl_easy *data, int sockindex)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return Curl_conn_cf_cntrl(data->conn->cfilter[sockindex], data, FALSE,
                            CF_CTRL_FLUSH, 0, NULL);
}

/**
 * Notify connection filters that the transfer represented by `data`
 * is done with sending data (e.g. has uploaded everything).
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

static void cf_cntrl_update_info(struct Curl_easy *data,
                                 struct connectdata *conn)
{
  cf_cntrl_all(conn, data, TRUE, CF_CTRL_CONN_INFO_UPDATE, 0, NULL);
}

/**
 * Update connection statistics
 */
static void conn_report_connect_stats(struct Curl_easy *data,
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
  struct Curl_cfilter *cf;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  cf = conn->cfilter[sockindex];
  return cf ? cf->cft->keep_alive(cf, data) : CURLE_OK;
}

size_t Curl_conn_get_max_concurrent(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int sockindex)
{
  struct Curl_cfilter *cf;
  CURLcode result;
  int n = -1;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return 0;

  cf = conn->cfilter[sockindex];
  result = cf ? cf->cft->query(cf, data, CF_QUERY_MAX_CONCURRENT,
                               &n, NULL) : CURLE_UNKNOWN_OPTION;
  /* If no filter answered the query, the default is a non-multiplexed
   * connection with limit 1. Otherwise, the the query may return 0
   * for connections that are in shutdown, e.g. server HTTP/2 GOAWAY. */
  return (result || n < 0) ? 1 : (size_t)n;
}

int Curl_conn_get_stream_error(struct Curl_easy *data,
                               struct connectdata *conn,
                               int sockindex)
{
  struct Curl_cfilter *cf;
  CURLcode result;
  int n = 0;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return 0;

  cf = conn->cfilter[sockindex];
  result = cf ? cf->cft->query(cf, data, CF_QUERY_STREAM_ERROR,
                               &n, NULL) : CURLE_UNKNOWN_OPTION;
  return (result || n < 0) ? 0 : n;
}

int Curl_conn_sockindex(struct Curl_easy *data, curl_socket_t sockfd)
{
  if(data && data->conn &&
     sockfd != CURL_SOCKET_BAD && sockfd == data->conn->sock[SECONDARYSOCKET])
    return SECONDARYSOCKET;
  return FIRSTSOCKET;
}

CURLcode Curl_conn_recv(struct Curl_easy *data, int sockindex,
                        char *buf, size_t blen, size_t *pnread)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(data && data->conn && data->conn->recv[sockindex])
    return data->conn->recv[sockindex](data, sockindex, buf, blen, pnread);
  *pnread = 0;
  return CURLE_FAILED_INIT;
}

CURLcode Curl_conn_send(struct Curl_easy *data, int sockindex,
                        const void *buf, size_t blen, bool eos,
                        size_t *pnwritten)
{
  size_t write_len = blen;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  DEBUGASSERT(CONN_SOCK_IDX_VALID(sockindex));
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;
#ifdef DEBUGBUILD
  if(write_len) {
    /* Allow debug builds to override this logic to force short sends
    */
    const char *p = getenv("CURL_SMALLSENDS");
    if(p) {
      curl_off_t altsize;
      if(!curlx_str_number(&p, &altsize, write_len))
        write_len = (size_t)altsize;
    }
  }
#endif
  if(write_len != blen)
    eos = FALSE;
  if(data && data->conn && data->conn->send[sockindex])
    return data->conn->send[sockindex](data, sockindex, buf, write_len, eos,
                                       pnwritten);
  *pnwritten = 0;
  return CURLE_FAILED_INIT;
}
