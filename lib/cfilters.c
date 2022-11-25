/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "http_proxy.h"
#include "socks.h"
#include "vtls/vtls.h"

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

CURLcode Curl_cf_def_setup(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           const struct Curl_dns_entry *remotehost)
{
  DEBUGASSERT(cf->next);
  return cf->next->cft->setup(cf->next, data, remotehost);
}

void     Curl_cf_def_attach_data(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  (void)cf;
  (void)data;
}

void     Curl_cf_def_detach_data(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  (void)cf;
  (void)data;
}

void Curl_cf_def_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  DEBUGASSERT(cf->next);
  cf->connected = FALSE;
  cf->next->cft->close(cf->next, data);
}

CURLcode Curl_cf_def_connect(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             bool blocking, bool *done)
{
  DEBUGASSERT(cf->next);
  return cf->next->cft->connect(cf->next, data, blocking, done);
}

void Curl_cf_def_get_host(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const char **phost, const char **pdisplay_host,
                          int *pport)
{
  DEBUGASSERT(cf->next);
  cf->next->cft->get_host(cf->next, data, phost, pdisplay_host, pport);
}

int Curl_cf_def_get_select_socks(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 curl_socket_t *socks)
{
  DEBUGASSERT(cf->next);
  return cf->next->cft->get_select_socks(cf->next, data, socks);
}

bool Curl_cf_def_data_pending(struct Curl_cfilter *cf,
                              const struct Curl_easy *data)
{
  DEBUGASSERT(cf->next);
  return cf->next->cft->has_data_pending(cf->next, data);
}

ssize_t  Curl_cf_def_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err)
{
  DEBUGASSERT(cf->next);
  return cf->next->cft->do_send(cf->next, data, buf, len, err);
}

ssize_t  Curl_cf_def_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err)
{
  DEBUGASSERT(cf->next);
  return cf->next->cft->do_recv(cf->next, data, buf, len, err);
}

void Curl_conn_cf_discard_all(struct Curl_easy *data,
                              struct connectdata *conn, int index)
{
  struct Curl_cfilter *cfn, *cf = conn->cfilter[index];

  if(cf) {
    conn->cfilter[index] = NULL;
    while(cf) {
      cfn = cf->next;
      cf->cft->destroy(cf, data);
      free(cf);
      cf = cfn;
    }
  }
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
  ssize_t nread;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[num];
  while(cf && !cf->connected) {
    cf = cf->next;
  }
  if(cf) {
    nread = cf->cft->do_recv(cf, data, buf, len, code);
    /* DEBUGF(infof(data, "Curl_conn_recv(handle=%p, index=%d)"
           "-> %ld, err=%d", data, num, nread, *code));*/
    return nread;
  }
  failf(data, "no filter connected, conn=%ld, sockindex=%d",
        data->conn->connection_id, num);
  *code = CURLE_FAILED_INIT;
  return -1;
}

ssize_t Curl_conn_send(struct Curl_easy *data, int num,
                       const void *mem, size_t len, CURLcode *code)
{
  struct Curl_cfilter *cf;
  ssize_t nwritten;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[num];
  while(cf && !cf->connected) {
    cf = cf->next;
  }
  if(cf) {
    nwritten = cf->cft->do_send(cf, data, mem, len, code);
    /* DEBUGF(infof(data, "Curl_conn_send(handle=%p, index=%d, len=%ld)"
           " -> %ld, err=%d", data, num, len, nwritten, *code));*/
    return nwritten;
  }
  failf(data, "no filter connected, conn=%ld, sockindex=%d",
        data->conn->connection_id, num);
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

  DEBUGF(infof(data, CMSGI(conn, index, "cf_add(filter=%s)"),
               cf->cft->name));
  cf->next = conn->cfilter[index];
  cf->conn = conn;
  cf->sockindex = index;
  conn->cfilter[index] = cf;
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

ssize_t Curl_conn_cf_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err)
{
  return cf->cft->do_send(cf, data, buf, len, err);
}

ssize_t Curl_conn_cf_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err)
{
  return cf->cft->do_recv(cf, data, buf, len, err);
}

CURLcode Curl_conn_setup(struct Curl_easy *data,
                         struct connectdata *conn,
                         int sockindex,
                         const struct Curl_dns_entry *remotehost,
                         int ssl_mode)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  DEBUGASSERT(data);
  /* If no filter is set, we have the "default" setup of connection filters.
   * The filter chain from botton to top will be:
   * - SOCKET       socket filter for outgoing connection to remotehost
   * if http_proxy tunneling is engaged:
   *    - SSL                 if proxytype is CURLPROXY_HTTPS
   *    - HTTP_PROXY_TUNNEL
   * otherwise, if socks_proxy is engaged:
   *    - SOCKS_PROXY_TUNNEL
   * - SSL          if conn->handler has PROTOPT_SSL
   */
  if(!conn->cfilter[sockindex]) {
    DEBUGF(infof(data, DMSGI(data, sockindex, "setup, init filter chain")));
    result = Curl_conn_socket_set(data, conn, sockindex);
    if(result)
      goto out;

#ifndef CURL_DISABLE_PROXY
    if(conn->bits.socksproxy) {
      result = Curl_conn_socks_proxy_add(data, conn, sockindex);
      if(result)
        goto out;
    }

    if(conn->bits.httpproxy) {
#ifdef USE_SSL
      if(conn->http_proxy.proxytype == CURLPROXY_HTTPS) {
        result = Curl_ssl_cfilter_proxy_add(data, conn, sockindex);
        if(result)
          goto out;
      }
#endif /* USE_SSL */

#if !defined(CURL_DISABLE_HTTP)
      if(conn->bits.tunnel_proxy) {
        result = Curl_conn_http_proxy_add(data, conn, sockindex);
        if(result)
          goto out;
      }
#endif /* !CURL_DISABLE_HTTP */
    }
#endif /* !CURL_DISABLE_PROXY */

#ifdef USE_SSL
    if(ssl_mode == CURL_CF_SSL_ENABLE
      || (ssl_mode != CURL_CF_SSL_DISABLE
           && conn->handler->flags & PROTOPT_SSL)) {
      result = Curl_ssl_cfilter_add(data, conn, sockindex);
      if(result)
        goto out;
    }
#else
    (void)ssl_mode;
#endif /* USE_SSL */

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)
    if(data->set.haproxyprotocol) {
      result = Curl_conn_haproxy_add(data, conn, sockindex);
      if(result)
        goto out;
    }
#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP */

  }
  DEBUGASSERT(conn->cfilter[sockindex]);
  cf = data->conn->cfilter[sockindex];
  result = cf->cft->setup(cf, data, remotehost);

out:
  return result;
}

CURLcode Curl_conn_connect(struct Curl_easy *data,
                           int sockindex,
                           bool blocking,
                           bool *done)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  DEBUGASSERT(data);

  cf = data->conn->cfilter[sockindex];
  DEBUGASSERT(cf);
  result = cf->cft->connect(cf, data, blocking, done);

  DEBUGF(infof(data, DMSGI(data, sockindex, "connect(block=%d)-> %d, done=%d"),
         blocking, result, *done));
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

bool Curl_conn_is_ssl(struct Curl_easy *data, int sockindex)
{
  struct Curl_cfilter *cf = data->conn? data->conn->cfilter[sockindex] : NULL;

  (void)data;
  for(; cf; cf = cf->next) {
    if(cf->cft->flags & CF_TYPE_SSL)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
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
  if(Curl_recv_has_postponed_data(data->conn, sockindex))
    return TRUE;

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
  if(cf) {
    return cf->cft->get_select_socks(cf, data, socks);
  }
  return GETSOCK_BLANK;
}

void Curl_conn_attach_data(struct connectdata *conn,
                           struct Curl_easy *data)
{
  size_t i;
  struct Curl_cfilter *cf;

  for(i = 0; i < ARRAYSIZE(conn->cfilter); ++i) {
    cf = conn->cfilter[i];
    if(cf) {
      while(cf) {
        cf->cft->attach_data(cf, data);
        cf = cf->next;
      }
    }
  }
}

void Curl_conn_detach_data(struct connectdata *conn,
                           struct Curl_easy *data)
{
  size_t i;
  struct Curl_cfilter *cf;

  for(i = 0; i < ARRAYSIZE(conn->cfilter); ++i) {
    cf = conn->cfilter[i];
    if(cf) {
      while(cf) {
        cf->cft->detach_data(cf, data);
        cf = cf->next;
      }
    }
  }
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
     * accurate, as the connction might be tunneled, etc. But all that
     * state is already gone here. */
    *phost = data->conn->host.name;
    *pdisplay_host = data->conn->host.dispname;
    *pport = data->conn->remote_port;
  }
}


