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

#if !defined(FETCH_DISABLE_PROXY)

#include <fetch/fetch.h>
#include "urldata.h"
#include "cfilters.h"
#include "cf-haproxy.h"
#include "fetch_trc.h"
#include "multiif.h"

/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

typedef enum
{
  HAPROXY_INIT, /* init/default/no tunnel state */
  HAPROXY_SEND, /* data_out being sent */
  HAPROXY_DONE  /* all work done */
} haproxy_state;

struct cf_haproxy_ctx
{
  int state;
  struct dynbuf data_out;
};

static void cf_haproxy_ctx_reset(struct cf_haproxy_ctx *ctx)
{
  DEBUGASSERT(ctx);
  ctx->state = HAPROXY_INIT;
  Fetch_dyn_reset(&ctx->data_out);
}

static void cf_haproxy_ctx_free(struct cf_haproxy_ctx *ctx)
{
  if (ctx)
  {
    Fetch_dyn_free(&ctx->data_out);
    free(ctx);
  }
}

static FETCHcode cf_haproxy_date_out_set(struct Fetch_cfilter *cf,
                                         struct Fetch_easy *data)
{
  struct cf_haproxy_ctx *ctx = cf->ctx;
  FETCHcode result;
  const char *client_ip;
  struct ip_quadruple ipquad;
  int is_ipv6;

  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->state == HAPROXY_INIT);
#ifdef USE_UNIX_SOCKETS
  if (cf->conn->unix_domain_socket)
    /* the buffer is large enough to hold this! */
    result = Fetch_dyn_addn(&ctx->data_out, STRCONST("PROXY UNKNOWN\r\n"));
  else
  {
#endif /* USE_UNIX_SOCKETS */
    result = Fetch_conn_cf_get_ip_info(cf->next, data, &is_ipv6, &ipquad);
    if (result)
      return result;

    /* Emit the correct prefix for IPv6 */
    if (data->set.str[STRING_HAPROXY_CLIENT_IP])
      client_ip = data->set.str[STRING_HAPROXY_CLIENT_IP];
    else
      client_ip = ipquad.local_ip;

    result = Fetch_dyn_addf(&ctx->data_out, "PROXY %s %s %s %i %i\r\n",
                           is_ipv6 ? "TCP6" : "TCP4",
                           client_ip, ipquad.remote_ip,
                           ipquad.local_port, ipquad.remote_port);

#ifdef USE_UNIX_SOCKETS
  }
#endif /* USE_UNIX_SOCKETS */
  return result;
}

static FETCHcode cf_haproxy_connect(struct Fetch_cfilter *cf,
                                    struct Fetch_easy *data,
                                    bool blocking, bool *done)
{
  struct cf_haproxy_ctx *ctx = cf->ctx;
  FETCHcode result;
  size_t len;

  DEBUGASSERT(ctx);
  if (cf->connected)
  {
    *done = TRUE;
    return FETCHE_OK;
  }

  result = cf->next->cft->do_connect(cf->next, data, blocking, done);
  if (result || !*done)
    return result;

  switch (ctx->state)
  {
  case HAPROXY_INIT:
    result = cf_haproxy_date_out_set(cf, data);
    if (result)
      goto out;
    ctx->state = HAPROXY_SEND;
    FALLTHROUGH();
  case HAPROXY_SEND:
    len = Fetch_dyn_len(&ctx->data_out);
    if (len > 0)
    {
      ssize_t nwritten;
      nwritten = Fetch_conn_cf_send(cf->next, data,
                                   Fetch_dyn_ptr(&ctx->data_out), len, FALSE,
                                   &result);
      if (nwritten < 0)
      {
        if (result != FETCHE_AGAIN)
          goto out;
        result = FETCHE_OK;
        nwritten = 0;
      }
      Fetch_dyn_tail(&ctx->data_out, len - (size_t)nwritten);
      if (Fetch_dyn_len(&ctx->data_out) > 0)
      {
        result = FETCHE_OK;
        goto out;
      }
    }
    ctx->state = HAPROXY_DONE;
    FALLTHROUGH();
  default:
    Fetch_dyn_free(&ctx->data_out);
    break;
  }

out:
  *done = (!result) && (ctx->state == HAPROXY_DONE);
  cf->connected = *done;
  return result;
}

static void cf_haproxy_destroy(struct Fetch_cfilter *cf,
                               struct Fetch_easy *data)
{
  (void)data;
  FETCH_TRC_CF(data, cf, "destroy");
  cf_haproxy_ctx_free(cf->ctx);
}

static void cf_haproxy_close(struct Fetch_cfilter *cf,
                             struct Fetch_easy *data)
{
  FETCH_TRC_CF(data, cf, "close");
  cf->connected = FALSE;
  cf_haproxy_ctx_reset(cf->ctx);
  if (cf->next)
    cf->next->cft->do_close(cf->next, data);
}

static void cf_haproxy_adjust_pollset(struct Fetch_cfilter *cf,
                                      struct Fetch_easy *data,
                                      struct easy_pollset *ps)
{
  if (cf->next->connected && !cf->connected)
  {
    /* If we are not connected, but the filter "below" is
     * and not waiting on something, we are sending. */
    Fetch_pollset_set_out_only(data, ps, Fetch_conn_cf_get_socket(cf, data));
  }
}

struct Fetch_cftype Fetch_cft_haproxy = {
    "HAPROXY",
    CF_TYPE_PROXY,
    0,
    cf_haproxy_destroy,
    cf_haproxy_connect,
    cf_haproxy_close,
    Fetch_cf_def_shutdown,
    Fetch_cf_def_get_host,
    cf_haproxy_adjust_pollset,
    Fetch_cf_def_data_pending,
    Fetch_cf_def_send,
    Fetch_cf_def_recv,
    Fetch_cf_def_cntrl,
    Fetch_cf_def_conn_is_alive,
    Fetch_cf_def_conn_keep_alive,
    Fetch_cf_def_query,
};

static FETCHcode cf_haproxy_create(struct Fetch_cfilter **pcf,
                                   struct Fetch_easy *data)
{
  struct Fetch_cfilter *cf = NULL;
  struct cf_haproxy_ctx *ctx;
  FETCHcode result;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
  {
    result = FETCHE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->state = HAPROXY_INIT;
  Fetch_dyn_init(&ctx->data_out, DYN_HAXPROXY);

  result = Fetch_cf_create(&cf, &Fetch_cft_haproxy, ctx);
  if (result)
    goto out;
  ctx = NULL;

out:
  cf_haproxy_ctx_free(ctx);
  *pcf = result ? NULL : cf;
  return result;
}

FETCHcode Fetch_cf_haproxy_insert_after(struct Fetch_cfilter *cf_at,
                                       struct Fetch_easy *data)
{
  struct Fetch_cfilter *cf;
  FETCHcode result;

  result = cf_haproxy_create(&cf, data);
  if (result)
    goto out;
  Fetch_conn_cf_insert_after(cf_at, cf);

out:
  return result;
}

#endif /* !FETCH_DISABLE_PROXY */
