/***************************************************************************
 *                                  _   _ ____  _
 *                                 | | | |  _ \| |
 *                                 | |_| | |_) | |
 *                                 |  _  |  _ <| |___
 *                                 |_| |_|_| \_\____|
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
#include "unitcheck.h"

#include "urldata.h"
#include "cfilters.h"
#include "conncache.h"
#include "curl_trc.h"
#include "hash.h"
#include "progress.h"
#include "protocol.h"
#include "url.h"

struct t2607_cf_ctx {
  size_t *calls;
  size_t *closed;
  bool fail;
};

struct t2607_run {
  size_t calls;
  size_t closed;
};

static void t2607_cf_destroy(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  struct t2607_cf_ctx *ctx = cf->ctx;
  (void)data;
  if(ctx) {
    ++*ctx->closed;
    curlx_free(ctx);
    cf->ctx = NULL;
  }
}

static CURLcode t2607_cf_keep_alive(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct t2607_cf_ctx *ctx = cf->ctx;
  (void)data;
  ++*ctx->calls;
  return ctx->fail ? CURLE_SEND_ERROR : CURLE_OK;
}

static const struct Curl_cftype t2607_cft = {
  "TEST-UPKEEP",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  t2607_cf_destroy,
  Curl_cf_def_connect,
  Curl_cf_def_shutdown,
  Curl_cf_def_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  t2607_cf_keep_alive,
  Curl_cf_def_query,
};

static void t2607_meta_free(void *ptr)
{
  (void)ptr;
}

static CURLcode t2607_add_conn(struct Curl_easy *data,
                                const char *destination,
                                bool fail,
                                size_t *calls,
                                size_t *closed)
{
  struct connectdata *conn = NULL;
  struct Curl_cfilter *cf = NULL;
  struct t2607_cf_ctx *ctx = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  conn = curlx_calloc(1, sizeof(*conn));
  if(!conn)
    return result;

  Curl_hash_init(&conn->meta_hash, 23, Curl_hash_str,
                 curlx_str_key_compare, t2607_meta_free);
  conn->sock[FIRSTSOCKET] = CURL_SOCKET_BAD;
  conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD;
  conn->connection_id = -1;
  conn->scheme = conn->given = &Curl_scheme_http;
  conn->destination = curlx_strdup(destination);
  if(!conn->destination)
    goto out;

  conn->created = *Curl_pgrs_now(data);
  conn->keepalive = conn->created;
  conn->lastused = conn->created;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx)
    goto out;
  ctx->calls = calls;
  ctx->closed = closed;
  ctx->fail = fail;

  result = Curl_cf_create(&cf, &t2607_cft, ctx);
  if(result)
    goto out;
  ctx = NULL;

  Curl_conn_cf_add(data, conn, FIRSTSOCKET, cf);
  cf->connected = TRUE;

  result = Curl_cpool_add(data, conn);
  if(!result)
    return CURLE_OK;

out:
  Curl_conn_free(data, conn);
  curlx_free(ctx);
  return result;
}

static CURLcode t2607_run(size_t retained, size_t failed,
                          struct t2607_run *run)
{
  CURL *easy = NULL;
  CURLM *multi = NULL;
  struct Curl_easy *data;
  struct cpool *cpool;
  CURLcode result = CURLE_OK;
  size_t calls = 0;
  size_t closed = 0;
  size_t i;

  memset(run, 0, sizeof(*run));
  easy = curl_easy_init();
  if(!easy)
    return CURLE_OUT_OF_MEMORY;

  multi = curl_multi_init();
  if(!multi) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  if(curl_multi_add_handle(multi, easy)) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  data = (struct Curl_easy *)easy;
  /* Use zero as a synthetic amplifier: every connection is due per pass. */
  result = curl_easy_setopt(easy, CURLOPT_UPKEEP_INTERVAL_MS, 0L);
  if(result)
    goto out;

  cpool = Curl_cpool_get_instance(data);
  if(!cpool) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  /* Put retained connections before failures in one destination bundle. */
  for(i = 0; i < retained && !result; ++i)
    result = t2607_add_conn(data, "upkeep.test:80", FALSE,
                            &calls, &closed);
  for(i = 0; i < failed && !result; ++i)
    result = t2607_add_conn(data, "upkeep.test:80", TRUE,
                            &calls, &closed);
  if(result)
    goto out;

  result = curl_easy_upkeep(easy);
  run->calls = calls;
  run->closed = closed;
  if(!result && (run->closed != failed || cpool->num_conn != retained))
    result = CURLE_FAILED_INIT;

out:
  if(multi && curl_multi_cleanup(multi) != CURLM_OK && !result)
    result = CURLE_FAILED_INIT;
  curl_easy_cleanup(easy);
  return result;
}

static bool t2607_destination_for_slot(struct cpool *cpool,
                                       size_t slot,
                                       char *destination,
                                       size_t destination_size)
{
  size_t i;

  for(i = 0; i < 10000; ++i) {
    curl_msnprintf(destination, destination_size, "upkeep-%zu.test:80",
                   (slot * 10000) + i);
    if(Curl_hash_str(destination, strlen(destination) + 1,
                     cpool->dest2bundle.slots) == slot)
      return TRUE;
  }
  return FALSE;
}

static CURLcode t2607_multi_destination(void)
{
  CURL *easy = NULL;
  CURLM *multi = NULL;
  struct Curl_easy *data;
  struct cpool *cpool;
  char destinations[3][32];
  size_t destination_slots[3];
  size_t calls = 0;
  size_t closed = 0;
  CURLcode result = CURLE_OK;
  size_t i;

  easy = curl_easy_init();
  if(!easy)
    return CURLE_OUT_OF_MEMORY;

  multi = curl_multi_init();
  if(!multi) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  if(curl_multi_add_handle(multi, easy)) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  data = (struct Curl_easy *)easy;
  result = curl_easy_setopt(easy, CURLOPT_UPKEEP_INTERVAL_MS, 0L);
  if(result)
    goto out;

  cpool = Curl_cpool_get_instance(data);
  if(!cpool || cpool->dest2bundle.slots < 3) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  destination_slots[0] = 0;
  destination_slots[1] = cpool->dest2bundle.slots / 2;
  destination_slots[2] = cpool->dest2bundle.slots - 1;
  for(i = 0; i < CURL_ARRAYSIZE(destinations); ++i) {
    if(!t2607_destination_for_slot(cpool, destination_slots[i],
                                   destinations[i],
                                   sizeof(destinations[i]))) {
      result = CURLE_FAILED_INIT;
      goto out;
    }
  }

  /* Add out of iterator order. The first failing bundle is removed alone. */
  result = t2607_add_conn(data, destinations[2], TRUE, &calls, &closed);
  if(!result)
    result = t2607_add_conn(data, destinations[0], TRUE, &calls, &closed);
  if(!result)
    result = t2607_add_conn(data, destinations[1], FALSE, &calls, &closed);
  if(result)
    goto out;

  if(Curl_hash_count(&cpool->dest2bundle) != CURL_ARRAYSIZE(destinations)) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  result = curl_easy_upkeep(easy);
  if(!result && (closed != 2 || cpool->num_conn != 1 ||
                 Curl_hash_count(&cpool->dest2bundle) != 1))
    result = CURLE_FAILED_INIT;

out:
  if(multi && curl_multi_cleanup(multi) != CURLM_OK && !result)
    result = CURLE_FAILED_INIT;
  curl_easy_cleanup(easy);
  return result;
}

static CURLcode t2607_setup(void)
{
  return curl_global_init(CURL_GLOBAL_ALL);
}

static void t2607_stop(void)
{
  curl_global_cleanup();
}

static CURLcode test_unit2607(const char *arg)
{
  bool measure = arg && !strcmp(arg, "measure");
  struct t2607_run run;
  CURLcode result;

  UNITTEST_BEGIN(t2607_setup())

  /* Two retained connections precede two failed connections. */
  result = t2607_run(2, 2, &run);
  if(!result && !measure && run.calls != 4)
    result = CURLE_FAILED_INIT;
  if(!result)
    result = t2607_multi_destination();
  fail_unless(result == CURLE_OK, "connection pool upkeep failed");
  if(measure && !result) {
    curl_mprintf("{\"metric\":\"upkeep_keepalive_calls\",\"value\":%zu}\n",
                 run.calls);
  }

  UNITTEST_END(t2607_stop())
}
