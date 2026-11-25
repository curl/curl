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
#include "unitcheck.h"

#if defined(USE_NGHTTP2) && !defined(CURL_DISABLE_HTTP)
#include "urldata.h"
#include "cfilters.h"
#include "curl_trc.h"
#include "http2.h"
#include "multiif.h"
#include "url.h"

/* One SETTINGS frame followed by a GOAWAY with last stream ID 0. */
static const unsigned char t2642_reply[] = {
  0, 0, 0, 4, 0, 0, 0, 0, 0,
  0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

struct t2642_input {
  size_t offset;
  size_t reads;
  bool shutdown_complete;
};

static bool t2642_pending(struct Curl_cfilter *cf,
                          const struct Curl_easy *data)
{
  struct t2642_input *in = cf->ctx;
  (void)data;
  return in->offset < sizeof(t2642_reply);
}

static CURLcode t2642_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           char *buf, size_t len, size_t *nread)
{
  struct t2642_input *in = cf->ctx;
  (void)data;
  in->reads++;
  /* Make the first receive a short read containing just SETTINGS. */
  if(!in->offset)
    len = CURLMIN(len, 9);
  *nread = CURLMIN(len, sizeof(t2642_reply) - in->offset);
  if(!*nread)
    return CURLE_AGAIN;
  memcpy(buf, t2642_reply + in->offset, *nread);
  in->offset += *nread;
  return CURLE_OK;
}

static CURLcode t2642_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                           const uint8_t *buf, size_t len, bool eos,
                           size_t *nwritten)
{
  (void)cf;
  (void)data;
  (void)buf;
  (void)eos;
  *nwritten = len;
  return CURLE_OK;
}

static void t2642_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct t2642_input *in = cf->ctx;
  (void)data;
  in->shutdown_complete = cf->shutdown;
}

static const struct Curl_cftype t2642_cft = {
  "TEST", CF_TYPE_IP_CONNECT, CURL_LOG_LVL_NONE,
  t2642_destroy, Curl_cf_def_connect, Curl_cf_def_shutdown,
  Curl_cf_def_adjust_pollset, t2642_pending, t2642_send, t2642_recv,
  Curl_cf_def_cntrl, Curl_cf_def_conn_is_alive, Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query
};
#endif

static CURLcode test_unit2642(const char *arg)
{
#if defined(USE_NGHTTP2) && !defined(CURL_DISABLE_HTTP)
  struct Curl_multi *multi = NULL;
  struct Curl_easy *easy = NULL;
  struct connectdata *conn = NULL;
  struct Curl_cfilter *lower;
  struct t2642_input in = { 0 };
  CURLcode result;
  int running;
  long timeout_ms = -1;

  (void)arg;
  global_init(CURL_GLOBAL_ALL);
  multi = curl_multi_init();
  easy = curl_easy_init();
  abort_unless(multi && easy, "creating handles");
  abort_unless(!curl_multi_add_handle(multi, easy), "adding transfer");

  conn = curlx_calloc(1, sizeof(*conn));
  abort_unless(conn, "allocating connection");
  conn->cpid = UINT32_MAX;
  conn->created = curlx_now();
  Curl_hash_init(&conn->meta_hash, 1, CURL_HASH_TYPE_BYTES, curl_free);
  Curl_cfchain_init(&conn->chain, conn, TRUE);
  abort_unless(!Curl_cf_create(&lower, &t2642_cft, &in), "creating filter");
  Curl_cfchain_add(&conn->chain, lower);

  /* An upgrade opens stream 1. The admin handle doing the shutdown
   * has no stream of its own. */
  Curl_attach_connection(easy, conn, TRUE);
  result = Curl_http2_upgrade(easy, NULL, 0);
  Curl_detach_connection(easy);
  abort_unless(!result, "opening HTTP/2 session");
  abort_unless(!curl_multi_remove_handle(multi, easy), "removing transfer");

  Curl_cshutdn_add(&multi->cshutdn, multi, conn, 1);
  conn = NULL; /* owned by the shutdown list */
  abort_unless(!curl_multi_perform(multi, &running), "first shutdown pass");
  fail_unless(in.reads == 1 && in.offset == 9,
              "process one short receive during shutdown");
  fail_unless(!curl_multi_timeout(multi, &timeout_ms) && !timeout_ms,
              "run again without waiting for a socket");

  abort_unless(!curl_multi_perform(multi, &running), "second shutdown pass");
  fail_unless(in.reads == 2 && in.offset == sizeof(t2642_reply),
              "process GOAWAY on the next pass");
  fail_unless(!Curl_cshutdn_count(&multi->cshutdn), "shutdown completed");
  fail_unless(in.shutdown_complete, "lower filter shutdown completed");

unit_test_abort:
  if(conn)
    Curl_conn_free(easy, conn);
  if(multi)
    curl_multi_cleanup(multi);
  curl_easy_cleanup(easy);
  curl_global_cleanup();
  return (CURLcode)unitfail;
#else
  (void)arg;
  return CURLE_OK;
#endif
}
