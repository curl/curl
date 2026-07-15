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

#include "urldata.h"
#include "cfilters.h"
#include "curl_trc.h"
#include "select.h"

/* Test the gating in Curl_conn_adjust_pollset(): each filter chain
 * of a connection must only get to adjust the pollset when the transfer
 * wants to send or receive, or when that chain itself is connecting or
 * shutting down. One chain being in connect or shutdown must not add
 * poll events for the other, see #21671. */

struct t2606_ctx {
  int calls;
  bool add_socket;
  curl_socket_t sock;
};

static void t2606_cf_destroy(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  (void)data;
  /* ctx is owned by the test case, nothing to free */
  cf->ctx = NULL;
}

static CURLcode t2606_cf_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *done)
{
  (void)cf;
  (void)data;
  *done = TRUE;
  return CURLE_OK;
}

static CURLcode t2606_cf_adjust_pollset(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct easy_pollset *ps)
{
  struct t2606_ctx *ctx = cf->ctx;
  ctx->calls++;
  if(ctx->add_socket)
    return Curl_pollset_add_in(data, ps, ctx->sock);
  return CURLE_OK;
}

static const struct Curl_cftype t2606_cft = {
  "TEST-PS",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  t2606_cf_destroy,
  t2606_cf_connect,
  Curl_cf_def_shutdown,
  t2606_cf_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

struct t2606_case {
  int id;
  bool has_c1;        /* a SECONDARYSOCKET chain exists */
  bool c0_connected;
  bool c1_connected;
  bool c0_shutdown;   /* shutdown started on the chain */
  bool c1_shutdown;
  bool xfer_io;       /* the pollset holds a transfer socket already */
  bool c0_adds;       /* chain 0 adds a socket when called */
  int exp_c0_calls;
  int exp_c1_calls;
};

static CURLcode t2606_setup(CURL **easy)
{
  CURLcode result = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  *easy = curl_easy_init();
  if(!*easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return result;
}

static void t2606_stop(CURL *easy)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

static void t2606_run(struct Curl_easy *data, const struct t2606_case *tc)
{
  struct connectdata *conn;
  struct Curl_cfilter *cf0 = NULL, *cf1 = NULL;
  struct t2606_ctx ctx0, ctx1;
  struct easy_pollset ps;
  CURLcode result;
  char msg[128];

  conn = curlx_calloc(1, sizeof(*conn));
  abort_if(!conn, "could not allocate a connection");

  memset(&ctx0, 0, sizeof(ctx0));
  memset(&ctx1, 0, sizeof(ctx1));
  ctx0.sock = 42;
  ctx0.add_socket = tc->c0_adds;
  ctx1.sock = 43;

  result = Curl_cf_create(&cf0, &t2606_cft, &ctx0);
  fail_unless(!result, "creating filter chain 0 failed");
  if(!result) {
    Curl_conn_cf_add(data, conn, FIRSTSOCKET, cf0);
    cf0->connected = tc->c0_connected;
    if(tc->c0_shutdown)
      conn->shutdown.start[FIRSTSOCKET] = curlx_now();
  }

  if(tc->has_c1) {
    result = Curl_cf_create(&cf1, &t2606_cft, &ctx1);
    fail_unless(!result, "creating filter chain 1 failed");
    if(!result) {
      Curl_conn_cf_add(data, conn, SECONDARYSOCKET, cf1);
      cf1->connected = tc->c1_connected;
      if(tc->c1_shutdown)
        conn->shutdown.start[SECONDARYSOCKET] = curlx_now();
    }
  }

  Curl_pollset_init(&ps);
  if(tc->xfer_io) {
    result = Curl_pollset_add_in(data, &ps, 7);
    fail_unless(!result, "preloading the pollset failed");
  }

  result = Curl_conn_adjust_pollset(data, conn, &ps);

  curl_msprintf(msg, "case %d: adjust_pollset failed", tc->id);
  fail_unless(!result, msg);
  curl_msprintf(msg, "case %d: chain 0 called %d times, expected %d",
                tc->id, ctx0.calls, tc->exp_c0_calls);
  fail_unless(ctx0.calls == tc->exp_c0_calls, msg);
  curl_msprintf(msg, "case %d: chain 1 called %d times, expected %d",
                tc->id, ctx1.calls, tc->exp_c1_calls);
  fail_unless(ctx1.calls == tc->exp_c1_calls, msg);
  if(tc->c0_adds && tc->exp_c0_calls) {
    curl_msprintf(msg, "case %d: chain 0 did not add its socket", tc->id);
    fail_unless(ps.n > 0, msg);
  }

  Curl_pollset_cleanup(&ps);
  Curl_conn_cf_discard_all(data, conn, SECONDARYSOCKET);
  Curl_conn_cf_discard_all(data, conn, FIRSTSOCKET);
unit_test_abort:
  curlx_free(conn);
}

static CURLcode test_unit2606(const char *arg)
{
  CURL *easy;

  UNITTEST_BEGIN(t2606_setup(&easy))

  static const struct t2606_case TEST_CASES[] = {
    /* both chains connected and quiet, transfer idle: nothing runs */
    { 1, TRUE,  TRUE,  TRUE,  FALSE, FALSE, FALSE, FALSE, 0, 0 },
    /* transfer wants IO: both chains run */
    { 2, TRUE,  TRUE,  TRUE,  FALSE, FALSE, TRUE,  FALSE, 1, 1 },
    /* chain 0 connecting, chain 1 connected and quiet: only chain 0 */
    { 3, TRUE,  FALSE, TRUE,  FALSE, FALSE, FALSE, FALSE, 1, 0 },
    /* chain 1 connecting, chain 0 connected and quiet: only chain 1 */
    { 4, TRUE,  TRUE,  FALSE, FALSE, FALSE, FALSE, FALSE, 0, 1 },
    /* chain 0 shutting down, chain 1 connected and quiet: only chain 0 */
    { 5, TRUE,  TRUE,  TRUE,  TRUE,  FALSE, FALSE, FALSE, 1, 0 },
    /* chain 1 shutting down, chain 0 connected and quiet: only chain 1 */
    { 6, TRUE,  TRUE,  TRUE,  FALSE, TRUE,  FALSE, FALSE, 0, 1 },
    /* single connected quiet chain, transfer idle: nothing runs */
    { 7, FALSE, TRUE,  FALSE, FALSE, FALSE, FALSE, FALSE, 0, 0 },
    /* single chain shutting down: runs */
    { 8, FALSE, TRUE,  FALSE, TRUE,  FALSE, FALSE, FALSE, 1, 0 },
    /* a socket added by connecting chain 0 must not run quiet chain 1 */
    { 9, TRUE,  FALSE, TRUE,  FALSE, FALSE, FALSE, TRUE,  1, 0 },
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(TEST_CASES); ++i) {
    t2606_run(easy, &TEST_CASES[i]);
  }

  UNITTEST_END(t2606_stop(easy))
}
