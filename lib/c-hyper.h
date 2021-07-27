#ifndef HEADER_CURL_HYPER_H
#define HEADER_CURL_HYPER_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_HYPER)

#include <hyper.h>

/* this is stored in the user data of each asynchronous task to distinguish
 * them */
typedef enum hyptaskud {
  /* from hyper_clientconn_handshake(), outputs a hyper_clientconn* */
  CURL_HYPER_TASKUD_HANDSHAKE = 1,
  /* from hyper_clientconn_send(), outputs a hyper_response* */
  CURL_HYPER_TASKUD_RESPONSE,
  /* from hyper_body_foreach(), no output */
  CURL_HYPER_TASKUD_BODY_FOREACH,
  /* for proxy CONNECT, from hyper_clientconn_handshake(),
   * outputs a hyper_clientconn* */
  CURL_HYPER_TASKUD_CONNECT_HANDSHAKE,
  /* for proxy CONNECT, from hyper_clientconn_send(),
   * outputs a hyper_response* */
  CURL_HYPER_TASKUD_CONNECT_RESPONSE,
  /* for proxy CONNECT, from hyper_body_foreach(), no output */
  CURL_HYPER_TASKUD_CONNECT_BODY_FOREACH,
} hyptaskud;

/* whether a task has completed yet, and whether it returned its output or an
 * error */
typedef enum hyptaskstatus {
  CURL_HYPER_TASK_NOT_DONE = 0,
  CURL_HYPER_TASK_COMPLETE,
  CURL_HYPER_TASK_ERROR,
} hyptaskstatus;

/* per-transfer data for the Hyper backend */
struct hyptransfer {
  hyper_waker *write_waker;
  hyper_waker *read_waker;
  const hyper_executor *exec;

  hyptaskstatus handshake_status;
  union {
    hyper_clientconn* output;
    hyper_error* error;
  } handshake_result;

  hyptaskstatus response_status;
  union {
    hyper_response* output;
    hyper_error* error;
  } response_result;

  hyptaskstatus body_foreach_status;
  hyper_error* body_foreach_error;

  hyptaskstatus connect_handshake_status;
  union {
    hyper_clientconn* output;
    hyper_error* error;
  } connect_handshake_result;

  hyptaskstatus connect_response_status;
  union {
    hyper_response* output;
    hyper_error* error;
  } connect_response_result;

  hyptaskstatus connect_body_foreach_status;
  hyper_error* connect_body_foreach_error;

  hyper_waker *exp100_waker;
};

size_t Curl_hyper_recv(void *userp, hyper_context *ctx,
                       uint8_t *buf, size_t buflen);
size_t Curl_hyper_send(void *userp, hyper_context *ctx,
                       const uint8_t *buf, size_t buflen);
CURLcode Curl_hyper_stream(struct Curl_easy *data,
                           struct connectdata *conn,
                           int *didwhat,
                           bool *done,
                           int select_res);

CURLcode Curl_hyper_header(struct Curl_easy *data, hyper_headers *headers,
                           const char *line);
void Curl_hyper_done(struct Curl_easy *);
bool Curl_hyper_poll_executor(struct hyptransfer *h);

#else
#define Curl_hyper_done(x)

#endif /* !defined(CURL_DISABLE_HTTP) && defined(USE_HYPER) */
#endif /* HEADER_CURL_HYPER_H */
