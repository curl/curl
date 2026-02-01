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
#include "gopher.h"

#ifndef CURL_DISABLE_GOPHER

#include "transfer.h"
#include "sendf.h"
#include "curl_trc.h"
#include "cfilters.h"
#include "connect.h"
#include "select.h"
#include "url.h"
#include "escape.h"

#ifdef USE_SSL
static CURLcode gopher_connect(struct Curl_easy *data, bool *done)
{
  (void)data;
  (void)done;
  return CURLE_OK;
}

static CURLcode gopher_connecting(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  CURLcode result;

  result = Curl_conn_connect(data, FIRSTSOCKET, TRUE, done);
  if(result)
    connclose(conn, "Failed TLS connection");
  *done = TRUE;
  return result;
}
#endif

static CURLcode gopher_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  char *gopherpath;
  const char *path = data->state.up.path;
  const char *query = data->state.up.query;
  const char *buf = NULL;
  char *buf_alloc = NULL;
  size_t nwritten, buf_len;
  timediff_t timeout_ms;
  int what;

  *done = TRUE; /* unconditionally */

  /* path is guaranteed non-NULL */
  DEBUGASSERT(path);

  if(query)
    gopherpath = curl_maprintf("%s?%s", path, query);
  else
    gopherpath = curlx_strdup(path);

  if(!gopherpath)
    return CURLE_OUT_OF_MEMORY;

  /* Create selector. Degenerate cases: / and /1 => convert to "" */
  if(strlen(gopherpath) <= 2) {
    buf = "";
    buf_len = 0;
    curlx_free(gopherpath);
  }
  else {
    const char *newp;

    /* Otherwise, drop / and the first character (i.e., item type) ... */
    newp = gopherpath;
    newp += 2;

    /* ... and finally unescape */
    result = Curl_urldecode(newp, 0, &buf_alloc, &buf_len, REJECT_ZERO);
    curlx_free(gopherpath);
    if(result)
      return result;
    buf = buf_alloc;
  }

  for(; buf_len;) {

    result = Curl_xfer_send(data, buf, buf_len, FALSE, &nwritten);
    if(!result) { /* Which may not have written it all! */
      result = Curl_client_write(data, CLIENTWRITE_HEADER, buf, nwritten);
      if(result)
        break;

      if(nwritten > buf_len) {
        DEBUGASSERT(0);
        break;
      }
      buf_len -= nwritten;
      buf += nwritten;
      if(!buf_len)
        break; /* but it did write it all */
    }
    else
      break;

    timeout_ms = Curl_timeleft_ms(data);
    if(timeout_ms < 0) {
      result = CURLE_OPERATION_TIMEDOUT;
      break;
    }
    if(!timeout_ms)
      timeout_ms = TIMEDIFF_T_MAX;

    /* Do not busyloop. The entire loop thing is a work-around as it causes a
       BLOCKING behavior which is a NO-NO. This function should rather be
       split up in a do and a doing piece where the pieces that are not
       possible to send now will be sent in the doing function repeatedly
       until the entire request is sent.
    */
    what = SOCKET_WRITABLE(sockfd, timeout_ms);
    if(what < 0) {
      result = CURLE_SEND_ERROR;
      break;
    }
    else if(!what) {
      result = CURLE_OPERATION_TIMEDOUT;
      break;
    }
  }

  curlx_free(buf_alloc);

  if(!result)
    result = Curl_xfer_send(data, "\r\n", 2, FALSE, &nwritten);
  if(result) {
    failf(data, "Failed sending Gopher request");
    return result;
  }
  result = Curl_client_write(data, CLIENTWRITE_HEADER, "\r\n", 2);
  if(result)
    return result;

  Curl_xfer_setup_recv(data, FIRSTSOCKET, -1);
  return CURLE_OK;
}

/*
 * Gopher protocol handler.
 * This is also a nice simple template to build off for simple
 * connect-command-download protocols.
 */

static const struct Curl_protocol Curl_protocol_gopher = {
  ZERO_NULL,                            /* setup_connection */
  gopher_do,                            /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_pollset */
  ZERO_NULL,                            /* doing_pollset */
  ZERO_NULL,                            /* domore_pollset */
  ZERO_NULL,                            /* perform_pollset */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  ZERO_NULL,                            /* follow */
};

#ifdef USE_SSL
static const struct Curl_protocol Curl_protocol_gophers = {
  ZERO_NULL,                            /* setup_connection */
  gopher_do,                            /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  gopher_connect,                       /* connect_it */
  gopher_connecting,                    /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_pollset */
  ZERO_NULL,                            /* doing_pollset */
  ZERO_NULL,                            /* domore_pollset */
  ZERO_NULL,                            /* perform_pollset */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  ZERO_NULL,                            /* follow */
};
#endif

#endif /* CURL_DISABLE_GOPHER */

const struct Curl_scheme Curl_scheme_gopher = {
  "gopher",                             /* scheme */
#ifdef CURL_DISABLE_GOPHER
  ZERO_NULL,
#else
  &Curl_protocol_gopher,
#endif
  CURLPROTO_GOPHER,                     /* protocol */
  CURLPROTO_GOPHER,                     /* family */
  PROTOPT_NONE,                         /* flags */
  PORT_GOPHER,                          /* defport */
};

const struct Curl_scheme Curl_scheme_gophers = {
  "gophers",                            /* scheme */
#if defined(CURL_DISABLE_GOPHER) || !defined(USE_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_gophers,
#endif
  CURLPROTO_GOPHERS,                    /* protocol */
  CURLPROTO_GOPHER,                     /* family */
  PROTOPT_SSL,                          /* flags */
  PORT_GOPHER,                          /* defport */
};
