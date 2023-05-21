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

#if defined(USE_SSL) && !defined(CURL_DISABLE_GEMINI)

#include <string.h>
#include "urldata.h"
#include "transfer.h"
#include "connect.h"
#include "cfilters.h"
#include "sendf.h"
#include "multiif.h"
#include "select.h"
#include "strdup.h"
#include "url.h"
#include "curl_printf.h"
#include "gemini.h"
#include "memdebug.h"

static CURLcode gemini_setup_connection(struct Curl_easy *data,
                                        struct connectdata *conn)
{
  DEBUGASSERT(data->req.p.gemini == NULL);

  data->req.p.gemini = calloc(1, sizeof(struct GEMINI));

  if(!data->req.p.gemini)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

static CURLcode gemini_connect(struct Curl_easy *data, bool *done)
{
  char *url = data->state.url;
  struct GEMINI *gemini = data->req.p.gemini;

  /* url is guaranteed to be non-NULL and non-empty */
  DEBUGASSERT(url);

  /* gemini is guaranteed to be non-NULL */
  DEBUGASSERT(gemini);

  /* url must not start with 0xFEFF */
  if((unsigned char)url[0] == 0xFF && (unsigned char)url[1] == 0xFE) {
    failf(data, "URL starts with 0xFEFF");
    return CURLE_URL_MALFORMAT;
  }

  /* url must be 1024 bytes or less */
  if(strlen(url) > 1024) {
    failf(data, "URL is too long");
    return CURLE_URL_MALFORMAT;
  }

  /* Copy the URL and termination to the GEMINI struct */
  gemini->reqindex = 0;
  gemini->reqlen = curl_msnprintf(gemini->request,
                                  sizeof(gemini->request),
                                  "%s%s",
                                  url,
                                  GEMINI_TERMINATION);

  if(gemini->reqlen < 0) {
    failf(data, "Failed to copy URL to GEMINI struct");
    return CURLE_URL_MALFORMAT;
  }

  *done = true;
  return CURLE_OK;
}

static CURLcode gemini_connecting(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  CURLcode result;

  result = Curl_conn_connect(data, FIRSTSOCKET, TRUE, done);
  if(result)
    connclose(conn, "Failed TLS connection");

  *done = TRUE;
  return result;
}

static CURLcode gemini_doing(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  struct GEMINI *gemini = data->req.p.gemini;
  size_t rx_size = GEMINI_STATUS_SIZE + 1 + GEMINI_META_MAX;

  /* Send request */
  if(gemini->reqindex < gemini->reqlen) {
    result = Curl_write(data,
                        sockfd,
                        &gemini->request[gemini->reqindex],
                        gemini->reqlen - gemini->reqindex,
                        &data->info.request_size);

    if(result)
      return result;

    gemini->reqindex += data->info.request_size;

    /* If we haven't sent the entire request yet, return */
    if(gemini->reqindex < gemini->reqlen)
      return CURLE_OK;
  }

  /* Receive response header */
  if(gemini->reslen < rx_size) {

    /* Not ready to read */
    if(SOCKET_READABLE(sockfd, 0) <= 0)
      return CURLE_OK;

    result = Curl_read(data,
                       sockfd,
                       &gemini->response[gemini->reslen],
                       rx_size - gemini->reslen,
                       &data->info.header_size);

    if(result && result != CURLE_AGAIN)
      return result;

    gemini->reslen += data->info.header_size;

    /* If we haven't received the entire response yet, return */
    if(gemini->response[gemini->reslen - 2] != GEMINI_TERMINATION[0] ||
       gemini->response[gemini->reslen - 1] != GEMINI_TERMINATION[1])
      return CURLE_OK;
  }

  /* Too short header */
  if(gemini->reslen < 5) {
    failf(data, "Response is too short");
    return CURLE_WEIRD_SERVER_REPLY;
  }

  /* Write Header: <status><space><meta><cr><lf> */
  result = Curl_client_write(data,
                             CLIENTWRITE_HEADER,
                             gemini->response,
                             gemini->reslen);

  if(result)
    return result;

  /* Redirect: 3x <redirect url>\r\n */
  if(gemini->response[0] == '3') {
    char *redirect = &gemini->response[3];
    size_t redirect_len = gemini->reslen - 5;
    redirect[redirect_len] = '\0';

    /* Redirect URL must not start with 0xFEFF */
    if((unsigned char)redirect[0] == 0xFF &&
       (unsigned char)redirect[1] == 0xFE) {
      failf(data, "Redirect URL starts with 0xFEFF");
      return CURLE_URL_MALFORMAT;
    }

    /* Setting new URL */
    Curl_safefree(data->req.newurl);
    data->req.newurl = strdup(redirect);

    if(!data->req.newurl)
      return CURLE_OUT_OF_MEMORY;

    /* Close connection and trigger to retry */
    connclose(conn, "Redirecting");
    conn->bits.retry = TRUE;

    *done = TRUE;
    return CURLE_OK;
  }

  /* Input: 1x <meta>\r\n */
  if(gemini->response[0] == '1') {
    char *meta = &gemini->response[0];
    size_t meta_len = gemini->reslen;
    char *msg;
    msg = "Status Code: ";
    meta[meta_len] = '\0';

    /* Write msg */
    result = Curl_client_write(data, CLIENTWRITE_BODY, msg, strlen(msg));

    if(result)
      return result;

    /* Write Meta: 1x <meta>\r\n */
    result = Curl_client_write(data, CLIENTWRITE_BODY, meta, meta_len);

    if(result)
      return result;

    /* Process the rest of the response payload */
    *done = TRUE;
    Curl_setup_transfer(data, FIRSTSOCKET, -1, FALSE, -1);

    return result;
  }


  /* All non-successful status codes */
  if(gemini->response[0] != '2') {
    failf(data, "Response status code is not 1x, 2x, or 3X");
    return CURLE_WEIRD_SERVER_REPLY;
  }

  /* Process the rest of the response payload */
  *done = TRUE;
  Curl_setup_transfer(data, FIRSTSOCKET, -1, FALSE, -1);

  return result;
}

static int gemini_doing_getsock(struct Curl_easy *data,
                                struct connectdata *conn, curl_socket_t *socks)
{
  (void)data;
  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_WRITESOCK(0);
}

static CURLcode gemini_done(struct Curl_easy *data,
                            CURLcode curl_code, bool done)
{
  (void)data;
  (void)curl_code;
  (void)done;
  return CURLE_OK;
}

static CURLcode gemini_disconnect(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  bool dead_connection)
{
  (void)conn;
  (void)dead_connection;

  if(!data->req.p.gemini)
    return CURLE_OK;

  free(data->req.p.gemini);
  data->req.p.gemini = NULL;

  return CURLE_OK;
}

/*
 * Gemini protocol handler.
 */

const struct Curl_handler Curl_handler_gemini = {
  "GEMINI",                             /* scheme */
  gemini_setup_connection,              /* setup_connection */
  gemini_doing,                         /* do_it */
  gemini_done,                          /* done */
  ZERO_NULL,                            /* do_more */
  gemini_connect,                       /* connect_it */
  gemini_connecting,                    /* connecting */
  gemini_doing,                         /* doing */
  ZERO_NULL,                            /* proto_getsock */
  gemini_doing_getsock,                 /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  gemini_disconnect,                    /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_GEMINI,                          /* defport */
  CURLPROTO_GEMINI,                     /* protocol */
  CURLPROTO_GEMINI,                     /* family */
  PROTOPT_SSL                           /* flags */
};

#endif
