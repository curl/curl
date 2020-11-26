/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#if !defined CURL_DISABLE_GEMINI && defined USE_SSL

#include <ctype.h>
#include <string.h>
#include "gemini.h"
#include "urldata.h"
#include "vtls/vtls.h"
#include "transfer.h"
#include "sendf.h"
#include "multiif.h"
#include "select.h"
#include "strdup.h"
#include "url.h"
#include "curl_printf.h"
/* The last #include file should be: */
#include "memdebug.h"

static CURLcode gemini_setup_connection(struct connectdata *conn)
{
  struct GEMINI *gemini;
  struct Curl_easy *data = conn->data;
  DEBUGASSERT(data->req.p.gemini == NULL);

  gemini = calloc(1, sizeof(struct GEMINI));
  if(!gemini)
    return CURLE_OUT_OF_MEMORY;
  data->req.p.gemini = gemini;
  return CURLE_OK;
}

static CURLcode gemini_connecting(struct connectdata *conn, bool *done)
{
  return Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, done);
}

static CURLcode gemini_do_it(struct connectdata *conn, bool *done)
{
  struct GEMINI *gemini;
  struct Curl_easy *data;
  char *request;

  data = conn->data;
  request = aprintf("%s\r\n", data->change.url);

  if(!request)
    return CURLE_OUT_OF_MEMORY;

  gemini = data->req.p.gemini;
  gemini->request.memory = request;
  gemini->request.amount_total = strlen(request);
  gemini->request.amount_sent = 0;

  /* Real work happens in gemini_doing, so we can use non-blocking
   * functions and avoid busy loops.
   */

  return CURLE_OK;
}

static CURLcode gemini_doing_finish(struct connectdata *, bool *);
static CURLcode gemini_doing(struct connectdata *conn, bool *done)
{
  CURLcode result;
  curl_socket_t sockfd;
  struct Curl_easy *data;
  struct GEMINI *gemini;
  size_t more;
  size_t sent;
  size_t amount;

  data = conn->data;
  gemini = conn->data->req.p.gemini;
  sockfd = conn->sock[FIRSTSOCKET];

  /* stage1: send request */
  sent = gemini->request.amount_sent;
  more = gemini->request.amount_total - sent;
  if(more) {
    char *from;

    from = gemini->request.memory + sent;
    result = Curl_write(conn, sockfd, from, more, &amount);
    if(result)
      return result;

    gemini->request.amount_sent += amount;
    more -= amount;

    if(more)
      return CURLE_OK;
  }

  /* stage2: read block big enough to contain header */
  if(!gemini->block.done) {
    char *into;

    into = gemini->block.memory + gemini->block.amount;
    more = GEMINI_RESPONSE_BUFSIZE - gemini->block.amount;

    if(SOCKET_READABLE(sockfd, 0) <= 0)
      return CURLE_OK;

    result = Curl_read(conn, sockfd, into, more, &amount);

    if(result)
      return result;

    gemini->block.amount += amount;
    more -= amount;

    /* !more means that we succesfully read GEMINI_RESPONSE_BUFSIZE bytes.
     * !amount means that there is no more data. It is quite possible
     * for whole response, header + body combined to be less than
     * GEMINI_RESPONSE_BUFSIZE bytes big.
     */

    if(!amount || !more)
      gemini->block.done = TRUE;

    /* Optimization: We check for LF, and skip reading more when it is
     * found. Curl main engine adds noticable delays between
     * invokactions of "doing" function, so it is desirable to get
     * things done in as little calls to "doing" function, as possible,
     * but without busy looping on socket that is not yet ready.
     *
     * For many servers first read returns exacly header, because it is
     * natural thing to do on server side, although we can't rely on it.
     * This is the reason why it does not worth to optimize search by
     * keeping track of old {amount} value and searching only in bytes
     * just read.
     */
    gemini->block.lf = memchr(gemini->block.memory, '\n',
                              gemini->block.amount);
    if(!gemini->block.lf && gemini->block.done) {
      /* Distinguish between header being too big and response lacking LF */
      if(more) {
        failf(data, "Response did not contain LF character");
      }
      else {
        failf(data, "Server returned header too big");
      }

      return CURLE_WEIRD_SERVER_REPLY;
    }

    if(gemini->block.lf)
      gemini->block.done = TRUE;

    if(!gemini->block.done)
      return CURLE_OK;
  }

  return gemini_doing_finish(conn, done);
}

static CURLcode gemini_doing_finish(struct connectdata *conn, bool *done)
{
  CURLcode result;
  struct GEMINI *gemini;
  char *block;
  struct Curl_easy *data;
  size_t amount;
  size_t hsize;
  char status;
  char *lf;

  data = conn->data;
  gemini = data->req.p.gemini;
  block = gemini->block.memory;
  amount = gemini->block.amount;
  lf = gemini->block.lf;

  if(!amount)
    return CURLE_GOT_NOTHING;

  /* Two digit status, space, empty meta string and \r\n at least. */
  if(amount < 5) {
    failf(data, "Response is too short");
    return CURLE_WEIRD_SERVER_REPLY;
  }

  if(block[2] != ' ' || !isdigit(block[0]) || !isdigit(block[1])) {
    failf(data, "First 3 bytes of response violate specification");
    return CURLE_WEIRD_SERVER_REPLY;
  }

  /* We already checked that first byte is digit, so {lf} can't point to
   * first byte of buffer and {cr} can't undresultun buffer.
   */
  if(*(lf - 1) != '\r') {
    failf(data, "Next-to-last character in response header is not CR");
    return CURLE_WEIRD_SERVER_REPLY;
  }

  hsize = lf - block + 1;
  result = Curl_client_write(conn, CLIENTWRITE_HEADER, block, hsize);
  if(result)
    return result;

  status = block[0];
  if(status != '2') { /* TODO: handle redirects */
    *done = TRUE;
    return CURLE_OK;
  }

  result = Curl_client_write(conn, CLIENTWRITE_BODY, block + hsize,
                          amount - hsize);
  if(result)
    return result;

  *done = TRUE;
  Curl_setup_transfer(data, FIRSTSOCKET, -1, FALSE, -1);
  return CURLE_OK;
}

static int gemini_doing_getsock(struct connectdata *conn, curl_socket_t *socks)
{
  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_WRITESOCK(0);
}

static CURLcode gemini_disconnect(struct connectdata *conn, bool _ignored)
{
  struct GEMINI *gemini;

  /* Curl engine will free GEMINI structure itself */
  gemini = conn->data->req.p.gemini;
  free(gemini->request.memory);

  return CURLE_OK;
}

const struct Curl_handler Curl_handler_gemini = {
  "GEMINI",                             /* scheme */
  gemini_setup_connection,              /* setup_connection */
  gemini_do_it,                         /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  gemini_connecting,                    /* connect_it */
  gemini_connecting,                    /* connecting */
  gemini_doing,                         /* doing */
  Curl_ssl_getsock,                     /* proto_getsock */
  gemini_doing_getsock,                 /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  gemini_disconnect,                    /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  PORT_GEMINI,                          /* defport */
  CURLPROTO_GEMINI,                     /* protocol */
  CURLPROTO_GEMINI,                     /* family */
  PROTOPT_SSL                           /* flags */
};

#endif /*CURL_DISABLE_GEMINI*/
