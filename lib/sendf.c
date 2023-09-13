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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif

#include <curl/curl.h>

#include "urldata.h"
#include "sendf.h"
#include "cfilters.h"
#include "connect.h"
#include "vtls/vtls.h"
#include "vssh/ssh.h"
#include "easyif.h"
#include "multiif.h"
#include "strerror.h"
#include "select.h"
#include "strdup.h"
#include "http2.h"
#include "headers.h"
#include "ws.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Curl_nwrite() is an internal write function that sends data to the
 * server. Works with a socket index for the connection.
 *
 * If the write would block (CURLE_AGAIN), it returns CURLE_OK and
 * (*nwritten == 0). Otherwise we return regular CURLcode value.
 */
CURLcode Curl_nwrite(struct Curl_easy *data,
                     int sockindex,
                     const void *buf,
                     size_t blen,
                     ssize_t *pnwritten)
{
  ssize_t nwritten;
  CURLcode result = CURLE_OK;
  struct connectdata *conn;

  DEBUGASSERT(sockindex >= 0 && sockindex < 2);
  DEBUGASSERT(pnwritten);
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  conn = data->conn;
#ifdef CURLDEBUG
  {
    /* Allow debug builds to override this logic to force short sends
    */
    char *p = getenv("CURL_SMALLSENDS");
    if(p) {
      size_t altsize = (size_t)strtoul(p, NULL, 10);
      if(altsize)
        blen = CURLMIN(blen, altsize);
    }
  }
#endif
  nwritten = conn->send[sockindex](data, sockindex, buf, blen, &result);
  if(result == CURLE_AGAIN) {
    nwritten = 0;
    result = CURLE_OK;
  }
  else if(result) {
    nwritten = -1; /* make sure */
  }
  else {
    DEBUGASSERT(nwritten >= 0);
  }

  *pnwritten = nwritten;
  return result;
}

/*
 * Curl_write() is an internal write function that sends data to the
 * server. Works with plain sockets, SCP, SSL or kerberos.
 *
 * If the write would block (CURLE_AGAIN), we return CURLE_OK and
 * (*written == 0). Otherwise we return regular CURLcode value.
 */
CURLcode Curl_write(struct Curl_easy *data,
                    curl_socket_t sockfd,
                    const void *mem,
                    size_t len,
                    ssize_t *written)
{
  struct connectdata *conn;
  int num;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  conn = data->conn;
  num = (sockfd != CURL_SOCKET_BAD && sockfd == conn->sock[SECONDARYSOCKET]);
  return Curl_nwrite(data, num, mem, len, written);
}

/*
 * Internal read-from-socket function. This is meant to deal with plain
 * sockets, SSL sockets and kerberos sockets.
 *
 * Returns a regular CURLcode value.
 */
CURLcode Curl_read(struct Curl_easy *data,   /* transfer */
                   curl_socket_t sockfd,     /* read from this socket */
                   char *buf,                /* store read data here */
                   size_t sizerequested,     /* max amount to read */
                   ssize_t *n)               /* amount bytes read */
{
  CURLcode result = CURLE_RECV_ERROR;
  ssize_t nread = 0;
  size_t bytesfromsocket = 0;
  char *buffertofill = NULL;
  struct connectdata *conn = data->conn;

  /* Set 'num' to 0 or 1, depending on which socket that has been sent here.
     If it is the second socket, we set num to 1. Otherwise to 0. This lets
     us use the correct ssl handle. */
  int num = (sockfd == conn->sock[SECONDARYSOCKET]);

  *n = 0; /* reset amount to zero */

  bytesfromsocket = CURLMIN(sizerequested, (size_t)data->set.buffer_size);
  buffertofill = buf;

  nread = conn->recv[num](data, num, buffertofill, bytesfromsocket, &result);
  if(nread < 0)
    goto out;

  *n += nread;
  result = CURLE_OK;
out:
  return result;
}
