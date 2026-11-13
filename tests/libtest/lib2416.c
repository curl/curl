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
#include "first.h"

#if defined(HAVE_SOCKETPAIR) && defined(AF_UNIX)

#define T2416_VALUELEN 4000
#define T2416_FIELDS   40

struct t2416_ctx {
  curl_socket_t sock[2];
  unsigned char resp[T2416_VALUELEN + 256];
  size_t resplen;
};

static size_t t2416_frame_head(unsigned char *p, size_t len,
                               unsigned char type, unsigned char flags,
                               unsigned char stream_id)
{
  p[0] = (unsigned char)((len >> 16) & 0xff);
  p[1] = (unsigned char)((len >> 8) & 0xff);
  p[2] = (unsigned char)(len & 0xff);
  p[3] = type;
  p[4] = flags;
  p[5] = 0;
  p[6] = 0;
  p[7] = 0;
  p[8] = stream_id;
  return 9;
}

/* An HTTP/2 response with 40 header fields and 40 trailer fields of 4000
   bytes each. The first field enters the HPACK dynamic table, all others
   refer to it, so that the whole response is small on the wire. */
static void t2416_response(struct t2416_ctx *ctx)
{
  unsigned char *p = ctx->resp;
  size_t hlen = 1 + 5 + 3 + T2416_VALUELEN + (T2416_FIELDS - 1);

  p += t2416_frame_head(p, 0, 0x04, 0x00, 0); /* SETTINGS */

  p += t2416_frame_head(p, hlen, 0x01, 0x04, 1); /* HEADERS, END_HEADERS */
  *p++ = 0x88; /* :status: 200 */
  *p++ = 0x40; /* literal field with incremental indexing, new name */
  *p++ = 0x03;
  *p++ = 'x';
  *p++ = '-';
  *p++ = 't';
  *p++ = 0x7f; /* value length as 127 + the rest in 7 bit groups */
  *p++ = (unsigned char)(((T2416_VALUELEN - 127) & 0x7f) | 0x80);
  *p++ = (unsigned char)((T2416_VALUELEN - 127) >> 7);
  memset(p, 'a', T2416_VALUELEN);
  p += T2416_VALUELEN;
  memset(p, 0xbe, T2416_FIELDS - 1); /* first dynamic table entry */
  p += T2416_FIELDS - 1;

  p += t2416_frame_head(p, 2, 0x00, 0x00, 1); /* DATA */
  *p++ = 'o';
  *p++ = 'k';

  /* HEADERS, END_HEADERS | END_STREAM */
  p += t2416_frame_head(p, T2416_FIELDS, 0x01, 0x05, 1);
  memset(p, 0xbe, T2416_FIELDS);
  p += T2416_FIELDS;

  ctx->resplen = (size_t)(p - ctx->resp);
}

static curl_socket_t t2416_opensocket(void *clientp, curlsocktype purpose,
                                      struct curl_sockaddr *address)
{
  struct t2416_ctx *ctx = clientp;
  (void)purpose;
  (void)address;
  return ctx->sock[0];
}

static int t2416_sockopt(void *clientp, curl_socket_t curlfd,
                         curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  (void)purpose;
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

static int t2416_closesocket(void *clientp, curl_socket_t item)
{
  (void)clientp;
  (void)item;
  return 0;
}

/* the connection is set up, the request is not yet sent: queue the
   response for it */
static int t2416_prereq(void *clientp, char *conn_primary_ip,
                        char *conn_local_ip, int conn_primary_port,
                        int conn_local_port)
{
  struct t2416_ctx *ctx = clientp;
  (void)conn_primary_ip;
  (void)conn_local_ip;
  (void)conn_primary_port;
  (void)conn_local_port;
  if(swrite(ctx->sock[1], ctx->resp, ctx->resplen) != (ssize_t)ctx->resplen)
    return CURL_PREREQFUNC_ABORT;
  return CURL_PREREQFUNC_OK;
}

static CURLcode test_lib2416(const char *URL)
{
  static struct t2416_ctx ctx;
  CURL *curl = NULL;
  CURLcode result = TEST_ERR_MAJOR_BAD;

  if(!strcmp("check", URL))
    return CURLE_OK; /* no output makes it not skipped */

  ctx.sock[0] = CURL_SOCKET_BAD;
  ctx.sock[1] = CURL_SOCKET_BAD;
  t2416_response(&ctx);

  global_init(CURL_GLOBAL_ALL);

  if(CURL_SOCKETPAIR(AF_UNIX, SOCK_STREAM, 0, ctx.sock)) {
    curl_mfprintf(stderr, "socketpair() failed\n");
    goto test_cleanup;
  }

  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HTTP_VERSION,
              (long)CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, t2416_opensocket);
  easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &ctx);
  easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, t2416_sockopt);
  easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, t2416_closesocket);
  easy_setopt(curl, CURLOPT_PREREQFUNCTION, t2416_prereq);
  easy_setopt(curl, CURLOPT_PREREQDATA, &ctx);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* the trailers make the response exceed the header size limit */
  result = curl_easy_perform(curl);

test_cleanup:
  curl_easy_cleanup(curl);
  if(ctx.sock[0] != CURL_SOCKET_BAD)
    sclose(ctx.sock[0]);
  if(ctx.sock[1] != CURL_SOCKET_BAD)
    sclose(ctx.sock[1]);
  curl_global_cleanup();

  return result;
}

#else

static CURLcode test_lib2416(const char *URL)
{
  (void)URL;
  curl_mprintf("socketpair() with AF_UNIX is needed\n");
  return CURLE_OK;
}

#endif
