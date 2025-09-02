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
/* <DESC>
 * WebSocket download-only using write callback
 * </DESC>
 */
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

static size_t writecb(char *b, size_t size, size_t nitems, void *p)
{
  CURL *easy = p;
  size_t i;
  unsigned int blen = (unsigned int)(nitems * size);
  const struct curl_ws_frame *frame = curl_ws_meta(easy);
  fprintf(stderr, "Type: %s\n", frame->flags & CURLWS_BINARY ?
          "binary" : "text");
  if(frame->flags & CURLWS_BINARY) {
    fprintf(stderr, "Bytes: %u", blen);
    for(i = 0; i < nitems; i++)
      fprintf(stderr, "%02x ", (unsigned char)b[i]);
    fprintf(stderr, "\n");
  }
  else
    fprintf(stderr, "Text: %.*s\n", (int)blen, b);
  return nitems;
}

struct read_ctx {
  CURL *easy;
  char buf[1024];
  size_t blen;
  size_t nsent;
};

static size_t readcb(char *buf, size_t nitems, size_t buflen, void *p)
{
  struct read_ctx *ctx = p;
  size_t len = nitems * buflen;
  size_t left = ctx->blen - ctx->nsent;
  CURLcode result;

  if(!ctx->nsent) {
    /* On first call, set the FRAME information to be used (it defaults
     * to CURLWS_BINARY otherwise). */
    result = curl_ws_start_frame(ctx->easy, CURLWS_TEXT,
                                 (curl_off_t)ctx->blen);
    if(result) {
      fprintf(stderr, "error starting frame: %d\n", result);
      return CURL_READFUNC_ABORT;
    }
  }
  fprintf(stderr, "read(len=%d, left=%d)\n", (int)len, (int)left);
  if(left) {
    if(left < len)
      len = left;
    memcpy(buf, ctx->buf + ctx->nsent, len);
    ctx->nsent += len;
    return len;
  }
  return 0;
}

int main(int argc, const char *argv[])
{
  CURL *easy;
  struct read_ctx rctx;
  CURLcode res;
  const char *payload = "Hello, friend!";

  memset(&rctx, 0, sizeof(rctx));

  easy = curl_easy_init();
  if(!easy)
    return 1;

  if(argc == 2)
    curl_easy_setopt(easy, CURLOPT_URL, argv[1]);
  else
    curl_easy_setopt(easy, CURLOPT_URL, "wss://example.com");

  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, writecb);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, easy);
  curl_easy_setopt(easy, CURLOPT_READFUNCTION, readcb);
  /* tell curl that we want to send the payload */
  rctx.easy = easy;
  rctx.blen = strlen(payload);
  memcpy(rctx.buf, payload, rctx.blen);
  curl_easy_setopt(easy, CURLOPT_READDATA, &rctx);
  curl_easy_setopt(easy, CURLOPT_UPLOAD, 1L);


  /* Perform the request, res gets the return code */
  res = curl_easy_perform(easy);
  /* Check for errors */
  if(res != CURLE_OK)
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));

  /* always cleanup */
  curl_easy_cleanup(easy);
  return 0;
}
