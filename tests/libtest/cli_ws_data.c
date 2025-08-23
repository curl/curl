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

#include "testtrace.h"
#include "memdebug.h"

#ifndef CURL_DISABLE_WEBSOCKETS

static CURLcode
test_ws_data_m2_check_recv(const struct curl_ws_frame *frame,
                           size_t r_offset, size_t nread,
                           size_t exp_len)
{
  if(!frame)
    return CURLE_OK;

  if(frame->flags & CURLWS_CLOSE) {
    curl_mfprintf(stderr, "recv_data: unexpected CLOSE frame from server, "
                  "got %zu bytes, offset=%zu, rflags %x\n",
                  nread, r_offset, frame->flags);
    return CURLE_RECV_ERROR;
  }
  if(!r_offset && !(frame->flags & CURLWS_BINARY)) {
    curl_mfprintf(stderr, "recv_data: wrong frame, got %zu bytes, offset=%zu, "
                  "rflags %x\n",
                  nread, r_offset, frame->flags);
    return CURLE_RECV_ERROR;
  }
  if(frame->offset != (curl_off_t)r_offset) {
    curl_mfprintf(stderr, "recv_data: frame offset, expected %zu, "
                  "got %" CURL_FORMAT_CURL_OFF_T "\n",
                  r_offset, frame->offset);
    return CURLE_RECV_ERROR;
  }
  if(frame->bytesleft != (curl_off_t)(exp_len - r_offset - nread)) {
    curl_mfprintf(stderr, "recv_data: frame bytesleft, "
                  "expected %" CURL_FORMAT_CURL_OFF_T ", "
                  "got %" CURL_FORMAT_CURL_OFF_T "\n",
                  (curl_off_t)(exp_len - r_offset - nread), frame->bytesleft);
    return CURLE_RECV_ERROR;
  }
  if(r_offset + nread > exp_len) {
    curl_mfprintf(stderr, "recv_data: data length, expected %zu, now at %zu\n",
                  exp_len, r_offset + nread);
    return CURLE_RECV_ERROR;
  }
  return CURLE_OK;
}

/* WebSocket Mode 2: CONNECT_ONLY 2, curl_ws_send()/curl_ws_recv() */
static CURLcode test_ws_data_m2_echo(const char *url,
                                     size_t count,
                                     size_t plen_min,
                                     size_t plen_max)
{
  CURL *curl = NULL;
  CURLcode r = CURLE_OK;
  const struct curl_ws_frame *frame;
  size_t len;
  char *send_buf = NULL, *recv_buf = NULL;
  size_t i, scount = count, rcount = count;
  int rblock, sblock;

  send_buf = calloc(1, plen_max + 1);
  recv_buf = calloc(1, plen_max + 1);
  if(!send_buf || !recv_buf) {
    r = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  for(i = 0; i < plen_max; ++i) {
    send_buf[i] = (char)('0' + ((int)i % 10));
  }

  curl = curl_easy_init();
  if(!curl) {
    r = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);

  /* use the callback style */
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "ws-data");
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */
  r = curl_easy_perform(curl);
  curl_mfprintf(stderr, "curl_easy_perform() returned %u\n", (int)r);
  if(r != CURLE_OK)
    goto out;

  for(len = plen_min; len <= plen_max; ++len) {
    size_t nwritten, nread, slen = len, rlen = len;
    char *sbuf = send_buf, *rbuf = recv_buf;

    memset(recv_buf, 0, plen_max);
    while(slen || rlen || scount || rcount) {
      sblock = rblock = 1;
      if(slen) {
        r = curl_ws_send(curl, sbuf, slen, &nwritten, 0, CURLWS_BINARY);
        sblock = (r == CURLE_AGAIN);
        if(!r || (r == CURLE_AGAIN)) {
          curl_mfprintf(stderr, "curl_ws_send(len=%zu) -> %d, "
                        "%zu (%" CURL_FORMAT_CURL_OFF_T "/%zu)\n",
                        slen, r, nwritten, (curl_off_t)(len - slen), len);
          sbuf += nwritten;
          slen -= nwritten;
        }
        else
          goto out;
      }
      if(!slen && scount) { /* go again? */
        scount--;
        sbuf = send_buf;
        slen = len;
      }

      if(rlen) {
        size_t max_recv = (64 * 1024);
        r = curl_ws_recv(curl, rbuf, (rlen > max_recv) ? max_recv : rlen,
                         &nread, &frame);
        if(!r || (r == CURLE_AGAIN)) {
          rblock = (r == CURLE_AGAIN);
          curl_mfprintf(stderr, "curl_ws_recv(len=%zu) -> %d, %zu (%ld/%zu) "
                        "\n", rlen, r, nread, (long)(len - rlen), len);
          if(!r) {
            r = test_ws_data_m2_check_recv(frame, len - rlen, nread, len);
            if(r)
              goto out;
          }
          rbuf += nread;
          rlen -= nread;
        }
        else
          goto out;
      }
      if(!rlen && rcount) { /* go again? */
        rcount--;
        rbuf = recv_buf;
        rlen = len;
      }

      if(rblock && sblock) {
        curl_mfprintf(stderr, "EAGAIN, sleep, try again\n");
        curlx_wait_ms(1);
      }
    }

    if(memcmp(send_buf, recv_buf, len)) {
      curl_mfprintf(stderr, "recv_data: data differs\n");
      debug_dump("", "expected:", stderr,
                 (const unsigned char *)send_buf, len, FALSE);
      debug_dump("", "received:", stderr,
                 (const unsigned char *)recv_buf, len, FALSE);
      r = CURLE_RECV_ERROR;
      goto out;
    }
  }

out:
  if(curl) {
    if(!r)
      ws_close(curl);
    curl_easy_cleanup(curl);
  }
  free(send_buf);
  free(recv_buf);
  return r;
}

struct test_ws_m1_ctx {
  CURL *easy;
  char *send_buf;
  char *recv_buf;
  size_t send_len, nsent;
  size_t recv_len, nrcvd;
  int nframes;
  int read_calls;
  int write_calls;
  int frames_read;
  int frames_written;
  BIT(frame_reading);
};

static size_t test_ws_data_m1_read(char *buf, size_t nitems, size_t buflen,
                                   void *userdata)
{
  struct test_ws_m1_ctx *ctx = userdata;
  size_t len = nitems * buflen;
  size_t left = ctx->send_len - ctx->nsent;

  ctx->read_calls++;

  if(ctx->frames_read >= ctx->nframes)
    goto out;

  if(!ctx->frame_reading) {
    curl_ws_start_frame(ctx->easy, CURLWS_BINARY, ctx->send_len);
    ctx->frame_reading = TRUE;
  }

  if(ctx->frame_reading) {
    bool complete;
    if(left > len)
      left = len;
    memcpy(buf, ctx->send_buf + ctx->nsent, left);
    ctx->nsent += left;
    complete = (ctx->send_len == ctx->nsent);
    curl_mfprintf(stderr, "m1_read(len=%zu, call #%d, frame #%d%s) -> %zu\n",
                  len, ctx->read_calls, ctx->frames_read,
                  complete ? " complete" : "", left);
    if(complete) {
      ++ctx->frames_read;
      ctx->frame_reading = FALSE;
      ctx->nsent = 0;
    }
    return left;
  }
out:
  curl_mfprintf(stderr, "m1_read(len=%zu, call #%d) -> EOS\n",
                len, ctx->read_calls);
  return 0;
}

static size_t test_ws_data_m1_write(char *buf, size_t nitems, size_t buflen,
                                    void *userdata)
{
  struct test_ws_m1_ctx *ctx = userdata;
  size_t len = nitems * buflen;
  bool complete;

  ctx->write_calls++;
  if(len > (ctx->recv_len - ctx->nrcvd)) {
    curl_mfprintf(stderr, "m1_write(len=%zu, call #%d) -> ERROR\n",
                  len, ctx->write_calls);
    return CURL_WRITEFUNC_ERROR;
  }
  memcpy(ctx->recv_buf + ctx->nrcvd, buf, len);
  ctx->nrcvd += len;
  complete = (ctx->recv_len == ctx->nrcvd);

  if(memcmp(ctx->send_buf, ctx->recv_buf, ctx->nrcvd)) {
    curl_mfprintf(stderr, "m1_write(len=%zu, call #%d, frame #%d) -> "
                  "data differs\n",
                  len, ctx->write_calls, ctx->frames_written);
    debug_dump("", "expected:", stderr,
               (unsigned char *)ctx->send_buf, ctx->nrcvd, 0);
    debug_dump("", "received:", stderr,
               (unsigned char *)ctx->recv_buf, ctx->nrcvd, 0);
    return CURL_WRITEFUNC_ERROR;
  }

  curl_mfprintf(stderr, "m1_write(len=%zu, call #%d, frame #%d%s) -> %zu\n",
                len, ctx->write_calls, ctx->frames_written,
                complete ? " complete" : "", len);
  if(complete) {
    ++ctx->frames_written;
    ctx->nrcvd = 0;
  }
  return len;
}

/* WebSocket Mode 1: multi handle, READ/WRITEFUNCTION use */
static CURLcode test_ws_data_m1_echo(const char *url,
                                     size_t plen_min,
                                     size_t plen_max)
{
  CURLM *multi = NULL;
  CURLcode r = CURLE_OK;
  struct test_ws_m1_ctx m1_ctx;
  size_t i, len;

  curl_mfprintf(stderr, "test_ws_data_m1_echo(min=%zu, max=%zu)\n",
                plen_min, plen_max);
  memset(&m1_ctx, 0, sizeof(m1_ctx));
  m1_ctx.send_buf = calloc(1, plen_max + 1);
  m1_ctx.recv_buf = calloc(1, plen_max + 1);
  if(!m1_ctx.send_buf || !m1_ctx.recv_buf) {
    r = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  for(i = 0; i < plen_max; ++i) {
    m1_ctx.send_buf[i] = (char)('0' + ((int)i % 10));
  }

  multi = curl_multi_init();
  if(!multi) {
    r = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  m1_ctx.easy = curl_easy_init();
  if(!m1_ctx.easy) {
    r = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  for(len = plen_min; len <= plen_max; ++len) {
    /* init what we want to send and expect to receive */
    curl_mfprintf(stderr, "m1_echo, iter len=%zu\n", len);

    m1_ctx.send_len = len;
    m1_ctx.nsent = 0;
    m1_ctx.recv_len = len;
    m1_ctx.nrcvd = 0;
    m1_ctx.nframes = 2;
    m1_ctx.read_calls = 0;
    m1_ctx.write_calls = 0;
    m1_ctx.frames_read = 0;
    m1_ctx.frames_written = 0;
    memset(m1_ctx.recv_buf, 0, plen_max);
    curl_easy_pause(m1_ctx.easy, CURLPAUSE_CONT);

    curl_easy_reset(m1_ctx.easy);
    curl_easy_setopt(m1_ctx.easy, CURLOPT_URL, url);
    /* use the callback style */
    curl_easy_setopt(m1_ctx.easy, CURLOPT_USERAGENT, "ws-data");
    curl_easy_setopt(m1_ctx.easy, CURLOPT_VERBOSE, 1L);
    /* we want to send */
    curl_easy_setopt(m1_ctx.easy, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(m1_ctx.easy, CURLOPT_READFUNCTION, test_ws_data_m1_read);
    curl_easy_setopt(m1_ctx.easy, CURLOPT_READDATA, &m1_ctx);
    curl_easy_setopt(m1_ctx.easy, CURLOPT_WRITEFUNCTION,
                     test_ws_data_m1_write);
    curl_easy_setopt(m1_ctx.easy, CURLOPT_WRITEDATA, &m1_ctx);

    curl_multi_add_handle(multi, m1_ctx.easy);

    while(1) {
      int still_running; /* keep number of running handles */
      CURLMcode mc = curl_multi_perform(multi, &still_running);

      if(!still_running || (m1_ctx.frames_written >= m1_ctx.nframes)) {
        /* got the full echo back or failed */
        break;
      }

      if(!mc && still_running) {
        mc = curl_multi_poll(multi, NULL, 0, 1, NULL);
      }
      if(mc) {
        r = CURLE_RECV_ERROR;
        goto out;
      }

    }

    curl_multi_remove_handle(multi, m1_ctx.easy);

    /* check results */
    if(m1_ctx.frames_read < m1_ctx.nframes) {
      curl_mfprintf(stderr, "m1_echo, sent only %d/%d frames\n",
                    m1_ctx.frames_read, m1_ctx.nframes);
      r = CURLE_SEND_ERROR;
      goto out;
    }
    if(m1_ctx.frames_written < m1_ctx.frames_read) {
      curl_mfprintf(stderr, "m1_echo, received only %d/%d frames\n",
                    m1_ctx.frames_written, m1_ctx.frames_read);
      r = CURLE_RECV_ERROR;
      goto out;
    }
  }

out:
  if(multi)
    curl_multi_cleanup(multi);
  if(m1_ctx.easy) {
    curl_easy_cleanup(m1_ctx.easy);
  }
  free(m1_ctx.send_buf);
  free(m1_ctx.recv_buf);
  return r;
}


static void test_ws_data_usage(const char *msg)
{
  if(msg)
    curl_mfprintf(stderr, "%s\n", msg);
  curl_mfprintf(stderr,
    "usage: [options] url\n"
    "  -m number  minimum frame size\n"
    "  -M number  maximum frame size\n"
  );
}

#endif

static CURLcode test_cli_ws_data(const char *URL)
{
#ifndef CURL_DISABLE_WEBSOCKETS
  CURLcode res = CURLE_OK;
  const char *url;
  size_t plen_min = 0, plen_max = 0, count = 1;
  int ch, model = 2;

  (void)URL;

  while((ch = cgetopt(test_argc, test_argv, "12c:hm:M:")) != -1) {
    switch(ch) {
    case '1':
      model = 1;
      break;
    case '2':
      model = 2;
      break;
    case 'h':
      test_ws_data_usage(NULL);
      res = CURLE_BAD_FUNCTION_ARGUMENT;
      goto cleanup;
    case 'c':
      count = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'm':
      plen_min = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'M':
      plen_max = (size_t)strtol(coptarg, NULL, 10);
      break;
    default:
      test_ws_data_usage("invalid option");
      res = CURLE_BAD_FUNCTION_ARGUMENT;
      goto cleanup;
    }
  }
  test_argc -= coptind;
  test_argv += coptind;

  if(!plen_max)
    plen_max = plen_min;

  if(plen_max < plen_min) {
    curl_mfprintf(stderr, "maxlen must be >= minlen, got %zu-%zu\n",
                  plen_min, plen_max);
    res = CURLE_BAD_FUNCTION_ARGUMENT;
    goto cleanup;
  }

  if(test_argc != 1) {
    test_ws_data_usage(NULL);
    res = CURLE_BAD_FUNCTION_ARGUMENT;
    goto cleanup;
  }
  url = test_argv[0];

  curl_global_init(CURL_GLOBAL_ALL);

  if(model == 1)
    res = test_ws_data_m1_echo(url, plen_min, plen_max);
  else
    res = test_ws_data_m2_echo(url, count, plen_min, plen_max);

cleanup:
  curl_global_cleanup();
  return res;

#else /* !CURL_DISABLE_WEBSOCKETS */
  (void)URL;
  curl_mfprintf(stderr, "WebSockets not enabled in libcurl\n");
  return (CURLcode)1;
#endif /* CURL_DISABLE_WEBSOCKETS */
}
