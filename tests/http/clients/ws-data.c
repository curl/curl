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
 * Websockets data echos
 * </DESC>
 */

/* curl stuff */
#include "curl_setup.h"
#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* somewhat unix-specific */
#include <sys/time.h>
#include <unistd.h>

#ifdef USE_WEBSOCKETS

static
void dump(const char *text, unsigned char *ptr, size_t size,
          char nohex)
{
  size_t i;
  size_t c;

  unsigned int width = 0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stderr, "%s, %lu bytes (0x%lx)\n",
          text, (unsigned long)size, (unsigned long)size);

  for(i = 0; i<size; i += width) {

    fprintf(stderr, "%4.4lx: ", (unsigned long)i);

    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i + c < size)
          fprintf(stderr, "%02x ", ptr[i + c]);
        else
          fputs("   ", stderr);
    }

    for(c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      fprintf(stderr, "%c",
              (ptr[i + c] >= 0x20) && (ptr[i + c]<0x80)?ptr[i + c]:'.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stderr); /* newline */
  }
}

static CURLcode send_binary(CURL *curl, char *buf, size_t buflen)
{
  size_t nwritten;
  CURLcode result =
    curl_ws_send(curl, buf, buflen, &nwritten, 0, CURLWS_BINARY);
  fprintf(stderr, "ws: send_binary(len=%ld) -> %d, %ld\n",
          (long)buflen, result, (long)nwritten);
  return result;
}

static CURLcode recv_binary(CURL *curl, char *exp_data, size_t exp_len)
{
  struct curl_ws_frame *frame;
  char recvbuf[256];
  size_t r_offset, nread;
  CURLcode result;

  fprintf(stderr, "recv_binary: expected payload %ld bytes\n", (long)exp_len);
  r_offset = 0;
  while(1) {
    result = curl_ws_recv(curl, recvbuf, sizeof(recvbuf), &nread, &frame);
    if(result == CURLE_AGAIN) {
      fprintf(stderr, "EAGAIN, sleep, try again\n");
      usleep(100*1000);
      continue;
    }
    fprintf(stderr, "ws: curl_ws_recv(offset=%ld, len=%ld) -> %d, %ld\n",
            (long)r_offset, (long)sizeof(recvbuf), result, (long)nread);
    if(result) {
      return result;
    }
    if(!(frame->flags & CURLWS_BINARY)) {
      fprintf(stderr, "recv_data: wrong frame, got %ld bytes rflags %x\n",
              (long)nread, frame->flags);
      return CURLE_RECV_ERROR;
    }
    if(frame->offset != (curl_off_t)r_offset) {
      fprintf(stderr, "recv_data: frame offset, expected %ld, got %ld\n",
              (long)r_offset, (long)frame->offset);
      return CURLE_RECV_ERROR;
    }
    if(frame->bytesleft != (curl_off_t)(exp_len - r_offset - nread)) {
      fprintf(stderr, "recv_data: frame bytesleft, expected %ld, got %ld\n",
              (long)(exp_len - r_offset - nread), (long)frame->bytesleft);
      return CURLE_RECV_ERROR;
    }
    if(r_offset + nread > exp_len) {
      fprintf(stderr, "recv_data: data length, expected %ld, now at %ld\n",
              (long)exp_len, (long)(r_offset + nread));
      return CURLE_RECV_ERROR;
    }
    if(memcmp(exp_data + r_offset, recvbuf, nread)) {
      fprintf(stderr, "recv_data: data differs, offset=%ld, len=%ld\n",
              (long)r_offset, (long)nread);
      dump("expected:", (unsigned char *)exp_data + r_offset, nread, 0);
      dump("received:", (unsigned char *)recvbuf, nread, 0);
      return CURLE_RECV_ERROR;
    }
    r_offset += nread;
    if(r_offset >= exp_len) {
      fprintf(stderr, "recv_data: frame complete\n");
      break;
    }
  }
  return CURLE_OK;
}

/* just close the connection */
static void websocket_close(CURL *curl)
{
  size_t sent;
  CURLcode result =
    curl_ws_send(curl, "", 0, &sent, 0, CURLWS_CLOSE);
  fprintf(stderr,
          "ws: curl_ws_send returned %u, sent %u\n", (int)result, (int)sent);
}

static CURLcode data_echo(CURL *curl, size_t plen_min, size_t plen_max)
{
  CURLcode res;
  size_t len;
  char *send_buf;
  size_t i;

  send_buf = calloc(1, plen_max);
  if(!send_buf)
    return CURLE_OUT_OF_MEMORY;
  for(i = 0; i < plen_max; ++i) {
    send_buf[i] = (char)('0' + ((int)i % 10));
  }

  for(len = plen_min; len <= plen_max; ++len) {
    res = send_binary(curl, send_buf, len);
    if(res)
      goto out;
    res = recv_binary(curl, send_buf, len);
    if(res) {
      fprintf(stderr, "recv_data(len=%ld) -> %d\n", (long)len, res);
      goto out;
    }
  }

out:
  if(!res)
    websocket_close(curl);
  free(send_buf);
  return res;
}

#endif

int main(int argc, char *argv[])
{
#ifdef USE_WEBSOCKETS
  CURL *curl;
  CURLcode res = CURLE_OK;
  const char *url;
  curl_off_t l1, l2;
  size_t plen_min, plen_max;


  if(argc != 4) {
    fprintf(stderr, "usage: ws-data url minlen maxlen\n");
    return 2;
  }
  url = argv[1];
  l1 = strtol(argv[2], NULL, 10);
  if(l1 < 0) {
    fprintf(stderr, "minlen must be >= 0, got %ld\n", (long)l1);
    return 2;
  }
  l2 = strtol(argv[3], NULL, 10);
  if(l2 < 0) {
    fprintf(stderr, "maxlen must be >= 0, got %ld\n", (long)l2);
    return 2;
  }
  plen_min = l1;
  plen_max = l2;
  if(plen_max < plen_min) {
    fprintf(stderr, "maxlen must be >= minlen, got %ld-%ld\n",
            (long)plen_min, (long)plen_max);
    return 2;
  }

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* use the callback style */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ws-data");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = curl_easy_perform(curl);
    fprintf(stderr, "curl_easy_perform() returned %u\n", (int)res);
    if(res == CURLE_OK)
      res = data_echo(curl, plen_min, plen_max);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return (int)res;

#else /* USE_WEBSOCKETS */
  (void)argc;
  (void)argv;
  fprintf(stderr, "websockets not enabled in libcurl\n");
  return 1;
#endif /* !USE_WEBSOCKETS */
}
