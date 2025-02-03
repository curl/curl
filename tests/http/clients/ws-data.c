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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * WebSockets data echos
 * </DESC>
 */
/* fetch stuff */
#include <fetch/fetch.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(FETCH_DISABLE_WEBSOCKETS) && !defined(_MSC_VER)

#ifndef _MSC_VER
/* somewhat Unix-specific */
#include <unistd.h>  /* getopt() */
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/time.h>
#endif


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

  for(i = 0; i < size; i += width) {

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
              (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.');
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

static FETCHcode check_recv(const struct fetch_ws_frame *frame,
                           size_t r_offset, size_t nread, size_t exp_len)
{
  if(!frame)
    return FETCHE_OK;

  if(frame->flags & FETCHWS_CLOSE) {
    fprintf(stderr, "recv_data: unexpected CLOSE frame from server, "
            "got %ld bytes, offset=%ld, rflags %x\n",
            (long)nread, (long)r_offset, frame->flags);
    return FETCHE_RECV_ERROR;
  }
  if(!r_offset && !(frame->flags & FETCHWS_BINARY)) {
    fprintf(stderr, "recv_data: wrong frame, got %ld bytes, offset=%ld, "
            "rflags %x\n",
            (long)nread, (long)r_offset, frame->flags);
    return FETCHE_RECV_ERROR;
  }
  if(frame->offset != (fetch_off_t)r_offset) {
    fprintf(stderr, "recv_data: frame offset, expected %ld, got %ld\n",
            (long)r_offset, (long)frame->offset);
    return FETCHE_RECV_ERROR;
  }
  if(frame->bytesleft != (fetch_off_t)(exp_len - r_offset - nread)) {
    fprintf(stderr, "recv_data: frame bytesleft, expected %ld, got %ld\n",
            (long)(exp_len - r_offset - nread), (long)frame->bytesleft);
    return FETCHE_RECV_ERROR;
  }
  if(r_offset + nread > exp_len) {
    fprintf(stderr, "recv_data: data length, expected %ld, now at %ld\n",
            (long)exp_len, (long)(r_offset + nread));
    return FETCHE_RECV_ERROR;
  }
  return FETCHE_OK;
}

#if defined(__TANDEM)
# include <cextdecs.h(PROCESS_DELAY_)>
#endif

/* just close the connection */
static void websocket_close(FETCH *fetch)
{
  size_t sent;
  FETCHcode result =
    fetch_ws_send(fetch, "", 0, &sent, 0, FETCHWS_CLOSE);
  fprintf(stderr,
          "ws: fetch_ws_send returned %u, sent %u\n", (int)result, (int)sent);
}

static FETCHcode data_echo(FETCH *fetch, size_t count,
                          size_t plen_min, size_t plen_max)
{
  FETCHcode r = FETCHE_OK;
  const struct fetch_ws_frame *frame;
  size_t len;
  char *send_buf = NULL, *recv_buf = NULL;
  size_t i, scount = count, rcount = count;
  int rblock, sblock;

  send_buf = calloc(1, plen_max + 1);
  recv_buf = calloc(1, plen_max + 1);
  if(!send_buf || !recv_buf) {
    r = FETCHE_OUT_OF_MEMORY;
    goto out;
  }

  for(i = 0; i < plen_max; ++i) {
    send_buf[i] = (char)('0' + ((int)i % 10));
  }

  for(len = plen_min; len <= plen_max; ++len) {
    size_t nwritten, nread, slen = len, rlen = len;
    char *sbuf = send_buf, *rbuf = recv_buf;

    memset(recv_buf, 0, plen_max);
    while(slen || rlen || scount || rcount) {
      sblock = rblock = 1;
      if(slen) {
        r = fetch_ws_send(fetch, sbuf, slen, &nwritten, 0, FETCHWS_BINARY);
        sblock = (r == FETCHE_AGAIN);
        if(!r || (r == FETCHE_AGAIN)) {
          fprintf(stderr, "fetch_ws_send(len=%ld) -> %d, %ld (%ld/%ld)\n",
                  (long)slen, r, (long)nwritten,
                  (long)(len - slen), (long)len);
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
        r = fetch_ws_recv(fetch, rbuf, (rlen > max_recv) ? max_recv : rlen,
                         &nread, &frame);
        if(!r || (r == FETCHE_AGAIN)) {
          rblock = (r == FETCHE_AGAIN);
          fprintf(stderr, "fetch_ws_recv(len=%ld) -> %d, %ld (%ld/%ld) \n",
                  (long)rlen, r, (long)nread, (long)(len - rlen), (long)len);
          if(!r) {
            r = check_recv(frame, len - rlen, nread, len);
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
        fprintf(stderr, "EAGAIN, sleep, try again\n");
  #ifdef _WIN32
        Sleep(100);
  #elif defined(__TANDEM)
        /* NonStop only defines usleep when building for a threading model */
  # if defined(_PUT_MODEL_) || defined(_KLT_MODEL_)
        usleep(100*1000);
  # else
        PROCESS_DELAY_(100*1000);
  # endif
  #else
        usleep(100*1000);
  #endif
      }
    }

    if(memcmp(send_buf, recv_buf, len)) {
      fprintf(stderr, "recv_data: data differs\n");
      dump("expected:", (unsigned char *)send_buf, len, 0);
      dump("received:", (unsigned char *)recv_buf, len, 0);
      r = FETCHE_RECV_ERROR;
      goto out;
    }
  }

out:
  if(!r)
    websocket_close(fetch);
  free(send_buf);
  free(recv_buf);
  return r;
}

static void usage(const char *msg)
{
  if(msg)
    fprintf(stderr, "%s\n", msg);
  fprintf(stderr,
    "usage: [options] url\n"
    "  -m number  minimum frame size\n"
    "  -M number  maximum frame size\n"
  );
}

#endif

int main(int argc, char *argv[])
{
#if !defined(FETCH_DISABLE_WEBSOCKETS) && !defined(_MSC_VER)
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;
  const char *url;
  size_t plen_min = 0, plen_max = 0, count = 1;
  int ch;

  while((ch = getopt(argc, argv, "c:hm:M:")) != -1) {
    switch(ch) {
    case 'h':
      usage(NULL);
      res = FETCHE_BAD_FUNCTION_ARGUMENT;
      goto cleanup;
    case 'c':
      count = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'm':
      plen_min = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'M':
      plen_max = (size_t)strtol(optarg, NULL, 10);
      break;
    default:
      usage("invalid option");
      res = FETCHE_BAD_FUNCTION_ARGUMENT;
      goto cleanup;
    }
  }
  argc -= optind;
  argv += optind;

  if(!plen_max)
    plen_max = plen_min;

  if(plen_max < plen_min) {
    fprintf(stderr, "maxlen must be >= minlen, got %ld-%ld\n",
            (long)plen_min, (long)plen_max);
    res = FETCHE_BAD_FUNCTION_ARGUMENT;
    goto cleanup;
  }

  if(argc != 1) {
    usage(NULL);
    res = FETCHE_BAD_FUNCTION_ARGUMENT;
    goto cleanup;
  }
  url = argv[0];

  fetch_global_init(FETCH_GLOBAL_ALL);

  fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, url);

    /* use the callback style */
    fetch_easy_setopt(fetch, FETCHOPT_USERAGENT, "ws-data");
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 2L); /* websocket style */
    res = fetch_easy_perform(fetch);
    fprintf(stderr, "fetch_easy_perform() returned %u\n", (int)res);
    if(res == FETCHE_OK)
      res = data_echo(fetch, count, plen_min, plen_max);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }

cleanup:
  fetch_global_cleanup();
  return (int)res;

#else /* !FETCH_DISABLE_WEBSOCKETS */
  (void)argc;
  (void)argv;
  fprintf(stderr, "WebSockets not enabled in libfetch\n");
  return 1;
#endif /* FETCH_DISABLE_WEBSOCKETS */
}
