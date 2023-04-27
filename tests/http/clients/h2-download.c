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
 * HTTP/2 server push
 * </DESC>
 */

/* curl stuff */
#include <curl/curl.h>
#include <curl/mprintf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* somewhat unix-specific */
#include <sys/time.h>
#include <unistd.h>

#ifndef CURLPIPE_MULTIPLEX
#error "too old libcurl, cannot do HTTP/2 server push!"
#endif

static int verbose = 1;

static
int my_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
  const char *text;
  (void)handle; /* prevent compiler warning */
  (void)userp;

  switch(type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "== Info: %s", data);
    /* FALLTHROUGH */
  default: /* in case a new one is introduced to shock us */
    return 0;

  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    if(verbose <= 1)
      return 0;
    text = "=> Send data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    if(verbose <= 1)
      return 0;
    text = "<= Recv data";
    break;
  }

  fprintf(stderr, "%s, %lu bytes (0x%lx)\n",
          text, (unsigned long)size, (unsigned long)size);
  return 0;
}

struct transfer {
  int idx;
  CURL *easy;
  char filename[128];
  FILE *out;
  curl_off_t recv_size;
  curl_off_t pause_at;
  int paused;
  int resumed;
  int done;
};

static size_t transfer_count;
static struct transfer *transfers;

static struct transfer *get_transfer_for_easy(CURL *easy)
{
  size_t i;
  for(i = 0; i < transfer_count; ++i) {
    if(easy == transfers[i].easy)
      return &transfers[i];
  }
  return NULL;
}

static size_t my_write_cb(char *buf, size_t nitems, size_t buflen,
                          void *userdata)
{
  struct transfer *t = userdata;
  ssize_t nwritten;

  if(!t->resumed &&
     t->recv_size < t->pause_at &&
     ((curl_off_t)(t->recv_size + (nitems * buflen)) >= t->pause_at)) {
    fprintf(stderr, "transfer %d: PAUSE\n", t->idx);
    t->paused = 1;
    return CURL_WRITEFUNC_PAUSE;
  }

  if(!t->out) {
    curl_msnprintf(t->filename, sizeof(t->filename)-1, "download_%u.data",
                   t->idx);
    t->out = fopen(t->filename, "wb");
    if(!t->out)
      return 0;
  }

  nwritten = fwrite(buf, nitems, buflen, t->out);
  if(nwritten < 0) {
    fprintf(stderr, "transfer %d: write failure\n", t->idx);
    return 0;
  }
  t->recv_size += nwritten;
  return (size_t)nwritten;
}

static int setup(CURL *hnd, const char *url, struct transfer *t)
{
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);

  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, my_write_cb);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, t);

  /* please be verbose */
  if(verbose) {
    curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, my_trace);
  }

#if (CURLPIPE_MULTIPLEX > 0)
  /* wait for pipe connection to confirm */
  curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);
#endif
  return 0; /* all is good */
}

/*
 * Download a file over HTTP/2, take care of server push.
 */
int main(int argc, char *argv[])
{
  CURLM *multi_handle;
  int active_transfers;
  struct CURLMsg *m;
  const char *url;
  size_t i;
  long pause_offset;
  struct transfer *t;

  if(argc != 4) {
    fprintf(stderr, "usage: h2-download count pause-offset url\n");
    return 2;
  }

  transfer_count = (size_t)strtol(argv[1], NULL, 10);
  pause_offset = strtol(argv[2], NULL, 10);
  url = argv[3];

  transfers = calloc(transfer_count, sizeof(*transfers));
  if(!transfers) {
    fprintf(stderr, "error allocating transfer structs\n");
    return 1;
  }

  multi_handle = curl_multi_init();
  curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  active_transfers = 0;
  for(i = 0; i < transfer_count; ++i) {
    t = &transfers[i];
    t->idx = (int)i;
    t->pause_at = (curl_off_t)pause_offset * i;
    t->easy = curl_easy_init();
    if(!t->easy || setup(t->easy, url, t)) {
      fprintf(stderr, "setup of transfer #%d failed\n", (int)i);
      return 1;
    }
    curl_multi_add_handle(multi_handle, t->easy);
    ++active_transfers;
  }

  do {
    int still_running; /* keep number of running handles */
    CURLMcode mc = curl_multi_perform(multi_handle, &still_running);

    if(still_running) {
      /* wait for activity, timeout or "nothing" */
      mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);
      fprintf(stderr, "curl_multi_poll() -> %d\n", mc);
    }

    if(mc)
      break;

    /*
     * A little caution when doing server push is that libcurl itself has
     * created and added one or more easy handles but we need to clean them up
     * when we are done.
     */
    do {
      int msgq = 0;
      m = curl_multi_info_read(multi_handle, &msgq);
      if(m && (m->msg == CURLMSG_DONE)) {
        CURL *e = m->easy_handle;
        active_transfers--;
        curl_multi_remove_handle(multi_handle, e);
        t = get_transfer_for_easy(e);
        if(t) {
          t->done = 1;
        }
        else
          curl_easy_cleanup(e);
      }
      else {
        /* nothing happending, resume one paused transfer if there is one */
        for(i = 0; i < transfer_count; ++i) {
          t = &transfers[i];
          if(!t->done && t->paused) {
            t->resumed = 1;
            t->paused = 0;
            curl_easy_pause(t->easy, CURLPAUSE_CONT);
            fprintf(stderr, "transfer %d: RESUME\n", t->idx);
            break;
          }
        }

      }
    } while(m);

  } while(active_transfers); /* as long as we have transfers going */

  for(i = 0; i < transfer_count; ++i) {
    t = &transfers[i];
    if(t->out) {
      fclose(t->out);
      t->out = NULL;
    }
    if(t->easy) {
      curl_easy_cleanup(t->easy);
      t->easy = NULL;
    }
  }
  free(transfers);

  curl_multi_cleanup(multi_handle);

  return 0;
}
