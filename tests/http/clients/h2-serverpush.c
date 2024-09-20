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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CURLPIPE_MULTIPLEX
#error "too old libcurl, cannot do HTTP/2 server push!"
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
    return 0;
  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  default: /* in case a new one is introduced to shock us */
    return 0;
  }

  dump(text, (unsigned char *)data, size, 1);
  return 0;
}

#define OUTPUTFILE "download_0.data"

static int setup(CURL *hnd, const char *url)
{
  FILE *out = fopen(OUTPUTFILE, "wb");
  if(!out)
    /* failed */
    return 1;

  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);

  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, out);

  /* please be verbose */
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, my_trace);

#if (CURLPIPE_MULTIPLEX > 0)
  /* wait for pipe connection to confirm */
  curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);
#endif
  return 0; /* all is good */
}

/* called when there's an incoming push */
static int server_push_callback(CURL *parent,
                                CURL *easy,
                                size_t num_headers,
                                struct curl_pushheaders *headers,
                                void *userp)
{
  char *headp;
  size_t i;
  int *transfers = (int *)userp;
  char filename[128];
  FILE *out;
  static unsigned int count = 0;
  int rv;

  (void)parent; /* we have no use for this */
  curl_msnprintf(filename, sizeof(filename)-1, "push%u", count++);

  /* here's a new stream, save it in a new file for each new push */
  out = fopen(filename, "wb");
  if(!out) {
    /* if we cannot save it, deny it */
    fprintf(stderr, "Failed to create output file for push\n");
    rv = CURL_PUSH_DENY;
    goto out;
  }

  /* write to this file */
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, out);

  fprintf(stderr, "**** push callback approves stream %u, got %lu headers!\n",
          count, (unsigned long)num_headers);

  for(i = 0; i < num_headers; i++) {
    headp = curl_pushheader_bynum(headers, i);
    fprintf(stderr, "**** header %lu: %s\n", (unsigned long)i, headp);
  }

  headp = curl_pushheader_byname(headers, ":path");
  if(headp) {
    fprintf(stderr, "**** The PATH is %s\n", headp /* skip :path + colon */);
  }

  (*transfers)++; /* one more */
  rv = CURL_PUSH_OK;

out:
  return rv;
}


/*
 * Download a file over HTTP/2, take care of server push.
 */
int main(int argc, char *argv[])
{
  CURL *easy;
  CURLM *multi_handle;
  int transfers = 1; /* we start with one */
  struct CURLMsg *m;
  const char *url;

  if(argc != 2) {
    fprintf(stderr, "need URL as argument\n");
    return 2;
  }
  url = argv[1];

  multi_handle = curl_multi_init();
  curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  curl_multi_setopt(multi_handle, CURLMOPT_PUSHFUNCTION, server_push_callback);
  curl_multi_setopt(multi_handle, CURLMOPT_PUSHDATA, &transfers);

  easy = curl_easy_init();
  if(setup(easy, url)) {
    fprintf(stderr, "failed\n");
    return 1;
  }

  curl_multi_add_handle(multi_handle, easy);
  do {
    int still_running; /* keep number of running handles */
    CURLMcode mc = curl_multi_perform(multi_handle, &still_running);

    if(still_running)
      /* wait for activity, timeout or "nothing" */
      mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);

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
        transfers--;
        curl_multi_remove_handle(multi_handle, e);
        curl_easy_cleanup(e);
      }
    } while(m);

  } while(transfers); /* as long as we have transfers going */

  curl_multi_cleanup(multi_handle);

  return 0;
}
