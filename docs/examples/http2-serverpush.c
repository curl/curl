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
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS  /* for _snprintf(), fopen() */
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#ifndef CURLPIPE_MULTIPLEX
#error "too old libcurl, cannot do HTTP/2 server push!"
#endif

#if defined(_MSC_VER) && (_MSC_VER < 1900)
#define snprintf _snprintf
#endif

static FILE *out_download;

static void dump(const char *text, const unsigned char *ptr,
                 size_t size, char nohex)
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
      /* check again for 0D0A, to avoid an extra \n if it is at width */
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stderr); /* newline */
  }
}

static int my_trace(CURL *curl, curl_infotype type,
                    char *data, size_t size, void *userp)
{
  const char *text;
  (void)curl;
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

  dump(text, (const unsigned char *)data, size, 1);
  return 0;
}

#define OUTPUTFILE "dl"

static int setup(CURL *curl, const char *url)
{
  out_download = fopen(OUTPUTFILE, "wb");
  if(!out_download)
    return 1; /* failed */

  /* set the same URL */
  curl_easy_setopt(curl, CURLOPT_URL, url);

  /* HTTP/2 please */
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

  /* we use a self-signed test server, skip verification during debugging */
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  /* write to this file */
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, out_download);

  /* please be verbose */
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);

#if CURLPIPE_MULTIPLEX > 0
  /* wait for pipe connection to confirm */
  curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
  return 0; /* all is good */
}

static FILE *out_push;

/* called when there is an incoming push */
static int server_push_callback(CURL *parent,
                                CURL *curl,
                                size_t num_headers,
                                struct curl_pushheaders *headers,
                                void *userp)
{
  const char *headp;
  size_t i;
  int *transfers = (int *)userp;
  char filename[128];
  static unsigned int count = 0;

  (void)parent;

  snprintf(filename, sizeof(filename), "push%u", count++);

  /* here's a new stream, save it in a new file for each new push */
  out_push = fopen(filename, "wb");
  if(!out_push) {
    /* if we cannot save it, deny it */
    fprintf(stderr, "Failed to create output file for push\n");
    return CURL_PUSH_DENY;
  }

  /* write to this file */
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, out_push);

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

  return CURL_PUSH_OK;
}

/*
 * Download a file over HTTP/2, take care of server push.
 */
int main(int argc, const char *argv[])
{
  CURLcode result;
  CURL *curl;
  CURLM *multi;
  int transfers = 1; /* we start with one */
  const char *url = "https://localhost:8443/index.html";

  if(argc == 2)
    url = argv[1];

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return (int)result;

  /* init a multi stack */
  multi = curl_multi_init();
  if(!multi)
    goto error;

  curl = curl_easy_init();

  /* set options */
  if(!curl || setup(curl, url)) {
    fprintf(stderr, "failed\n");
    goto error;
  }

  curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  curl_multi_setopt(multi, CURLMOPT_PUSHFUNCTION, server_push_callback);
  curl_multi_setopt(multi, CURLMOPT_PUSHDATA, &transfers);

  /* add the easy transfer */
  curl_multi_add_handle(multi, curl);

  do {
    struct CURLMsg *m;
    int still_running; /* keep number of running handles */
    CURLMcode mresult = curl_multi_perform(multi, &still_running);

    if(still_running)
      /* wait for activity, timeout or "nothing" */
      mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);

    if(mresult)
      break;

    /*
     * A little caution when doing server push is that libcurl itself has
     * created and added one or more easy handles but we need to clean them up
     * when we are done.
     */
    do {
      int msgq = 0;
      m = curl_multi_info_read(multi, &msgq);
      if(m && (m->msg == CURLMSG_DONE)) {
        curl = m->easy_handle;
        transfers--;
        curl_multi_remove_handle(multi, curl);
        curl_easy_cleanup(curl);
      }
    } while(m);

  } while(transfers); /* as long as we have transfers going */

error:

  if(multi)
    curl_multi_cleanup(multi);

  curl_global_cleanup();

  fclose(out_download);
  if(out_push)
    fclose(out_push);

  return 0;
}
