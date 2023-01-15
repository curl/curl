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
 * HTTP/2 server push. Receive all data in memory.
 * </DESC>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* somewhat unix-specific */
#include <sys/time.h>
#include <unistd.h>

/* curl stuff */
#include <curl/curl.h>

struct Memory {
  char *memory;
  size_t size;
};

static size_t
write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct Memory *mem = (struct Memory *)userp;
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

#define MAX_FILES 10
static struct Memory files[MAX_FILES];
static int pushindex = 1;

static void init_memory(struct Memory *chunk)
{
  chunk->memory = malloc(1);  /* grown as needed with realloc */
  chunk->size = 0;            /* no data at this point */
}

static void setup(CURL *hnd)
{
  /* set the same URL */
  curl_easy_setopt(hnd, CURLOPT_URL, "https://localhost:8443/index.html");

  /* HTTP/2 please */
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

  /* we use a self-signed test server, skip verification during debugging */
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);

  /* write data to a struct  */
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_cb);
  init_memory(&files[0]);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &files[0]);

  /* wait for pipe connection to confirm */
  curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);
}

/* called when there's an incoming push */
static int server_push_callback(CURL *parent,
                                CURL *easy,
                                size_t num_headers,
                                struct curl_pushheaders *headers,
                                void *userp)
{
  char *headp;
  int *transfers = (int *)userp;
  (void)parent; /* we have no use for this */
  (void)num_headers; /* unused */

  if(pushindex == MAX_FILES)
    /* cannot fit anymore */
    return CURL_PUSH_DENY;

  /* write to this buffer */
  init_memory(&files[pushindex]);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &files[pushindex]);
  pushindex++;

  headp = curl_pushheader_byname(headers, ":path");
  if(headp)
    fprintf(stderr, "* Pushed :path '%s'\n", headp /* skip :path + colon */);

  (*transfers)++; /* one more */
  return CURL_PUSH_OK;
}


/*
 * Download a file over HTTP/2, take care of server push.
 */
int main(void)
{
  CURL *easy;
  CURLM *multi;
  int still_running; /* keep number of running handles */
  int transfers = 1; /* we start with one */
  int i;
  struct CURLMsg *m;

  /* init a multi stack */
  multi = curl_multi_init();

  easy = curl_easy_init();

  /* set options */
  setup(easy);

  /* add the easy transfer */
  curl_multi_add_handle(multi, easy);

  curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  curl_multi_setopt(multi, CURLMOPT_PUSHFUNCTION, server_push_callback);
  curl_multi_setopt(multi, CURLMOPT_PUSHDATA, &transfers);

  while(transfers) {
    int rc;
    CURLMcode mcode = curl_multi_perform(multi, &still_running);
    if(mcode)
      break;

    mcode = curl_multi_wait(multi, NULL, 0, 1000, &rc);
    if(mcode)
      break;


    /*
     * When doing server push, libcurl itself created and added one or more
     * easy handles but *we* need to clean them up when they are done.
     */
    do {
      int msgq = 0;
      m = curl_multi_info_read(multi, &msgq);
      if(m && (m->msg == CURLMSG_DONE)) {
        CURL *e = m->easy_handle;
        transfers--;
        curl_multi_remove_handle(multi, e);
        curl_easy_cleanup(e);
      }
    } while(m);

  }


  curl_multi_cleanup(multi);

  /* 'pushindex' is now the number of received transfers */
  for(i = 0; i < pushindex; i++) {
    /* do something fun with the data, and then free it when done */
    free(files[i].memory);
  }

  return 0;
}
