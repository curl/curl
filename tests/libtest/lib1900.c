/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2013 - 2020, Linus Nielsen Feltzing, <linus@haxx.se>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000
#define MAX_URLS 200
#define MAX_BLOCKLIST 20

static int urltime[MAX_URLS];
static char *urlstring[MAX_URLS];
static CURL *handles[MAX_URLS];
static char *site_blocklist[MAX_BLOCKLIST];
static char *server_blocklist[MAX_BLOCKLIST];
static int num_handles;
static int blocklist_num_servers;
static int blocklist_num_sites;

static size_t
write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  (void)contents;
  (void)userp;

  return realsize;
}

static int parse_url_file(const char *filename)
{
  FILE *f;
  int filetime;
  char buf[200];

  num_handles = 0;
  blocklist_num_sites = 0;
  blocklist_num_servers = 0;

  f = fopen(filename, "rb");
  if(!f)
    return 0;

  while(!feof(f)) {
    if(fscanf(f, "%d %199s\n", &filetime, buf)) {
      urltime[num_handles] = filetime;
      urlstring[num_handles] = strdup(buf);
      num_handles++;
      continue;
    }

    if(fscanf(f, "blocklist_site %199s\n", buf)) {
      site_blocklist[blocklist_num_sites] = strdup(buf);
      blocklist_num_sites++;
      continue;
    }

    break;
  }
  fclose(f);

  site_blocklist[blocklist_num_sites] = NULL;
  server_blocklist[blocklist_num_servers] = NULL;
  return num_handles;
}

static void free_urls(void)
{
  int i;
  for(i = 0; i < num_handles; i++) {
    Curl_safefree(urlstring[i]);
  }
  for(i = 0; i < blocklist_num_servers; i++) {
    Curl_safefree(server_blocklist[i]);
  }
  for(i = 0; i < blocklist_num_sites; i++) {
    Curl_safefree(site_blocklist[i]);
  }
}

static int create_handles(void)
{
  int i;

  for(i = 0; i < num_handles; i++) {
    handles[i] = curl_easy_init();
  }
  return 0;
}

static void setup_handle(char *base_url, CURLM *m, int handlenum)
{
  char urlbuf[256];

  msnprintf(urlbuf, sizeof(urlbuf), "%s%s", base_url, urlstring[handlenum]);
  curl_easy_setopt(handles[handlenum], CURLOPT_URL, urlbuf);
  curl_easy_setopt(handles[handlenum], CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(handles[handlenum], CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(handles[handlenum], CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(handles[handlenum], CURLOPT_WRITEDATA, NULL);
  curl_multi_add_handle(m, handles[handlenum]);
}

static void remove_handles(void)
{
  int i;

  for(i = 0; i < num_handles; i++) {
    if(handles[i])
      curl_easy_cleanup(handles[i]);
  }
}

int test(char *URL)
{
  int res = 0;
  CURLM *m = NULL;
  CURLMsg *msg; /* for picking up messages with the transfer status */
  int msgs_left; /* how many messages are left */
  int running = 0;
  int handlenum = 0;
  struct timeval last_handle_add;

  if(parse_url_file(libtest_arg2) <= 0)
    goto test_cleanup;

  start_test_timing();

  curl_global_init(CURL_GLOBAL_ALL);

  multi_init(m);

  create_handles();

  multi_setopt(m, CURLMOPT_PIPELINING, 1L);
  multi_setopt(m, CURLMOPT_MAX_HOST_CONNECTIONS, 2L);
  multi_setopt(m, CURLMOPT_MAX_PIPELINE_LENGTH, 3L);
  multi_setopt(m, CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE, 15000L);
  multi_setopt(m, CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE, 10000L);

  multi_setopt(m, CURLMOPT_PIPELINING_SITE_BL, site_blocklist);
  multi_setopt(m, CURLMOPT_PIPELINING_SERVER_BL, server_blocklist);

  last_handle_add = tutil_tvnow();

  for(;;) {
    struct timeval interval;
    struct timeval now;
    fd_set rd, wr, exc;
    int maxfd = -99;
    long timeout;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    if(handlenum < num_handles) {
      now = tutil_tvnow();
      if(tutil_tvdiff(now, last_handle_add) >= urltime[handlenum]) {
        fprintf(stdout, "Adding handle %d\n", handlenum);
        setup_handle(URL, m, handlenum);
        last_handle_add = now;
        handlenum++;
      }
    }

    curl_multi_perform(m, &running);

    abort_on_test_timeout();

    /* See how the transfers went */
    do {
      msg = curl_multi_info_read(m, &msgs_left);
      if(msg && msg->msg == CURLMSG_DONE) {
        int i;

        /* Find out which handle this message is about */
        for(i = 0; i < num_handles; i++) {
          int found = (msg->easy_handle == handles[i]);
          if(found)
            break;
        }

        printf("Handle %d Completed with status %d\n", i, msg->data.result);
        curl_multi_remove_handle(m, handles[i]);
      }
    } while(msg);

    if(handlenum == num_handles && !running) {
      break; /* done */
    }

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&exc);

    curl_multi_fdset(m, &rd, &wr, &exc, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    curl_multi_timeout(m, &timeout);

    if(timeout < 0)
      timeout = 1;

    interval.tv_sec = timeout / 1000;
    interval.tv_usec = (timeout % 1000) * 1000;

    interval.tv_sec = 0;
    interval.tv_usec = 1000;

    select_test(maxfd + 1, &rd, &wr, &exc, &interval);

    abort_on_test_timeout();
  }

test_cleanup:

  remove_handles();

  /* undocumented cleanup sequence - type UB */

  curl_multi_cleanup(m);
  curl_global_cleanup();

  free_urls();
  return res;
}
