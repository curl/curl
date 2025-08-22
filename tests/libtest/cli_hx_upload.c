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

static int verbose_u = 1;

struct transfer_u {
  size_t idx;
  CURL *easy;
  const char *method;
  char filename[128];
  FILE *out;
  curl_off_t send_total;
  curl_off_t recv_size;
  curl_off_t send_size;
  curl_off_t fail_at;
  curl_off_t pause_at;
  curl_off_t abort_at;
  int started;
  int paused;
  int resumed;
  int done;
};

static size_t transfer_count_u = 1;
static struct transfer_u *transfer_u;
static int forbid_reuse_u = 0;

static struct transfer_u *get_transfer_for_easy_u(CURL *easy)
{
  size_t i;
  for(i = 0; i < transfer_count_u; ++i) {
    if(easy == transfer_u[i].easy)
      return &transfer_u[i];
  }
  return NULL;
}

static size_t my_write_u_cb(char *buf, size_t nitems, size_t buflen,
                            void *userdata)
{
  struct transfer_u *t = userdata;
  size_t blen = (nitems * buflen);
  size_t nwritten;

  curl_mfprintf(stderr, "[t-%zu] RECV %zu bytes, "
                "total=%" CURL_FORMAT_CURL_OFF_T ", "
                "pause_at=%" CURL_FORMAT_CURL_OFF_T "\n",
                t->idx, blen, t->recv_size, t->pause_at);
  if(!t->out) {
    curl_msnprintf(t->filename, sizeof(t->filename)-1, "download_%zu.data",
                   t->idx);
    t->out = fopen(t->filename, "wb");
    if(!t->out)
      return 0;
  }

  nwritten = fwrite(buf, nitems, buflen, t->out);
  if(nwritten < blen) {
    curl_mfprintf(stderr, "[t-%zu] write failure\n", t->idx);
    return 0;
  }
  t->recv_size += (curl_off_t)nwritten;
  return (size_t)nwritten;
}

static size_t my_read_cb(char *buf, size_t nitems, size_t buflen,
                         void *userdata)
{
  struct transfer_u *t = userdata;
  size_t blen = (nitems * buflen);
  size_t nread;

  if(t->send_total <= t->send_size)
    nread = 0;
  else if((t->send_total - t->send_size) < (curl_off_t)blen)
    nread = (size_t)(t->send_total - t->send_size);
  else
    nread = blen;

  curl_mfprintf(stderr, "[t-%zu] SEND %zu bytes, "
                "total=%" CURL_FORMAT_CURL_OFF_T ", "
                "pause_at=%" CURL_FORMAT_CURL_OFF_T "\n",
                t->idx, nread, t->send_total, t->pause_at);

  if(!t->resumed &&
     t->send_size < t->pause_at &&
     ((t->send_size + (curl_off_t)blen) >= t->pause_at)) {
    curl_mfprintf(stderr, "[t-%zu] PAUSE\n", t->idx);
    t->paused = 1;
    return CURL_READFUNC_PAUSE;
  }

  memset(buf, 'x', nread);
  t->send_size += (curl_off_t)nread;
  if(t->fail_at > 0 && t->send_size >= t->fail_at) {
    curl_mfprintf(stderr, "[t-%zu] ABORT by read callback at "
                  "%" CURL_FORMAT_CURL_OFF_T " bytes\n", t->idx, t->send_size);
    return CURL_READFUNC_ABORT;
  }
  return (size_t)nread;
}

static int my_progress_u_cb(void *userdata,
                            curl_off_t dltotal, curl_off_t dlnow,
                            curl_off_t ultotal, curl_off_t ulnow)
{
  struct transfer_u *t = userdata;
  (void)ultotal;
  (void)dlnow;
  (void)dltotal;
  if(t->abort_at > 0 && ulnow >= t->abort_at) {
    curl_mfprintf(stderr, "[t-%zu] ABORT by progress_cb at "
                  "%" CURL_FORMAT_CURL_OFF_T " bytes sent\n", t->idx, ulnow);
    return 1;
  }
  return 0;
}

static int setup_hx_upload(CURL *hnd, const char *url, struct transfer_u *t,
                           long http_version, struct curl_slist *host,
                           CURLSH *share, int use_earlydata,
                           int announce_length)
{
  curl_easy_setopt(hnd, CURLOPT_SHARE, share);
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, http_version);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, (long)(128 * 1024));
  curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, CURLFOLLOW_OBEYCODE);
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, my_write_u_cb);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, t);
  if(use_earlydata)
    curl_easy_setopt(hnd, CURLOPT_SSL_OPTIONS, CURLSSLOPT_EARLYDATA);

  if(!t->method || !strcmp("PUT", t->method))
    curl_easy_setopt(hnd, CURLOPT_UPLOAD, 1L);
  else if(!strcmp("POST", t->method))
    curl_easy_setopt(hnd, CURLOPT_POST, 1L);
  else {
    curl_mfprintf(stderr, "unsupported method '%s'\n", t->method);
    return 1;
  }
  curl_easy_setopt(hnd, CURLOPT_READFUNCTION, my_read_cb);
  curl_easy_setopt(hnd, CURLOPT_READDATA, t);
  if(announce_length)
    curl_easy_setopt(hnd, CURLOPT_INFILESIZE_LARGE, t->send_total);

  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(hnd, CURLOPT_XFERINFOFUNCTION, my_progress_u_cb);
  curl_easy_setopt(hnd, CURLOPT_XFERINFODATA, t);
  if(forbid_reuse_u)
    curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);
  if(host)
    curl_easy_setopt(hnd, CURLOPT_RESOLVE, host);

  /* please be verbose */
  if(verbose_u) {
    curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, cli_debug_cb);
  }

  /* wait for pipe connection to confirm */
  curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);

  return 0; /* all is good */
}

static void usage_hx_upload(const char *msg)
{
  if(msg)
    curl_mfprintf(stderr, "%s\n", msg);
  curl_mfprintf(stderr,
    "usage: [options] url\n"
    "  upload to a url with following options:\n"
    "  -a         abort paused transfer\n"
    "  -e         use TLS earlydata\n"
    "  -m number  max parallel uploads\n"
    "  -n number  total uploads\n"
    "  -A number  abort transfer after `number` request body bytes\n"
    "  -F number  fail reading request body after `number` of bytes\n"
    "  -P number  pause transfer after `number` request body bytes\n"
    "  -r <host>:<port>:<addr>  resolve information\n"
    "  -S number  size to upload\n"
    "  -V http_version (http/1.1, h2, h3) http version to use\n"
  );
}

/*
 * Download a file over HTTP/2, take care of server push.
 */
static CURLcode test_cli_hx_upload(const char *URL)
{
  CURLM *multi_handle;
  CURLSH *share;
  const char *url;
  const char *method = "PUT";
  size_t i, n, max_parallel = 1;
  size_t active_transfers;
  size_t pause_offset = 0;
  size_t abort_offset = 0;
  size_t fail_offset = 0;
  size_t send_total = (128 * 1024);
  int abort_paused = 0;
  int reuse_easy = 0;
  int use_earlydata = 0;
  int announce_length = 0;
  struct transfer_u *t;
  long http_version = CURL_HTTP_VERSION_2_0;
  struct curl_slist *host = NULL;
  const char *resolve = NULL;
  int ch;

  (void)URL;

  while((ch = cgetopt(test_argc, test_argv, "aefhlm:n:A:F:M:P:r:RS:V:"))
        != -1) {
    switch(ch) {
    case 'h':
      usage_hx_upload(NULL);
      return (CURLcode)2;
    case 'a':
      abort_paused = 1;
      break;
    case 'e':
      use_earlydata = 1;
      break;
    case 'f':
      forbid_reuse_u = 1;
      break;
    case 'l':
      announce_length = 1;
      break;
    case 'm':
      max_parallel = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'n':
      transfer_count_u = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'A':
      abort_offset = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'F':
      fail_offset = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'M':
      method = coptarg;
      break;
    case 'P':
      pause_offset = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'r':
      resolve = coptarg;
      break;
    case 'R':
      reuse_easy = 1;
      break;
    case 'S':
      send_total = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'V': {
      if(!strcmp("http/1.1", coptarg))
        http_version = CURL_HTTP_VERSION_1_1;
      else if(!strcmp("h2", coptarg))
        http_version = CURL_HTTP_VERSION_2_0;
      else if(!strcmp("h3", coptarg))
        http_version = CURL_HTTP_VERSION_3ONLY;
      else {
        usage_hx_upload("invalid http version");
        return (CURLcode)1;
      }
      break;
    }
    default:
      usage_hx_upload("invalid option");
      return (CURLcode)1;
    }
  }
  test_argc -= coptind;
  test_argv += coptind;

  if(max_parallel > 1 && reuse_easy) {
    usage_hx_upload("cannot mix -R and -P");
    return (CURLcode)2;
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_global_trace("ids,time,http/2,http/3");

  if(test_argc != 1) {
    usage_hx_upload("not enough arguments");
    return (CURLcode)2;
  }
  url = test_argv[0];

  if(resolve)
    host = curl_slist_append(NULL, resolve);

  share = curl_share_init();
  if(!share) {
    curl_mfprintf(stderr, "error allocating share\n");
    return (CURLcode)1;
  }
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_PSL);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_HSTS);

  transfer_u = calloc(transfer_count_u, sizeof(*transfer_u));
  if(!transfer_u) {
    curl_mfprintf(stderr, "error allocating transfer structs\n");
    return (CURLcode)1;
  }

  active_transfers = 0;
  for(i = 0; i < transfer_count_u; ++i) {
    t = &transfer_u[i];
    t->idx = i;
    t->method = method;
    t->send_total = (curl_off_t)send_total;
    t->abort_at = (curl_off_t)abort_offset;
    t->fail_at = (curl_off_t)fail_offset;
    t->pause_at = (curl_off_t)pause_offset;
  }

  if(reuse_easy) {
    CURL *easy = curl_easy_init();
    CURLcode rc = CURLE_OK;
    if(!easy) {
      curl_mfprintf(stderr, "failed to init easy handle\n");
      return (CURLcode)1;
    }
    for(i = 0; i < transfer_count_u; ++i) {
      t = &transfer_u[i];
      t->easy = easy;
      if(setup_hx_upload(t->easy, url, t, http_version, host, share,
                         use_earlydata, announce_length)) {
        curl_mfprintf(stderr, "[t-%zu] FAILED setup\n", i);
        return (CURLcode)1;
      }

      curl_mfprintf(stderr, "[t-%zu] STARTING\n", t->idx);
      rc = curl_easy_perform(easy);
      curl_mfprintf(stderr, "[t-%zu] DONE -> %d\n", t->idx, rc);
      t->easy = NULL;
      curl_easy_reset(easy);
    }
    curl_easy_cleanup(easy);
  }
  else {
    multi_handle = curl_multi_init();
    curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

    n = (max_parallel < transfer_count_u) ? max_parallel : transfer_count_u;
    for(i = 0; i < n; ++i) {
      t = &transfer_u[i];
      t->easy = curl_easy_init();
      if(!t->easy || setup_hx_upload(t->easy, url, t, http_version, host,
                                     share, use_earlydata, announce_length)) {
        curl_mfprintf(stderr, "[t-%zu] FAILED setup\n", i);
        return (CURLcode)1;
      }
      curl_multi_add_handle(multi_handle, t->easy);
      t->started = 1;
      ++active_transfers;
      curl_mfprintf(stderr, "[t-%zu] STARTED\n", t->idx);
    }

    do {
      int still_running; /* keep number of running handles */
      CURLMcode mc = curl_multi_perform(multi_handle, &still_running);
      struct CURLMsg *m;

      if(still_running) {
        /* wait for activity, timeout or "nothing" */
        mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);
      }

      if(mc)
        break;

      do {
        int msgq = 0;
        m = curl_multi_info_read(multi_handle, &msgq);
        if(m && (m->msg == CURLMSG_DONE)) {
          CURL *e = m->easy_handle;
          --active_transfers;
          curl_multi_remove_handle(multi_handle, e);
          t = get_transfer_for_easy_u(e);
          if(t) {
            long res_status;
            curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &res_status);
            t->done = 1;
            curl_mfprintf(stderr, "[t-%zu] FINISHED, "
                          "result=%d, response=%ld\n",
                          t->idx, m->data.result, res_status);
            if(use_earlydata) {
              curl_off_t sent;
              curl_easy_getinfo(e, CURLINFO_EARLYDATA_SENT_T, &sent);
              curl_mfprintf(stderr, "[t-%zu] EarlyData: "
                            "%" CURL_FORMAT_CURL_OFF_T "\n", t->idx, sent);
            }
          }
          else {
            curl_easy_cleanup(e);
            curl_mfprintf(stderr, "unknown FINISHED???\n");
          }
        }


        /* nothing happening, maintenance */
        if(abort_paused) {
          /* abort paused transfers */
          for(i = 0; i < transfer_count_u; ++i) {
            t = &transfer_u[i];
            if(!t->done && t->paused && t->easy) {
              curl_multi_remove_handle(multi_handle, t->easy);
              t->done = 1;
              active_transfers--;
              curl_mfprintf(stderr, "[t-%zu] ABORTED\n", t->idx);
            }
          }
        }
        else {
          /* resume one paused transfer */
          for(i = 0; i < transfer_count_u; ++i) {
            t = &transfer_u[i];
            if(!t->done && t->paused) {
              t->resumed = 1;
              t->paused = 0;
              curl_easy_pause(t->easy, CURLPAUSE_CONT);
              curl_mfprintf(stderr, "[t-%zu] RESUMED\n", t->idx);
              break;
            }
          }
        }

        while(active_transfers < max_parallel) {
          for(i = 0; i < transfer_count_u; ++i) {
            t = &transfer_u[i];
            if(!t->started) {
              t->easy = curl_easy_init();
              if(!t->easy || setup_hx_upload(t->easy, url, t, http_version,
                                             host, share, use_earlydata,
                                             announce_length)) {
                curl_mfprintf(stderr, "[t-%zu] FAILED setup\n", i);
                return (CURLcode)1;
              }
              curl_multi_add_handle(multi_handle, t->easy);
              t->started = 1;
              ++active_transfers;
              curl_mfprintf(stderr, "[t-%zu] STARTED\n", t->idx);
              break;
            }
          }
          /* all started */
          if(i == transfer_count_u)
            break;
        }
      } while(m);

    } while(active_transfers); /* as long as we have transfers going */

    curl_multi_cleanup(multi_handle);
  }

  for(i = 0; i < transfer_count_u; ++i) {
    t = &transfer_u[i];
    if(t->out) {
      fclose(t->out);
      t->out = NULL;
    }
    if(t->easy) {
      curl_easy_cleanup(t->easy);
      t->easy = NULL;
    }
  }
  free(transfer_u);
  curl_share_cleanup(share);

  return CURLE_OK;
}
