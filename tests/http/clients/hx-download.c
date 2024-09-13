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

#ifndef _MSC_VER
/* somewhat Unix-specific */
#include <unistd.h>  /* getopt() */
#endif

#ifndef CURLPIPE_MULTIPLEX
#error "too old libcurl, cannot do HTTP/2 server push!"
#endif

#ifndef _MSC_VER
static int verbose = 1;

static void log_line_start(FILE *log, const char *idsbuf, curl_infotype type)
{
  /*
   * This is the trace look that is similar to what libcurl makes on its
   * own.
   */
  static const char * const s_infotype[] = {
    "* ", "< ", "> ", "{ ", "} ", "{ ", "} "
  };
  if(idsbuf && *idsbuf)
    fprintf(log, "%s%s", idsbuf, s_infotype[type]);
  else
    fputs(s_infotype[type], log);
}

#define TRC_IDS_FORMAT_IDS_1  "[%" CURL_FORMAT_CURL_OFF_T "-x] "
#define TRC_IDS_FORMAT_IDS_2  "[%" CURL_FORMAT_CURL_OFF_T "-%" \
                                   CURL_FORMAT_CURL_OFF_T "] "
/*
** callback for CURLOPT_DEBUGFUNCTION
*/
static int debug_cb(CURL *handle, curl_infotype type,
                    char *data, size_t size,
                    void *userdata)
{
  FILE *output = stderr;
  static int newl = 0;
  static int traced_data = 0;
  char idsbuf[60];
  curl_off_t xfer_id, conn_id;

  (void)handle; /* not used */
  (void)userdata;

  if(!curl_easy_getinfo(handle, CURLINFO_XFER_ID, &xfer_id) && xfer_id >= 0) {
    if(!curl_easy_getinfo(handle, CURLINFO_CONN_ID, &conn_id) &&
       conn_id >= 0) {
      curl_msnprintf(idsbuf, sizeof(idsbuf), TRC_IDS_FORMAT_IDS_2, xfer_id,
                     conn_id);
    }
    else {
      curl_msnprintf(idsbuf, sizeof(idsbuf), TRC_IDS_FORMAT_IDS_1, xfer_id);
    }
  }
  else
    idsbuf[0] = 0;

  switch(type) {
  case CURLINFO_HEADER_OUT:
    if(size > 0) {
      size_t st = 0;
      size_t i;
      for(i = 0; i < size - 1; i++) {
        if(data[i] == '\n') { /* LF */
          if(!newl) {
            log_line_start(output, idsbuf, type);
          }
          (void)fwrite(data + st, i - st + 1, 1, output);
          st = i + 1;
          newl = 0;
        }
      }
      if(!newl)
        log_line_start(output, idsbuf, type);
      (void)fwrite(data + st, i - st + 1, 1, output);
    }
    newl = (size && (data[size - 1] != '\n')) ? 1 : 0;
    traced_data = 0;
    break;
  case CURLINFO_TEXT:
  case CURLINFO_HEADER_IN:
    if(!newl)
      log_line_start(output, idsbuf, type);
    (void)fwrite(data, size, 1, output);
    newl = (size && (data[size - 1] != '\n')) ? 1 : 0;
    traced_data = 0;
    break;
  case CURLINFO_DATA_OUT:
  case CURLINFO_DATA_IN:
  case CURLINFO_SSL_DATA_IN:
  case CURLINFO_SSL_DATA_OUT:
    if(!traced_data) {
      if(!newl)
        log_line_start(output, idsbuf, type);
      fprintf(output, "[%ld bytes data]\n", (long)size);
      newl = 0;
      traced_data = 1;
    }
    break;
  default: /* nada */
    newl = 0;
    traced_data = 1;
    break;
  }

  return 0;
}

struct transfer {
  int idx;
  CURL *easy;
  char filename[128];
  FILE *out;
  curl_off_t recv_size;
  curl_off_t fail_at;
  curl_off_t pause_at;
  curl_off_t abort_at;
  int started;
  int paused;
  int resumed;
  int done;
};

static size_t transfer_count = 1;
static struct transfer *transfers;
static int forbid_reuse = 0;

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
  size_t blen = (nitems * buflen);
  size_t nwritten;

  fprintf(stderr, "[t-%d] RECV %ld bytes, total=%ld, pause_at=%ld\n",
          t->idx, (long)blen, (long)t->recv_size, (long)t->pause_at);
  if(!t->out) {
    curl_msnprintf(t->filename, sizeof(t->filename)-1, "download_%u.data",
                   t->idx);
    t->out = fopen(t->filename, "wb");
    if(!t->out)
      return 0;
  }

  if(!t->resumed &&
     t->recv_size < t->pause_at &&
     ((t->recv_size + (curl_off_t)blen) >= t->pause_at)) {
    fprintf(stderr, "[t-%d] PAUSE\n", t->idx);
    t->paused = 1;
    return CURL_WRITEFUNC_PAUSE;
  }

  nwritten = fwrite(buf, nitems, buflen, t->out);
  if(nwritten < blen) {
    fprintf(stderr, "[t-%d] write failure\n", t->idx);
    return 0;
  }
  t->recv_size += (curl_off_t)nwritten;
  if(t->fail_at > 0 && t->recv_size >= t->fail_at) {
    fprintf(stderr, "[t-%d] FAIL by write callback at %ld bytes\n",
            t->idx, (long)t->recv_size);
    return CURL_WRITEFUNC_ERROR;
  }

  return (size_t)nwritten;
}

static int my_progress_cb(void *userdata,
                          curl_off_t dltotal, curl_off_t dlnow,
                          curl_off_t ultotal, curl_off_t ulnow)
{
  struct transfer *t = userdata;
  (void)ultotal;
  (void)ulnow;
  (void)dltotal;
  if(t->abort_at > 0 && dlnow >= t->abort_at) {
    fprintf(stderr, "[t-%d] ABORT by progress_cb at %ld bytes\n",
            t->idx, (long)dlnow);
    return 1;
  }
  return 0;
}

static int setup(CURL *hnd, const char *url, struct transfer *t,
                 int http_version)
{
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, http_version);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, (long)(128 * 1024));
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, my_write_cb);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, t);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(hnd, CURLOPT_XFERINFOFUNCTION, my_progress_cb);
  curl_easy_setopt(hnd, CURLOPT_XFERINFODATA, t);
  if(forbid_reuse)
    curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);

  /* please be verbose */
  if(verbose) {
    curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, debug_cb);
  }

#if (CURLPIPE_MULTIPLEX > 0)
  /* wait for pipe connection to confirm */
  curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);
#endif
  return 0; /* all is good */
}

static void usage(const char *msg)
{
  if(msg)
    fprintf(stderr, "%s\n", msg);
  fprintf(stderr,
    "usage: [options] url\n"
    "  download a url with following options:\n"
    "  -a         abort paused transfer\n"
    "  -m number  max parallel downloads\n"
    "  -n number  total downloads\n"
    "  -A number  abort transfer after `number` response bytes\n"
    "  -F number  fail writing response after `number` response bytes\n"
    "  -P number  pause transfer after `number` response bytes\n"
    "  -V http_version (http/1.1, h2, h3) http version to use\n"
  );
}
#endif /* !_MSC_VER */

/*
 * Download a file over HTTP/2, take care of server push.
 */
int main(int argc, char *argv[])
{
#ifndef _MSC_VER
  CURLM *multi_handle;
  struct CURLMsg *m;
  const char *url;
  size_t i, n, max_parallel = 1;
  size_t active_transfers;
  size_t pause_offset = 0;
  size_t abort_offset = 0;
  size_t fail_offset = 0;
  int abort_paused = 0;
  struct transfer *t;
  int http_version = CURL_HTTP_VERSION_2_0;
  int ch;

  while((ch = getopt(argc, argv, "afhm:n:A:F:P:V:")) != -1) {
    switch(ch) {
    case 'h':
      usage(NULL);
      return 2;
    case 'a':
      abort_paused = 1;
      break;
    case 'f':
      forbid_reuse = 1;
      break;
    case 'm':
      max_parallel = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'n':
      transfer_count = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'A':
      abort_offset = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'F':
      fail_offset = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'P':
      pause_offset = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'V': {
      if(!strcmp("http/1.1", optarg))
        http_version = CURL_HTTP_VERSION_1_1;
      else if(!strcmp("h2", optarg))
        http_version = CURL_HTTP_VERSION_2_0;
      else if(!strcmp("h3", optarg))
        http_version = CURL_HTTP_VERSION_3ONLY;
      else {
        usage("invalid http version");
        return 1;
      }
      break;
    }
    default:
     usage("invalid option");
     return 1;
    }
  }
  argc -= optind;
  argv += optind;

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_global_trace("ids,time,http/2,http/3");

  if(argc != 1) {
    usage("not enough arguments");
    return 2;
  }
  url = argv[0];

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
    t->abort_at = (curl_off_t)abort_offset;
    t->fail_at = (curl_off_t)fail_offset;
    t->pause_at = (curl_off_t)pause_offset;
  }

  n = (max_parallel < transfer_count)? max_parallel : transfer_count;
  for(i = 0; i < n; ++i) {
    t = &transfers[i];
    t->easy = curl_easy_init();
    if(!t->easy || setup(t->easy, url, t, http_version)) {
      fprintf(stderr, "[t-%d] FAILED setup\n", (int)i);
      return 1;
    }
    curl_multi_add_handle(multi_handle, t->easy);
    t->started = 1;
    ++active_transfers;
    fprintf(stderr, "[t-%d] STARTED\n", t->idx);
  }

  do {
    int still_running; /* keep number of running handles */
    CURLMcode mc = curl_multi_perform(multi_handle, &still_running);

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
        t = get_transfer_for_easy(e);
        if(t) {
          t->done = 1;
          fprintf(stderr, "[t-%d] FINISHED\n", t->idx);
        }
        else {
          curl_easy_cleanup(e);
          fprintf(stderr, "unknown FINISHED???\n");
        }
      }


      /* nothing happening, maintenance */
      if(abort_paused) {
        /* abort paused transfers */
        for(i = 0; i < transfer_count; ++i) {
          t = &transfers[i];
          if(!t->done && t->paused && t->easy) {
            curl_multi_remove_handle(multi_handle, t->easy);
            t->done = 1;
            active_transfers--;
            fprintf(stderr, "[t-%d] ABORTED\n", t->idx);
          }
        }
      }
      else {
        /* resume one paused transfer */
        for(i = 0; i < transfer_count; ++i) {
          t = &transfers[i];
          if(!t->done && t->paused) {
            t->resumed = 1;
            t->paused = 0;
            curl_easy_pause(t->easy, CURLPAUSE_CONT);
            fprintf(stderr, "[t-%d] RESUMED\n", t->idx);
            break;
          }
        }
      }

      while(active_transfers < max_parallel) {
        for(i = 0; i < transfer_count; ++i) {
          t = &transfers[i];
          if(!t->started) {
            t->easy = curl_easy_init();
            if(!t->easy || setup(t->easy, url, t, http_version)) {
              fprintf(stderr, "[t-%d] FAILED setup\n", (int)i);
              return 1;
            }
            curl_multi_add_handle(multi_handle, t->easy);
            t->started = 1;
            ++active_transfers;
            fprintf(stderr, "[t-%d] STARTED\n", t->idx);
            break;
          }
        }
        /* all started */
        if(i == transfer_count)
          break;
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
#else
  (void)argc;
  (void)argv;
  fprintf(stderr, "Not supported with this compiler.\n");
  return 1;
#endif /* !_MSC_VER */
}
