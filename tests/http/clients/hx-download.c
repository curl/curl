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
 * HTTP/2 server push
 * </DESC>
 */
/* fetch stuff */
#include <fetch/fetch.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _MSC_VER
/* somewhat Unix-specific */
#include <unistd.h>  /* getopt() */
#endif

#ifdef _WIN32
#define strdup _strdup
#endif

#ifndef FETCHPIPE_MULTIPLEX
#error "too old libfetch, cannot do HTTP/2 server push!"
#endif

#ifndef _MSC_VER
static int verbose = 1;

static void log_line_start(FILE *log, const char *idsbuf, fetch_infotype type)
{
  /*
   * This is the trace look that is similar to what libfetch makes on its
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

#define TRC_IDS_FORMAT_IDS_1  "[%" FETCH_FORMAT_FETCH_OFF_T "-x] "
#define TRC_IDS_FORMAT_IDS_2  "[%" FETCH_FORMAT_FETCH_OFF_T "-%" \
                                   FETCH_FORMAT_FETCH_OFF_T "] "
/*
** callback for FETCHOPT_DEBUGFUNCTION
*/
static int debug_cb(FETCH *handle, fetch_infotype type,
                    char *data, size_t size,
                    void *userdata)
{
  FILE *output = stderr;
  static int newl = 0;
  static int traced_data = 0;
  char idsbuf[60];
  fetch_off_t xfer_id, conn_id;

  (void)handle; /* not used */
  (void)userdata;

  if(!fetch_easy_getinfo(handle, FETCHINFO_XFER_ID, &xfer_id) && xfer_id >= 0) {
    if(!fetch_easy_getinfo(handle, FETCHINFO_CONN_ID, &conn_id) &&
       conn_id >= 0) {
      fetch_msnprintf(idsbuf, sizeof(idsbuf), TRC_IDS_FORMAT_IDS_2, xfer_id,
                     conn_id);
    }
    else {
      fetch_msnprintf(idsbuf, sizeof(idsbuf), TRC_IDS_FORMAT_IDS_1, xfer_id);
    }
  }
  else
    idsbuf[0] = 0;

  switch(type) {
  case FETCHINFO_HEADER_OUT:
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
  case FETCHINFO_TEXT:
  case FETCHINFO_HEADER_IN:
    if(!newl)
      log_line_start(output, idsbuf, type);
    (void)fwrite(data, size, 1, output);
    newl = (size && (data[size - 1] != '\n')) ? 1 : 0;
    traced_data = 0;
    break;
  case FETCHINFO_DATA_OUT:
  case FETCHINFO_DATA_IN:
  case FETCHINFO_SSL_DATA_IN:
  case FETCHINFO_SSL_DATA_OUT:
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
  FETCH *easy;
  char filename[128];
  FILE *out;
  fetch_off_t recv_size;
  fetch_off_t fail_at;
  fetch_off_t pause_at;
  fetch_off_t abort_at;
  int started;
  int paused;
  int resumed;
  int done;
};

static size_t transfer_count = 1;
static struct transfer *transfers;
static int forbid_reuse = 0;

static struct transfer *get_transfer_for_easy(FETCH *easy)
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
    fetch_msnprintf(t->filename, sizeof(t->filename)-1, "download_%u.data",
                   t->idx);
    t->out = fopen(t->filename, "wb");
    if(!t->out)
      return 0;
  }

  if(!t->resumed &&
     t->recv_size < t->pause_at &&
     ((t->recv_size + (fetch_off_t)blen) >= t->pause_at)) {
    fprintf(stderr, "[t-%d] PAUSE\n", t->idx);
    t->paused = 1;
    return FETCH_WRITEFUNC_PAUSE;
  }

  nwritten = fwrite(buf, nitems, buflen, t->out);
  if(nwritten < blen) {
    fprintf(stderr, "[t-%d] write failure\n", t->idx);
    return 0;
  }
  t->recv_size += (fetch_off_t)nwritten;
  if(t->fail_at > 0 && t->recv_size >= t->fail_at) {
    fprintf(stderr, "[t-%d] FAIL by write callback at %ld bytes\n",
            t->idx, (long)t->recv_size);
    return FETCH_WRITEFUNC_ERROR;
  }

  return (size_t)nwritten;
}

static int my_progress_cb(void *userdata,
                          fetch_off_t dltotal, fetch_off_t dlnow,
                          fetch_off_t ultotal, fetch_off_t ulnow)
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

static int setup(FETCH *hnd, const char *url, struct transfer *t,
                 int http_version, struct fetch_slist *host,
                 FETCHSH *share, int use_earlydata, int fresh_connect)
{
  fetch_easy_setopt(hnd, FETCHOPT_SHARE, share);
  fetch_easy_setopt(hnd, FETCHOPT_URL, url);
  fetch_easy_setopt(hnd, FETCHOPT_HTTP_VERSION, http_version);
  fetch_easy_setopt(hnd, FETCHOPT_SSL_VERIFYPEER, 0L);
  fetch_easy_setopt(hnd, FETCHOPT_SSL_VERIFYHOST, 0L);
  fetch_easy_setopt(hnd, FETCHOPT_BUFFERSIZE, (long)(128 * 1024));
  fetch_easy_setopt(hnd, FETCHOPT_WRITEFUNCTION, my_write_cb);
  fetch_easy_setopt(hnd, FETCHOPT_WRITEDATA, t);
  fetch_easy_setopt(hnd, FETCHOPT_NOPROGRESS, 0L);
  fetch_easy_setopt(hnd, FETCHOPT_XFERINFOFUNCTION, my_progress_cb);
  fetch_easy_setopt(hnd, FETCHOPT_XFERINFODATA, t);
  if(use_earlydata)
    fetch_easy_setopt(hnd, FETCHOPT_SSL_OPTIONS, (long)FETCHSSLOPT_EARLYDATA);
  if(forbid_reuse)
    fetch_easy_setopt(hnd, FETCHOPT_FORBID_REUSE, 1L);
  if(host)
    fetch_easy_setopt(hnd, FETCHOPT_RESOLVE, host);
  if(fresh_connect)
    fetch_easy_setopt(hnd, FETCHOPT_FRESH_CONNECT, 1L);

  /* please be verbose */
  if(verbose) {
    fetch_easy_setopt(hnd, FETCHOPT_VERBOSE, 1L);
    fetch_easy_setopt(hnd, FETCHOPT_DEBUGFUNCTION, debug_cb);
  }

#if (FETCHPIPE_MULTIPLEX > 0)
  /* wait for pipe connection to confirm */
  fetch_easy_setopt(hnd, FETCHOPT_PIPEWAIT, 1L);
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
    "  -e         use TLS early data when possible\n"
    "  -f         forbid connection reuse\n"
    "  -n number  total downloads\n");
  fprintf(stderr,
    "  -A number  abort transfer after `number` response bytes\n"
    "  -F number  fail writing response after `number` response bytes\n"
    "  -M number  max concurrent connections to a host\n"
    "  -P number  pause transfer after `number` response bytes\n"
    "  -r <host>:<port>:<addr>  resolve information\n"
    "  -T number  max concurrent connections total\n"
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
  FETCHM *multi_handle;
  struct FETCHMsg *m;
  FETCHSH *share;
  const char *url;
  size_t i, n, max_parallel = 1;
  size_t active_transfers;
  size_t pause_offset = 0;
  size_t abort_offset = 0;
  size_t fail_offset = 0;
  int abort_paused = 0, use_earlydata = 0;
  struct transfer *t;
  int http_version = FETCH_HTTP_VERSION_2_0;
  int ch;
  struct fetch_slist *host = NULL;
  char *resolve = NULL;
  size_t max_host_conns = 0;
  size_t max_total_conns = 0;
  int fresh_connect = 0;
  int result = 0;

  while((ch = getopt(argc, argv, "aefhm:n:xA:F:M:P:r:T:V:")) != -1) {
    switch(ch) {
    case 'h':
      usage(NULL);
      result = 2;
      goto cleanup;
    case 'a':
      abort_paused = 1;
      break;
    case 'e':
      use_earlydata = 1;
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
    case 'x':
      fresh_connect = 1;
      break;
    case 'A':
      abort_offset = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'F':
      fail_offset = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'M':
      max_host_conns = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'P':
      pause_offset = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'r':
      free(resolve);
      resolve = strdup(optarg);
      break;
    case 'T':
      max_total_conns = (size_t)strtol(optarg, NULL, 10);
      break;
    case 'V': {
      if(!strcmp("http/1.1", optarg))
        http_version = FETCH_HTTP_VERSION_1_1;
      else if(!strcmp("h2", optarg))
        http_version = FETCH_HTTP_VERSION_2_0;
      else if(!strcmp("h3", optarg))
        http_version = FETCH_HTTP_VERSION_3ONLY;
      else {
        usage("invalid http version");
        result = 1;
        goto cleanup;
      }
      break;
    }
    default:
      usage("invalid option");
      result = 1;
      goto cleanup;
    }
  }
  argc -= optind;
  argv += optind;

  fetch_global_init(FETCH_GLOBAL_DEFAULT);
  fetch_global_trace("ids,time,http/2,http/3");

  if(argc != 1) {
    usage("not enough arguments");
    result = 2;
    goto cleanup;
  }
  url = argv[0];

  if(resolve)
    host = fetch_slist_append(NULL, resolve);

  share = fetch_share_init();
  if(!share) {
    fprintf(stderr, "error allocating share\n");
    result = 1;
    goto cleanup;
  }
  fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_COOKIE);
  fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_DNS);
  fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_SSL_SESSION);
  /* fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_CONNECT); */
  fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_PSL);
  fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_HSTS);

  transfers = calloc(transfer_count, sizeof(*transfers));
  if(!transfers) {
    fprintf(stderr, "error allocating transfer structs\n");
    result = 1;
    goto cleanup;
  }

  multi_handle = fetch_multi_init();
  fetch_multi_setopt(multi_handle, FETCHMOPT_PIPELINING, FETCHPIPE_MULTIPLEX);
  fetch_multi_setopt(multi_handle, FETCHMOPT_MAX_TOTAL_CONNECTIONS,
                    (long)max_total_conns);
  fetch_multi_setopt(multi_handle, FETCHMOPT_MAX_HOST_CONNECTIONS,
                    (long)max_host_conns);

  active_transfers = 0;
  for(i = 0; i < transfer_count; ++i) {
    t = &transfers[i];
    t->idx = (int)i;
    t->abort_at = (fetch_off_t)abort_offset;
    t->fail_at = (fetch_off_t)fail_offset;
    t->pause_at = (fetch_off_t)pause_offset;
  }

  n = (max_parallel < transfer_count) ? max_parallel : transfer_count;
  for(i = 0; i < n; ++i) {
    t = &transfers[i];
    t->easy = fetch_easy_init();
    if(!t->easy ||
       setup(t->easy, url, t, http_version, host, share, use_earlydata,
             fresh_connect)) {
      fprintf(stderr, "[t-%d] FAILED setup\n", (int)i);
      result = 1;
      goto cleanup;
    }
    fetch_multi_add_handle(multi_handle, t->easy);
    t->started = 1;
    ++active_transfers;
    fprintf(stderr, "[t-%d] STARTED\n", t->idx);
  }

  do {
    int still_running; /* keep number of running handles */
    FETCHMcode mc = fetch_multi_perform(multi_handle, &still_running);

    if(still_running) {
      /* wait for activity, timeout or "nothing" */
      mc = fetch_multi_poll(multi_handle, NULL, 0, 1000, NULL);
    }

    if(mc)
      break;

    do {
      int msgq = 0;
      m = fetch_multi_info_read(multi_handle, &msgq);
      if(m && (m->msg == FETCHMSG_DONE)) {
        FETCH *e = m->easy_handle;
        --active_transfers;
        fetch_multi_remove_handle(multi_handle, e);
        t = get_transfer_for_easy(e);
        if(t) {
          t->done = 1;
          fprintf(stderr, "[t-%d] FINISHED\n", t->idx);
          if(use_earlydata) {
            fetch_off_t sent;
            fetch_easy_getinfo(e, FETCHINFO_EARLYDATA_SENT_T, &sent);
            fprintf(stderr, "[t-%d] EarlyData: %ld\n", t->idx, (long)sent);
          }
        }
        else {
          fetch_easy_cleanup(e);
          fprintf(stderr, "unknown FINISHED???\n");
        }
      }

      /* nothing happening, maintenance */
      if(abort_paused) {
        /* abort paused transfers */
        for(i = 0; i < transfer_count; ++i) {
          t = &transfers[i];
          if(!t->done && t->paused && t->easy) {
            fetch_multi_remove_handle(multi_handle, t->easy);
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
            fetch_easy_pause(t->easy, FETCHPAUSE_CONT);
            fprintf(stderr, "[t-%d] RESUMED\n", t->idx);
            break;
          }
        }
      }

      while(active_transfers < max_parallel) {
        for(i = 0; i < transfer_count; ++i) {
          t = &transfers[i];
          if(!t->started) {
            t->easy = fetch_easy_init();
            if(!t->easy ||
               setup(t->easy, url, t, http_version, host, share,
                     use_earlydata, fresh_connect)) {
              fprintf(stderr, "[t-%d] FAILED setup\n", (int)i);
              result = 1;
              goto cleanup;
            }
            fetch_multi_add_handle(multi_handle, t->easy);
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

  fetch_multi_cleanup(multi_handle);

  for(i = 0; i < transfer_count; ++i) {
    t = &transfers[i];
    if(t->out) {
      fclose(t->out);
      t->out = NULL;
    }
    if(t->easy) {
      fetch_easy_cleanup(t->easy);
      t->easy = NULL;
    }
  }
  free(transfers);

  fetch_share_cleanup(share);
  fetch_slist_free_all(host);
cleanup:
  free(resolve);

  return result;
#else
  (void)argc;
  (void)argv;
  fprintf(stderr, "Not supported with this compiler.\n");
  return 1;
#endif /* !_MSC_VER */
}
