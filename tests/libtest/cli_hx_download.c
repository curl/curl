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

#include "curl_mem_undef.h"

#if defined(USE_QUICHE) || defined(USE_OPENSSL)
#include <openssl/ssl.h>
#endif
#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#endif
#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#endif
#ifdef USE_MBEDTLS
#include <mbedtls/ssl.h>
#endif
#ifdef USE_RUSTLS
#include <rustls.h>
#endif

#include "memdebug.h"

static int verbose_d = 1;

struct transfer_d {
  size_t idx;
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
  int checked_ssl;
  CURLcode result;
};

static size_t transfer_count_d = 1;
static struct transfer_d *transfer_d;
static int forbid_reuse_d = 0;

static struct transfer_d *get_transfer_for_easy_d(CURL *easy)
{
  size_t i;
  for(i = 0; i < transfer_count_d; ++i) {
    if(easy == transfer_d[i].easy)
      return &transfer_d[i];
  }
  return NULL;
}

static size_t my_write_d_cb(char *buf, size_t nitems, size_t buflen,
                            void *userdata)
{
  struct transfer_d *t = userdata;
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

  if(!t->resumed &&
     t->recv_size < t->pause_at &&
     ((t->recv_size + (curl_off_t)blen) >= t->pause_at)) {
    curl_mfprintf(stderr, "[t-%zu] PAUSE\n", t->idx);
    t->paused = 1;
    return CURL_WRITEFUNC_PAUSE;
  }

  nwritten = fwrite(buf, nitems, buflen, t->out);
  if(nwritten < blen) {
    curl_mfprintf(stderr, "[t-%zu] write failure\n", t->idx);
    return 0;
  }
  t->recv_size += (curl_off_t)nwritten;
  if(t->fail_at > 0 && t->recv_size >= t->fail_at) {
    curl_mfprintf(stderr, "[t-%zu] FAIL by write callback at "
                  "%" CURL_FORMAT_CURL_OFF_T " bytes\n", t->idx, t->recv_size);
    return CURL_WRITEFUNC_ERROR;
  }

  return (size_t)nwritten;
}

static int my_progress_d_cb(void *userdata,
                            curl_off_t dltotal, curl_off_t dlnow,
                            curl_off_t ultotal, curl_off_t ulnow)
{
  struct transfer_d *t = userdata;
  (void)ultotal;
  (void)ulnow;
  (void)dltotal;
  if(t->abort_at > 0 && dlnow >= t->abort_at) {
    curl_mfprintf(stderr, "[t-%zu] ABORT by progress_cb at "
                  "%" CURL_FORMAT_CURL_OFF_T " bytes\n", t->idx, dlnow);
    return 1;
  }

#if defined(USE_QUICHE) || defined(USE_OPENSSL) || defined(USE_WOLFSSL) || \
  defined(USE_GNUTLS) || defined(USE_MBEDTLS) || defined(USE_RUSTLS)
  if(!t->checked_ssl && dlnow > 0) {
    struct curl_tlssessioninfo *tls;
    CURLcode res;

    t->checked_ssl = TRUE;
    res = curl_easy_getinfo(t->easy, CURLINFO_TLS_SSL_PTR, &tls);
    if(res) {
      curl_mfprintf(stderr, "[t-%zu] info CURLINFO_TLS_SSL_PTR failed: %d\n",
                    t->idx, res);
      assert(0);
    }
    else {
      switch(tls->backend) {
#if defined(USE_QUICHE) || defined(USE_OPENSSL)
      case CURLSSLBACKEND_OPENSSL: {
        const char *version = SSL_get_version((SSL*)tls->internals);
        assert(version);
        assert(strcmp(version, "unknown"));
        curl_mfprintf(stderr, "[t-%zu] info OpenSSL using %s\n",
                      t->idx, version);
        break;
      }
#endif
#ifdef USE_WOLFSSL
      case CURLSSLBACKEND_WOLFSSL: {
        const char *version = wolfSSL_get_version((WOLFSSL*)tls->internals);
        assert(version);
        assert(strcmp(version, "unknown"));
        curl_mfprintf(stderr, "[t-%zu] info wolfSSL using %s\n",
                      t->idx, version);
        break;
      }
#endif
#ifdef USE_GNUTLS
      case CURLSSLBACKEND_GNUTLS: {
        int v = gnutls_protocol_get_version((gnutls_session_t)tls->internals);
        assert(v);
        curl_mfprintf(stderr, "[t-%zu] info GnuTLS using %s\n",
                      t->idx, gnutls_protocol_get_name(v));
        break;
      }
#endif
#ifdef USE_MBEDTLS
      case CURLSSLBACKEND_MBEDTLS: {
        const char *version = mbedtls_ssl_get_version(
          (mbedtls_ssl_context*)tls->internals);
        assert(version);
        assert(strcmp(version, "unknown"));
        curl_mfprintf(stderr, "[t-%zu] info mbedTLS using %s\n",
                      t->idx, version);
        break;
      }
#endif
#ifdef USE_RUSTLS
      case CURLSSLBACKEND_RUSTLS: {
        int v = rustls_connection_get_protocol_version(
          (struct rustls_connection*)tls->internals);
        assert(v);
        curl_mfprintf(stderr, "[t-%zu] info rustls TLS version 0x%x\n",
                      t->idx, v);
        break;
      }
#endif
      default:
        curl_mfprintf(stderr, "[t-%zu] info SSL_PTR backend=%d, ptr=%p\n",
                      t->idx, tls->backend, (void *)tls->internals);
        break;
      }
    }
  }
#endif
  return 0;
}

static int setup_hx_download(CURL *hnd, const char *url, struct transfer_d *t,
                             long http_version, struct curl_slist *host,
                             CURLSH *share, int use_earlydata,
                             int fresh_connect)
{
  curl_easy_setopt(hnd, CURLOPT_SHARE, share);
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, http_version);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(hnd, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, (long)(128 * 1024));
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, my_write_d_cb);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, t);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(hnd, CURLOPT_XFERINFOFUNCTION, my_progress_d_cb);
  curl_easy_setopt(hnd, CURLOPT_XFERINFODATA, t);
  if(use_earlydata)
    curl_easy_setopt(hnd, CURLOPT_SSL_OPTIONS, CURLSSLOPT_EARLYDATA);
  if(forbid_reuse_d)
    curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);
  if(host)
    curl_easy_setopt(hnd, CURLOPT_RESOLVE, host);
  if(fresh_connect)
    curl_easy_setopt(hnd, CURLOPT_FRESH_CONNECT, 1L);

  /* please be verbose */
  if(verbose_d) {
    curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, cli_debug_cb);
  }

  /* wait for pipe connection to confirm */
  curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);

  return 0; /* all is good */
}

static void usage_hx_download(const char *msg)
{
  if(msg)
    curl_mfprintf(stderr, "%s\n", msg);
  curl_mfprintf(stderr,
    "usage: [options] url\n"
    "  download a url with following options:\n"
    "  -a         abort paused transfer\n"
    "  -m number  max parallel downloads\n"
    "  -e         use TLS early data when possible\n"
    "  -f         forbid connection reuse\n"
    "  -n number  total downloads\n");
  curl_mfprintf(stderr,
    "  -A number  abort transfer after `number` response bytes\n"
    "  -F number  fail writing response after `number` response bytes\n"
    "  -M number  max concurrent connections to a host\n"
    "  -P number  pause transfer after `number` response bytes\n"
    "  -r <host>:<port>:<addr>  resolve information\n"
    "  -T number  max concurrent connections total\n"
    "  -V http_version (http/1.1, h2, h3) http version to use\n"
  );
}

/*
 * Download a file over HTTP/2, take care of server push.
 */
static CURLcode test_cli_hx_download(const char *URL)
{
  CURLM *multi_handle;
  struct CURLMsg *m;
  CURLSH *share;
  const char *url;
  size_t i, n, max_parallel = 1;
  size_t active_transfers;
  size_t pause_offset = 0;
  size_t abort_offset = 0;
  size_t fail_offset = 0;
  int abort_paused = 0, use_earlydata = 0;
  struct transfer_d *t;
  long http_version = CURL_HTTP_VERSION_2_0;
  int ch;
  struct curl_slist *host = NULL;
  char *resolve = NULL;
  size_t max_host_conns = 0;
  size_t max_total_conns = 0;
  int fresh_connect = 0;
  CURLcode result = CURLE_OK;

  (void)URL;

  while((ch = cgetopt(test_argc, test_argv, "aefhm:n:xA:F:M:P:r:T:V:"))
        != -1) {
    switch(ch) {
    case 'h':
      usage_hx_download(NULL);
      result = (CURLcode)2;
      goto cleanup;
    case 'a':
      abort_paused = 1;
      break;
    case 'e':
      use_earlydata = 1;
      break;
    case 'f':
      forbid_reuse_d = 1;
      break;
    case 'm':
      max_parallel = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'n':
      transfer_count_d = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'x':
      fresh_connect = 1;
      break;
    case 'A':
      abort_offset = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'F':
      fail_offset = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'M':
      max_host_conns = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'P':
      pause_offset = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'r':
      free(resolve);
      resolve = strdup(coptarg);
      break;
    case 'T':
      max_total_conns = (size_t)strtol(coptarg, NULL, 10);
      break;
    case 'V': {
      if(!strcmp("http/1.1", coptarg))
        http_version = CURL_HTTP_VERSION_1_1;
      else if(!strcmp("h2", coptarg))
        http_version = CURL_HTTP_VERSION_2_0;
      else if(!strcmp("h3", coptarg))
        http_version = CURL_HTTP_VERSION_3ONLY;
      else {
        usage_hx_download("invalid http version");
        result = (CURLcode)1;
        goto cleanup;
      }
      break;
    }
    default:
      usage_hx_download("invalid option");
      result = (CURLcode)1;
      goto cleanup;
    }
  }
  test_argc -= coptind;
  test_argv += coptind;

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_global_trace("ids,time,http/2,http/3");

  if(test_argc != 1) {
    usage_hx_download("not enough arguments");
    result = (CURLcode)2;
    goto cleanup;
  }
  url = test_argv[0];

  if(resolve)
    host = curl_slist_append(NULL, resolve);

  share = curl_share_init();
  if(!share) {
    curl_mfprintf(stderr, "error allocating share\n");
    result = (CURLcode)1;
    goto cleanup;
  }
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
  /* curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT); */
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_PSL);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_HSTS);

  transfer_d = calloc(transfer_count_d, sizeof(*transfer_d));
  if(!transfer_d) {
    curl_mfprintf(stderr, "error allocating transfer structs\n");
    result = (CURLcode)1;
    goto cleanup;
  }

  multi_handle = curl_multi_init();
  curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS,
                    (long)max_total_conns);
  curl_multi_setopt(multi_handle, CURLMOPT_MAX_HOST_CONNECTIONS,
                    (long)max_host_conns);

  active_transfers = 0;
  for(i = 0; i < transfer_count_d; ++i) {
    t = &transfer_d[i];
    t->idx = i;
    t->abort_at = (curl_off_t)abort_offset;
    t->fail_at = (curl_off_t)fail_offset;
    t->pause_at = (curl_off_t)pause_offset;
  }

  n = (max_parallel < transfer_count_d) ? max_parallel : transfer_count_d;
  for(i = 0; i < n; ++i) {
    t = &transfer_d[i];
    t->easy = curl_easy_init();
    if(!t->easy ||
       setup_hx_download(t->easy, url, t, http_version, host, share,
                         use_earlydata, fresh_connect)) {
      curl_mfprintf(stderr, "[t-%zu] FAILED setup\n", i);
      result = (CURLcode)1;
      goto cleanup;
    }
    curl_multi_add_handle(multi_handle, t->easy);
    t->started = 1;
    ++active_transfers;
    curl_mfprintf(stderr, "[t-%zu] STARTED\n", t->idx);
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
        t = get_transfer_for_easy_d(e);
        if(t) {
          t->done = 1;
          t->result = m->data.result;
          curl_mfprintf(stderr, "[t-%zu] FINISHED with result %d\n",
                        t->idx, t->result);
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
        for(i = 0; i < transfer_count_d; ++i) {
          t = &transfer_d[i];
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
        for(i = 0; i < transfer_count_d; ++i) {
          t = &transfer_d[i];
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
        for(i = 0; i < transfer_count_d; ++i) {
          t = &transfer_d[i];
          if(!t->started) {
            t->easy = curl_easy_init();
            if(!t->easy ||
              setup_hx_download(t->easy, url, t, http_version, host, share,
                                use_earlydata, fresh_connect)) {
              curl_mfprintf(stderr, "[t-%zu] FAILED setup\n", i);
              result = (CURLcode)1;
              goto cleanup;
            }
            curl_multi_add_handle(multi_handle, t->easy);
            t->started = 1;
            ++active_transfers;
            curl_mfprintf(stderr, "[t-%zu] STARTED\n", t->idx);
            break;
          }
        }
        /* all started */
        if(i == transfer_count_d)
          break;
      }
    } while(m);

  } while(active_transfers); /* as long as we have transfers going */

  curl_multi_cleanup(multi_handle);

  for(i = 0; i < transfer_count_d; ++i) {
    t = &transfer_d[i];
    if(t->out) {
      fclose(t->out);
      t->out = NULL;
    }
    if(t->easy) {
      curl_easy_cleanup(t->easy);
      t->easy = NULL;
    }
    if(t->result)
      result = t->result;
    else /* on success we expect ssl to have been checked */
      assert(t->checked_ssl);
  }
  free(transfer_d);

  curl_share_cleanup(share);
  curl_slist_free_all(host);
cleanup:
  free(resolve);

  return result;
}
