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

#include "curl_setup.h"

#include <curl/curl.h>

#include "curl_log.h"
#include "urldata.h"
#include "easyif.h"
#include "cfilters.h"
#include "timeval.h"
#include "multiif.h"
#include "strcase.h"

#include "cf-socket.h"
#include "connect.h"
#include "http2.h"
#include "http_proxy.h"
#include "cf-http.h"
#include "socks.h"
#include "strtok.h"
#include "vtls/vtls.h"
#include "vquic/vquic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


void Curl_debug(struct Curl_easy *data, curl_infotype type,
                char *ptr, size_t size)
{
  if(data->set.verbose) {
    static const char s_infotype[CURLINFO_END][3] = {
      "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };
    if(data->set.fdebug) {
      bool inCallback = Curl_is_in_callback(data);
      Curl_set_in_callback(data, true);
      (void)(*data->set.fdebug)(data, type, ptr, size, data->set.debugdata);
      Curl_set_in_callback(data, inCallback);
    }
    else {
      switch(type) {
      case CURLINFO_TEXT:
      case CURLINFO_HEADER_OUT:
      case CURLINFO_HEADER_IN:
        fwrite(s_infotype[type], 2, 1, data->set.err);
        fwrite(ptr, size, 1, data->set.err);
        break;
      default: /* nada */
        break;
      }
    }
  }
}


/* Curl_failf() is for messages stating why we failed.
 * The message SHALL NOT include any LF or CR.
 */
void Curl_failf(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(data->set.verbose || data->set.errorbuffer) {
    va_list ap;
    int len;
    char error[CURL_ERROR_SIZE + 2];
    va_start(ap, fmt);
    len = mvsnprintf(error, CURL_ERROR_SIZE, fmt, ap);

    if(data->set.errorbuffer && !data->state.errorbuf) {
      strcpy(data->set.errorbuffer, error);
      data->state.errorbuf = TRUE; /* wrote error string */
    }
    error[len++] = '\n';
    error[len] = '\0';
    Curl_debug(data, CURLINFO_TEXT, error, len);
    va_end(ap);
  }
}

/* Curl_infof() is for info message along the way */
#define MAXINFO 2048

void Curl_infof(struct Curl_easy *data, const char *fmt, ...)
{
  DEBUGASSERT(!strchr(fmt, '\n'));
  if(data && data->set.verbose) {
    va_list ap;
    int len;
    char buffer[MAXINFO + 2];
    va_start(ap, fmt);
    len = mvsnprintf(buffer, MAXINFO, fmt, ap);
    va_end(ap);
    buffer[len++] = '\n';
    buffer[len] = '\0';
    Curl_debug(data, CURLINFO_TEXT, buffer, len);
  }
}

#ifdef DEBUGBUILD

void Curl_log_cf_debug(struct Curl_easy *data, struct Curl_cfilter *cf,
                       const char *fmt, ...)
{
  DEBUGASSERT(cf);
  if(data && Curl_log_cf_is_debug(cf)) {
    va_list ap;
    int len;
    char buffer[MAXINFO + 2];
    len = msnprintf(buffer, MAXINFO, "[CONN-%ld%s-%s] ",
                    cf->conn->connection_id, cf->sockindex? "/2" : "",
                    cf->cft->name);
    va_start(ap, fmt);
    len += mvsnprintf(buffer + len, MAXINFO - len, fmt, ap);
    va_end(ap);
    buffer[len++] = '\n';
    buffer[len] = '\0';
    Curl_debug(data, CURLINFO_TEXT, buffer, len);
  }
}


static struct Curl_cftype *cf_types[] = {
  &Curl_cft_tcp,
  &Curl_cft_udp,
  &Curl_cft_unix,
  &Curl_cft_tcp_accept,
  &Curl_cft_happy_eyeballs,
  &Curl_cft_setup,
#ifdef USE_NGHTTP2
  &Curl_cft_nghttp2,
#endif
#ifdef USE_SSL
  &Curl_cft_ssl,
  &Curl_cft_ssl_proxy,
#endif
#if !defined(CURL_DISABLE_PROXY)
#if !defined(CURL_DISABLE_HTTP)
  &Curl_cft_http_proxy,
#endif /* !CURL_DISABLE_HTTP */
  &Curl_cft_haproxy,
  &Curl_cft_socks_proxy,
#endif /* !CURL_DISABLE_PROXY */
#ifdef ENABLE_QUIC
  &Curl_cft_http3,
#endif
#if !defined(CURL_DISABLE_HTTP) && !defined(USE_HYPER)
  &Curl_cft_http_connect,
#endif
  NULL,
};

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

CURLcode Curl_log_init(void)
{
  const char *setting = getenv("CURL_DEBUG");
  if(setting) {
    char *token, *tok_buf, *tmp;
    size_t i;

    tmp = strdup(setting);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;

    token = strtok_r(tmp, ", ", &tok_buf);
    while(token) {
      for(i = 0; cf_types[i]; ++i) {
        if(strcasecompare(token, cf_types[i]->name)) {
          cf_types[i]->log_level = CURL_LOG_DEBUG;
          break;
        }
      }
      token = strtok_r(NULL, ", ", &tok_buf);
    }
    free(tmp);
  }
  return CURLE_OK;
}
#else /* DEBUGBUILD */

CURLcode Curl_log_init(void)
{
  return CURLE_OK;
}

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
void Curl_log_cf_debug(struct Curl_easy *data, struct Curl_cfilter *cf,
                       const char *fmt, ...)
{
  (void)data;
  (void)cf;
  (void)fmt;
}
#endif

#endif /* !DEBUGBUILD */
