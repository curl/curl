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

#include "urldata.h"
#include <curl/curl.h>
#include <stddef.h>

#include "curl_trc.h"
#include "cfilters.h"
#include "dfilters.h"
#include "df-http.h"
#include "http.h"
#include "headers.h"
#include "strdup.h"
#include "strcase.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#if !defined(CURL_DISABLE_HTTP)

static CURLcode df_http_ch_init(struct Curl_df_writer *writer,
                                struct Curl_easy *data)
{
  (void)writer;
  (void)data;
  return CURLE_OK;
}

static CURLcode df_http_ch_do_meta(struct Curl_df_writer *writer,
                                   struct Curl_easy *data, int meta_type,
                                   const char *buf, size_t blen)
{
  /* HTTP header, but not status-line
   * TODO: this assumes `buf` is NUL-terminated */
  if(!(meta_type & DF_WRITE_STATUS) ) {
    CURLcode result;
    unsigned char htype = (unsigned char)
      (meta_type & DF_WRITE_CONNECT ? CURLH_CONNECT :
       (meta_type & DF_WRITE_1XX ? CURLH_1XX :
        (meta_type & DF_WRITE_TRAILER ? CURLH_TRAILER :
         CURLH_HEADER)));
    result = Curl_headers_push(data, buf, htype);
    if(result)
      return result;
  }
  return Curl_df_write_meta(writer->next, data, meta_type, buf, blen);
}

static void df_http_ch_close(struct Curl_df_writer *writer,
                             struct Curl_easy *data)
{
  (void)writer;
  (void)data;
}

static const struct Curl_df_write_type df_http_ch = {
  "http",
  NULL,
  df_http_ch_init,
  df_http_ch_do_meta,
  Curl_df_def_do_body,
  df_http_ch_close,
  Curl_df_def_is_paused,
  Curl_df_def_unpause,
  sizeof(struct Curl_df_write_type)
};

CURLcode Curl_df_http_collect_header_add(struct Curl_easy *data)
{
  return Curl_df_add_writer(data, &df_http_ch, CURL_DF_PHASE_PROTOCOL, NULL);
}

#endif /* !CURL_DISABLE_HTTP */
