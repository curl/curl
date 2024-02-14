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
#include "dynbuf.h"
#include "doh.h"
#include "request.h"
#include "sendf.h"
#include "url.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

CURLcode Curl_req_init(struct SingleRequest *req)
{
  memset(req, 0, sizeof(*req));
  Curl_bufq_init2(&req->sendbuf, UPLOADBUFFER_DEFAULT, 1,
                  BUFQ_OPT_SOFT_LIMIT);
  return CURLE_OK;
}

CURLcode Curl_req_start(struct SingleRequest *req,
                        struct Curl_easy *data)
{
  req->start = Curl_now();
  Curl_cw_reset(data);
  return CURLE_OK;
}

CURLcode Curl_req_done(struct SingleRequest *req,
                       struct Curl_easy *data, bool aborted)
{
  (void)req;
  /* TODO: add flush handling for client output */
  (void)aborted;
  Curl_cw_reset(data);
  return CURLE_OK;
}

void Curl_req_reset(struct SingleRequest *req, struct Curl_easy *data)
{
  /* This is a bit ugly. `req->p` is a union and we assume we can
   * free this safely without leaks. */
  Curl_safefree(req->p.http);
  Curl_safefree(req->newurl);
  Curl_cw_reset(data);

  Curl_bufq_reset(&req->sendbuf);
  if(data->set.upload_buffer_size != req->sendbuf.chunk_size) {
    Curl_bufq_free(&req->sendbuf);
    Curl_bufq_init2(&req->sendbuf, data->set.upload_buffer_size, 1,
                    BUFQ_OPT_SOFT_LIMIT);
  }

#ifndef CURL_DISABLE_DOH
  if(req->doh) {
    Curl_close(&req->doh->probe[0].easy);
    Curl_close(&req->doh->probe[1].easy);
  }
#endif
}

void Curl_req_free(struct SingleRequest *req, struct Curl_easy *data)
{
  /* This is a bit ugly. `req->p` is a union and we assume we can
   * free this safely without leaks. */
  Curl_safefree(req->p.http);
  Curl_safefree(req->newurl);
  Curl_bufq_free(&req->sendbuf);
  Curl_cw_reset(data);

#ifndef CURL_DISABLE_DOH
  if(req->doh) {
    Curl_close(&req->doh->probe[0].easy);
    Curl_close(&req->doh->probe[1].easy);
    Curl_dyn_free(&req->doh->probe[0].serverdoh);
    Curl_dyn_free(&req->doh->probe[1].serverdoh);
    curl_slist_free_all(req->doh->headers);
    Curl_safefree(req->doh);
  }
#endif
}

