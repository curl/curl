/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2020 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) 2019, Björn Stenberg, <bjorn@haxx.se>
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
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_IPFS

#include "urldata.h"
#include <curl/curl.h>

/* The last #include file should be: */
#include "memdebug.h"

/*
 * Forward declarations.
 */

static CURLcode ipfs_do(struct Curl_easy *data, bool *done);

/*
 * MQTT protocol handler.
 */

const struct Curl_handler Curl_handler_ipfs = {
  "IPFS",                             /* scheme */
  ZERO_NULL,                    /* setup_connection */
  ipfs_do,                            /* do_it */
  ZERO_NULL,                          /* done */
  ZERO_NULL,                          /* do_more */
  ZERO_NULL,                          /* connect_it */
  ZERO_NULL,                          /* connecting */
  ZERO_NULL,                         /* doing */
  ZERO_NULL,                          /* proto_getsock */
  ZERO_NULL,                       /* doing_getsock */
  ZERO_NULL,                          /* domore_getsock */
  ZERO_NULL,                          /* perform_getsock */
  ZERO_NULL,                          /* disconnect */
  ZERO_NULL,                          /* readwrite */
  ZERO_NULL,                          /* connection_check */
  ZERO_NULL,                          /* attach connection */
  PORT_HTTPS,                         /* defport */
  CURLPROTO_IPFS,                     /* protocol */
  CURLPROTO_IPFS,                     /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL
};

static CURLcode ipfs_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  return result;
}

#endif /* CURL_DISABLE_IPFS */
