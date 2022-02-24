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
#include "http.h"
#include "sendf.h"

/* The last #include file should be: */
#include "curl_printf.h"
#include "memdebug.h"

/*
 * Forward declarations.
 */

static CURLcode ipfs_setup(struct Curl_easy *data,
                                struct connectdata *conn);

/*
 * IPFS protocol handler.
 */

const struct Curl_handler Curl_handler_ipfs = {
  "IPFS",                             /* scheme */
  ipfs_setup,                    /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                          /* done */
  ZERO_NULL,                          /* do_more */
  Curl_http_connect,                          /* connect_it */
  ZERO_NULL,                          /* connecting */
  ZERO_NULL,                         /* doing */
  ZERO_NULL,                          /* proto_getsock */
  Curl_http_getsock_do,                       /* doing_getsock */
  ZERO_NULL,                          /* domore_getsock */
  ZERO_NULL,                          /* perform_getsock */
  ZERO_NULL,                          /* disconnect */
  ZERO_NULL,                          /* readwrite */
  ZERO_NULL,                          /* connection_check */
  ZERO_NULL,                          /* attach connection */
  PORT_HTTP,                         /* defport */
  CURLPROTO_HTTP,                     /* protocol */
  CURLPROTO_HTTP,                     /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL
};
/*
see url.c line 1957 for url changes
or maybe tool_operate.c line 1185
*/

// this is getting called after the connection is established, 
// so we need to figure out how to call a host rewrite before anything else happens
// otherwise it just tries to connect to a host based on the CID

/*

I've been reading the codebase and I am starting to see why this is hard. It seems 
that by the time any of the protocol handlers are called, the DNS lookup has already been performed. 
Or at least that changing the hostname in the setup_connection handler doesn't not have an
effect on the behavior.

Does it make sense to add a new callback to the Curl_handler that can be called for each data URL, 
maybe from something like parseurlandfillconn?

Are there any more resources to help me understand the control flow?

*/


static CURLcode ipfs_setup(struct Curl_easy *data,
                                struct connectdata *conn)
{
    char *env_gate;
    char *gate;
    char *url;
    env_gate = (char *)"CURL_IPFS_GATEWAY";
    gate = curl_getenv(env_gate);

    url = aprintf("http://%s/%s", gate,
                        data->state.url);

    if(!url)
      return CURLE_OUT_OF_MEMORY;

    failf(data, "Uses IPFS gateway URL: '%s'", url);

    if(data->state.url_alloc)
      free(data->state.url);
    data->state.url = url;
    data->state.url_alloc = TRUE;
    return Curl_http_setup_conn(data, conn);
}


#endif /* CURL_DISABLE_IPFS */
