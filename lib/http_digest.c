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

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_DIGEST_AUTH)

#include "urldata.h"
#include "strcase.h"
#include "vauth/vauth.h"
#include "http_digest.h"
#include "curlx/strparse.h"

/* Test example headers:

WWW-Authenticate: Digest realm="testrealm", nonce="1053604598"
Proxy-Authenticate: Digest realm="testrealm", nonce="1053604598"

*/

CURLcode Curl_input_digest(struct Curl_easy *data,
                           bool proxy,
                           const char *header) /* rest of the *-authenticate:
                                                  header */
{
  /* Point to the correct struct with this */
  struct digestdata *digest;

  if(proxy) {
    digest = &data->state.proxydigest;
  }
  else {
    digest = &data->state.digest;
  }

  if(!checkprefix("Digest", header) || !ISBLANK(header[6]))
    return CURLE_AUTH_ERROR;

  header += strlen("Digest");
  curlx_str_passblanks(&header);

  return Curl_auth_decode_digest_http_message(header, digest);
}

/* Flush the Digest state if it was created for a different origin or with
   different credentials than the ones now in use, then link the current
   ones. */
static void digest_flush_stale(struct digestdata *digest,
                               struct Curl_peer *peer,
                               struct Curl_creds *creds)
{
  bool flush = FALSE;
  if(digest->origin && !Curl_peer_same_destination(peer, digest->origin))
    flush = TRUE;
  else if(digest->creds && !Curl_creds_same(creds, digest->creds))
    flush = TRUE;

  if(flush)
    /* flush Digest state */
    Curl_auth_digest_cleanup(digest);

  Curl_peer_link(&digest->origin, peer);
  Curl_creds_link(&digest->creds, creds);
}

CURLcode Curl_output_digest(struct Curl_easy *data,
                            bool proxy,
                            const unsigned char *request,
                            const unsigned char *uripath)
{
  CURLcode result;
  char *response;
  size_t len;
  bool have_chlg;

  /* Point to the address of the pointer that holds the string to send to the
     server, which is for a plain host or for an HTTP proxy */
  char **allocuserpwd;

  /* Point to the name and password for this */
  struct Curl_creds *creds = NULL;

  /* Point to the correct struct with this */
  struct digestdata *digest;
  struct auth *authp;

  if(proxy) {
#ifdef CURL_DISABLE_PROXY
    return CURLE_NOT_BUILT_IN;
#else
    digest = &data->state.proxydigest;
    digest_flush_stale(digest, data->conn->http_proxy.peer,
                       data->conn->http_proxy.creds);
    allocuserpwd = &data->req.hd_proxy_auth;
    creds = data->conn->http_proxy.creds;
    authp = &data->state.authproxy;
#endif
  }
  else {
    DEBUGASSERT(data->state.origin);
    digest = &data->state.digest;
    digest_flush_stale(digest, data->state.origin, data->state.creds);
    allocuserpwd = &data->req.hd_auth;
    creds = data->state.creds;
    authp = &data->state.authhost;
  }

  curlx_safefree(*allocuserpwd);

#ifdef USE_WINDOWS_SSPI
  have_chlg = !!digest->input_token;
#else
  have_chlg = !!digest->nonce;
#endif

  if(!have_chlg) {
    authp->done = FALSE;
    return CURLE_OK;
  }

  result = Curl_auth_create_digest_http_message(data, creds, request,
                                                uripath, digest,
                                                &response, &len);
  if(result)
    return result;

  *allocuserpwd = curl_maprintf("%sAuthorization: Digest %s\r\n",
                                proxy ? "Proxy-" : "", response);
  curlx_free(response);
  if(!*allocuserpwd)
    return CURLE_OUT_OF_MEMORY;

  authp->done = TRUE;

  return CURLE_OK;
}

void Curl_http_auth_cleanup_digest(struct Curl_easy *data)
{
  Curl_auth_digest_cleanup(&data->state.digest);
  Curl_auth_digest_cleanup(&data->state.proxydigest);
}

#endif
