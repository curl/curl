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
#include "curl_trc.h"
#include "strcase.h"
#include "vauth/vauth.h"
#include "http_digest.h"
#include "curlx/strparse.h"

/* Flush the Digest state if it was created for a different origin or with
   different credentials than the ones now in use, then link the current
   ones. */
static void digest_flush_stale(struct Curl_easy *data,
                               struct digestdata *digest,
                               struct Curl_peer *peer,
                               struct Curl_creds *creds)
{
  bool flush = FALSE;
  if(digest->origin && !Curl_peer_same_destination(peer, digest->origin)) {
    CURL_TRC_M(data, "http_digest, reset on peer change to %s:%u",
               peer->hostname, peer->port);
    flush = TRUE;
  }
  else if(digest->creds && !Curl_creds_same(creds, digest->creds)) {
    CURL_TRC_M(data, "http_digest, reset on creds change to %s",
               creds ? creds->user : "-");
    flush = TRUE;
  }

  if(flush) {
    /* flush Digest state */
    Curl_auth_digest_cleanup(digest);
  }

  Curl_peer_link(&digest->origin, peer);
  Curl_creds_link(&digest->creds, creds);
}

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
  struct Curl_peer *origin = NULL;
  CURLcode result;

  if(proxy) {
    digest = &data->state.proxydigest;
#ifdef CURL_DISABLE_PROXY
    Curl_auth_digest_cleanup(digest);
    return CURLE_OK;  /* just ignore such a header without proxy support */
#else
    origin = data->conn->http_proxy.peer;
#endif
  }
  else {
    digest = &data->state.digest;
    origin = data->state.origin;
  }

  if(!checkprefix("Digest", header) || !ISBLANK(header[6])) {
    Curl_auth_digest_cleanup(digest);
    return CURLE_AUTH_ERROR;
  }

  header += CURL_CSTRLEN("Digest");
  curlx_str_passblanks(&header);

  /* This resets the digest struct before decoding */
  result = Curl_auth_decode_digest_http_message(header, digest);
  /* Remember only the peer, the data we take in has no relation to creds
   * at this time. We can use it even if creds change. */
  Curl_peer_link(&digest->origin, origin);
  return result;
}

CURLcode Curl_output_digest(struct Curl_easy *data,
                            bool proxy,
                            const unsigned char *request,
                            const unsigned char *uripath)
{
  struct Curl_peer *origin = NULL;
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
    origin = data->conn->http_proxy.peer;
    creds = data->conn->http_proxy.creds;
    allocuserpwd = &data->req.hd_proxy_auth;
    authp = &data->state.authproxy;
#endif
  }
  else {
    DEBUGASSERT(data->state.origin);
    digest = &data->state.digest;
    origin = data->state.origin;
    creds = data->state.creds;
    allocuserpwd = &data->req.hd_auth;
    authp = &data->state.authhost;
  }

  digest_flush_stale(data, digest, origin, creds);
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
