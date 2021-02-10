/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2020 - 2021, Simon Josefsson, <simon@josefsson.org>, et al.
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
 * RFC5802 SCRAM-SHA-1 authentication
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_GSASL

#include <curl/curl.h>

#include "curl_base64.h"
#include "vauth/vauth.h"
#include "urldata.h"
#include "sendf.h"

#include <gsasl.h>

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

bool Curl_auth_gsasl_is_supported(struct Curl_easy *data,
                                  const char *mech,
                                  struct gsasldata *gsasl)
{
  int res;

  res = gsasl_init(&gsasl->ctx);
  if(res != GSASL_OK) {
    failf(data, "gsasl init: %s\n", gsasl_strerror(res));
    return FALSE;
  }

  res = gsasl_client_start(gsasl->ctx, mech, &gsasl->client);
  if(res != GSASL_OK) {
    gsasl_done(gsasl->ctx);
    return FALSE;
  }

  return true;
}

CURLcode Curl_auth_gsasl_start(struct Curl_easy *data,
                               const char *userp,
                               const char *passwdp,
                               struct gsasldata *gsasl)
{
#if GSASL_VERSION_NUMBER >= 0x010b00
  int res;
  res =
#endif
    gsasl_property_set(gsasl->client, GSASL_AUTHID, userp);
#if GSASL_VERSION_NUMBER >= 0x010b00
  if(res != GSASL_OK) {
    failf(data, "setting AUTHID failed: %s\n", gsasl_strerror(res));
    return CURLE_OUT_OF_MEMORY;
  }
#endif

#if GSASL_VERSION_NUMBER >= 0x010b00
  res =
#endif
    gsasl_property_set(gsasl->client, GSASL_PASSWORD, passwdp);
#if GSASL_VERSION_NUMBER >= 0x010b00
  if(res != GSASL_OK) {
    failf(data, "setting PASSWORD failed: %s\n", gsasl_strerror(res));
    return CURLE_OUT_OF_MEMORY;
  }
#endif

  (void)data;

  return CURLE_OK;
}

CURLcode Curl_auth_gsasl_token(struct Curl_easy *data,
                               const char *chlg64,
                               struct gsasldata *gsasl,
                               char **outptr, size_t *outlen)
{
  unsigned char *chlg = NULL;
  size_t chlglen = 0;
  CURLcode result = CURLE_OK;
  int res;
  char *response;

  if(chlg64) {
    result = Curl_base64_decode(chlg64, &chlg, &chlglen);
    if(result)
      return result;
  }

  res = gsasl_step(gsasl->client,
                   (const char *)chlg, chlglen, &response, outlen);
  if(res != GSASL_OK && res != GSASL_NEEDS_MORE) {
    if(chlg64)
      free(chlg);
    failf(data, "GSASL step: %s\n", gsasl_strerror(res));
    return CURLE_BAD_CONTENT_ENCODING;
  }

  if(*outlen > 0) {
    result = Curl_base64_encode(data, response, 0, outptr, outlen);
    gsasl_free(response);
  }
  else {
    *outptr = strdup("");
    if(!*outptr)
      result = CURLE_OUT_OF_MEMORY;
  }

  return result;
}

void Curl_auth_gsasl_cleanup(struct gsasldata *gsasl)
{
  gsasl_finish(gsasl->client);
  gsasl->client = NULL;

  gsasl_done(gsasl->ctx);
  gsasl->ctx = NULL;
}
#endif
