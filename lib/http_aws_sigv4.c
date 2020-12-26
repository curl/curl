/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_CRYPTO_AUTH)

#include "urldata.h"
#include "strcase.h"
#include "vauth/vauth.h"
#include "vauth/digest.h"
#include "http_aws_sigv4.h"
#include "curl_sha256.h"
#include "transfer.h"

#include "strcase.h"
#include "parsedate.h"
#include "sendf.h"

#include <time.h>

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define HMAC_SHA256(k, kl, d, dl, o)                                    \
  do {                                                                  \
    if(Curl_hmacit(Curl_HMAC_SHA256, (unsigned char *)k,                \
                   (unsigned int)kl,                                    \
                   (unsigned char *)d,                                  \
                   (unsigned int)dl, o) != CURLE_OK) {                  \
      ret = CURLE_OUT_OF_MEMORY;                                        \
      goto free_all;                                                    \
    }                                                                   \
  } while(0)

#define PROVIDER_MAX_L 16
#define REQUEST_TYPE_L (PROVIDER_MAX_L + sizeof("4_request"))
/* secret key is 40 bytes long + PROVIDER_MAX_L + \0 */
#define FULL_SK_L (PROVIDER_MAX_L + 40 + 1)

static void sha256_to_hex(char *dst, unsigned char *sha, size_t dst_l)
{
  int i;

  DEBUGASSERT(dst_l >= 65);
  for(i = 0; i < 32; ++i) {
    curl_msnprintf(dst + (i * 2), dst_l - (i * 2), "%02x", sha[i]);
  }
}

CURLcode Curl_output_aws_sigv4(struct connectdata *conn, bool proxy)
{
  CURLcode ret = CURLE_OK;
  char sk[FULL_SK_L] = {0};
  struct Curl_easy *data = conn->data;
  const char *customrequest = data->set.str[STRING_CUSTOMREQUEST];
  const char *hostname = data->state.up.hostname;
  struct tm info;
  time_t rawtime;
  /* aws is the default because some provider that are not amazone still use
   * aws:amz as prefix
   */
  const char *provider = data->set.str[STRING_AWS_SIGV4] ?
    data->set.str[STRING_AWS_SIGV4] : "aws:amz";
  size_t provider_l = strlen(provider);
  char low_provider0[PROVIDER_MAX_L + 1] = {0};
  char low_provider[PROVIDER_MAX_L + 1] = {0};
  char up_provider[PROVIDER_MAX_L + 1] = {0};
  char mid_provider[PROVIDER_MAX_L + 1] = {0};
  char *region = NULL;
  char *uri = NULL;
  char *api_type = NULL;
  char date_iso[17];
  char date[9];
  char date_str[64];
  const char *post_data = data->set.postfields ?
    data->set.postfields : "";
  const char *content_type = Curl_checkheaders(conn, "Content-Type");
  unsigned char sha_d[32];
  char sha_hex[65];
  char *cred_scope = NULL;
  char *signed_headers = NULL;
  char request_type[REQUEST_TYPE_L];
  char *canonical_hdr = NULL;
  char *canonical_request = NULL;
  char *str_to_sign = NULL;
  unsigned char tmp_sign0[32] = {0};
  unsigned char tmp_sign1[32] = {0};
  char *auth = NULL;
  char *tmp;
  #ifdef DEBUGBUILD
  char *force_timestamp;
  #endif

  DEBUGASSERT(!proxy);
  (void)proxy;

  if(Curl_checkheaders(conn, "Authorization")) {
    /* Authorization already present, Bailing out */
    return CURLE_OK;
  }

  if(content_type) {
    content_type = strchr(content_type, ':');
    if(!content_type)
      return CURLE_FAILED_INIT;
    content_type++;
    /* Skip whitespace now */
    while(*content_type == ' ' || *content_type == '\t')
      ++content_type;
  }

  /* Get Parameter
     Google and Outscale use the same OSC or GOOG,
     but Amazon use AWS and AMZ for header arguments */
  tmp = strchr(provider, ':');
  if(tmp) {
    provider_l = tmp - provider;
    if(provider_l >= PROVIDER_MAX_L) {
      infof(data, "v4 signature argument string too long\n");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    Curl_strntolower(low_provider0, provider, provider_l);
    Curl_strntoupper(up_provider, provider, provider_l);
    provider = tmp + 1;
    /* if "xxx:" was pass as parameter, tmp + 1 should point to \0 */
    provider_l = strlen(provider);
    if(provider_l >= PROVIDER_MAX_L) {
      infof(data, "v4 signature argument string too long\n");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    Curl_strntolower(low_provider, provider, provider_l);
    Curl_strntolower(mid_provider, provider, provider_l);
  }
  else if(provider_l <= PROVIDER_MAX_L) {
    Curl_strntolower(low_provider0, provider, provider_l);
    Curl_strntolower(low_provider, provider, provider_l);
    Curl_strntolower(mid_provider, provider, provider_l);
    Curl_strntoupper(up_provider, provider, provider_l);
    mid_provider[0] = Curl_raw_toupper(mid_provider[0]);
  }
  else {
    infof(data, "v4 signature argument string too long\n");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

#ifdef DEBUGBUILD
  force_timestamp = getenv("CURL_FORCETIME");
  if(force_timestamp)
    rawtime = 0;
  else
#endif
    time(&rawtime);

  ret = Curl_gmtime(rawtime, &info);
  if(ret != CURLE_OK) {
    return ret;
  }

  if(!strftime(date_iso, sizeof(date_iso), "%Y%m%dT%H%M%SZ", &info)) {
    return CURLE_OUT_OF_MEMORY;
  }

  memcpy(date, date_iso, sizeof(date));
  date[sizeof(date) - 1] = 0;
  api_type = strdup(hostname);
  if(!api_type) {
    ret = CURLE_OUT_OF_MEMORY;
    goto free_all;
  }

  tmp = strchr(api_type, '.');
  if(!tmp) {
    ret = CURLE_URL_MALFORMAT;
    goto free_all;
  }
  *tmp = 0;

  /* at worst, *(tmp + 1) is a '\0' */
  region = tmp + 1;

  tmp = strchr(region, '.');
  if(!tmp) {
    ret = CURLE_URL_MALFORMAT;
    goto free_all;
  }
  *tmp = 0;

  uri = data->state.up.path;

  if(!curl_msnprintf(request_type, REQUEST_TYPE_L, "%s4_request",
                     low_provider0)) {
    ret = CURLE_OUT_OF_MEMORY;
    goto free_all;
  }

  cred_scope = curl_maprintf("%s/%s/%s/%s", date, region, api_type,
                             request_type);
  if(!cred_scope) {
    ret = CURLE_OUT_OF_MEMORY;
    goto free_all;
  }

  if(content_type) {
    canonical_hdr = curl_maprintf(
      "content-type:%s\n"
      "host:%s\n"
      "x-%s-date:%s\n", content_type, hostname, low_provider, date_iso);
    signed_headers = curl_maprintf("content-type;host;x-%s-date",
                                   low_provider);
  }
  else if(data->state.up.query) {
    canonical_hdr = curl_maprintf(
      "host:%s\n"
      "x-%s-date:%s\n", hostname, low_provider, date_iso);
    signed_headers = curl_maprintf("host;x-%s-date", low_provider);
  }
  else {
    ret = CURLE_FAILED_INIT;
    goto free_all;
  }

  if(!canonical_hdr || !signed_headers) {
    ret = CURLE_OUT_OF_MEMORY;
    goto free_all;
  }

  Curl_sha256it(sha_d, (const unsigned char *)post_data, strlen(post_data));
  sha256_to_hex(sha_hex, sha_d, sizeof(sha_hex));

  canonical_request = curl_maprintf(
    "%s\n" /* Method */
    "%s\n" /* uri */
    "%s\n" /* querystring */
    "%s\n" /* canonical_headers */
    "%s\n" /* signed header */
    "%s" /* SHA ! */,
    customrequest, uri,
    data->state.up.query ? data->state.up.query : "",
    canonical_hdr, signed_headers, sha_hex);
  if(!canonical_request) {
    ret = CURLE_OUT_OF_MEMORY;
    goto free_all;
  }

  Curl_sha256it(sha_d, (unsigned char *)canonical_request,
                strlen(canonical_request));
  sha256_to_hex(sha_hex, sha_d, sizeof(sha_hex));

  /* Google allow to use rsa key instead of HMAC, so this code might change
   * In the furure, but for now we support only HMAC version
   */
  str_to_sign = curl_maprintf("%s4-HMAC-SHA256\n"
                              "%s\n%s\n%s",
                              up_provider, date_iso, cred_scope, sha_hex);
  if(!str_to_sign) {
    ret = CURLE_OUT_OF_MEMORY;
    goto free_all;
  }

  curl_msnprintf(sk, sizeof(sk) - 1, "%s4%s", up_provider,
                 data->set.str[STRING_PASSWORD]);

  HMAC_SHA256(sk, strlen(sk), date,
              strlen(date), tmp_sign0);
  sha256_to_hex(sha_hex, tmp_sign0, sizeof(sha_hex));

  HMAC_SHA256(tmp_sign0, sizeof(tmp_sign0), region,
              strlen(region), tmp_sign1);
  HMAC_SHA256(tmp_sign1, sizeof(tmp_sign1), api_type,
              strlen(api_type), tmp_sign0);
  HMAC_SHA256(tmp_sign0, sizeof(tmp_sign0), request_type,
              strlen(request_type),
              tmp_sign1);
  HMAC_SHA256(tmp_sign1, sizeof(tmp_sign1), str_to_sign,
              strlen(str_to_sign), tmp_sign0);

  sha256_to_hex(sha_hex, tmp_sign0, sizeof(sha_hex));

  auth = curl_maprintf("Authorization: %s4-HMAC-SHA256 Credential=%s/%s, "
                       "SignedHeaders=%s, Signature=%s",
                       up_provider, data->set.str[STRING_USERNAME], cred_scope,
                       signed_headers, sha_hex);
  if(!auth) {
    ret = CURLE_OUT_OF_MEMORY;
    goto free_all;
  }

  curl_msnprintf(date_str, sizeof(date_str), "X-%s-Date: %s",
                 mid_provider, date_iso);
  data->set.headers = curl_slist_append(data->set.headers, date_str);
  if(!data->set.headers) {
    ret = CURLE_FAILED_INIT;
    goto free_all;
  }
  data->set.headers = curl_slist_append(data->set.headers, auth);
  if(!data->set.headers) {
    ret = CURLE_FAILED_INIT;
    goto free_all;
  }
  data->state.authhost.done = 1;

free_all:
  free(canonical_request);
  free(signed_headers);
  free(str_to_sign);
  free(canonical_hdr);
  free(auth);
  free(cred_scope);
  free(api_type);
  return ret;
}

#endif /* !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_CRYPTO_AUTH) */
