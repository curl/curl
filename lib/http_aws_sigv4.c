/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#define PROVIDER_MAX_L 16

#define HMAC_SHA256(k, kl, d, dl, o)        \
  do {                                      \
    ret = Curl_hmacit(Curl_HMAC_SHA256,     \
                      (unsigned char *)k,   \
                      (unsigned int)kl,     \
                      (unsigned char *)d,   \
                      (unsigned int)dl, o); \
    if(ret != CURLE_OK) {                   \
      goto fail;                            \
    }                                       \
  } while(0)

static void sha256_to_hex(char *dst, unsigned char *sha, size_t dst_l)
{
  int i;

  DEBUGASSERT(dst_l >= 65);
  for(i = 0; i < 32; ++i) {
    curl_msnprintf(dst + (i * 2), dst_l - (i * 2), "%02x", sha[i]);
  }
}

CURLcode Curl_output_aws_sigv4(struct Curl_easy *data, bool proxy)
{
  CURLcode ret = CURLE_OUT_OF_MEMORY;
  struct connectdata *conn = data->conn;
  size_t len;
  const char *tmp0;
  char *tmp1;
  char *provider0_low = NULL;
  char *provider0_up = NULL;
  char *provider1_low = NULL;
  char *provider1_mid = NULL;
  char *region = NULL;
  char *service = NULL;
  const char *hostname = data->state.up.hostname;
#ifdef DEBUGBUILD
  char *force_timestamp;
#endif
  time_t clock;
  struct tm tm;
  char timestamp[17];
  char date[9];
  const char *content_type = Curl_checkheaders(data, "Content-Type");
  char *canonical_headers = NULL;
  char *signed_headers = NULL;
  Curl_HttpReq httpreq;
  const char *method;
  const char *post_data = data->set.postfields ? data->set.postfields : "";
  unsigned char sha_hash[32];
  char sha_hex[65];
  char *canonical_request = NULL;
  char *request_type = NULL;
  char *credential_scope = NULL;
  char *str_to_sign = NULL;
  char *secret = NULL;
  unsigned char tmp_sign0[32] = {0};
  unsigned char tmp_sign1[32] = {0};
  char *auth_header = NULL;
  char *date_header = NULL;

  DEBUGASSERT(!proxy);
  (void)proxy;

  if(Curl_checkheaders(data, "Authorization")) {
    /* Authorization already present, Bailing out */
    return CURLE_OK;
  }

  /*
   * Parameters parsing
   * Google and Outscale use the same OSC or GOOG,
   * but Amazon uses AWS and AMZ for header arguments.
   * AWS is the default because most of non-amazon providers
   * are still using aws:amz as a prefix.
   */
  tmp0 = data->set.str[STRING_AWS_SIGV4] ?
    data->set.str[STRING_AWS_SIGV4] : "aws:amz";
  tmp1 = strchr(tmp0, ':');
  len = tmp1 ? tmp1 - tmp0 : strlen(tmp0);
  if(len > PROVIDER_MAX_L || len < 1) {
    infof(data, "wrong provider1 argument\n");
    ret = CURLE_BAD_FUNCTION_ARGUMENT;
    goto fail;
  }
  provider0_low = malloc(len + 1);
  provider0_up = malloc(len + 1);
  if(!provider0_low || !provider0_up) {
    goto fail;
  }
  Curl_strntolower(provider0_low, tmp0, len);
  provider0_low[len] = '\0';
  Curl_strntoupper(provider0_up, tmp0, len);
  provider0_up[len] = '\0';

  if(tmp1) {
    tmp0 = tmp1 + 1;
    tmp1 = strchr(tmp0, ':');
    len = tmp1 ? tmp1 - tmp0 : strlen(tmp0);
    if(len > PROVIDER_MAX_L || len < 1) {
      infof(data, "wrong provider2 argument\n");
      ret = CURLE_BAD_FUNCTION_ARGUMENT;
      goto fail;
    }
    provider1_low = malloc(len + 1);
    provider1_mid = malloc(len + 1);
    if(!provider1_low || !provider1_mid) {
      goto fail;
    }
    Curl_strntolower(provider1_low, tmp0, len);
    provider1_low[len] = '\0';
    Curl_strntolower(provider1_mid, tmp0, len);
    provider1_mid[0] = Curl_raw_toupper(provider1_mid[0]);
    provider1_mid[len] = '\0';

    if(tmp1) {
      tmp0 = tmp1 + 1;
      tmp1 = strchr(tmp0, ':');
      len = tmp1 ? tmp1 - tmp0 : strlen(tmp0);
      region = strndup(tmp0, len);
      if(!region) {
        goto fail;
      }

      if(tmp1) {
        tmp0 = tmp1 + 1;
        service = strdup(tmp0);
        if(!service) {
          goto fail;
        }
      }
    }
  }
  else {
    provider1_low = strndup(provider0_low, len);
    provider1_mid = strndup(provider0_low, len);
    if(!provider1_low || !provider1_mid) {
      goto fail;
    }
    provider1_mid[0] = Curl_raw_toupper(provider1_mid[0]);
  }

  if(!service) {
    tmp0 = hostname;
    tmp1 = strchr(tmp0, '.');
    if(!tmp1) {
      ret = CURLE_URL_MALFORMAT;
      goto fail;
    }
    service = strndup(tmp0, tmp1 - tmp0);
    if(!service) {
      goto fail;
    }

    if(!region) {
      tmp0 = tmp1 + 1;
      tmp1 = strchr(tmp0, '.');
      if(!tmp1) {
        ret = CURLE_URL_MALFORMAT;
        goto fail;
      }
      region = strndup(tmp0, tmp1 - tmp0);
      if(!region) {
        goto fail;
      }
    }
  }

#ifdef DEBUGBUILD
  force_timestamp = getenv("CURL_FORCETIME");
  if(force_timestamp)
    clock = 0;
  else
    time(&clock);
#else
  time(&clock);
#endif
  ret = Curl_gmtime(clock, &tm);
  if(ret != CURLE_OK) {
    goto fail;
  }
  if(!strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%SZ", &tm)) {
    goto fail;
  }
  memcpy(date, timestamp, sizeof(date));
  date[sizeof(date) - 1] = 0;

  if(content_type) {
    content_type = strchr(content_type, ':');
    if(!content_type) {
      ret = CURLE_FAILED_INIT;
      goto fail;
    }
    content_type++;
    /* Skip whitespace now */
    while(*content_type == ' ' || *content_type == '\t')
      ++content_type;

    canonical_headers = curl_maprintf("content-type:%s\n"
                                      "host:%s\n"
                                      "x-%s-date:%s\n",
                                      content_type,
                                      hostname,
                                      provider1_low, timestamp);
    signed_headers = curl_maprintf("content-type;host;x-%s-date",
                                   provider1_low);
  }
  else {
    canonical_headers = curl_maprintf("host:%s\n"
                                      "x-%s-date:%s\n",
                                      hostname,
                                      provider1_low, timestamp);
    signed_headers = curl_maprintf("host;x-%s-date", provider1_low);
  }

  if(!canonical_headers || !signed_headers) {
    goto fail;
  }

  Curl_sha256it(sha_hash,
                (const unsigned char *) post_data, strlen(post_data));
  sha256_to_hex(sha_hex, sha_hash, sizeof(sha_hex));

  Curl_http_method(data, conn, &method, &httpreq);

  canonical_request =
    curl_maprintf("%s\n" /* HTTPRequestMethod */
                  "%s\n" /* CanonicalURI */
                  "%s\n" /* CanonicalQueryString */
                  "%s\n" /* CanonicalHeaders */
                  "%s\n" /* SignedHeaders */
                  "%s",  /* HashedRequestPayload in hex */
                  method,
                  data->state.up.path,
                  data->state.up.query ? data->state.up.query : "",
                  canonical_headers,
                  signed_headers,
                  sha_hex);
  if(!canonical_request) {
    goto fail;
  }

  request_type = curl_maprintf("%s4_request", provider0_low);
  if(!request_type) {
    goto fail;
  }

  credential_scope = curl_maprintf("%s/%s/%s/%s",
                                   date, region, service, request_type);
  if(!credential_scope) {
    goto fail;
  }

  Curl_sha256it(sha_hash, (unsigned char *) canonical_request,
                strlen(canonical_request));
  sha256_to_hex(sha_hex, sha_hash, sizeof(sha_hex));

/* Google allow to use rsa key instead of HMAC, so this code might change
 * In the furure, but for now we support only HMAC version
 */
  str_to_sign = curl_maprintf("%s4-HMAC-SHA256\n" /* Algorithm */
                              "%s\n" /* RequestDateTime */
                              "%s\n" /* CredentialScope */
                              "%s",  /* HashedCanonicalRequest in hex */
                              provider0_up,
                              timestamp,
                              credential_scope,
                              sha_hex);
  if(!str_to_sign) {
    goto fail;
  }

  secret = curl_maprintf("%s4%s",
                         provider0_up, data->set.str[STRING_PASSWORD]);
  if(!secret) {
    goto fail;
  }

  HMAC_SHA256(secret, strlen(secret),
              date, strlen(date), tmp_sign0);
  HMAC_SHA256(tmp_sign0, sizeof(tmp_sign0),
              region, strlen(region), tmp_sign1);
  HMAC_SHA256(tmp_sign1, sizeof(tmp_sign1),
              service, strlen(service), tmp_sign0);
  HMAC_SHA256(tmp_sign0, sizeof(tmp_sign0),
              request_type, strlen(request_type), tmp_sign1);
  HMAC_SHA256(tmp_sign1, sizeof(tmp_sign1),
              str_to_sign, strlen(str_to_sign), tmp_sign0);

  sha256_to_hex(sha_hex, tmp_sign0, sizeof(sha_hex));

  auth_header = curl_maprintf("Authorization: %s4-HMAC-SHA256 "
                              "Credential=%s/%s, "
                              "SignedHeaders=%s, "
                              "Signature=%s",
                              provider0_up,
                              data->set.str[STRING_USERNAME],
                              credential_scope,
                              signed_headers,
                              sha_hex);
  if(!auth_header) {
    goto fail;
  }

  data->set.headers = curl_slist_append(data->set.headers, auth_header);
  if(!data->set.headers) {
    ret = CURLE_FAILED_INIT;
    goto fail;
  }

  date_header = curl_maprintf("X-%s-Date: %s", provider1_mid, timestamp);
  if(!date_header) {
    goto fail;
  }

  data->set.headers = curl_slist_append(data->set.headers, date_header);
  if(!data->set.headers) {
    ret = CURLE_FAILED_INIT;
    goto fail;
  }

  data->state.authhost.done = 1;
  ret = CURLE_OK;

fail:
  free(provider0_low);
  free(provider0_up);
  free(provider1_low);
  free(provider1_mid);
  free(region);
  free(service);
  free(canonical_headers);
  free(signed_headers);
  free(canonical_request);
  free(request_type);
  free(credential_scope);
  free(str_to_sign);
  free(secret);
  free(auth_header);
  free(date_header);
  return ret;
}

#endif /* !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_CRYPTO_AUTH) */
