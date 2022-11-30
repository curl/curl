/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_CRYPTO_AUTH)

#include "urldata.h"
#include "strcase.h"
#include "strdup.h"
#include "http_aws_sigv4.h"
#include "curl_sha256.h"
#include "transfer.h"
#include "parsedate.h"
#include "sendf.h"

#include <time.h>

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#include "slist.h"

#define HMAC_SHA256(k, kl, d, dl, o)        \
  do {                                      \
    ret = Curl_hmacit(Curl_HMAC_SHA256,     \
                      (unsigned char *)k,   \
                      (unsigned int)kl,     \
                      (unsigned char *)d,   \
                      (unsigned int)dl, o); \
    if(ret) {                               \
      goto fail;                            \
    }                                       \
  } while(0)

#define TIMESTAMP_SIZE 17

static void sha256_to_hex(char *dst, unsigned char *sha, size_t dst_l)
{
  int i;

  DEBUGASSERT(dst_l >= 65);
  for(i = 0; i < 32; ++i) {
    msnprintf(dst + (i * 2), dst_l - (i * 2), "%02x", sha[i]);
  }
}

static char *find_date_hdr(struct Curl_easy *data, const char *sig_hdr)
{
  char *tmp = Curl_checkheaders(data, sig_hdr, strlen(sig_hdr));

  if(tmp)
    return tmp;
  return Curl_checkheaders(data, STRCONST("Date"));
}

/* remove whitespace, and lowercase all headers */
static void trim_headers(struct curl_slist *head)
{
  struct curl_slist *l;
  for(l = head; l; l = l->next) {
    char *value; /* to read from */
    char *store;
    size_t colon = strcspn(l->data, ":");
    Curl_strntolower(l->data, l->data, colon);

    value = &l->data[colon];
    if(!*value)
      continue;
    ++value;
    store = value;

    /* skip leading whitespace */
    while(*value && ISBLANK(*value))
      value++;

    while(*value) {
      int space = 0;
      while(*value && ISBLANK(*value)) {
        value++;
        space++;
      }
      if(space) {
        /* replace any number of consecutive whitespace with a single space,
           unless at the end of the string, then nothing */
        if(*value)
          *store++ = ' ';
      }
      else
        *store++ = *value++;
    }
    *store = 0; /* null terminate */
  }
}

/* maximum length for the aws sivg4 parts */
#define MAX_SIGV4_LEN 64
#define MAX_SIGV4_LEN_TXT "64"

#define DATE_HDR_KEY_LEN (MAX_SIGV4_LEN + sizeof("X--Date"))

#define MAX_HOST_LEN 255
/* FQDN + host: */
#define FULL_HOST_LEN (MAX_HOST_LEN + sizeof("host:"))

/* string been x-PROVIDER-date:TIMESTAMP, I need +1 for ':' */
#define DATE_FULL_HDR_LEN (DATE_HDR_KEY_LEN + TIMESTAMP_SIZE + 1)

/* timestamp should point to a buffer of at last TIMESTAMP_SIZE bytes */
static CURLcode make_headers(struct Curl_easy *data,
                             const char *hostname,
                             char *timestamp,
                             char *provider1,
                             char **date_header,
                             struct dynbuf *canonical_headers,
                             struct dynbuf *signed_headers)
{
  char date_hdr_key[DATE_HDR_KEY_LEN];
  char date_full_hdr[DATE_FULL_HDR_LEN];
  struct curl_slist *head = NULL;
  struct curl_slist *tmp_head = NULL;
  CURLcode ret = CURLE_OUT_OF_MEMORY;
  struct curl_slist *l;
  int again = 1;

  /* provider1 mid */
  Curl_strntolower(provider1, provider1, strlen(provider1));
  provider1[0] = Curl_raw_toupper(provider1[0]);

  msnprintf(date_hdr_key, DATE_HDR_KEY_LEN, "X-%s-Date", provider1);

  /* provider1 lowercase */
  Curl_strntolower(provider1, provider1, 1); /* first byte only */
  msnprintf(date_full_hdr, DATE_FULL_HDR_LEN,
            "x-%s-date:%s", provider1, timestamp);

  if(Curl_checkheaders(data, STRCONST("Host"))) {
    head = NULL;
  }
  else {
    char full_host[FULL_HOST_LEN + 1];

    if(data->state.aptr.host) {
      size_t pos;

      if(strlen(data->state.aptr.host) > FULL_HOST_LEN) {
        ret = CURLE_URL_MALFORMAT;
        goto fail;
      }
      strcpy(full_host, data->state.aptr.host);
      /* remove /r/n as the separator for canonical request must be '\n' */
      pos = strcspn(full_host, "\n\r");
      full_host[pos] = 0;
    }
    else {
      if(strlen(hostname) > MAX_HOST_LEN) {
        ret = CURLE_URL_MALFORMAT;
        goto fail;
      }
      msnprintf(full_host, FULL_HOST_LEN, "host:%s", hostname);
    }

    head = curl_slist_append(NULL, full_host);
    if(!head)
      goto fail;
  }


  for(l = data->set.headers; l; l = l->next) {
    tmp_head = curl_slist_append(head, l->data);
    if(!tmp_head)
      goto fail;
    head = tmp_head;
  }

  trim_headers(head);

  *date_header = find_date_hdr(data, date_hdr_key);
  if(!*date_header) {
    tmp_head = curl_slist_append(head, date_full_hdr);
    if(!tmp_head)
      goto fail;
    head = tmp_head;
    *date_header = curl_maprintf("%s: %s", date_hdr_key, timestamp);
  }
  else {
    char *value;

    *date_header = strdup(*date_header);
    if(!*date_header)
      goto fail;

    value = strchr(*date_header, ':');
    if(!value)
      goto fail;
    ++value;
    while(ISBLANK(*value))
      ++value;
    strncpy(timestamp, value, TIMESTAMP_SIZE - 1);
    timestamp[TIMESTAMP_SIZE - 1] = 0;
  }

  /* alpha-sort in a case sensitive manner */
  do {
    again = 0;
    for(l = head; l; l = l->next) {
      struct curl_slist *next = l->next;

      if(next && strcmp(l->data, next->data) > 0) {
        char *tmp = l->data;

        l->data = next->data;
        next->data = tmp;
        again = 1;
      }
    }
  } while(again);

  for(l = head; l; l = l->next) {
    char *tmp;

    if(Curl_dyn_add(canonical_headers, l->data))
      goto fail;
    if(Curl_dyn_add(canonical_headers, "\n"))
      goto fail;

    tmp = strchr(l->data, ':');
    if(tmp)
      *tmp = 0;

    if(l != head) {
      if(Curl_dyn_add(signed_headers, ";"))
        goto fail;
    }
    if(Curl_dyn_add(signed_headers, l->data))
      goto fail;
  }

  ret = CURLE_OK;
fail:
  curl_slist_free_all(head);

  return ret;
}

#define CONTENT_SHA256_KEY_LEN (MAX_SIGV4_LEN + sizeof("X--Content-Sha256"))

/* try to parse a payload hash from the content-sha256 header */
static char *parse_content_sha_hdr(struct Curl_easy *data,
                                   const char *provider1,
                                   size_t *value_len)
{
  char key[CONTENT_SHA256_KEY_LEN];
  size_t key_len;
  char *value;
  size_t len;

  key_len = msnprintf(key, sizeof(key), "x-%s-content-sha256", provider1);

  value = Curl_checkheaders(data, key, key_len);
  if(!value)
    return NULL;

  value = strchr(value, ':');
  if(!value)
    return NULL;
  ++value;

  while(*value && ISBLANK(*value))
    ++value;

  len = strlen(value);
  while(len > 0 && ISBLANK(value[len-1]))
    --len;

  *value_len = len;
  return value;
}

CURLcode Curl_output_aws_sigv4(struct Curl_easy *data, bool proxy)
{
  CURLcode ret = CURLE_OUT_OF_MEMORY;
  struct connectdata *conn = data->conn;
  size_t len;
  const char *arg;
  char provider0[MAX_SIGV4_LEN + 1]="";
  char provider1[MAX_SIGV4_LEN + 1]="";
  char region[MAX_SIGV4_LEN + 1]="";
  char service[MAX_SIGV4_LEN + 1]="";
  const char *hostname = conn->host.name;
  time_t clock;
  struct tm tm;
  char timestamp[TIMESTAMP_SIZE];
  char date[9];
  struct dynbuf canonical_headers;
  struct dynbuf signed_headers;
  char *date_header = NULL;
  char *payload_hash = NULL;
  size_t payload_hash_len = 0;
  const char *post_data = data->set.postfields;
  size_t post_data_len = 0;
  unsigned char sha_hash[32];
  char sha_hex[65];
  char *canonical_request = NULL;
  char *request_type = NULL;
  char *credential_scope = NULL;
  char *str_to_sign = NULL;
  const char *user = data->state.aptr.user ? data->state.aptr.user : "";
  char *secret = NULL;
  unsigned char sign0[32] = {0};
  unsigned char sign1[32] = {0};
  char *auth_headers = NULL;

  DEBUGASSERT(!proxy);
  (void)proxy;

  if(Curl_checkheaders(data, STRCONST("Authorization"))) {
    /* Authorization already present, Bailing out */
    return CURLE_OK;
  }

  /* we init those buffers here, so goto fail will free initialized dynbuf */
  Curl_dyn_init(&canonical_headers, CURL_MAX_HTTP_HEADER);
  Curl_dyn_init(&signed_headers, CURL_MAX_HTTP_HEADER);

  /*
   * Parameters parsing
   * Google and Outscale use the same OSC or GOOG,
   * but Amazon uses AWS and AMZ for header arguments.
   * AWS is the default because most of non-amazon providers
   * are still using aws:amz as a prefix.
   */
  arg = data->set.str[STRING_AWS_SIGV4] ?
    data->set.str[STRING_AWS_SIGV4] : "aws:amz";

  /* provider1[:provider2[:region[:service]]]

     No string can be longer than N bytes of non-whitespace
   */
  (void)sscanf(arg, "%" MAX_SIGV4_LEN_TXT "[^:]"
               ":%" MAX_SIGV4_LEN_TXT "[^:]"
               ":%" MAX_SIGV4_LEN_TXT "[^:]"
               ":%" MAX_SIGV4_LEN_TXT "s",
               provider0, provider1, region, service);
  if(!provider0[0]) {
    failf(data, "first provider can't be empty");
    ret = CURLE_BAD_FUNCTION_ARGUMENT;
    goto fail;
  }
  else if(!provider1[0])
    strcpy(provider1, provider0);

  if(!service[0]) {
    char *hostdot = strchr(hostname, '.');
    if(!hostdot) {
      failf(data, "service missing in parameters and hostname");
      ret = CURLE_URL_MALFORMAT;
      goto fail;
    }
    len = hostdot - hostname;
    if(len > MAX_SIGV4_LEN) {
      failf(data, "service too long in hostname");
      ret = CURLE_URL_MALFORMAT;
      goto fail;
    }
    strncpy(service, hostname, len);
    service[len] = '\0';

    if(!region[0]) {
      const char *reg = hostdot + 1;
      const char *hostreg = strchr(reg, '.');
      if(!hostreg) {
        failf(data, "region missing in parameters and hostname");
        ret = CURLE_URL_MALFORMAT;
        goto fail;
      }
      len = hostreg - reg;
      if(len > MAX_SIGV4_LEN) {
        failf(data, "region too long in hostname");
        ret = CURLE_URL_MALFORMAT;
        goto fail;
      }
      strncpy(region, reg, len);
      region[len] = '\0';
    }
  }

#ifdef DEBUGBUILD
  {
    char *force_timestamp = getenv("CURL_FORCETIME");
    if(force_timestamp)
      clock = 0;
    else
      time(&clock);
  }
#else
  time(&clock);
#endif
  ret = Curl_gmtime(clock, &tm);
  if(ret) {
    goto fail;
  }
  if(!strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%SZ", &tm)) {
    ret = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  ret = make_headers(data, hostname, timestamp, provider1,
                     &date_header, &canonical_headers, &signed_headers);
  if(ret)
    goto fail;
  ret = CURLE_OUT_OF_MEMORY;

  memcpy(date, timestamp, sizeof(date));
  date[sizeof(date) - 1] = 0;

  payload_hash = parse_content_sha_hdr(data, provider1, &payload_hash_len);

  if(!payload_hash) {
    if(post_data) {
      if(data->set.postfieldsize < 0)
        post_data_len = strlen(post_data);
      else
        post_data_len = (size_t)data->set.postfieldsize;
    }
    if(Curl_sha256it(sha_hash, (const unsigned char *) post_data,
                     post_data_len))
      goto fail;

    sha256_to_hex(sha_hex, sha_hash, sizeof(sha_hex));
    payload_hash = sha_hex;
    payload_hash_len = strlen(sha_hex);
  }

  {
    Curl_HttpReq httpreq;
    const char *method;

    Curl_http_method(data, conn, &method, &httpreq);

    canonical_request =
      curl_maprintf("%s\n" /* HTTPRequestMethod */
                    "%s\n" /* CanonicalURI */
                    "%s\n" /* CanonicalQueryString */
                    "%s\n" /* CanonicalHeaders */
                    "%s\n" /* SignedHeaders */
                    "%.*s",  /* HashedRequestPayload in hex */
                    method,
                    data->state.up.path,
                    data->state.up.query ? data->state.up.query : "",
                    Curl_dyn_ptr(&canonical_headers),
                    Curl_dyn_ptr(&signed_headers),
                    (int)payload_hash_len, payload_hash);
    if(!canonical_request)
      goto fail;
  }

  /* provider 0 lowercase */
  Curl_strntolower(provider0, provider0, strlen(provider0));
  request_type = curl_maprintf("%s4_request", provider0);
  if(!request_type)
    goto fail;

  credential_scope = curl_maprintf("%s/%s/%s/%s",
                                   date, region, service, request_type);
  if(!credential_scope)
    goto fail;

  if(Curl_sha256it(sha_hash, (unsigned char *) canonical_request,
                   strlen(canonical_request)))
    goto fail;

  sha256_to_hex(sha_hex, sha_hash, sizeof(sha_hex));

  /* provider 0 uppercase */
  Curl_strntoupper(provider0, provider0, strlen(provider0));

  /*
   * Google allows using RSA key instead of HMAC, so this code might change
   * in the future. For now we only support HMAC.
   */
  str_to_sign = curl_maprintf("%s4-HMAC-SHA256\n" /* Algorithm */
                              "%s\n" /* RequestDateTime */
                              "%s\n" /* CredentialScope */
                              "%s",  /* HashedCanonicalRequest in hex */
                              provider0,
                              timestamp,
                              credential_scope,
                              sha_hex);
  if(!str_to_sign) {
    goto fail;
  }

  /* provider 0 uppercase */
  secret = curl_maprintf("%s4%s", provider0,
                         data->state.aptr.passwd ?
                         data->state.aptr.passwd : "");
  if(!secret)
    goto fail;

  HMAC_SHA256(secret, strlen(secret), date, strlen(date), sign0);
  HMAC_SHA256(sign0, sizeof(sign0), region, strlen(region), sign1);
  HMAC_SHA256(sign1, sizeof(sign1), service, strlen(service), sign0);
  HMAC_SHA256(sign0, sizeof(sign0), request_type, strlen(request_type), sign1);
  HMAC_SHA256(sign1, sizeof(sign1), str_to_sign, strlen(str_to_sign), sign0);

  sha256_to_hex(sha_hex, sign0, sizeof(sha_hex));

  /* provider 0 uppercase */
  auth_headers = curl_maprintf("Authorization: %s4-HMAC-SHA256 "
                               "Credential=%s/%s, "
                               "SignedHeaders=%s, "
                               "Signature=%s\r\n"
                               "%s\r\n",
                               provider0,
                               user,
                               credential_scope,
                               Curl_dyn_ptr(&signed_headers),
                               sha_hex,
                               date_header);
  if(!auth_headers) {
    goto fail;
  }

  Curl_safefree(data->state.aptr.userpwd);
  data->state.aptr.userpwd = auth_headers;
  data->state.authhost.done = TRUE;
  ret = CURLE_OK;

fail:
  Curl_dyn_free(&canonical_headers);
  Curl_dyn_free(&signed_headers);
  free(canonical_request);
  free(request_type);
  free(credential_scope);
  free(str_to_sign);
  free(secret);
  free(date_header);
  return ret;
}

#endif /* !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_CRYPTO_AUTH) */
