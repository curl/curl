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

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS)

#include "urldata.h"
#include "strcase.h"
#include "strdup.h"
#include "http_aws_sigv4.h"
#include "curl_sha256.h"
#include "transfer.h"
#include "parsedate.h"
#include "sendf.h"
#include "escape.h"

#include <time.h>

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#include "slist.h"

#define HMAC_SHA256(k, kl, d, dl, o)           \
  do {                                         \
    result = Curl_hmacit(Curl_HMAC_SHA256,     \
                         (unsigned char *)k,   \
                         kl,                   \
                         (unsigned char *)d,   \
                         dl, o);               \
    if(result) {                               \
      goto fail;                               \
    }                                          \
  } while(0)

#define TIMESTAMP_SIZE 17

/* hex-encoded with trailing null */
#define SHA256_HEX_LENGTH (2 * SHA256_DIGEST_LENGTH + 1)

static void sha256_to_hex(char *dst, unsigned char *sha)
{
  Curl_hexencode(sha, SHA256_DIGEST_LENGTH,
                 (unsigned char *)dst, SHA256_HEX_LENGTH);
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
                             char *content_sha256_header,
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


  if(*content_sha256_header) {
    tmp_head = curl_slist_append(head, content_sha256_header);
    if(!tmp_head)
      goto fail;
    head = tmp_head;
  }

  /* copy user headers to our header list. the logic is based on how http.c
     handles user headers.

     user headers in format 'name:' with no value are used to signal that an
     internal header of that name should be removed. those user headers are not
     added to this list.

     user headers in format 'name;' with no value are used to signal that a
     header of that name with no value should be sent. those user headers are
     added to this list but in the format that they will be sent, ie the
     semi-colon is changed to a colon for format 'name:'.

     user headers with a value of whitespace only, or without a colon or
     semi-colon, are not added to this list.
     */
  for(l = data->set.headers; l; l = l->next) {
    char *dupdata, *ptr;
    char *sep = strchr(l->data, ':');
    if(!sep)
      sep = strchr(l->data, ';');
    if(!sep || (*sep == ':' && !*(sep + 1)))
      continue;
    for(ptr = sep + 1; ISSPACE(*ptr); ++ptr)
      ;
    if(!*ptr && ptr != sep + 1) /* a value of whitespace only */
      continue;
    dupdata = strdup(l->data);
    if(!dupdata)
      goto fail;
    dupdata[sep - l->data] = ':';
    tmp_head = Curl_slist_append_nodup(head, dupdata);
    if(!tmp_head) {
      free(dupdata);
      goto fail;
    }
    head = tmp_head;
  }

  trim_headers(head);

  *date_header = find_date_hdr(data, date_hdr_key);
  if(!*date_header) {
    tmp_head = curl_slist_append(head, date_full_hdr);
    if(!tmp_head)
      goto fail;
    head = tmp_head;
    *date_header = curl_maprintf("%s: %s\r\n", date_hdr_key, timestamp);
  }
  else {
    char *value;
    char *endp;
    value = strchr(*date_header, ':');
    if(!value) {
      *date_header = NULL;
      goto fail;
    }
    ++value;
    while(ISBLANK(*value))
      ++value;
    endp = value;
    while(*endp && ISALNUM(*endp))
      ++endp;
    /* 16 bytes => "19700101T000000Z" */
    if((endp - value) == TIMESTAMP_SIZE - 1) {
      memcpy(timestamp, value, TIMESTAMP_SIZE - 1);
      timestamp[TIMESTAMP_SIZE - 1] = 0;
    }
    else
      /* bad timestamp length */
      timestamp[0] = 0;
    *date_header = NULL;
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
/* add 2 for ": " between header name and value */
#define CONTENT_SHA256_HDR_LEN (CONTENT_SHA256_KEY_LEN + 2 + \
                                SHA256_HEX_LENGTH)

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

static CURLcode calc_payload_hash(struct Curl_easy *data,
                                  unsigned char *sha_hash, char *sha_hex)
{
  const char *post_data = data->set.postfields;
  size_t post_data_len = 0;
  CURLcode result;

  if(post_data) {
    if(data->set.postfieldsize < 0)
      post_data_len = strlen(post_data);
    else
      post_data_len = (size_t)data->set.postfieldsize;
  }
  result = Curl_sha256it(sha_hash, (const unsigned char *) post_data,
                         post_data_len);
  if(!result)
    sha256_to_hex(sha_hex, sha_hash);
  return result;
}

#define S3_UNSIGNED_PAYLOAD "UNSIGNED-PAYLOAD"

static CURLcode calc_s3_payload_hash(struct Curl_easy *data,
                                     Curl_HttpReq httpreq, char *provider1,
                                     unsigned char *sha_hash,
                                     char *sha_hex, char *header)
{
  bool empty_method = (httpreq == HTTPREQ_GET || httpreq == HTTPREQ_HEAD);
  /* The request method or filesize indicate no request payload */
  bool empty_payload = (empty_method || data->set.filesize == 0);
  /* The POST payload is in memory */
  bool post_payload = (httpreq == HTTPREQ_POST && data->set.postfields);
  CURLcode ret = CURLE_OUT_OF_MEMORY;

  if(empty_payload || post_payload) {
    /* Calculate a real hash when we know the request payload */
    ret = calc_payload_hash(data, sha_hash, sha_hex);
    if(ret)
      goto fail;
  }
  else {
    /* Fall back to s3's UNSIGNED-PAYLOAD */
    size_t len = sizeof(S3_UNSIGNED_PAYLOAD) - 1;
    DEBUGASSERT(len < SHA256_HEX_LENGTH); /* 16 < 65 */
    memcpy(sha_hex, S3_UNSIGNED_PAYLOAD, len);
    sha_hex[len] = 0;
  }

  /* format the required content-sha256 header */
  msnprintf(header, CONTENT_SHA256_HDR_LEN,
            "x-%s-content-sha256: %s", provider1, sha_hex);

  ret = CURLE_OK;
fail:
  return ret;
}

struct pair {
  const char *p;
  size_t len;
};

static int compare_func(const void *a, const void *b)
{
  const struct pair *aa = a;
  const struct pair *bb = b;
  /* If one element is empty, the other is always sorted higher */
  if(aa->len == 0)
    return -1;
  if(bb->len == 0)
    return 1;
  return strncmp(aa->p, bb->p, aa->len < bb->len ? aa->len : bb->len);
}

#define MAX_QUERYPAIRS 64

static CURLcode canon_query(struct Curl_easy *data,
                            const char *query, struct dynbuf *dq)
{
  CURLcode result = CURLE_OK;
  int entry = 0;
  int i;
  const char *p = query;
  struct pair array[MAX_QUERYPAIRS];
  struct pair *ap = &array[0];
  if(!query)
    return result;

  /* sort the name=value pairs first */
  do {
    char *amp;
    entry++;
    ap->p = p;
    amp = strchr(p, '&');
    if(amp)
      ap->len = amp - p; /* excluding the ampersand */
    else {
      ap->len = strlen(p);
      break;
    }
    ap++;
    p = amp + 1;
  } while(entry < MAX_QUERYPAIRS);
  if(entry == MAX_QUERYPAIRS) {
    /* too many query pairs for us */
    failf(data, "aws-sigv4: too many query pairs in URL");
    return CURLE_URL_MALFORMAT;
  }

  qsort(&array[0], entry, sizeof(struct pair), compare_func);

  ap = &array[0];
  for(i = 0; !result && (i < entry); i++, ap++) {
    size_t len;
    const char *q = ap->p;
    bool found_equals = false;
    if(!ap->len)
      continue;
    for(len = ap->len; len && !result; q++, len--) {
      if(ISALNUM(*q))
        result = Curl_dyn_addn(dq, q, 1);
      else {
        switch(*q) {
        case '-':
        case '.':
        case '_':
        case '~':
          /* allowed as-is */
          result = Curl_dyn_addn(dq, q, 1);
          break;
        case '=':
          /* allowed as-is */
          result = Curl_dyn_addn(dq, q, 1);
          found_equals = true;
          break;
        case '%':
          /* uppercase the following if hexadecimal */
          if(ISXDIGIT(q[1]) && ISXDIGIT(q[2])) {
            char tmp[3]="%";
            tmp[1] = Curl_raw_toupper(q[1]);
            tmp[2] = Curl_raw_toupper(q[2]);
            result = Curl_dyn_addn(dq, tmp, 3);
            q += 2;
            len -= 2;
          }
          else
            /* '%' without a following two-digit hex, encode it */
            result = Curl_dyn_addn(dq, "%25", 3);
          break;
        default: {
          /* URL encode */
          const char hex[] = "0123456789ABCDEF";
          char out[3]={'%'};
          out[1] = hex[((unsigned char)*q)>>4];
          out[2] = hex[*q & 0xf];
          result = Curl_dyn_addn(dq, out, 3);
          break;
        }
        }
      }
    }
    if(!result && !found_equals) {
      /* queries without value still need an equals */
      result = Curl_dyn_addn(dq, "=", 1);
    }
    if(!result && i < entry - 1) {
      /* insert ampersands between query pairs */
      result = Curl_dyn_addn(dq, "&", 1);
    }
  }
  return result;
}


CURLcode Curl_output_aws_sigv4(struct Curl_easy *data, bool proxy)
{
  CURLcode result = CURLE_OUT_OF_MEMORY;
  struct connectdata *conn = data->conn;
  size_t len;
  const char *arg;
  char provider0[MAX_SIGV4_LEN + 1]="";
  char provider1[MAX_SIGV4_LEN + 1]="";
  char region[MAX_SIGV4_LEN + 1]="";
  char service[MAX_SIGV4_LEN + 1]="";
  bool sign_as_s3 = false;
  const char *hostname = conn->host.name;
  time_t clock;
  struct tm tm;
  char timestamp[TIMESTAMP_SIZE];
  char date[9];
  struct dynbuf canonical_headers;
  struct dynbuf signed_headers;
  struct dynbuf canonical_query;
  char *date_header = NULL;
  Curl_HttpReq httpreq;
  const char *method = NULL;
  char *payload_hash = NULL;
  size_t payload_hash_len = 0;
  unsigned char sha_hash[SHA256_DIGEST_LENGTH];
  char sha_hex[SHA256_HEX_LENGTH];
  char content_sha256_hdr[CONTENT_SHA256_HDR_LEN + 2] = ""; /* add \r\n */
  char *canonical_request = NULL;
  char *request_type = NULL;
  char *credential_scope = NULL;
  char *str_to_sign = NULL;
  const char *user = data->state.aptr.user ? data->state.aptr.user : "";
  char *secret = NULL;
  unsigned char sign0[SHA256_DIGEST_LENGTH] = {0};
  unsigned char sign1[SHA256_DIGEST_LENGTH] = {0};
  char *auth_headers = NULL;

  DEBUGASSERT(!proxy);
  (void)proxy;

  if(Curl_checkheaders(data, STRCONST("Authorization"))) {
    /* Authorization already present, Bailing out */
    return CURLE_OK;
  }

  /* we init those buffers here, so goto fail will free initialized dynbuf */
  Curl_dyn_init(&canonical_headers, CURL_MAX_HTTP_HEADER);
  Curl_dyn_init(&canonical_query, CURL_MAX_HTTP_HEADER);
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
    failf(data, "first aws-sigv4 provider can't be empty");
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto fail;
  }
  else if(!provider1[0])
    strcpy(provider1, provider0);

  if(!service[0]) {
    char *hostdot = strchr(hostname, '.');
    if(!hostdot) {
      failf(data, "aws-sigv4: service missing in parameters and hostname");
      result = CURLE_URL_MALFORMAT;
      goto fail;
    }
    len = hostdot - hostname;
    if(len > MAX_SIGV4_LEN) {
      failf(data, "aws-sigv4: service too long in hostname");
      result = CURLE_URL_MALFORMAT;
      goto fail;
    }
    memcpy(service, hostname, len);
    service[len] = '\0';

    infof(data, "aws_sigv4: picked service %s from host", service);

    if(!region[0]) {
      const char *reg = hostdot + 1;
      const char *hostreg = strchr(reg, '.');
      if(!hostreg) {
        failf(data, "aws-sigv4: region missing in parameters and hostname");
        result = CURLE_URL_MALFORMAT;
        goto fail;
      }
      len = hostreg - reg;
      if(len > MAX_SIGV4_LEN) {
        failf(data, "aws-sigv4: region too long in hostname");
        result = CURLE_URL_MALFORMAT;
        goto fail;
      }
      memcpy(region, reg, len);
      region[len] = '\0';
      infof(data, "aws_sigv4: picked region %s from host", region);
    }
  }

  Curl_http_method(data, conn, &method, &httpreq);

  /* AWS S3 requires a x-amz-content-sha256 header, and supports special
   * values like UNSIGNED-PAYLOAD */
  sign_as_s3 = (strcasecompare(provider0, "aws") &&
                strcasecompare(service, "s3"));

  payload_hash = parse_content_sha_hdr(data, provider1, &payload_hash_len);

  if(!payload_hash) {
    if(sign_as_s3)
      result = calc_s3_payload_hash(data, httpreq, provider1, sha_hash,
                                    sha_hex, content_sha256_hdr);
    else
      result = calc_payload_hash(data, sha_hash, sha_hex);
    if(result)
      goto fail;

    payload_hash = sha_hex;
    /* may be shorter than SHA256_HEX_LENGTH, like S3_UNSIGNED_PAYLOAD */
    payload_hash_len = strlen(sha_hex);
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
  result = Curl_gmtime(clock, &tm);
  if(result) {
    goto fail;
  }
  if(!strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%SZ", &tm)) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  result = make_headers(data, hostname, timestamp, provider1,
                        &date_header, content_sha256_hdr,
                        &canonical_headers, &signed_headers);
  if(result)
    goto fail;

  if(*content_sha256_hdr) {
    /* make_headers() needed this without the \r\n for canonicalization */
    size_t hdrlen = strlen(content_sha256_hdr);
    DEBUGASSERT(hdrlen + 3 < sizeof(content_sha256_hdr));
    memcpy(content_sha256_hdr + hdrlen, "\r\n", 3);
  }

  memcpy(date, timestamp, sizeof(date));
  date[sizeof(date) - 1] = 0;

  result = canon_query(data, data->state.up.query, &canonical_query);
  if(result)
    goto fail;
  result = CURLE_OUT_OF_MEMORY;

  canonical_request =
    curl_maprintf("%s\n" /* HTTPRequestMethod */
                  "%s\n" /* CanonicalURI */
                  "%s\n" /* CanonicalQueryString */
                  "%s\n" /* CanonicalHeaders */
                  "%s\n" /* SignedHeaders */
                  "%.*s",  /* HashedRequestPayload in hex */
                  method,
                  data->state.up.path,
                  Curl_dyn_ptr(&canonical_query) ?
                  Curl_dyn_ptr(&canonical_query) : "",
                  Curl_dyn_ptr(&canonical_headers),
                  Curl_dyn_ptr(&signed_headers),
                  (int)payload_hash_len, payload_hash);
  if(!canonical_request)
    goto fail;

  DEBUGF(infof(data, "Canonical request: %s", canonical_request));

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

  sha256_to_hex(sha_hex, sha_hash);

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

  sha256_to_hex(sha_hex, sign0);

  /* provider 0 uppercase */
  auth_headers = curl_maprintf("Authorization: %s4-HMAC-SHA256 "
                               "Credential=%s/%s, "
                               "SignedHeaders=%s, "
                               "Signature=%s\r\n"
                               /*
                                * date_header is added here, only if it wasn't
                                * user-specified (using CURLOPT_HTTPHEADER).
                                * date_header includes \r\n
                                */
                               "%s"
                               "%s", /* optional sha256 header includes \r\n */
                               provider0,
                               user,
                               credential_scope,
                               Curl_dyn_ptr(&signed_headers),
                               sha_hex,
                               date_header ? date_header : "",
                               content_sha256_hdr);
  if(!auth_headers) {
    goto fail;
  }

  Curl_safefree(data->state.aptr.userpwd);
  data->state.aptr.userpwd = auth_headers;
  data->state.authhost.done = TRUE;
  result = CURLE_OK;

fail:
  Curl_dyn_free(&canonical_query);
  Curl_dyn_free(&canonical_headers);
  Curl_dyn_free(&signed_headers);
  free(canonical_request);
  free(request_type);
  free(credential_scope);
  free(str_to_sign);
  free(secret);
  free(date_header);
  return result;
}

#endif /* !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS) */
