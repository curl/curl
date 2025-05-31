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
#include "curlx/strparse.h"

#include <time.h>

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#include "slist.h"

#define HMAC_SHA256(k, kl, d, dl, o)                \
  do {                                              \
    result = Curl_hmacit(&Curl_HMAC_SHA256,         \
                         (const unsigned char *)k,  \
                         kl,                        \
                         (const unsigned char *)d,  \
                         dl, o);                    \
    if(result) {                                    \
      goto fail;                                    \
    }                                               \
  } while(0)

#define TIMESTAMP_SIZE 17

/* hex-encoded with trailing null */
#define SHA256_HEX_LENGTH (2 * CURL_SHA256_DIGEST_LENGTH + 1)

#define MAX_QUERY_COMPONENTS 128

struct pair {
  struct dynbuf key;
  struct dynbuf value;
};

static void dyn_array_free(struct dynbuf *db, size_t num_elements);
static void pair_array_free(struct pair *pair_array, size_t num_elements);
static CURLcode split_to_dyn_array(const char *source,
                                   struct dynbuf db[MAX_QUERY_COMPONENTS],
                                   size_t *num_splits);
static bool is_reserved_char(const char c);
static CURLcode uri_encode_path(struct Curl_str *original_path,
                                struct dynbuf *new_path);
static CURLcode encode_query_component(char *component, size_t len,
                                       struct dynbuf *db);
static CURLcode http_aws_decode_encode(const char *in, size_t in_len,
                                       struct dynbuf *out);
static bool should_urlencode(struct Curl_str *service_name);

static void sha256_to_hex(char *dst, unsigned char *sha)
{
  Curl_hexencode(sha, CURL_SHA256_DIGEST_LENGTH,
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
    const char *value; /* to read from */
    char *store;
    size_t colon = strcspn(l->data, ":");
    Curl_strntolower(l->data, l->data, colon);

    value = &l->data[colon];
    if(!*value)
      continue;
    ++value;
    store = (char *)CURL_UNCONST(value);

    /* skip leading whitespace */
    curlx_str_passblanks(&value);

    while(*value) {
      int space = 0;
      while(ISBLANK(*value)) {
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
    *store = 0; /* null-terminate */
  }
}

/* maximum length for the aws sivg4 parts */
#define MAX_SIGV4_LEN 64
#define DATE_HDR_KEY_LEN (MAX_SIGV4_LEN + sizeof("X--Date"))

/* string been x-PROVIDER-date:TIMESTAMP, I need +1 for ':' */
#define DATE_FULL_HDR_LEN (DATE_HDR_KEY_LEN + TIMESTAMP_SIZE + 1)

/* alphabetically compare two headers by their name, expecting
   headers to use ':' at this point */
static int compare_header_names(const char *a, const char *b)
{
  const char *colon_a;
  const char *colon_b;
  size_t len_a;
  size_t len_b;
  size_t min_len;
  int cmp;

  colon_a = strchr(a, ':');
  colon_b = strchr(b, ':');

  DEBUGASSERT(colon_a);
  DEBUGASSERT(colon_b);

  len_a = colon_a ? (size_t)(colon_a - a) : strlen(a);
  len_b = colon_b ? (size_t)(colon_b - b) : strlen(b);

  min_len = (len_a < len_b) ? len_a : len_b;

  cmp = strncmp(a, b, min_len);

  /* return the shorter of the two if one is shorter */
  if(!cmp)
    return (int)(len_a - len_b);

  return cmp;
}

/* Merge duplicate header definitions by comma delimiting their values
   in the order defined the headers are defined, expecting headers to
   be alpha-sorted and use ':' at this point */
static CURLcode merge_duplicate_headers(struct curl_slist *head)
{
  struct curl_slist *curr = head;
  CURLcode result = CURLE_OK;

  while(curr) {
    struct curl_slist *next = curr->next;
    if(!next)
      break;

    if(compare_header_names(curr->data, next->data) == 0) {
      struct dynbuf buf;
      char *colon_next;
      char *val_next;

      curlx_dyn_init(&buf, CURL_MAX_HTTP_HEADER);

      result = curlx_dyn_add(&buf, curr->data);
      if(result)
        return result;

      colon_next = strchr(next->data, ':');
      DEBUGASSERT(colon_next);
      val_next = colon_next + 1;

      result = curlx_dyn_addn(&buf, ",", 1);
      if(result)
        return result;

      result = curlx_dyn_add(&buf, val_next);
      if(result)
        return result;

      free(curr->data);
      curr->data = curlx_dyn_ptr(&buf);

      curr->next = next->next;
      free(next->data);
      free(next);
    }
    else {
      curr = curr->next;
    }
  }

  return CURLE_OK;
}

/* timestamp should point to a buffer of at last TIMESTAMP_SIZE bytes */
static CURLcode make_headers(struct Curl_easy *data,
                             const char *hostname,
                             char *timestamp,
                             const char *provider1,
                             size_t plen, /* length of provider1 */
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
  bool again = TRUE;

  msnprintf(date_hdr_key, DATE_HDR_KEY_LEN, "X-%.*s-Date",
            (int)plen, provider1);
  /* provider1 ucfirst */
  Curl_strntolower(&date_hdr_key[2], provider1, plen);
  date_hdr_key[2] = Curl_raw_toupper(provider1[0]);

  msnprintf(date_full_hdr, DATE_FULL_HDR_LEN,
            "x-%.*s-date:%s", (int)plen, provider1, timestamp);
  /* provider1 lowercase */
  Curl_strntolower(&date_full_hdr[2], provider1, plen);

  if(!Curl_checkheaders(data, STRCONST("Host"))) {
    char *fullhost;

    if(data->state.aptr.host) {
      /* remove /r/n as the separator for canonical request must be '\n' */
      size_t pos = strcspn(data->state.aptr.host, "\n\r");
      fullhost = Curl_memdup0(data->state.aptr.host, pos);
    }
    else
      fullhost = aprintf("host:%s", hostname);

    if(fullhost)
      head = Curl_slist_append_nodup(NULL, fullhost);
    if(!head) {
      free(fullhost);
      goto fail;
    }
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
    for(ptr = sep + 1; ISBLANK(*ptr); ++ptr)
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
    *date_header = aprintf("%s: %s\r\n", date_hdr_key, timestamp);
  }
  else {
    const char *value;
    const char *endp;
    value = strchr(*date_header, ':');
    if(!value) {
      *date_header = NULL;
      goto fail;
    }
    ++value;
    curlx_str_passblanks(&value);
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

  /* alpha-sort by header name in a case sensitive manner */
  do {
    again = FALSE;
    for(l = head; l; l = l->next) {
      struct curl_slist *next = l->next;

      if(next && compare_header_names(l->data, next->data) > 0) {
        char *tmp = l->data;

        l->data = next->data;
        next->data = tmp;
        again = TRUE;
      }
    }
  } while(again);

  ret = merge_duplicate_headers(head);
  if(ret)
    goto fail;

  for(l = head; l; l = l->next) {
    char *tmp;

    if(curlx_dyn_add(canonical_headers, l->data))
      goto fail;
    if(curlx_dyn_add(canonical_headers, "\n"))
      goto fail;

    tmp = strchr(l->data, ':');
    if(tmp)
      *tmp = 0;

    if(l != head) {
      if(curlx_dyn_add(signed_headers, ";"))
        goto fail;
    }
    if(curlx_dyn_add(signed_headers, l->data))
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
static const char *parse_content_sha_hdr(struct Curl_easy *data,
                                         const char *provider1,
                                         size_t plen,
                                         size_t *value_len) {
  char key[CONTENT_SHA256_KEY_LEN];
  size_t key_len;
  const char *value;
  size_t len;

  key_len = msnprintf(key, sizeof(key), "x-%.*s-content-sha256",
                      (int)plen, provider1);

  value = Curl_checkheaders(data, key, key_len);
  if(!value)
    return NULL;

  value = strchr(value, ':');
  if(!value)
    return NULL;
  ++value;

  curlx_str_passblanks(&value);

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
                                     Curl_HttpReq httpreq,
                                     const char *provider1,
                                     size_t plen,
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
            "x-%.*s-content-sha256: %s", (int)plen, provider1, sha_hex);

  ret = CURLE_OK;
fail:
  return ret;
}

static int compare_func(const void *a, const void *b)
{

  const struct pair *aa = a;
  const struct pair *bb = b;
  const size_t aa_key_len = curlx_dyn_len(&aa->key);
  const size_t bb_key_len = curlx_dyn_len(&bb->key);
  const size_t aa_value_len = curlx_dyn_len(&aa->value);
  const size_t bb_value_len = curlx_dyn_len(&bb->value);
  int compare;

  /* If one element is empty, the other is always sorted higher */

  /* Compare keys */
  if((aa_key_len == 0) && (bb_key_len == 0))
    return 0;
  if(aa_key_len == 0)
    return -1;
  if(bb_key_len == 0)
    return 1;
  compare = strcmp(curlx_dyn_ptr(&aa->key), curlx_dyn_ptr(&bb->key));
  if(compare) {
    return compare;
  }

  /* Compare values */
  if((aa_value_len == 0) && (bb_value_len == 0))
    return 0;
  if(aa_value_len == 0)
    return -1;
  if(bb_value_len == 0)
    return 1;
  compare = strcmp(curlx_dyn_ptr(&aa->value), curlx_dyn_ptr(&bb->value));

  return compare;

}

UNITTEST CURLcode canon_path(const char *q, size_t len,
                              struct dynbuf *new_path,
                              bool do_uri_encode)
{
  CURLcode result = CURLE_OK;

  struct Curl_str original_path;

  curlx_str_assign(&original_path, q, len);

  /* Normalized path will be either the same or shorter than the original
   * path, plus trailing slash */

  if(do_uri_encode)
    result = uri_encode_path(&original_path, new_path);
  else
    result = curlx_dyn_addn(new_path, q, len);

  if(!result) {
    if(curlx_dyn_len(new_path) == 0)
      result = curlx_dyn_add(new_path, "/");
  }

  return result;
}

UNITTEST CURLcode canon_query(const char *query, struct dynbuf *dq)
{
  CURLcode result = CURLE_OK;

  struct dynbuf query_array[MAX_QUERY_COMPONENTS];
  struct pair encoded_query_array[MAX_QUERY_COMPONENTS];
  size_t num_query_components;
  size_t counted_query_components = 0;
  size_t index;

  if(!query)
    return result;

  result = split_to_dyn_array(query, &query_array[0],
                              &num_query_components);
  if(result) {
    goto fail;
  }

  /* Create list of pairs, each pair containing an encoded query
    * component */

  for(index = 0; index < num_query_components; index++) {
    const char *in_key;
    size_t in_key_len;
    char *offset;
    size_t query_part_len = curlx_dyn_len(&query_array[index]);
    char *query_part = curlx_dyn_ptr(&query_array[index]);

    in_key = query_part;

    offset = strchr(query_part, '=');
    /* If there is no equals, this key has no value */
    if(!offset) {
      in_key_len = strlen(in_key);
    }
    else {
      in_key_len = offset - in_key;
    }

    curlx_dyn_init(&encoded_query_array[index].key, query_part_len*3 + 1);
    curlx_dyn_init(&encoded_query_array[index].value, query_part_len*3 + 1);
    counted_query_components++;

    /* Decode/encode the key */
    result = http_aws_decode_encode(in_key, in_key_len,
                                    &encoded_query_array[index].key);
    if(result) {
      goto fail;
    }

    /* Decode/encode the value if it exists */
    if(offset && offset != (query_part + query_part_len - 1)) {
      size_t in_value_len;
      const char *in_value = offset + 1;
      in_value_len = query_part + query_part_len - (offset + 1);
      result = http_aws_decode_encode(in_value, in_value_len,
                                      &encoded_query_array[index].value);
      if(result) {
        goto fail;
      }
    }
    else {
      /* If there is no value, the value is an empty string */
      curlx_dyn_init(&encoded_query_array[index].value, 2);
      result = curlx_dyn_addn(&encoded_query_array[index].value, "", 1);
    }

    if(result) {
      goto fail;
    }
  }

  /* Sort the encoded query components by key and value */
  qsort(&encoded_query_array, num_query_components,
        sizeof(struct pair), compare_func);

  /* Append the query components together to make a full query string */
  for(index = 0; index < num_query_components; index++) {

    if(index)
      result = curlx_dyn_addn(dq, "&", 1);
    if(!result) {
      char *key_ptr = curlx_dyn_ptr(&encoded_query_array[index].key);
      char *value_ptr = curlx_dyn_ptr(&encoded_query_array[index].value);
      size_t vlen = curlx_dyn_len(&encoded_query_array[index].value);
      if(value_ptr && vlen) {
        result = curlx_dyn_addf(dq, "%s=%s", key_ptr, value_ptr);
      }
      else {
        /* Empty value is always encoded to key= */
        result = curlx_dyn_addf(dq, "%s=", key_ptr);
      }
    }
    if(result)
      break;
  }

fail:
  if(counted_query_components)
    /* the encoded_query_array might not be initialized yet */
    pair_array_free(&encoded_query_array[0], counted_query_components);
  dyn_array_free(&query_array[0], num_query_components);
  return result;
}

CURLcode Curl_output_aws_sigv4(struct Curl_easy *data)
{
  CURLcode result = CURLE_OUT_OF_MEMORY;
  struct connectdata *conn = data->conn;
  const char *line;
  struct Curl_str provider0;
  struct Curl_str provider1;
  struct Curl_str region = { NULL, 0};
  struct Curl_str service = { NULL, 0};
  const char *hostname = conn->host.name;
  time_t clock;
  struct tm tm;
  char timestamp[TIMESTAMP_SIZE];
  char date[9];
  struct dynbuf canonical_headers;
  struct dynbuf signed_headers;
  struct dynbuf canonical_query;
  struct dynbuf canonical_path;
  char *date_header = NULL;
  Curl_HttpReq httpreq;
  const char *method = NULL;
  const char *payload_hash = NULL;
  size_t payload_hash_len = 0;
  unsigned char sha_hash[CURL_SHA256_DIGEST_LENGTH];
  char sha_hex[SHA256_HEX_LENGTH];
  char content_sha256_hdr[CONTENT_SHA256_HDR_LEN + 2] = ""; /* add \r\n */
  char *canonical_request = NULL;
  char *request_type = NULL;
  char *credential_scope = NULL;
  char *str_to_sign = NULL;
  const char *user = data->state.aptr.user ? data->state.aptr.user : "";
  char *secret = NULL;
  unsigned char sign0[CURL_SHA256_DIGEST_LENGTH] = {0};
  unsigned char sign1[CURL_SHA256_DIGEST_LENGTH] = {0};
  char *auth_headers = NULL;

  if(data->set.path_as_is) {
    failf(data, "Cannot use sigv4 authentication with path-as-is flag");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(Curl_checkheaders(data, STRCONST("Authorization"))) {
    /* Authorization already present, Bailing out */
    return CURLE_OK;
  }

  /* we init those buffers here, so goto fail will free initialized dynbuf */
  curlx_dyn_init(&canonical_headers, CURL_MAX_HTTP_HEADER);
  curlx_dyn_init(&canonical_query, CURL_MAX_HTTP_HEADER);
  curlx_dyn_init(&signed_headers, CURL_MAX_HTTP_HEADER);
  curlx_dyn_init(&canonical_path, CURL_MAX_HTTP_HEADER);

  /*
   * Parameters parsing
   * Google and Outscale use the same OSC or GOOG,
   * but Amazon uses AWS and AMZ for header arguments.
   * AWS is the default because most of non-amazon providers
   * are still using aws:amz as a prefix.
   */
  line = data->set.str[STRING_AWS_SIGV4];
  if(!line || !*line)
    line = "aws:amz";

  /* provider0[:provider1[:region[:service]]]

     No string can be longer than N bytes of non-whitespace
  */
  if(curlx_str_until(&line, &provider0, MAX_SIGV4_LEN, ':')) {
    failf(data, "first aws-sigv4 provider cannot be empty");
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto fail;
  }
  if(curlx_str_single(&line, ':') ||
     curlx_str_until(&line, &provider1, MAX_SIGV4_LEN, ':')) {
    provider1 = provider0;
  }
  else if(curlx_str_single(&line, ':') ||
          curlx_str_until(&line, &region, MAX_SIGV4_LEN, ':') ||
          curlx_str_single(&line, ':') ||
          curlx_str_until(&line, &service, MAX_SIGV4_LEN, ':')) {
    /* nothing to do */
  }

  if(!curlx_strlen(&service)) {
    const char *p = hostname;
    if(curlx_str_until(&p, &service, MAX_SIGV4_LEN, '.') ||
       curlx_str_single(&p, '.')) {
      failf(data, "aws-sigv4: service missing in parameters and hostname");
      result = CURLE_URL_MALFORMAT;
      goto fail;
    }

    infof(data, "aws_sigv4: picked service %.*s from host",
          (int)curlx_strlen(&service), curlx_str(&service));

    if(!curlx_strlen(&region)) {
      if(curlx_str_until(&p, &region, MAX_SIGV4_LEN, '.') ||
         curlx_str_single(&p, '.')) {
        failf(data, "aws-sigv4: region missing in parameters and hostname");
        result = CURLE_URL_MALFORMAT;
        goto fail;
      }
      infof(data, "aws_sigv4: picked region %.*s from host",
            (int)curlx_strlen(&region), curlx_str(&region));
    }
  }

  Curl_http_method(data, conn, &method, &httpreq);

  payload_hash =
    parse_content_sha_hdr(data, curlx_str(&provider1),
                          curlx_strlen(&provider1), &payload_hash_len);

  if(!payload_hash) {
    /* AWS S3 requires a x-amz-content-sha256 header, and supports special
     * values like UNSIGNED-PAYLOAD */
    bool sign_as_s3 = curlx_str_casecompare(&provider0, "aws") &&
      curlx_str_casecompare(&service, "s3");

    if(sign_as_s3)
      result = calc_s3_payload_hash(data, httpreq, curlx_str(&provider1),
                                    curlx_strlen(&provider1), sha_hash,
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
      clock = time(NULL);
  }
#else
  clock = time(NULL);
#endif
  result = Curl_gmtime(clock, &tm);
  if(result) {
    goto fail;
  }
  if(!strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%SZ", &tm)) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  result = make_headers(data, hostname, timestamp,
                        curlx_str(&provider1), curlx_strlen(&provider1),
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

  result = canon_query(data->state.up.query, &canonical_query);
  if(result)
    goto fail;

  result = canon_path(data->state.up.path, strlen(data->state.up.path),
                        &canonical_path,
                        should_urlencode(&service));
  if(result)
    goto fail;
  result = CURLE_OUT_OF_MEMORY;

  canonical_request =
    aprintf("%s\n" /* HTTPRequestMethod */
            "%s\n" /* CanonicalURI */
            "%s\n" /* CanonicalQueryString */
            "%s\n" /* CanonicalHeaders */
            "%s\n" /* SignedHeaders */
            "%.*s",  /* HashedRequestPayload in hex */
            method,
            curlx_dyn_ptr(&canonical_path),
            curlx_dyn_ptr(&canonical_query) ?
            curlx_dyn_ptr(&canonical_query) : "",
            curlx_dyn_ptr(&canonical_headers),
            curlx_dyn_ptr(&signed_headers),
            (int)payload_hash_len, payload_hash);
  if(!canonical_request)
    goto fail;

  infof(data, "aws_sigv4: Canonical request (enclosed in []) - [%s]",
    canonical_request);

  request_type = aprintf("%.*s4_request",
                         (int)curlx_strlen(&provider0), curlx_str(&provider0));
  if(!request_type)
    goto fail;

  /* provider0 is lowercased *after* aprintf() so that the buffer can be
     written to */
  Curl_strntolower(request_type, request_type, curlx_strlen(&provider0));

  credential_scope = aprintf("%s/%.*s/%.*s/%s", date,
                             (int)curlx_strlen(&region), curlx_str(&region),
                             (int)curlx_strlen(&service), curlx_str(&service),
                             request_type);
  if(!credential_scope)
    goto fail;

  if(Curl_sha256it(sha_hash, (unsigned char *) canonical_request,
                   strlen(canonical_request)))
    goto fail;

  sha256_to_hex(sha_hex, sha_hash);

  /*
   * Google allows using RSA key instead of HMAC, so this code might change
   * in the future. For now we only support HMAC.
   */
  str_to_sign = aprintf("%.*s4-HMAC-SHA256\n" /* Algorithm */
                        "%s\n" /* RequestDateTime */
                        "%s\n" /* CredentialScope */
                        "%s",  /* HashedCanonicalRequest in hex */
                        (int)curlx_strlen(&provider0), curlx_str(&provider0),
                        timestamp,
                        credential_scope,
                        sha_hex);
  if(!str_to_sign)
    goto fail;

  /* make provider0 part done uppercase */
  Curl_strntoupper(str_to_sign, curlx_str(&provider0),
                   curlx_strlen(&provider0));

  infof(data, "aws_sigv4: String to sign (enclosed in []) - [%s]",
    str_to_sign);

  secret = aprintf("%.*s4%s", (int)curlx_strlen(&provider0),
                   curlx_str(&provider0), data->state.aptr.passwd ?
                   data->state.aptr.passwd : "");
  if(!secret)
    goto fail;
  /* make provider0 part done uppercase */
  Curl_strntoupper(secret, curlx_str(&provider0), curlx_strlen(&provider0));

  HMAC_SHA256(secret, strlen(secret), date, strlen(date), sign0);
  HMAC_SHA256(sign0, sizeof(sign0),
              curlx_str(&region), curlx_strlen(&region), sign1);
  HMAC_SHA256(sign1, sizeof(sign1),
              curlx_str(&service), curlx_strlen(&service), sign0);
  HMAC_SHA256(sign0, sizeof(sign0), request_type, strlen(request_type), sign1);
  HMAC_SHA256(sign1, sizeof(sign1), str_to_sign, strlen(str_to_sign), sign0);

  sha256_to_hex(sha_hex, sign0);

  infof(data, "aws_sigv4: Signature - %s", sha_hex);

  auth_headers = aprintf("Authorization: %.*s4-HMAC-SHA256 "
                         "Credential=%s/%s, "
                         "SignedHeaders=%s, "
                         "Signature=%s\r\n"
                         /*
                          * date_header is added here, only if it was not
                          * user-specified (using CURLOPT_HTTPHEADER).
                          * date_header includes \r\n
                          */
                         "%s"
                         "%s", /* optional sha256 header includes \r\n */
                         (int)curlx_strlen(&provider0), curlx_str(&provider0),
                         user,
                         credential_scope,
                         curlx_dyn_ptr(&signed_headers),
                         sha_hex,
                         date_header ? date_header : "",
                         content_sha256_hdr);
  if(!auth_headers) {
    goto fail;
  }
  /* provider 0 uppercase */
  Curl_strntoupper(&auth_headers[sizeof("Authorization: ") - 1],
                   curlx_str(&provider0), curlx_strlen(&provider0));

  free(data->state.aptr.userpwd);
  data->state.aptr.userpwd = auth_headers;
  data->state.authhost.done = TRUE;
  result = CURLE_OK;

fail:
  curlx_dyn_free(&canonical_query);
  curlx_dyn_free(&canonical_path);
  curlx_dyn_free(&canonical_headers);
  curlx_dyn_free(&signed_headers);
  free(canonical_request);
  free(request_type);
  free(credential_scope);
  free(str_to_sign);
  free(secret);
  free(date_header);
  return result;
}

/*
* Frees all allocated strings in a dynbuf pair array, and the dynbuf itself
*/

static void pair_array_free(struct pair *pair_array, size_t num_elements)
{
  size_t index;

  for(index = 0; index != num_elements; index++) {
    curlx_dyn_free(&pair_array[index].key);
    curlx_dyn_free(&pair_array[index].value);
  }

}

/*
* Frees all allocated strings in a split dynbuf, and the dynbuf itself
*/

static void dyn_array_free(struct dynbuf *db, size_t num_elements)
{
  size_t index;

  for(index = 0; index < num_elements; index++)
    curlx_dyn_free((&db[index]));
}

/*
* Splits source string by SPLIT_BY, and creates an array of dynbuf in db.
* db is initialized by this function.
* Caller is responsible for freeing the array elements with dyn_array_free
*/

#define SPLIT_BY '&'

static CURLcode split_to_dyn_array(const char *source,
                                   struct dynbuf db[MAX_QUERY_COMPONENTS],
                                   size_t *num_splits_out)
{
  CURLcode result = CURLE_OK;
  size_t len = strlen(source);
  size_t pos;         /* Position in result buffer */
  size_t start = 0;   /* Start of current segment */
  size_t segment_length = 0;
  size_t index = 0;
  size_t num_splits = 0;

  /* Split source_ptr on SPLIT_BY and store the segment offsets and length in
   * array */
  for(pos = 0; pos < len; pos++) {
    if(source[pos] == SPLIT_BY) {
      if(segment_length) {
        curlx_dyn_init(&db[index], segment_length + 1);
        result = curlx_dyn_addn(&db[index], &source[start],
                                segment_length);
        if(result)
          goto fail;

        segment_length = 0;
        index++;
        if(++num_splits == MAX_QUERY_COMPONENTS) {
          result = CURLE_TOO_LARGE;
          goto fail;
        }
      }
      start = pos + 1;
    }
    else {
      segment_length++;
    }
  }

  if(segment_length) {
    curlx_dyn_init(&db[index], segment_length + 1);
    result = curlx_dyn_addn(&db[index], &source[start], segment_length);
    if(!result) {
      if(++num_splits == MAX_QUERY_COMPONENTS)
        result = CURLE_TOO_LARGE;
    }
  }
fail:
  *num_splits_out = num_splits;
  return result;
}


static bool is_reserved_char(const char c)
{
  return (ISALNUM(c) || ISURLPUNTCS(c));
}

static CURLcode uri_encode_path(struct Curl_str *original_path,
                                struct dynbuf *new_path)
{
  const char *p = curlx_str(original_path);
  size_t i;

  for(i = 0; i < curlx_strlen(original_path); i++) {
    /* Do not encode slashes or unreserved chars from RFC 3986 */
    CURLcode result = CURLE_OK;
    unsigned char c = p[i];
    if(is_reserved_char(c) || c == '/')
      result = curlx_dyn_addn(new_path, &c, 1);
    else
      result = curlx_dyn_addf(new_path, "%%%02X", c);
    if(result)
      return result;
  }

  return CURLE_OK;
}


static CURLcode encode_query_component(char *component, size_t len,
                                       struct dynbuf *db)
{
  size_t i;
  for(i = 0; i < len; i++) {
    CURLcode result = CURLE_OK;
    unsigned char this_char = component[i];

    if(is_reserved_char(this_char))
      /* Escape unreserved chars from RFC 3986 */
      result = curlx_dyn_addn(db, &this_char, 1);
    else if(this_char == '+')
      /* Encode '+' as space */
      result = curlx_dyn_add(db, "%20");
    else
      result = curlx_dyn_addf(db, "%%%02X", this_char);
    if(result)
      return result;
  }

  return CURLE_OK;
}

/*
* Populates a dynbuf containing url_encode(url_decode(in))
*/

static CURLcode http_aws_decode_encode(const char *in, size_t in_len,
                                       struct dynbuf *out)
{
  char *out_s;
  size_t out_s_len;
  CURLcode result =
    Curl_urldecode(in, in_len, &out_s, &out_s_len, REJECT_NADA);

  if(!result) {
    result = encode_query_component(out_s, out_s_len, out);
    Curl_safefree(out_s);
  }
  return result;
}

static bool should_urlencode(struct Curl_str *service_name)
{
  /*
   * These services require unmodified (not additionally url encoded) URL
   * paths.
   * should_urlencode == true is equivalent to should_urlencode_uri_path
   * from the AWS SDK. Urls are already normalized by the curl url parser
   */

  if(curlx_str_cmp(service_name, "s3") ||
     curlx_str_cmp(service_name, "s3-express") ||
     curlx_str_cmp(service_name, "s3-outposts")) {
    return false;
  }
  return true;
}

#endif /* !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_AWS) */
