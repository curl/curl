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

#include "http_aws_sigv4a.h"

#include "curl_sha256.h"
#include "transfer.h"
#include "parsedate.h"
#include "sendf.h"
#include "escape.h"
#include "curlx/strparse.h"

#include <time.h>

/* The last 2 #include files should be in this order */
#include "curl_memory.h"
#include "memdebug.h"

#include "slist.h"

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
static bool has_query_param(const char *query, const char *param);
static CURLcode uri_encode_path(struct Curl_str *original_path,
                                struct dynbuf *new_path);
static bool should_urlencode(struct Curl_str *service_name);

static void sha256_to_hex(char *dst, unsigned char *sha)
{
  Curl_hexencode(sha, CURL_SHA256_DIGEST_LENGTH,
                 (unsigned char *)dst, SHA256_HEX_LENGTH);
}

static bool has_query_param(const char *query, const char *param)
{
  size_t param_len;
  const char *found;

  if(!query || !param)
    return false;

  param_len = strlen(param);
  found = query;

  found = strstr(found, param);
  while(found) {
    /* Check if it's at start or after & */
    if(found == query || *(found - 1) == '&') {
      /* Check if followed by = */
      if(found[param_len] == '=')
        return true;
    }
    found++;
    found = strstr(found, param);
  }
  return false;
}

static char *find_date_hdr(struct Curl_easy *data, const char *sig_hdr)
{
  char *tmp = Curl_checkheaders(data, sig_hdr, strlen(sig_hdr));

  if(tmp)
    return tmp;
  return Curl_checkheaders(data, STRCONST("Date"));
}

/* Parse AWS credentials from --user option */
UNITTEST CURLcode parse_aws_credentials(struct Curl_easy *data,
                                        const char **access_key,
                                        char **secret_key,
                                        char **security_token)
{
  const char *user = data->state.aptr.user;
  const char *passwd = data->state.aptr.passwd;
  char *token_sep;

  if(!user || !passwd) {
    failf(data, "AWS SigV4 requires access key and secret key");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  *access_key = user;

  /* Check if passwd contains security token (secret:token format) */
  token_sep = strchr(passwd, ':');
  if(token_sep) {
    /* Make a copy of passwd to modify */
    *secret_key = strdup(passwd);
    if(!*secret_key)
      return CURLE_OUT_OF_MEMORY;

    /* Split secret and token */
    token_sep = strchr(*secret_key, ':');
    *token_sep = '\0';
    *security_token = strdup(token_sep + 1);
    if(!*security_token) {
      free(*secret_key);
      return CURLE_OUT_OF_MEMORY;
    }
  }
  else {
    *secret_key = strdup(passwd);
    if(!*secret_key)
      return CURLE_OUT_OF_MEMORY;
    *security_token = NULL;
  }

  return CURLE_OK;
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
  bool first_signed_header = true;
  bool again = TRUE;

  curl_msnprintf(date_hdr_key, DATE_HDR_KEY_LEN, "X-%.*s-Date",
                 (int)plen, provider1);
  /* provider1 ucfirst */
  Curl_strntolower(&date_hdr_key[2], provider1, plen);
  date_hdr_key[2] = Curl_raw_toupper(provider1[0]);

  curl_msnprintf(date_full_hdr, DATE_FULL_HDR_LEN,
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
      fullhost = curl_maprintf("host:%s", hostname);

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
  if(*date_header) {
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

  /* Handle custom signed headers list if provided */
  if(data->set.str[STRING_AWS_SIGV4_SIGNEDHEADERS]) {
    const char *custom_headers = data->set.str[STRING_AWS_SIGV4_SIGNEDHEADERS];
    char *headers_copy = strdup(custom_headers);
    char *token, *next_token;
    struct curl_slist *custom_head = NULL;

    infof(data, "aws_sigv4: using signedheaders='%s'", custom_headers);

    if(!headers_copy) {
      ret = CURLE_OUT_OF_MEMORY;
      goto fail;
    }

    /* Parse semicolon-delimited header list */
    token = headers_copy;
    while(token && *token) {
      char *header_name = token;
      char *found_header = NULL;
      char *semicolon = strchr(token, ';');

      if(semicolon) {
        *semicolon = '\0';
        next_token = semicolon + 1;
      }
      else {
        next_token = NULL;
      }

      /* Trim whitespace */
      while(ISBLANK(*header_name))
        header_name++;

      /* Find this header in our collected headers */
      for(l = head; l; l = l->next) {
        char *colon = strchr(l->data, ':');
        if(colon) {
          size_t name_len = colon - l->data;
          if(curl_strnequal(l->data, header_name, name_len) &&
             strlen(header_name) == name_len) {
            found_header = strdup(l->data);
            break;
          }
        }
      }

      if(found_header) {
        tmp_head = Curl_slist_append_nodup(custom_head, found_header);
        if(!tmp_head) {
          free(found_header);
          free(headers_copy);
          curl_slist_free_all(custom_head);
          ret = CURLE_OUT_OF_MEMORY;
          goto fail;
        }
        custom_head = tmp_head;
      }

      token = next_token;
    }

    free(headers_copy);
    curl_slist_free_all(head);
    head = custom_head;
  }

  for(l = head; l; l = l->next) {
    char *tmp;

    if(curlx_dyn_add(canonical_headers, l->data))
      goto fail;
    if(curlx_dyn_add(canonical_headers, "\n"))
      goto fail;

    tmp = strchr(l->data, ':');
    if(tmp)
      *tmp = 0;

    if(!first_signed_header) {
      if(curlx_dyn_add(signed_headers, ";"))
        goto fail;
    }
    if(curlx_dyn_add(signed_headers, l->data))
      goto fail;
    first_signed_header = false;
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

  key_len = curl_msnprintf(key, sizeof(key), "x-%.*s-content-sha256",
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
  curl_msnprintf(header, CONTENT_SHA256_HDR_LEN,
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

/*
* Populates a dynbuf containing url_encode(url_decode(in))
*/

UNITTEST CURLcode http_aws_decode_encode(const char *in, size_t in_len,
                                         struct dynbuf *out)
{
  size_t i;

  for(i = 0; i < in_len; i++) {
    CURLcode result = CURLE_OK;

    if(in[i] == '%' && i + 2 < in_len &&
       ISXDIGIT(in[i + 1]) && ISXDIGIT(in[i + 2])) {
      /* Valid percent encoding - normalize to uppercase */
      result = curlx_dyn_addf(out, "%%%c%c",
                              Curl_raw_toupper(in[i + 1]),
                              Curl_raw_toupper(in[i + 2]));
      i += 2; /* Skip the two hex digits */
    }
    else if(is_reserved_char(in[i])) {
      /* Unreserved character - keep as-is */
      result = curlx_dyn_addn(out, &in[i], 1);
    }
    else {
      /* Reserved character - encode it */
      result = curlx_dyn_addf(out, "%%%02X", (unsigned char)in[i]);
    }

    if(result)
      return result;
  }

  return CURLE_OK;
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
  struct Curl_str region_set_or_region = { NULL, 0};
  struct Curl_str service = { NULL, 0};
  const char *hostname = conn->host.name;
  time_t clock;
  struct tm tm;
  char timestamp[TIMESTAMP_SIZE];
  char date[9];
  bool user_provided_date = false;
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
  char sha_hex[145]; /* Max DER signature: 72*2+1 */
  char content_sha256_hdr[CONTENT_SHA256_HDR_LEN + 2] = ""; /* add \r\n */
  char *canonical_request = NULL;
  char *request_type = NULL;
  char *credential_scope = NULL;
  char *str_to_sign = NULL;
  const char *access_key = NULL;
  char *secret_key = NULL;
  char *security_token = NULL;
  char *secret = NULL;
  unsigned char date_key[CURL_SHA256_DIGEST_LENGTH] = {0};
  unsigned char region_key[CURL_SHA256_DIGEST_LENGTH] = {0};
  unsigned char service_key[CURL_SHA256_DIGEST_LENGTH] = {0};
  /* Cache provider1 values to avoid repeated function calls */
  const char *provider_str;
  int provider_len;
  const char *query_date_param;
  char *header_date_param;
  unsigned char signing_key[CURL_SHA256_DIGEST_LENGTH] = {0};
  unsigned char signature[72] = {0};
  size_t sig_len = 0;
  char *auth_headers = NULL;
  const char *mode = data->set.str[STRING_AWS_SIGV4_MODE];
  const char *algorithm = data->set.str[STRING_AWS_SIGV4_ALGORITHM];
  const char *existing_query = NULL;
  bool querystring_mode = mode && !strcmp(mode, "querystring");
  bool sigv4a_mode;

  /* Default to AWS4-HMAC-SHA256 if no algorithm specified */
  if(!algorithm)
    algorithm = "AWS4-HMAC-SHA256";

  /* Map short form to full algorithm name */
  if(!strcmp(algorithm, "ECDSA-P256-SHA256"))
    algorithm = "AWS4-ECDSA-P256-SHA256";

  /* Set SigV4A mode after algorithm mapping */
  sigv4a_mode = algorithm && !strcmp(algorithm, "AWS4-ECDSA-P256-SHA256");

  infof(data, "aws_sigv4: mode='%s', algorithm='%s', querystring_mode=%d, "
              "sigv4a_mode=%d", mode ? mode : "(null)", algorithm,
              querystring_mode, sigv4a_mode);

  infof(data, "aws_sigv4: parsing sigv4='%s'",
        data->set.str[STRING_AWS_SIGV4]);

  /* Validate algorithm */
  if(strcmp(algorithm, "AWS4-HMAC-SHA256") &&
     strcmp(algorithm, "AWS4-ECDSA-P256-SHA256")) {
    failf(data, "Unsupported AWS SigV4 algorithm: %s", algorithm);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

#ifndef HAVE_SIGV4A_SUPPORT
  if(sigv4a_mode) {
    failf(data, "aws-sigv4: SigV4A (ECDSA-P256-SHA256) not supported - "
               "this version of OpenSSL was not compiled with required "
               "EC support");
    return CURLE_NOT_BUILT_IN;
  }
#endif

  if(data->set.path_as_is) {
    failf(data, "Cannot use sigv4 authentication with path-as-is flag");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(Curl_checkheaders(data, STRCONST("Authorization"))) {
    /* Authorization already present, Bailing out */
    return CURLE_OK;
  }

  /* Parse AWS credentials from --user option */
  result = parse_aws_credentials(data, &access_key, &secret_key,
                                 &security_token);
  if(result)
    return result;

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
  /* Parse: provider0:provider1:region_set_or_region:service */
  if(curlx_str_single(&line, ':')) {
    /* No provider1, use provider0 */
    provider1 = provider0;
    infof(data, "aws_sigv4: no provider1, using provider0");
  }
  else if(curlx_str_until(&line, &provider1, MAX_SIGV4_LEN, ':')) {
    /* Failed to parse provider1 */
    provider1 = provider0;
    infof(data, "aws_sigv4: failed to parse provider1, using provider0");
  }

  /* Parse region_set_or_region */
  if(curlx_str_single(&line, ':')) {
    infof(data, "aws_sigv4: no region_set_or_region");
  }
  else if(curlx_str_until(&line, &region_set_or_region, MAX_SIGV4_LEN,
                          ':')) {
    infof(data, "aws_sigv4: failed to parse region_set_or_region");
  }
  else {
    infof(data, "aws_sigv4: using region_set_or_region='%.*s'",
          (int)curlx_strlen(&region_set_or_region),
          curlx_str(&region_set_or_region));
  }

  /* Parse service */
  if(curlx_str_single(&line, ':')) {
    infof(data, "aws_sigv4: no service");
  }
  else if(curlx_str_until(&line, &service, MAX_SIGV4_LEN, ':')) {
    infof(data, "aws_sigv4: failed to parse service");
  }
  else {
    infof(data, "aws_sigv4: using service='%.*s'",
          (int)curlx_strlen(&service), curlx_str(&service));
  }

  /* Use region_set_or_region as region for now - interpretation later */
  if(curlx_strlen(&region_set_or_region)) {
    region = region_set_or_region;
  }
  else {
    infof(data, "aws_sigv4: no region specified");
  }

  /* Cache provider1 values to avoid repeated function calls */
  provider_str = curlx_str(&provider1);
  provider_len = (int)curlx_strlen(&provider1);

  /* Create capitalized provider string for querystring parameters */
  char capitalized_provider[64];
  if(provider_len < sizeof(capitalized_provider)) {
    Curl_strntolower(capitalized_provider, provider_str, provider_len);
    capitalized_provider[0] = Curl_raw_toupper(provider_str[0]);
    capitalized_provider[provider_len] = '\0';
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

  Curl_http_method(data, &method, &httpreq);

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

  /* Override timestamp if user provided X-{Provider1}-Date */
  if(querystring_mode && data->state.up.query) {
    char date_param_name[64];
    curl_msnprintf(date_param_name, sizeof(date_param_name), "X-%.*s-Date=",
                   provider_len, provider_str);
    /* provider1 ucfirst */
    Curl_strntolower(&date_param_name[2], provider_str, provider_len);
    date_param_name[2] = Curl_raw_toupper(provider_str[0]);

    query_date_param = strstr(data->state.up.query, date_param_name);
    if(query_date_param) {
      const char *end;
      size_t len;
      /* Skip "X-{Provider1}-Date=" */
      query_date_param += strlen(date_param_name);
      end = strchr(query_date_param, '&');
      len = end ? (size_t)(end - query_date_param) : strlen(query_date_param);
      if(len == 16) { /* YYYYMMDDTHHMMSSZ */
        memcpy(timestamp, query_date_param, len);
        timestamp[len] = 0;
        user_provided_date = true;
        infof(data, "aws_sigv4: using x-%.*s-date override='%s'",
              provider_len, provider_str, timestamp);
      }
    }
  }
  else if(!querystring_mode) {
    char date_header_name[64];
    curl_msnprintf(date_header_name, sizeof(date_header_name), "X-%.*s-Date",
                   provider_len, provider_str);
    /* provider1 ucfirst */
    Curl_strntolower(&date_header_name[2], provider_str, provider_len);
    date_header_name[2] = Curl_raw_toupper(provider_str[0]);

    header_date_param = Curl_checkheaders(data, date_header_name,
                                           strlen(date_header_name));
    if(header_date_param) {
      char *date_value = strchr(header_date_param, ':');
      if(date_value) {
        size_t len;
        date_value++;
        while(*date_value == ' ') date_value++;
        len = strlen(date_value);
        if(len == 16) { /* YYYYMMDDTHHMMSSZ */
          memcpy(timestamp, date_value, len);
          timestamp[len] = 0;
          user_provided_date = true;
          infof(data, "aws_sigv4: using x-%.*s-date override='%s'",
                provider_len, provider_str, timestamp);
        }
      }
    }
  }

  /* Add security token header to request headers if present and not in
     querystring mode */
  if(security_token && !querystring_mode) {
    /* Only add X-{Provider1}-Security-Token if not already provided by user */
    char security_token_header_name[128];
    curl_msnprintf(security_token_header_name,
                   sizeof(security_token_header_name),
                   "X-%.*s-Security-Token", provider_len, provider_str);
    /* provider1 ucfirst */
    Curl_strntolower(&security_token_header_name[2], provider_str,
                     provider_len);
    security_token_header_name[2] = Curl_raw_toupper(provider_str[0]);

    if(!Curl_checkheaders(data, security_token_header_name,
                          strlen(security_token_header_name))) {
      char *security_token_hdr = curl_maprintf("%s: %s",
                                               security_token_header_name,
                                               security_token);
      if(!security_token_hdr) {
        result = CURLE_OUT_OF_MEMORY;
        goto fail;
      }
      data->set.headers = curl_slist_append(data->set.headers,
                                           security_token_hdr);
      curl_free(security_token_hdr);
      if(!data->set.headers) {
        result = CURLE_OUT_OF_MEMORY;
        goto fail;
      }
    }
  }

  /* Add X-{Provider1}-Date header for header mode before canonicalization */
  if(!querystring_mode) {
    /* Only add X-{Provider1}-Date if not already provided by user */
    if(!user_provided_date) {
      char *date_hdr = curl_maprintf("X-%.*s-Date: %s",
                                     provider_len, provider_str, timestamp);
      if(!date_hdr) {
        result = CURLE_OUT_OF_MEMORY;
        goto fail;
      }
      /* provider1 ucfirst */
      Curl_strntolower(&date_hdr[2], provider_str, provider_len);
      date_hdr[2] = Curl_raw_toupper(provider_str[0]);

      data->set.headers = curl_slist_append(data->set.headers, date_hdr);
      curl_free(date_hdr);
      if(!data->set.headers) {
        result = CURLE_OUT_OF_MEMORY;
        goto fail;
      }
    }

    /* Add X-{Provider1}-Region-Set header if region_set_or_region specified */
    if(curlx_strlen(&region_set_or_region) && sigv4a_mode) {
      char *region_set_hdr = curl_maprintf("X-%.*s-Region-Set: %.*s",
                                           provider_len, provider_str,
                                           (int)curlx_strlen(
                                             &region_set_or_region),
                                           curlx_str(&region_set_or_region));
      if(!region_set_hdr) {
        result = CURLE_OUT_OF_MEMORY;
        goto fail;
      }
      /* provider1 ucfirst */
      Curl_strntolower(&region_set_hdr[2], provider_str, provider_len);
      region_set_hdr[2] = Curl_raw_toupper(provider_str[0]);

      data->set.headers = curl_slist_append(data->set.headers, region_set_hdr);
      curl_free(region_set_hdr);
      if(!data->set.headers) {
        result = CURLE_OUT_OF_MEMORY;
        goto fail;
      }
    }
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

  /* If user provided explicit X-{Provider}-Date, use it for credential */
  if(querystring_mode && data->state.up.query) {
    char date_param_name[32];
    const char *date_param;
    curl_msnprintf(date_param_name, sizeof(date_param_name), "X-%.*s-Date=",
                   provider_len, provider_str);
    date_param = strstr(data->state.up.query, date_param_name);
    if(date_param) {
      date_param += strlen(date_param_name);
      memcpy(date, date_param, 8); /* Extract YYYYMMDD */
      date[8] = 0;
    }
  }
  else if(!querystring_mode) {
    char date_hdr_name[32];
    char *explicit_date;
    curl_msnprintf(date_hdr_name, sizeof(date_hdr_name), "X-%.*s-Date",
                   provider_len, provider_str);
    explicit_date = Curl_checkheaders(data, date_hdr_name,
                                       strlen(date_hdr_name));
    if(explicit_date) {
      /* Find the value part after "X-{Provider}-Date: " */
      char *date_value = strchr(explicit_date, ':');
      if(date_value) {
        date_value++; /* Skip ':' */
        while(*date_value == ' ') date_value++; /* Skip spaces */
        memcpy(date, date_value, 8); /* Extract YYYYMMDD */
        date[8] = 0;
      }
    }
  }

  result = canon_query(data->state.up.query, &canonical_query);
  if(result)
    goto fail;

  /* Create credential scope early for querystring mode */
  request_type = curl_maprintf("%.*s4_request", (int)curlx_strlen(&provider0),
                               curlx_str(&provider0));
  if(!request_type)
    goto fail;

  /* provider0 is lowercased *after* curl_maprintf() so that the buffer
     can be written to */
  Curl_strntolower(request_type, request_type, curlx_strlen(&provider0));

  if(sigv4a_mode) {
    /* SigV4A: Credential scope excludes region */
    credential_scope = curl_maprintf("%s/%.*s/%s", date,
                                     (int)curlx_strlen(&service),
                                     curlx_str(&service),
                                     request_type);
    infof(data, "aws_sigv4: SigV4A credential_scope='%s'", credential_scope);
  }
  else {
    /* SigV4: Credential scope includes region */
    credential_scope = curl_maprintf("%s/%.*s/%.*s/%s", date,
                                     (int)curlx_strlen(&region),
                                     curlx_str(&region),
                                     (int)curlx_strlen(&service),
                                     curlx_str(&service),
                                     request_type);
    infof(data, "aws_sigv4: SigV4 credential_scope='%s' (region='%.*s')",
          credential_scope, (int)curlx_strlen(&region), curlx_str(&region));
  }
  if(!credential_scope)
    goto fail;

  /* Get existing query for later use */
  existing_query = curlx_dyn_ptr(&canonical_query);

  /* For querystring mode, add signature parameters to canonical query for
     signature calculation */
  if(querystring_mode) {
    struct dynbuf temp_query;

    curlx_dyn_init(&temp_query, CURL_MAX_HTTP_HEADER);

    /* Add existing query if present */
    if(existing_query && *existing_query) {
      result = curlx_dyn_add(&temp_query, existing_query);
      if(result) {
        curlx_dyn_free(&temp_query);
        goto fail;
      }
    }

    /* Add signature parameters - let canon_query() sort them */
    {
      char *credential_string = curl_maprintf("%s/%s", access_key,
                                               credential_scope);

      if(!credential_string) {
        result = CURLE_OUT_OF_MEMORY;
        curlx_dyn_free(&temp_query);
        goto fail;
      }

      /* Add each parameter separately so canon_query can sort them */
      result = curlx_dyn_addf(&temp_query,
                              "%sX-%.*s-Algorithm=%s",
                              (existing_query && *existing_query) ? "&" : "",
                              provider_len, capitalized_provider, algorithm);
      if(!result)
        result = curlx_dyn_addf(&temp_query, "&X-%.*s-Credential=%s",
                                provider_len, capitalized_provider, credential_string);
      if(!result) {
        /* Only add X-{Provider}-Date if not already in query string */
        char date_param_name[32];
        curl_msnprintf(date_param_name, sizeof(date_param_name), "X-%.*s-Date",
                       provider_len, provider_str);
        if(!has_query_param(data->state.up.query, date_param_name))
          result = curlx_dyn_addf(&temp_query, "&X-%.*s-Date=%s",
                                  provider_len, capitalized_provider, timestamp);
      }
      if(!result)
        result = curlx_dyn_addf(&temp_query, "&X-%.*s-SignedHeaders=%s",
                                provider_len, capitalized_provider,
                                curlx_dyn_ptr(&signed_headers));

      if(!result && curlx_strlen(&region_set_or_region) && sigv4a_mode) {
        result = curlx_dyn_addf(&temp_query, "&X-%.*s-Region-Set=%.*s",
                                provider_len, capitalized_provider,
                                (int)curlx_strlen(&region_set_or_region),
                                curlx_str(&region_set_or_region));
      }

      if(!result && security_token) {
        result = curlx_dyn_addf(&temp_query, "&X-%.*s-Security-Token=%s",
                                provider_len, capitalized_provider, security_token);
      }

      curl_free(credential_string);
    }

    if(result) {
      curlx_dyn_free(&temp_query);
      goto fail;
    }

    /* Replace canonical query with the version including signature params for
       signature calculation */
    curlx_dyn_free(&canonical_query);

    /* Re-canonicalize to ensure proper parameter sorting */
    result = canon_query(curlx_dyn_ptr(&temp_query), &canonical_query);
    curlx_dyn_free(&temp_query);
    if(result)
      goto fail;
  }

  result = canon_path(data->state.up.path, strlen(data->state.up.path),
                        &canonical_path,
                        should_urlencode(&service));
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

  if(Curl_sha256it(sha_hash, (unsigned char *) canonical_request,
                   strlen(canonical_request)))
    goto fail;

  sha256_to_hex(sha_hex, sha_hash);

  /*
   * Create string to sign with configurable algorithm.
   * SigV4A (ECDSA) uses different signing logic than HMAC.
   */
  str_to_sign = curl_maprintf("%s\n" /* Algorithm */
                              "%s\n" /* RequestDateTime */
                              "%s\n" /* CredentialScope */
                              "%s",  /* HashedCanonicalRequest in hex */
                              algorithm,
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

  secret = curl_maprintf("%.*s4%s", (int)curlx_strlen(&provider0),
                         curlx_str(&provider0), secret_key ? secret_key : "");
  if(!secret)
    goto fail;
  /* make provider0 part done uppercase */
  Curl_strntoupper(secret, curlx_str(&provider0), curlx_strlen(&provider0));

  if(sigv4a_mode) {
#ifdef HAVE_SIGV4A_SUPPORT
    /* Use SigV4A key derivation */
    result = Curl_aws_sigv4a_derive_key(access_key, secret_key, signing_key);
    if(result)
      goto fail;
#else
    /* Should not reach here due to earlier check */
    result = CURLE_NOT_BUILT_IN;
    goto fail;
#endif
  }
  else {
    /* Use SigV4 HMAC signing */
    HMAC_SHA256(secret, strlen(secret), date, strlen(date), date_key);
    HMAC_SHA256(date_key, sizeof(date_key),
                curlx_str(&region), curlx_strlen(&region), region_key);
    HMAC_SHA256(region_key, sizeof(region_key),
                curlx_str(&service), curlx_strlen(&service), service_key);
    HMAC_SHA256(service_key, sizeof(service_key), request_type,
                strlen(request_type), signing_key);
  }

  if(sigv4a_mode) {
#ifdef HAVE_SIGV4A_SUPPORT
    /* SigV4A uses ECDSA signing */
    result = Curl_aws_sigv4a_sign(signing_key, str_to_sign,
                                  strlen(str_to_sign), signature, &sig_len);
    if(result)
      goto fail;
#else
    /* Should not reach here due to earlier check */
    result = CURLE_NOT_BUILT_IN;
    goto fail;
#endif
  }
  else {
    /* SigV4 uses HMAC signing */
    HMAC_SHA256(signing_key, sizeof(signing_key), str_to_sign,
                strlen(str_to_sign), signature);
  }

  if(sigv4a_mode) {
    /* SigV4A signature uses DER encoding, convert actual length to hex */
    Curl_hexencode(signature, sig_len, (unsigned char *)sha_hex,
                   sig_len * 2 + 1);
  }
  else {
    /* SigV4 signature is 32 bytes */
    sha256_to_hex(sha_hex, signature);
  }

  infof(data, "aws_sigv4: Signature - %s", sha_hex);

  if(querystring_mode) {
    /* Add only AWS signature parameters to the actual wire query string */
    struct dynbuf aws_params;
    char *new_query = NULL;

    curlx_dyn_init(&aws_params, CURL_MAX_HTTP_HEADER);

    /* Build AWS signature parameters only */
    {
      char *credential_string = curl_maprintf("%s/%s", access_key,
                                               credential_scope);
      char *encoded_credential = curl_easy_escape(data, credential_string, 0);
      char *encoded_signed_headers = curl_easy_escape(data,
                                       curlx_dyn_ptr(&signed_headers), 0);
      char *encoded_region_set = NULL;
      if(curlx_strlen(&region_set_or_region) && sigv4a_mode) {
        encoded_region_set = curl_easy_escape(data,
                                              curlx_str(&region_set_or_region),
                                              (int)curlx_strlen(
                                                &region_set_or_region));
      }
      if(!credential_string || !encoded_credential ||
         !encoded_signed_headers ||
         (curlx_strlen(&region_set_or_region) && sigv4a_mode &&
          !encoded_region_set)) {
        result = CURLE_OUT_OF_MEMORY;
        curlx_dyn_free(&aws_params);
        curl_free(credential_string);
        curl_free(encoded_credential);
        curl_free(encoded_signed_headers);
        curl_free(encoded_region_set);
        goto fail;
      }

      if(encoded_region_set) {
        /* Check if X-{Provider}-Date already exists in query */
        char date_param_name[32];
        bool has_date;
        curl_msnprintf(date_param_name, sizeof(date_param_name), "X-%.*s-Date",
                       provider_len, capitalized_provider);
        has_date = has_query_param(data->state.up.query, date_param_name);
        if(has_date) {
          result = curlx_dyn_addf(&aws_params,
                                 "X-%.*s-Algorithm=%s&"
                                 "X-%.*s-Credential=%s&"
                                 "X-%.*s-Region-Set=%s&"
                                 "X-%.*s-SignedHeaders=%s&"
                                 "X-%.*s-Signature=%s",
                                 provider_len, capitalized_provider, algorithm,
                                 provider_len, capitalized_provider,
                                 encoded_credential,
                                 provider_len, capitalized_provider,
                                 encoded_region_set,
                                 provider_len, capitalized_provider,
                                 encoded_signed_headers,
                                 provider_len, capitalized_provider, sha_hex);
        }
        else {
          result = curlx_dyn_addf(&aws_params,
                                 "X-%.*s-Algorithm=%s&"
                                 "X-%.*s-Credential=%s&"
                                 "X-%.*s-Date=%s&"
                                 "X-%.*s-Region-Set=%s&"
                                 "X-%.*s-SignedHeaders=%s&"
                                 "X-%.*s-Signature=%s",
                                 provider_len, capitalized_provider, algorithm,
                                 provider_len, capitalized_provider,
                                 encoded_credential,
                                 provider_len, capitalized_provider, timestamp,
                                 provider_len, capitalized_provider,
                                 encoded_region_set,
                                 provider_len, capitalized_provider,
                                 encoded_signed_headers,
                                 provider_len, capitalized_provider, sha_hex);
        }
      }
      else {
        /* Check if X-{Provider}-Date already exists in query */
        char date_param_name[32];
        bool has_date;
        curl_msnprintf(date_param_name, sizeof(date_param_name), "X-%.*s-Date",
                       provider_len, capitalized_provider);
        has_date = has_query_param(data->state.up.query, date_param_name);
        if(has_date) {
          result = curlx_dyn_addf(&aws_params,
                                 "X-%.*s-Algorithm=%s&"
                                 "X-%.*s-Credential=%s&"
                                 "X-%.*s-SignedHeaders=%s&"
                                 "X-%.*s-Signature=%s",
                                 provider_len, capitalized_provider, algorithm,
                                 provider_len, capitalized_provider,
                                 encoded_credential,
                                 provider_len, capitalized_provider,
                                 encoded_signed_headers,
                                 provider_len, capitalized_provider, sha_hex);
        }
        else {
          result = curlx_dyn_addf(&aws_params,
                                 "X-%.*s-Algorithm=%s&"
                                 "X-%.*s-Credential=%s&"
                                 "X-%.*s-Date=%s&"
                                 "X-%.*s-SignedHeaders=%s&"
                                 "X-%.*s-Signature=%s",
                                 provider_len, capitalized_provider, algorithm,
                                 provider_len, capitalized_provider,
                                 encoded_credential,
                                 provider_len, capitalized_provider, timestamp,
                                 provider_len, capitalized_provider,
                                 encoded_signed_headers,
                                 provider_len, capitalized_provider, sha_hex);
        }
      }
      curl_free(credential_string);
      curl_free(encoded_credential);
      curl_free(encoded_signed_headers);
      curl_free(encoded_region_set);
    }

    /* Add security token if present */
    if(security_token) {
      char *encoded_security_token = curl_easy_escape(data, security_token, 0);
      if(encoded_security_token) {
        result = curlx_dyn_addf(&aws_params, "&X-%.*s-Security-Token=%s",
                                provider_len, capitalized_provider,
                                encoded_security_token);
        curl_free(encoded_security_token);
      }
    }

    if(result) {
      curlx_dyn_free(&aws_params);
      infof(data, "aws_sigv4: ERROR building aws_params, result=%d", result);
      goto fail;
    }

    if(result) {
      curlx_dyn_free(&aws_params);
      goto fail;
    }

    infof(data, "aws_sigv4: aws_params='%s'", curlx_dyn_ptr(&aws_params));
    infof(data, "aws_sigv4: existing query='%s'",
          data->state.up.query ? data->state.up.query : "(null)");

    /* Append AWS parameters to existing query string */
    if(data->state.up.query && *data->state.up.query) {
      new_query = curl_maprintf("%s&%s", data->state.up.query,
                                 curlx_dyn_ptr(&aws_params));
    }
    else {
      new_query = strdup(curlx_dyn_ptr(&aws_params));
    }

    curlx_dyn_free(&aws_params);

    infof(data, "aws_sigv4: new_query='%s'", new_query ? new_query : "(null)");

    if(!new_query) {
      result = CURLE_OUT_OF_MEMORY;
      goto fail;
    }

    /* Replace the query string */
    free(data->state.up.query);
    data->state.up.query = new_query;

    /* In querystring mode, add NO AWS headers use queryparams */
    auth_headers = strdup("");
    if(!auth_headers) {
      result = CURLE_OUT_OF_MEMORY;
      goto fail;
    }
  }
  else {
    /* Header mode - original implementation */

    auth_headers = curl_maprintf("Authorization: %.*s4-%s "
                                 "Credential=%s/%s, "
                                 "SignedHeaders=%s, "
                                 "Signature=%s\r\n"
                                 /*
                                  * date_header is added here, only if it was
                                  * not user-specified (using
                                  * CURLOPT_HTTPHEADER).
                                  * date_header includes \r\n
                                  */
                                 "%s"
                                 "%s", /* optional sha256 header includes
                                         \r\n */
                                 (int)curlx_strlen(&provider0),
                                 curlx_str(&provider0),
                                 sigv4a_mode ? "ECDSA-P256-SHA256" :
                                               "HMAC-SHA256",
                                 access_key,
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
  }

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
  free(secret_key);
  free(security_token);
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

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_AWS */
