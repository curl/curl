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

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_HTTPSIG)

#include "urldata.h"
#include "http_httpsig.h"
#include "httpsig_crypto.h"
#include "http.h"
#include "transfer.h"
#include "curl_trc.h"
#include "slist.h"
#include "curlx/dynbuf.h"
#include "curlx/base64.h"
#include "curlx/strdup.h"
#include "curlx/strparse.h"
#include "strcase.h"

#include <time.h>

#define HTTPSIG_MAX_SIG_BASE  CURL_MAX_HTTP_HEADER
#define HTTPSIG_MAX_COMPONENTS 16
#define HTTPSIG_MAX_KEY_LEN   128
#define HTTPSIG_MAX_RAW_SIG   CURL_HTTPSIG_ED25519_SIGLEN
#define HTTPSIG_DEFAULT_LABEL "sig1"

enum httpsig_alg {
  HTTPSIG_ALG_ED25519,
  HTTPSIG_ALG_HMAC_SHA256,
  HTTPSIG_ALG_UNKNOWN
};

static const char *alg_to_str(enum httpsig_alg alg)
{
  switch(alg) {
  case HTTPSIG_ALG_ED25519:
    return "ed25519";
  case HTTPSIG_ALG_HMAC_SHA256:
    return "hmac-sha256";
  default:
    break;
  }
  return NULL;
}

static enum httpsig_alg long_to_alg(long val)
{
  switch(val) {
  case CURLHTTPSIG_ED25519:
    return HTTPSIG_ALG_ED25519;
  case CURLHTTPSIG_HMAC_SHA256:
    return HTTPSIG_ALG_HMAC_SHA256;
  default:
    break;
  }
  return HTTPSIG_ALG_UNKNOWN;
}

static CURLcode decode_hex_key(struct Curl_easy *data,
                               const char *hexstr,
                               unsigned char *keybuf, size_t bufsz,
                               size_t *keylen)
{
  size_t len, i;

  len = strlen(hexstr);
  while(len > 0 && (hexstr[len - 1] == '\n' || hexstr[len - 1] == '\r'))
    len--;

  if(len == 0 || (len & 1) != 0 || (len / 2) > bufsz) {
    failf(data, "httpsig: invalid hex key (length %zu)", len);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  for(i = 0; i < len; i += 2) {
    if(!ISXDIGIT(hexstr[i]) || !ISXDIGIT(hexstr[i + 1])) {
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    keybuf[i / 2] = (unsigned char)((curlx_hexval(hexstr[i]) << 4) |
                                     curlx_hexval(hexstr[i + 1]));
  }

  *keylen = len / 2;
  return CURLE_OK;
}

static CURLcode sf_append_quoted(struct dynbuf *buf, const char *str)
{
  CURLcode result = curlx_dyn_addn(buf, "\"", 1);
  if(result)
    return result;
  while(*str) {
    if(*str == '\\' || *str == '"') {
      result = curlx_dyn_addn(buf, "\\", 1);
      if(result)
        return result;
    }
    result = curlx_dyn_addn(buf, str, 1);
    if(result)
      return result;
    str++;
  }
  return curlx_dyn_addn(buf, "\"", 1);
}

/* base64-encode raw bytes into an RFC 8941 byte sequence (:base64:) */
static CURLcode sf_encode_byte_seq(const unsigned char *raw, size_t rawlen,
                                   struct dynbuf *out)
{
  CURLcode result;
  size_t b64len;
  char *b64;

  result = curlx_base64_encode(raw, rawlen, &b64, &b64len);
  if(result)
    return result;

  result = curlx_dyn_addn(out, ":", 1);
  if(!result)
    result = curlx_dyn_addn(out, b64, b64len);
  if(!result)
    result = curlx_dyn_addn(out, ":", 1);

  curlx_free(b64);
  return result;
}

static CURLcode build_sig_params(struct dynbuf *params,
                                 const char **components, size_t count,
                                 time_t created, const char *keyid,
                                 enum httpsig_alg alg)
{
  CURLcode result;
  size_t i;

  result = curlx_dyn_addn(params, "(", 1);
  if(result)
    return result;

  for(i = 0; i < count; i++) {
    if(i > 0) {
      result = curlx_dyn_addn(params, " ", 1);
      if(result)
        return result;
    }
    result = sf_append_quoted(params, components[i]);
    if(result)
      return result;
  }

  result = curlx_dyn_addn(params, ")", 1);
  if(result)
    return result;

  result = curlx_dyn_addf(params, ";created=%lld", (long long)created);
  if(result)
    return result;

  if(keyid && *keyid) {
    result = curlx_dyn_add(params, ";keyid=");
    if(result)
      return result;
    result = sf_append_quoted(params, keyid);
    if(result)
      return result;
  }

  result = curlx_dyn_addf(params, ";alg=\"%s\"", alg_to_str(alg));
  return result;
}

/* Resolve a component identifier to its value.
 * For headers, we walk the full user-supplied header list to combine
 * duplicate field values with ", " per RFC 9421 Section 2.1. Each
 * individual value is trimmed of leading/trailing OWS and the trailing
 * \r\n. The combined result is written into the caller-provided buffer. */
static CURLcode resolve_component(const char *name,
                                  const char *method,
                                  const char *authority,
                                  const char *path,
                                  const char *query,
                                  struct Curl_easy *data,
                                  struct dynbuf *valbuf,
                                  const char **out)
{
  *out = NULL;

  if(name[0] == '@') {
    if(curl_strequal(name, "@method"))
      *out = method;
    else if(curl_strequal(name, "@authority"))
      *out = authority;
    else if(curl_strequal(name, "@path"))
      *out = path;
    else if(curl_strequal(name, "@query"))
      *out = query;
    else {
      failf(data, "httpsig: unsupported derived component '%s'", name);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(!*out) {
      failf(data, "httpsig: derived component '%s' has no value", name);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    return CURLE_OK;
  }
  else {
    /* RFC 9421 Section 2.1: walk all user-supplied headers and combine
       duplicate field values with ", " per HTTP field combination rules. */
    struct curl_slist *head;
    size_t namelen = strlen(name);
    bool found = FALSE;

    curlx_dyn_reset(valbuf);

    for(head = data->set.headers; head; head = head->next) {
      if(curl_strnequal(head->data, name, namelen) &&
         Curl_headersep(head->data[namelen])) {
        const char *colon = strchr(head->data, ':');
        if(colon) {
          const char *val = colon + 1;
          const char *end;
          CURLcode result;

          while(*val == ' ' || *val == '\t')
            val++;
          end = val + strlen(val);
          while(end > val &&
                (end[-1] == '\r' || end[-1] == '\n' ||
                 end[-1] == ' ' || end[-1] == '\t'))
            end--;

          if(found) {
            result = curlx_dyn_addn(valbuf, ", ", 2);
            if(result)
              return result;
          }
          result = curlx_dyn_addn(valbuf, val, (size_t)(end - val));
          if(result)
            return result;
          found = TRUE;
        }
      }
    }

    if(found) {
      *out = curlx_dyn_ptr(valbuf);
      return CURLE_OK;
    }
    failf(data, "httpsig: header '%s' not found in request", name);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
}

static CURLcode build_sig_base(struct dynbuf *base,
                               const char **components, size_t count,
                               const char *method,
                               const char *authority,
                               const char *path,
                               const char *query,
                               struct Curl_easy *data,
                               const char *sig_params)
{
  CURLcode result;
  size_t i;
  struct dynbuf hdrvalbuf;

  curlx_dyn_init(&hdrvalbuf, CURL_MAX_HTTP_HEADER);

  for(i = 0; i < count; i++) {
    const char *val = NULL;
    result = resolve_component(components[i], method,
                               authority, path, query, data,
                               &hdrvalbuf, &val);
    if(result || !val) {
      failf(data, "httpsig: cannot resolve component '%s'", components[i]);
      curlx_dyn_free(&hdrvalbuf);
      return result ? result : CURLE_BAD_FUNCTION_ARGUMENT;
    }

    result = curlx_dyn_addf(base, "\"%s\": %s\n", components[i], val);
    if(result) {
      curlx_dyn_free(&hdrvalbuf);
      return result;
    }
  }

  curlx_dyn_free(&hdrvalbuf);
  result = curlx_dyn_addf(base, "\"@signature-params\": %s", sig_params);
  return result;
}

CURLcode Curl_output_httpsig(struct Curl_easy *data)
{
  CURLcode result = CURLE_OUT_OF_MEMORY;
  struct connectdata *conn = data->conn;
  const char *hostname = conn->host.name;
  int port = conn->remote_port;
  const char *path;
  const char *query;
  Curl_HttpReq httpreq;
  const char *method = NULL;
  const char *hexkey;
  const char *keyid;
  enum httpsig_alg alg;
  time_t created;
  struct dynbuf sig_params;
  struct dynbuf sig_base;
  struct dynbuf sig_hdr;
  struct dynbuf input_hdr;
  struct dynbuf authority_buf;
  const char *authority;
  const char *components[HTTPSIG_MAX_COMPONENTS];
  size_t ncomp = 0;
  unsigned char keybuf[HTTPSIG_MAX_KEY_LEN];
  size_t keylen = 0;
  unsigned char raw_sig[HTTPSIG_MAX_RAW_SIG];
  size_t raw_sig_len = 0;
  char *auth_headers = NULL;
  char *hdrs_copy = NULL;
  struct dynbuf query_dyn;

  alg = long_to_alg(data->set.httpsig);
  if(alg == HTTPSIG_ALG_UNKNOWN) {
    failf(data, "httpsig: algorithm is required");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  hexkey = data->set.str[STRING_HTTPSIG_KEY];
  keyid = data->set.str[STRING_HTTPSIG_KEYID];

  if(!hexkey || !*hexkey) {
    failf(data, "httpsig: CURLOPT_HTTPSIG_KEY is required");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  if(!keyid || !*keyid) {
    failf(data, "httpsig: CURLOPT_HTTPSIG_KEYID is required");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(Curl_checkheaders(data, STRCONST("Signature")) ||
     Curl_checkheaders(data, STRCONST("Signature-Input"))) {
    return CURLE_OK;
  }

  curlx_dyn_init(&sig_params, CURL_MAX_HTTP_HEADER);
  curlx_dyn_init(&sig_base, HTTPSIG_MAX_SIG_BASE);
  curlx_dyn_init(&sig_hdr, CURL_MAX_HTTP_HEADER);
  curlx_dyn_init(&input_hdr, CURL_MAX_HTTP_HEADER);
  curlx_dyn_init(&authority_buf, CURL_MAX_HTTP_HEADER);
  curlx_dyn_init(&query_dyn, CURL_MAX_HTTP_HEADER);

  result = decode_hex_key(data, hexkey, keybuf, sizeof(keybuf), &keylen);
  if(result)
    goto fail;

  if(alg == HTTPSIG_ALG_ED25519 && keylen != 32) {
    failf(data, "httpsig: ed25519 requires a 32-byte key (got %zu)", keylen);
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto fail;
  }

  Curl_http_method(data, &method, &httpreq);

  path = data->state.up.path;
  if(!path || !*path)
    path = "/";

  query = data->state.up.query;

  /* Build @authority: only include port when non-default */
  if((conn->given->defport != port) && port)
    result = curlx_dyn_addf(&authority_buf, "%s:%d", hostname, port);
  else
    result = curlx_dyn_add(&authority_buf, hostname);
  if(result)
    goto fail;
  authority = curlx_dyn_ptr(&authority_buf);

  /* Build @query value: RFC 9421 Section 2.2.7 - always starts with "?" */
  if(query && *query)
    result = curlx_dyn_addf(&query_dyn, "?%s", query);
  else
    result = curlx_dyn_add(&query_dyn, "?");
  if(result)
    goto fail;

  {
    const char *hdrs = data->set.str[STRING_HTTPSIG_HEADERS];
    if(hdrs && *hdrs) {
      char *p;
      hdrs_copy = curlx_strdup(hdrs);
      if(!hdrs_copy)
        goto fail;
      p = hdrs_copy;
      while(*p && ncomp < HTTPSIG_MAX_COMPONENTS) {
        char *start;
        while(*p == ' ')
          p++;
        if(!*p)
          break;
        start = p;
        while(*p && *p != ' ')
          p++;
        if(*p)
          *p++ = '\0';
        /* RFC 9421 Section 2.1: field names MUST be lowercased */
        if(start[0] != '@')
          Curl_strntolower(start, start, strlen(start));
        components[ncomp++] = start;
      }
    }
    else {
      components[ncomp++] = "@method";
      components[ncomp++] = "@authority";
      components[ncomp++] = "@path";
      if(query && *query)
        components[ncomp++] = "@query";
    }
  }

#ifdef DEBUGBUILD
  {
    char *force = getenv("CURL_FORCETIME");
    if(force && *force) {
      char *sigts = getenv("CURL_HTTPSIG_CREATED");
      if(sigts && *sigts) {
        const char *p = sigts;
        curl_off_t num;
        if(!curlx_str_number(&p, &num, CURL_OFF_T_MAX))
          created = (time_t)num;
        else
          created = 0;
      }
      else
        created = 0;
    }
    else
      created = time(NULL);
  }
#else
  created = time(NULL);
#endif

  result = build_sig_params(&sig_params, components, ncomp,
                            created, keyid, alg);
  if(result)
    goto fail;

  infof(data, "httpsig: Signature-Input params: %s",
        curlx_dyn_ptr(&sig_params));

  result = build_sig_base(&sig_base, components, ncomp,
                          method, authority, path,
                          curlx_dyn_ptr(&query_dyn),
                          data, curlx_dyn_ptr(&sig_params));
  if(result)
    goto fail;

  infof(data, "httpsig: Signature base: [%s]",
        curlx_dyn_ptr(&sig_base));

  switch(alg) {
  case HTTPSIG_ALG_ED25519:
    result = Curl_httpsig_ed25519_sign(
      keybuf, keylen,
      (const unsigned char *)curlx_dyn_ptr(&sig_base),
      curlx_dyn_len(&sig_base),
      raw_sig, &raw_sig_len);
    break;
  case HTTPSIG_ALG_HMAC_SHA256:
    result = Curl_httpsig_hmac_sha256_sign(
      keybuf, keylen,
      (const unsigned char *)curlx_dyn_ptr(&sig_base),
      curlx_dyn_len(&sig_base),
      raw_sig, &raw_sig_len);
    break;
  default:
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  }

  if(result) {
    if(result == CURLE_NOT_BUILT_IN)
      failf(data, "httpsig: algorithm '%s' not supported by TLS backend",
            alg_to_str(alg));
    goto fail;
  }

  result = curlx_dyn_add(&sig_hdr, HTTPSIG_DEFAULT_LABEL "=");
  if(result)
    goto fail;
  result = sf_encode_byte_seq(raw_sig, raw_sig_len, &sig_hdr);
  if(result)
    goto fail;

  result = curlx_dyn_addf(&input_hdr, "%s=%s",
                           HTTPSIG_DEFAULT_LABEL,
                           curlx_dyn_ptr(&sig_params));
  if(result)
    goto fail;

  auth_headers = curl_maprintf(
    "Signature-Input: %s\r\n"
    "Signature: %s\r\n",
    curlx_dyn_ptr(&input_hdr),
    curlx_dyn_ptr(&sig_hdr));

  if(!auth_headers)
    goto fail;

  infof(data, "httpsig: Signature-Input: %s", curlx_dyn_ptr(&input_hdr));
  infof(data, "httpsig: Signature: %s", curlx_dyn_ptr(&sig_hdr));

  curlx_free(data->state.aptr.userpwd);
  data->state.aptr.userpwd = auth_headers;
  data->state.authhost.done = TRUE;
  result = CURLE_OK;

fail:
  memset(keybuf, 0, sizeof(keybuf));
  memset(raw_sig, 0, sizeof(raw_sig));
  curlx_free(hdrs_copy);
  curlx_dyn_free(&sig_params);
  curlx_dyn_free(&sig_base);
  curlx_dyn_free(&sig_hdr);
  curlx_dyn_free(&input_hdr);
  curlx_dyn_free(&authority_buf);
  curlx_dyn_free(&query_dyn);
  return result;
}

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_HTTPSIG */
