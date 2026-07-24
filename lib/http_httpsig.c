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
#include "curl_ed25519.h"
#include "curl_hmac.h"
#include "curl_sha256.h"
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

#define HTTPSIG_MAX_SIG_BASE   CURL_MAX_HTTP_HEADER
#define HTTPSIG_MAX_COMPONENTS 16
#define HTTPSIG_MAX_RAW_SIG    CURL_ED25519_SIGLEN
#define HTTPSIG_DEFAULT_LABEL  "sig1"

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

static enum httpsig_alg id_to_alg(uint8_t val)
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
                               unsigned char **keyout,
                               size_t *keylen)
{
  size_t len, i;
  unsigned char *keybuf;

  *keyout = NULL;
  *keylen = 0;

  len = strlen(hexstr);
  while(len > 0 && ISNEWLINE(hexstr[len - 1]))
    len--;

  if(len == 0 || (len & 1) != 0) {
    failf(data, "httpsig: invalid hex key (length %zu)", len);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(len > CURL_MAX_INPUT_LENGTH) {
    failf(data, "httpsig: hex key too long");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  keybuf = curlx_malloc(len / 2);
  if(!keybuf)
    return CURLE_OUT_OF_MEMORY;

  for(i = 0; i < len; i += 2) {
    if(!ISXDIGIT(hexstr[i]) || !ISXDIGIT(hexstr[i + 1])) {
      failf(data, "httpsig: invalid hex at position %zu ('%c%c')",
            i, hexstr[i], hexstr[i + 1]);
      curlx_free(keybuf);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    keybuf[i / 2] = (unsigned char)((curlx_hexval(hexstr[i]) << 4) |
                                     curlx_hexval(hexstr[i + 1]));
  }

  *keyout = keybuf;
  *keylen = len / 2;
  return CURLE_OK;
}

/* @authority matches the Host header field-value when available (RFC 9421).
   data->state.aptr.host is produced by http_set_aptr_host() before auth. */
static CURLcode httpsig_authority(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  struct dynbuf *authority_buf)
{
  const char *h = data->state.aptr.host;

  if(h && curl_strnequal(h, "host:", 5)) {
    const char *value = h + 5;
    const char *end;

    while(ISBLANK(*value))
      value++;
    if(*value) {
      CURLcode result;

      end = value;
      while(*end && !ISNEWLINE(*end))
        end++;
      while(end > value && ISBLANK(end[-1]))
        end--;
      result = curlx_dyn_addn(authority_buf, value, (size_t)(end - value));
      if(result)
        return result;
      return CURLE_OK;
    }
  }

  {
    const char *hostname = conn->origin->hostname;
    uint16_t port = conn->origin->port;

    if((conn->given->defport != port) && port)
      return curlx_dyn_addf(authority_buf, "%s:%u", hostname, port);
    return curlx_dyn_add(authority_buf, hostname);
  }
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

/* strings defined by RFC 9421 */
#define SIG_METHOD    "@method"
#define SIG_AUTHORITY "@authority"
#define SIG_PATH      "@path"
#define SIG_QUERY     "@query"

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
    if(curl_strequal(name, SIG_METHOD))
      *out = method;
    else if(curl_strequal(name, SIG_AUTHORITY))
      *out = authority;
    else if(curl_strequal(name, SIG_PATH))
      *out = path;
    else if(curl_strequal(name, SIG_QUERY))
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

          while(ISBLANK(*val))
            val++;
          end = val + strlen(val);
          while(end > val && ISSPACE(end[-1]))
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

static CURLcode parse_components(struct Curl_easy *data,
                                 const char *query,
                                 const char **components,
                                 size_t *ncomp_out,
                                 char **hdrs_copy_out)
{
  const char *hdrs = data->set.str[STRING_HTTPSIG_HEADERS];
  size_t ncomp = 0;

  *hdrs_copy_out = NULL;
  if(hdrs && *hdrs) {
    char *p;
    char *hdrs_copy = curlx_strdup(hdrs);
    if(!hdrs_copy)
      return CURLE_OUT_OF_MEMORY;
    *hdrs_copy_out = hdrs_copy;
    p = hdrs_copy;
    while(*p && ncomp < HTTPSIG_MAX_COMPONENTS) {
      char *start;
      size_t tlen;

      while(*p == ' ')
        p++;
      if(!*p)
        break;
      start = p;
      while(*p && *p != ' ')
        p++;
      if(*p)
        *p++ = '\0';

      tlen = strlen(start);

      if(tlen && start[tlen - 1] == ':') {
        /* Header field: drop the trailing ':' marker. RFC 9421 field
           names are canonically lowercase (Section 2.1). */
        start[--tlen] = '\0';
        if(!tlen) {
          failf(data, "httpsig: empty header component name");
          return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        Curl_strntolower(start, start, tlen);
        components[ncomp++] = start;
      }
      else {
        /* Derived component: map the bare name to its canonical RFC 9421
           '@'-prefixed identifier (Section 2.2). */
        Curl_strntolower(start, start, tlen);
        if(!strcmp(start, "method"))
          components[ncomp++] = SIG_METHOD;
        else if(!strcmp(start, "authority"))
          components[ncomp++] = SIG_AUTHORITY;
        else if(!strcmp(start, "path"))
          components[ncomp++] = SIG_PATH;
        else if(!strcmp(start, "query"))
          components[ncomp++] = SIG_QUERY;
        else {
          failf(data, "httpsig: unknown derived component '%s'; add a "
                "trailing ':' to sign a header field of that name", start);
          return CURLE_BAD_FUNCTION_ARGUMENT;
        }
      }
    }
    if(!ncomp) {
      failf(data, "httpsig: no signature components specified");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(*p) {
      failf(data, "httpsig: too many signature components (max %u)",
            (unsigned int)HTTPSIG_MAX_COMPONENTS);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    /* RFC 9421 Section 2: each covered component MUST occur only once */
    {
      size_t i, j;

      for(i = 0; i < ncomp; i++) {
        for(j = i + 1; j < ncomp; j++) {
          if(!strcmp(components[i], components[j])) {
            failf(data, "httpsig: duplicate signature component '%s'",
                  components[i]);
            return CURLE_BAD_FUNCTION_ARGUMENT;
          }
        }
      }
    }
  }
  else {
    components[ncomp++] = SIG_METHOD;
    components[ncomp++] = SIG_AUTHORITY;
    components[ncomp++] = SIG_PATH;
    if(query && *query)
      components[ncomp++] = SIG_QUERY;
  }

  *ncomp_out = ncomp;
  return CURLE_OK;
}

static time_t httpsig_get_created(void)
{
#ifdef DEBUGBUILD
  char *force = getenv("CURL_FORCETIME");
  if(force && *force) {
    char *sigts = getenv("CURL_HTTPSIG_CREATED");
    if(sigts && *sigts) {
      const char *p = sigts;
      curl_off_t num;
      if(!curlx_str_number(&p, &num, CURL_OFF_T_MAX))
        return (time_t)num;
    }
    return 0;
  }
#endif
  return time(NULL);
}

static CURLcode httpsig_sign_base(struct Curl_easy *data,
                                  enum httpsig_alg alg,
                                  const unsigned char *keybuf,
                                  size_t keylen,
                                  const struct dynbuf *sig_base,
                                  unsigned char *raw_sig,
                                  size_t *raw_sig_len)
{
  CURLcode result;

  switch(alg) {
  case HTTPSIG_ALG_ED25519:
    result = Curl_ed25519_sign(
      keybuf, keylen,
      (const unsigned char *)curlx_dyn_ptr(sig_base),
      curlx_dyn_len(sig_base),
      raw_sig, raw_sig_len);
    break;
  case HTTPSIG_ALG_HMAC_SHA256:
    result = Curl_hmacit(&Curl_HMAC_SHA256, keybuf, keylen,
                         (const unsigned char *)curlx_dyn_ptr(sig_base),
                         curlx_dyn_len(sig_base), raw_sig);
    if(!result)
      *raw_sig_len = CURL_SHA256_DIGEST_LENGTH;
    break;
  default:
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    break;
  }

  if(result && result == CURLE_NOT_BUILT_IN) {
    failf(data, "httpsig: algorithm '%s' not supported by TLS backend",
          alg_to_str(alg));
  }
  return result;
}

CURLcode Curl_output_httpsig(struct Curl_easy *data)
{
  CURLcode result = CURLE_OUT_OF_MEMORY;
  struct connectdata *conn = data->conn;
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
  unsigned char *keybuf = NULL;
  size_t keylen = 0;
  unsigned char raw_sig[HTTPSIG_MAX_RAW_SIG];
  size_t raw_sig_len = 0;
  char *auth_headers = NULL;
  char *hdrs_copy = NULL;
  struct dynbuf query_dyn;

  alg = id_to_alg(data->set.httpsig_algorithm);
  if(alg == HTTPSIG_ALG_UNKNOWN) {
    failf(data, "httpsig: CURLOPT_HTTPSIG_ALGORITHM is required");
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

  result = decode_hex_key(data, hexkey, &keybuf, &keylen);
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

  result = httpsig_authority(data, conn, &authority_buf);
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

  result = parse_components(data, query, components, &ncomp, &hdrs_copy);
  if(result)
    goto fail;

  created = httpsig_get_created();

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

  result = httpsig_sign_base(data, alg, keybuf, keylen, &sig_base,
                             raw_sig, &raw_sig_len);
  if(result)
    goto fail;

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

  curlx_free(data->req.hd_auth);
  data->req.hd_auth = auth_headers;
  data->state.authhost.done = TRUE;
  result = CURLE_OK;

fail:
  if(keybuf) {
    memset(keybuf, 0, keylen);
    curlx_free(keybuf);
  }
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
