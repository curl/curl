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
 * RFC2831 DIGEST-MD5 authentication
 * RFC7616 DIGEST-SHA256, DIGEST-SHA512-256 authentication
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_DIGEST_AUTH

#include <curl/curl.h>

#include "vauth/vauth.h"
#include "vauth/digest.h"
#include "urldata.h"
#include "curl_base64.h"
#include "curl_hmac.h"
#include "curl_md5.h"
#include "curl_sha256.h"
#include "curl_sha512_256.h"
#include "vtls/vtls.h"
#include "warnless.h"
#include "strtok.h"
#include "strcase.h"
#include "curl_printf.h"
#include "rand.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#define SESSION_ALGO 1 /* for algos with this bit set */

#define ALGO_MD5 0
#define ALGO_MD5SESS (ALGO_MD5 | SESSION_ALGO)
#define ALGO_SHA256 2
#define ALGO_SHA256SESS (ALGO_SHA256 | SESSION_ALGO)
#define ALGO_SHA512_256 4
#define ALGO_SHA512_256SESS (ALGO_SHA512_256 | SESSION_ALGO)

#if !defined(USE_WINDOWS_SSPI)
#define DIGEST_QOP_VALUE_AUTH             (1 << 0)
#define DIGEST_QOP_VALUE_AUTH_INT         (1 << 1)
#define DIGEST_QOP_VALUE_AUTH_CONF        (1 << 2)

#define DIGEST_QOP_VALUE_STRING_AUTH      "auth"
#define DIGEST_QOP_VALUE_STRING_AUTH_INT  "auth-int"
#define DIGEST_QOP_VALUE_STRING_AUTH_CONF "auth-conf"
#endif

bool Curl_auth_digest_get_pair(const char *str, char *value, char *content,
                               const char **endptr)
{
  int c;
  bool starts_with_quote = FALSE;
  bool escape = FALSE;

  for(c = DIGEST_MAX_VALUE_LENGTH - 1; (*str && (*str != '=') && c--);)
    *value++ = *str++;
  *value = 0;

  if('=' != *str++)
    /* eek, no match */
    return FALSE;

  if('\"' == *str) {
    /* This starts with a quote so it must end with one as well! */
    str++;
    starts_with_quote = TRUE;
  }

  for(c = DIGEST_MAX_CONTENT_LENGTH - 1; *str && c--; str++) {
    if(!escape) {
      switch(*str) {
      case '\\':
        if(starts_with_quote) {
          /* the start of an escaped quote */
          escape = TRUE;
          continue;
        }
        break;

      case ',':
        if(!starts_with_quote) {
          /* This signals the end of the content if we did not get a starting
             quote and then we do "sloppy" parsing */
          c = 0; /* the end */
          continue;
        }
        break;

      case '\r':
      case '\n':
        /* end of string */
        if(starts_with_quote)
          return FALSE; /* No closing quote */
        c = 0;
        continue;

      case '\"':
        if(starts_with_quote) {
          /* end of string */
          c = 0;
          continue;
        }
        else
          return FALSE;
      }
    }

    escape = FALSE;
    *content++ = *str;
  }
  if(escape)
    return FALSE; /* No character after backslash */

  *content = 0;
  *endptr = str;

  return TRUE;
}

#if !defined(USE_WINDOWS_SSPI)
/* Convert md5 chunk to RFC2617 (section 3.1.3) -suitable ASCII string */
static void auth_digest_md5_to_ascii(unsigned char *source, /* 16 bytes */
                                     unsigned char *dest) /* 33 bytes */
{
  int i;
  for(i = 0; i < 16; i++)
    msnprintf((char *) &dest[i * 2], 3, "%02x", source[i]);
}

/* Convert sha256 or SHA-512/256 chunk to RFC7616 -suitable ASCII string */
static void auth_digest_sha256_to_ascii(unsigned char *source, /* 32 bytes */
                                     unsigned char *dest) /* 65 bytes */
{
  int i;
  for(i = 0; i < 32; i++)
    msnprintf((char *) &dest[i * 2], 3, "%02x", source[i]);
}

/* Perform quoted-string escaping as described in RFC2616 and its errata */
static char *auth_digest_string_quoted(const char *source)
{
  char *dest;
  const char *s = source;
  size_t n = 1; /* null terminator */

  /* Calculate size needed */
  while(*s) {
    ++n;
    if(*s == '"' || *s == '\\') {
      ++n;
    }
    ++s;
  }

  dest = malloc(n);
  if(dest) {
    char *d = dest;
    s = source;
    while(*s) {
      if(*s == '"' || *s == '\\') {
        *d++ = '\\';
      }
      *d++ = *s++;
    }
    *d = '\0';
  }

  return dest;
}

/* Retrieves the value for a corresponding key from the challenge string
 * returns TRUE if the key could be found, FALSE if it does not exists
 */
static bool auth_digest_get_key_value(const char *chlg,
                                      const char *key,
                                      char *value,
                                      size_t max_val_len,
                                      char end_char)
{
  char *find_pos;
  size_t i;

  find_pos = strstr(chlg, key);
  if(!find_pos)
    return FALSE;

  find_pos += strlen(key);

  for(i = 0; *find_pos && *find_pos != end_char && i < max_val_len - 1; ++i)
    value[i] = *find_pos++;
  value[i] = '\0';

  return TRUE;
}

static CURLcode auth_digest_get_qop_values(const char *options, int *value)
{
  char *tmp;
  char *token;
  char *tok_buf = NULL;

  /* Initialise the output */
  *value = 0;

  /* Tokenise the list of qop values. Use a temporary clone of the buffer since
     Curl_strtok_r() ruins it. */
  tmp = strdup(options);
  if(!tmp)
    return CURLE_OUT_OF_MEMORY;

  token = Curl_strtok_r(tmp, ",", &tok_buf);
  while(token) {
    if(strcasecompare(token, DIGEST_QOP_VALUE_STRING_AUTH))
      *value |= DIGEST_QOP_VALUE_AUTH;
    else if(strcasecompare(token, DIGEST_QOP_VALUE_STRING_AUTH_INT))
      *value |= DIGEST_QOP_VALUE_AUTH_INT;
    else if(strcasecompare(token, DIGEST_QOP_VALUE_STRING_AUTH_CONF))
      *value |= DIGEST_QOP_VALUE_AUTH_CONF;

    token = Curl_strtok_r(NULL, ",", &tok_buf);
  }

  free(tmp);

  return CURLE_OK;
}

/*
 * auth_decode_digest_md5_message()
 *
 * This is used internally to decode an already encoded DIGEST-MD5 challenge
 * message into the separate attributes.
 *
 * Parameters:
 *
 * chlgref [in]     - The challenge message.
 * nonce   [in/out] - The buffer where the nonce will be stored.
 * nlen    [in]     - The length of the nonce buffer.
 * realm   [in/out] - The buffer where the realm will be stored.
 * rlen    [in]     - The length of the realm buffer.
 * alg     [in/out] - The buffer where the algorithm will be stored.
 * alen    [in]     - The length of the algorithm buffer.
 * qop     [in/out] - The buffer where the qop-options will be stored.
 * qlen    [in]     - The length of the qop buffer.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode auth_decode_digest_md5_message(const struct bufref *chlgref,
                                               char *nonce, size_t nlen,
                                               char *realm, size_t rlen,
                                               char *alg, size_t alen,
                                               char *qop, size_t qlen)
{
  const char *chlg = (const char *) Curl_bufref_ptr(chlgref);

  /* Ensure we have a valid challenge message */
  if(!Curl_bufref_len(chlgref))
    return CURLE_BAD_CONTENT_ENCODING;

  /* Retrieve nonce string from the challenge */
  if(!auth_digest_get_key_value(chlg, "nonce=\"", nonce, nlen, '\"'))
    return CURLE_BAD_CONTENT_ENCODING;

  /* Retrieve realm string from the challenge */
  if(!auth_digest_get_key_value(chlg, "realm=\"", realm, rlen, '\"')) {
    /* Challenge does not have a realm, set empty string [RFC2831] page 6 */
    *realm = '\0';
  }

  /* Retrieve algorithm string from the challenge */
  if(!auth_digest_get_key_value(chlg, "algorithm=", alg, alen, ','))
    return CURLE_BAD_CONTENT_ENCODING;

  /* Retrieve qop-options string from the challenge */
  if(!auth_digest_get_key_value(chlg, "qop=\"", qop, qlen, '\"'))
    return CURLE_BAD_CONTENT_ENCODING;

  return CURLE_OK;
}

/*
 * Curl_auth_is_digest_supported()
 *
 * This is used to evaluate if DIGEST is supported.
 *
 * Parameters: None
 *
 * Returns TRUE as DIGEST as handled by libcurl.
 */
bool Curl_auth_is_digest_supported(void)
{
  return TRUE;
}

/*
 * Curl_auth_create_digest_md5_message()
 *
 * This is used to generate an already encoded DIGEST-MD5 response message
 * ready for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * chlg    [in]     - The challenge message.
 * userp   [in]     - The username.
 * passwdp [in]     - The user's password.
 * service [in]     - The service type such as http, smtp, pop or imap.
 * out     [out]    - The result storage.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_digest_md5_message(struct Curl_easy *data,
                                             const struct bufref *chlg,
                                             const char *userp,
                                             const char *passwdp,
                                             const char *service,
                                             struct bufref *out)
{
  size_t i;
  struct MD5_context *ctxt;
  char *response = NULL;
  unsigned char digest[MD5_DIGEST_LEN];
  char HA1_hex[2 * MD5_DIGEST_LEN + 1];
  char HA2_hex[2 * MD5_DIGEST_LEN + 1];
  char resp_hash_hex[2 * MD5_DIGEST_LEN + 1];
  char nonce[64];
  char realm[128];
  char algorithm[64];
  char qop_options[64];
  int qop_values;
  char cnonce[33];
  char nonceCount[] = "00000001";
  char method[]     = "AUTHENTICATE";
  char qop[]        = DIGEST_QOP_VALUE_STRING_AUTH;
  char *spn         = NULL;

  /* Decode the challenge message */
  CURLcode result = auth_decode_digest_md5_message(chlg,
                                                   nonce, sizeof(nonce),
                                                   realm, sizeof(realm),
                                                   algorithm,
                                                   sizeof(algorithm),
                                                   qop_options,
                                                   sizeof(qop_options));
  if(result)
    return result;

  /* We only support md5 sessions */
  if(strcmp(algorithm, "md5-sess") != 0)
    return CURLE_BAD_CONTENT_ENCODING;

  /* Get the qop-values from the qop-options */
  result = auth_digest_get_qop_values(qop_options, &qop_values);
  if(result)
    return result;

  /* We only support auth quality-of-protection */
  if(!(qop_values & DIGEST_QOP_VALUE_AUTH))
    return CURLE_BAD_CONTENT_ENCODING;

  /* Generate 32 random hex chars, 32 bytes + 1 null-termination */
  result = Curl_rand_hex(data, (unsigned char *)cnonce, sizeof(cnonce));
  if(result)
    return result;

  /* So far so good, now calculate A1 and H(A1) according to RFC 2831 */
  ctxt = Curl_MD5_init(&Curl_DIGEST_MD5);
  if(!ctxt)
    return CURLE_OUT_OF_MEMORY;

  Curl_MD5_update(ctxt, (const unsigned char *) userp,
                  curlx_uztoui(strlen(userp)));
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);
  Curl_MD5_update(ctxt, (const unsigned char *) realm,
                  curlx_uztoui(strlen(realm)));
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);
  Curl_MD5_update(ctxt, (const unsigned char *) passwdp,
                  curlx_uztoui(strlen(passwdp)));
  Curl_MD5_final(ctxt, digest);

  ctxt = Curl_MD5_init(&Curl_DIGEST_MD5);
  if(!ctxt)
    return CURLE_OUT_OF_MEMORY;

  Curl_MD5_update(ctxt, (const unsigned char *) digest, MD5_DIGEST_LEN);
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);
  Curl_MD5_update(ctxt, (const unsigned char *) nonce,
                  curlx_uztoui(strlen(nonce)));
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);
  Curl_MD5_update(ctxt, (const unsigned char *) cnonce,
                  curlx_uztoui(strlen(cnonce)));
  Curl_MD5_final(ctxt, digest);

  /* Convert calculated 16 octet hex into 32 bytes string */
  for(i = 0; i < MD5_DIGEST_LEN; i++)
    msnprintf(&HA1_hex[2 * i], 3, "%02x", digest[i]);

  /* Generate our SPN */
  spn = Curl_auth_build_spn(service, data->conn->host.name, NULL);
  if(!spn)
    return CURLE_OUT_OF_MEMORY;

  /* Calculate H(A2) */
  ctxt = Curl_MD5_init(&Curl_DIGEST_MD5);
  if(!ctxt) {
    free(spn);

    return CURLE_OUT_OF_MEMORY;
  }

  Curl_MD5_update(ctxt, (const unsigned char *) method,
                  curlx_uztoui(strlen(method)));
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);
  Curl_MD5_update(ctxt, (const unsigned char *) spn,
                  curlx_uztoui(strlen(spn)));
  Curl_MD5_final(ctxt, digest);

  for(i = 0; i < MD5_DIGEST_LEN; i++)
    msnprintf(&HA2_hex[2 * i], 3, "%02x", digest[i]);

  /* Now calculate the response hash */
  ctxt = Curl_MD5_init(&Curl_DIGEST_MD5);
  if(!ctxt) {
    free(spn);

    return CURLE_OUT_OF_MEMORY;
  }

  Curl_MD5_update(ctxt, (const unsigned char *) HA1_hex, 2 * MD5_DIGEST_LEN);
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);
  Curl_MD5_update(ctxt, (const unsigned char *) nonce,
                  curlx_uztoui(strlen(nonce)));
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);

  Curl_MD5_update(ctxt, (const unsigned char *) nonceCount,
                  curlx_uztoui(strlen(nonceCount)));
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);
  Curl_MD5_update(ctxt, (const unsigned char *) cnonce,
                  curlx_uztoui(strlen(cnonce)));
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);
  Curl_MD5_update(ctxt, (const unsigned char *) qop,
                  curlx_uztoui(strlen(qop)));
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);

  Curl_MD5_update(ctxt, (const unsigned char *) HA2_hex, 2 * MD5_DIGEST_LEN);
  Curl_MD5_final(ctxt, digest);

  for(i = 0; i < MD5_DIGEST_LEN; i++)
    msnprintf(&resp_hash_hex[2 * i], 3, "%02x", digest[i]);

  /* Generate the response */
  response = aprintf("username=\"%s\",realm=\"%s\",nonce=\"%s\","
                     "cnonce=\"%s\",nc=\"%s\",digest-uri=\"%s\",response=%s,"
                     "qop=%s",
                     userp, realm, nonce,
                     cnonce, nonceCount, spn, resp_hash_hex, qop);
  free(spn);
  if(!response)
    return CURLE_OUT_OF_MEMORY;

  /* Return the response. */
  Curl_bufref_set(out, response, strlen(response), curl_free);
  return result;
}

/*
 * Curl_auth_decode_digest_http_message()
 *
 * This is used to decode an HTTP DIGEST challenge message into the separate
 * attributes.
 *
 * Parameters:
 *
 * chlg    [in]     - The challenge message.
 * digest  [in/out] - The digest data struct being used and modified.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_decode_digest_http_message(const char *chlg,
                                              struct digestdata *digest)
{
  bool before = FALSE; /* got a nonce before */
  bool foundAuth = FALSE;
  bool foundAuthInt = FALSE;
  char *token = NULL;
  char *tmp = NULL;

  /* If we already have received a nonce, keep that in mind */
  if(digest->nonce)
    before = TRUE;

  /* Clean up any former leftovers and initialise to defaults */
  Curl_auth_digest_cleanup(digest);

  for(;;) {
    char value[DIGEST_MAX_VALUE_LENGTH];
    char content[DIGEST_MAX_CONTENT_LENGTH];

    /* Pass all additional spaces here */
    while(*chlg && ISBLANK(*chlg))
      chlg++;

    /* Extract a value=content pair */
    if(Curl_auth_digest_get_pair(chlg, value, content, &chlg)) {
      if(strcasecompare(value, "nonce")) {
        free(digest->nonce);
        digest->nonce = strdup(content);
        if(!digest->nonce)
          return CURLE_OUT_OF_MEMORY;
      }
      else if(strcasecompare(value, "stale")) {
        if(strcasecompare(content, "true")) {
          digest->stale = TRUE;
          digest->nc = 1; /* we make a new nonce now */
        }
      }
      else if(strcasecompare(value, "realm")) {
        free(digest->realm);
        digest->realm = strdup(content);
        if(!digest->realm)
          return CURLE_OUT_OF_MEMORY;
      }
      else if(strcasecompare(value, "opaque")) {
        free(digest->opaque);
        digest->opaque = strdup(content);
        if(!digest->opaque)
          return CURLE_OUT_OF_MEMORY;
      }
      else if(strcasecompare(value, "qop")) {
        char *tok_buf = NULL;
        /* Tokenize the list and choose auth if possible, use a temporary
           clone of the buffer since Curl_strtok_r() ruins it */
        tmp = strdup(content);
        if(!tmp)
          return CURLE_OUT_OF_MEMORY;

        token = Curl_strtok_r(tmp, ",", &tok_buf);
        while(token) {
          /* Pass additional spaces here */
          while(*token && ISBLANK(*token))
            token++;
          if(strcasecompare(token, DIGEST_QOP_VALUE_STRING_AUTH)) {
            foundAuth = TRUE;
          }
          else if(strcasecompare(token, DIGEST_QOP_VALUE_STRING_AUTH_INT)) {
            foundAuthInt = TRUE;
          }
          token = Curl_strtok_r(NULL, ",", &tok_buf);
        }

        free(tmp);

        /* Select only auth or auth-int. Otherwise, ignore */
        if(foundAuth) {
          free(digest->qop);
          digest->qop = strdup(DIGEST_QOP_VALUE_STRING_AUTH);
          if(!digest->qop)
            return CURLE_OUT_OF_MEMORY;
        }
        else if(foundAuthInt) {
          free(digest->qop);
          digest->qop = strdup(DIGEST_QOP_VALUE_STRING_AUTH_INT);
          if(!digest->qop)
            return CURLE_OUT_OF_MEMORY;
        }
      }
      else if(strcasecompare(value, "algorithm")) {
        free(digest->algorithm);
        digest->algorithm = strdup(content);
        if(!digest->algorithm)
          return CURLE_OUT_OF_MEMORY;

        if(strcasecompare(content, "MD5-sess"))
          digest->algo = ALGO_MD5SESS;
        else if(strcasecompare(content, "MD5"))
          digest->algo = ALGO_MD5;
        else if(strcasecompare(content, "SHA-256"))
          digest->algo = ALGO_SHA256;
        else if(strcasecompare(content, "SHA-256-SESS"))
          digest->algo = ALGO_SHA256SESS;
        else if(strcasecompare(content, "SHA-512-256")) {
#ifdef CURL_HAVE_SHA512_256
          digest->algo = ALGO_SHA512_256;
#else  /* ! CURL_HAVE_SHA512_256 */
          return CURLE_NOT_BUILT_IN;
#endif /* ! CURL_HAVE_SHA512_256 */
        }
        else if(strcasecompare(content, "SHA-512-256-SESS")) {
#ifdef CURL_HAVE_SHA512_256
          digest->algo = ALGO_SHA512_256SESS;
#else  /* ! CURL_HAVE_SHA512_256 */
          return CURLE_NOT_BUILT_IN;
#endif /* ! CURL_HAVE_SHA512_256 */
        }
        else
          return CURLE_BAD_CONTENT_ENCODING;
      }
      else if(strcasecompare(value, "userhash")) {
        if(strcasecompare(content, "true")) {
          digest->userhash = TRUE;
        }
      }
      else {
        /* Unknown specifier, ignore it! */
      }
    }
    else
      break; /* We are done here */

    /* Pass all additional spaces here */
    while(*chlg && ISBLANK(*chlg))
      chlg++;

    /* Allow the list to be comma-separated */
    if(',' == *chlg)
      chlg++;
  }

  /* We had a nonce since before, and we got another one now without
     'stale=true'. This means we provided bad credentials in the previous
     request */
  if(before && !digest->stale)
    return CURLE_BAD_CONTENT_ENCODING;

  /* We got this header without a nonce, that is a bad Digest line! */
  if(!digest->nonce)
    return CURLE_BAD_CONTENT_ENCODING;

  /* "<algo>-sess" protocol versions require "auth" or "auth-int" qop */
  if(!digest->qop && (digest->algo & SESSION_ALGO))
    return CURLE_BAD_CONTENT_ENCODING;

  return CURLE_OK;
}

/*
 * auth_create_digest_http_message()
 *
 * This is used to generate an HTTP DIGEST response message ready for sending
 * to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The username.
 * passwdp [in]     - The user's password.
 * request [in]     - The HTTP request.
 * uripath [in]     - The path of the HTTP uri.
 * digest  [in/out] - The digest data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode auth_create_digest_http_message(
                  struct Curl_easy *data,
                  const char *userp,
                  const char *passwdp,
                  const unsigned char *request,
                  const unsigned char *uripath,
                  struct digestdata *digest,
                  char **outptr, size_t *outlen,
                  void (*convert_to_ascii)(unsigned char *, unsigned char *),
                  CURLcode (*hash)(unsigned char *, const unsigned char *,
                                   const size_t))
{
  CURLcode result;
  unsigned char hashbuf[32]; /* 32 bytes/256 bits */
  unsigned char request_digest[65];
  unsigned char ha1[65];    /* 64 digits and 1 zero byte */
  unsigned char ha2[65];    /* 64 digits and 1 zero byte */
  char userh[65];
  char *cnonce = NULL;
  size_t cnonce_sz = 0;
  char *userp_quoted;
  char *realm_quoted;
  char *nonce_quoted;
  char *response = NULL;
  char *hashthis = NULL;
  char *tmp = NULL;

  memset(hashbuf, 0, sizeof(hashbuf));
  if(!digest->nc)
    digest->nc = 1;

  if(!digest->cnonce) {
    char cnoncebuf[12];
    result = Curl_rand_bytes(data,
#ifdef DEBUGBUILD
                             TRUE,
#endif
                             (unsigned char *)cnoncebuf,
                             sizeof(cnoncebuf));
    if(result)
      return result;

    result = Curl_base64_encode(cnoncebuf, sizeof(cnoncebuf),
                                &cnonce, &cnonce_sz);
    if(result)
      return result;

    digest->cnonce = cnonce;
  }

  if(digest->userhash) {
    hashthis = aprintf("%s:%s", userp, digest->realm ? digest->realm : "");
    if(!hashthis)
      return CURLE_OUT_OF_MEMORY;

    result = hash(hashbuf, (unsigned char *) hashthis, strlen(hashthis));
    free(hashthis);
    if(result)
      return result;
    convert_to_ascii(hashbuf, (unsigned char *)userh);
  }

  /*
    If the algorithm is "MD5" or unspecified (which then defaults to MD5):

      A1 = unq(username-value) ":" unq(realm-value) ":" passwd

    If the algorithm is "MD5-sess" then:

      A1 = H(unq(username-value) ":" unq(realm-value) ":" passwd) ":"
           unq(nonce-value) ":" unq(cnonce-value)
  */

  hashthis = aprintf("%s:%s:%s", userp, digest->realm ? digest->realm : "",
                     passwdp);
  if(!hashthis)
    return CURLE_OUT_OF_MEMORY;

  result = hash(hashbuf, (unsigned char *) hashthis, strlen(hashthis));
  free(hashthis);
  if(result)
    return result;
  convert_to_ascii(hashbuf, ha1);

  if(digest->algo & SESSION_ALGO) {
    /* nonce and cnonce are OUTSIDE the hash */
    tmp = aprintf("%s:%s:%s", ha1, digest->nonce, digest->cnonce);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;

    result = hash(hashbuf, (unsigned char *) tmp, strlen(tmp));
    free(tmp);
    if(result)
      return result;
    convert_to_ascii(hashbuf, ha1);
  }

  /*
    If the "qop" directive's value is "auth" or is unspecified, then A2 is:

      A2 = Method ":" digest-uri-value

    If the "qop" value is "auth-int", then A2 is:

      A2 = Method ":" digest-uri-value ":" H(entity-body)

    (The "Method" value is the HTTP request method as specified in section
    5.1.1 of RFC 2616)
  */

  hashthis = aprintf("%s:%s", request, uripath);
  if(!hashthis)
    return CURLE_OUT_OF_MEMORY;

  if(digest->qop && strcasecompare(digest->qop, "auth-int")) {
    /* We do not support auth-int for PUT or POST */
    char hashed[65];
    char *hashthis2;

    result = hash(hashbuf, (const unsigned char *)"", 0);
    if(result) {
      free(hashthis);
      return result;
    }
    convert_to_ascii(hashbuf, (unsigned char *)hashed);

    hashthis2 = aprintf("%s:%s", hashthis, hashed);
    free(hashthis);
    hashthis = hashthis2;
  }

  if(!hashthis)
    return CURLE_OUT_OF_MEMORY;

  result = hash(hashbuf, (unsigned char *) hashthis, strlen(hashthis));
  free(hashthis);
  if(result)
    return result;
  convert_to_ascii(hashbuf, ha2);

  if(digest->qop) {
    hashthis = aprintf("%s:%s:%08x:%s:%s:%s", ha1, digest->nonce, digest->nc,
                       digest->cnonce, digest->qop, ha2);
  }
  else {
    hashthis = aprintf("%s:%s:%s", ha1, digest->nonce, ha2);
  }

  if(!hashthis)
    return CURLE_OUT_OF_MEMORY;

  result = hash(hashbuf, (unsigned char *) hashthis, strlen(hashthis));
  free(hashthis);
  if(result)
    return result;
  convert_to_ascii(hashbuf, request_digest);

  /* For test case 64 (snooped from a Mozilla 1.3a request)

     Authorization: Digest username="testuser", realm="testrealm", \
     nonce="1053604145", uri="/64", response="c55f7f30d83d774a3d2dcacf725abaca"

     Digest parameters are all quoted strings. Username which is provided by
     the user will need double quotes and backslashes within it escaped.
     realm, nonce, and opaque will need backslashes as well as they were
     de-escaped when copied from request header. cnonce is generated with
     web-safe characters. uri is already percent encoded. nc is 8 hex
     characters. algorithm and qop with standard values only contain web-safe
     characters.
  */
  userp_quoted = auth_digest_string_quoted(digest->userhash ? userh : userp);
  if(!userp_quoted)
    return CURLE_OUT_OF_MEMORY;
  if(digest->realm)
    realm_quoted = auth_digest_string_quoted(digest->realm);
  else {
    realm_quoted = malloc(1);
    if(realm_quoted)
      realm_quoted[0] = 0;
  }
  if(!realm_quoted) {
    free(userp_quoted);
    return CURLE_OUT_OF_MEMORY;
  }
  nonce_quoted = auth_digest_string_quoted(digest->nonce);
  if(!nonce_quoted) {
    free(realm_quoted);
    free(userp_quoted);
    return CURLE_OUT_OF_MEMORY;
  }

  if(digest->qop) {
    response = aprintf("username=\"%s\", "
                       "realm=\"%s\", "
                       "nonce=\"%s\", "
                       "uri=\"%s\", "
                       "cnonce=\"%s\", "
                       "nc=%08x, "
                       "qop=%s, "
                       "response=\"%s\"",
                       userp_quoted,
                       realm_quoted,
                       nonce_quoted,
                       uripath,
                       digest->cnonce,
                       digest->nc,
                       digest->qop,
                       request_digest);

    /* Increment nonce-count to use another nc value for the next request */
    digest->nc++;
  }
  else {
    response = aprintf("username=\"%s\", "
                       "realm=\"%s\", "
                       "nonce=\"%s\", "
                       "uri=\"%s\", "
                       "response=\"%s\"",
                       userp_quoted,
                       realm_quoted,
                       nonce_quoted,
                       uripath,
                       request_digest);
  }
  free(nonce_quoted);
  free(realm_quoted);
  free(userp_quoted);
  if(!response)
    return CURLE_OUT_OF_MEMORY;

  /* Add the optional fields */
  if(digest->opaque) {
    char *opaque_quoted;
    /* Append the opaque */
    opaque_quoted = auth_digest_string_quoted(digest->opaque);
    if(!opaque_quoted) {
      free(response);
      return CURLE_OUT_OF_MEMORY;
    }
    tmp = aprintf("%s, opaque=\"%s\"", response, opaque_quoted);
    free(response);
    free(opaque_quoted);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;

    response = tmp;
  }

  if(digest->algorithm) {
    /* Append the algorithm */
    tmp = aprintf("%s, algorithm=%s", response, digest->algorithm);
    free(response);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;

    response = tmp;
  }

  if(digest->userhash) {
    /* Append the userhash */
    tmp = aprintf("%s, userhash=true", response);
    free(response);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;

    response = tmp;
  }

  /* Return the output */
  *outptr = response;
  *outlen = strlen(response);

  return CURLE_OK;
}

/*
 * Curl_auth_create_digest_http_message()
 *
 * This is used to generate an HTTP DIGEST response message ready for sending
 * to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The username.
 * passwdp [in]     - The user's password.
 * request [in]     - The HTTP request.
 * uripath [in]     - The path of the HTTP uri.
 * digest  [in/out] - The digest data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_digest_http_message(struct Curl_easy *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const unsigned char *request,
                                              const unsigned char *uripath,
                                              struct digestdata *digest,
                                              char **outptr, size_t *outlen)
{
  if(digest->algo <= ALGO_MD5SESS)
    return auth_create_digest_http_message(data, userp, passwdp,
                                           request, uripath, digest,
                                           outptr, outlen,
                                           auth_digest_md5_to_ascii,
                                           Curl_md5it);

  if(digest->algo <= ALGO_SHA256SESS)
    return auth_create_digest_http_message(data, userp, passwdp,
                                           request, uripath, digest,
                                           outptr, outlen,
                                           auth_digest_sha256_to_ascii,
                                           Curl_sha256it);
#ifdef CURL_HAVE_SHA512_256
  if(digest->algo <= ALGO_SHA512_256SESS)
    return auth_create_digest_http_message(data, userp, passwdp,
                                           request, uripath, digest,
                                           outptr, outlen,
                                           auth_digest_sha256_to_ascii,
                                           Curl_sha512_256it);
#endif /* CURL_HAVE_SHA512_256 */

  /* Should be unreachable */
  return CURLE_BAD_CONTENT_ENCODING;
}

/*
 * Curl_auth_digest_cleanup()
 *
 * This is used to clean up the digest specific data.
 *
 * Parameters:
 *
 * digest    [in/out] - The digest data struct being cleaned up.
 *
 */
void Curl_auth_digest_cleanup(struct digestdata *digest)
{
  Curl_safefree(digest->nonce);
  Curl_safefree(digest->cnonce);
  Curl_safefree(digest->realm);
  Curl_safefree(digest->opaque);
  Curl_safefree(digest->qop);
  Curl_safefree(digest->algorithm);

  digest->nc = 0;
  digest->algo = ALGO_MD5; /* default algorithm */
  digest->stale = FALSE; /* default means normal, not stale */
  digest->userhash = FALSE;
}
#endif  /* !USE_WINDOWS_SSPI */

#endif  /* !CURL_DISABLE_DIGEST_AUTH */
