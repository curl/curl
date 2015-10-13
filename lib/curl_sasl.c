/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * RFC2195 CRAM-MD5 authentication
 * RFC2617 Basic and Digest Access Authentication
 * RFC2831 DIGEST-MD5 authentication
 * RFC4422 Simple Authentication and Security Layer (SASL)
 * RFC4616 PLAIN authentication
 * RFC6749 OAuth 2.0 Authorization Framework
 * Draft   LOGIN SASL Mechanism <draft-murchison-sasl-login-00.txt>
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>
#include "urldata.h"

#include "curl_base64.h"
#include "curl_md5.h"
#include "vtls/vtls.h"
#include "curl_hmac.h"
#include "curl_sasl.h"
#include "warnless.h"
#include "strtok.h"
#include "strequal.h"
#include "rawstr.h"
#include "sendf.h"
#include "non-ascii.h" /* included for Curl_convert_... prototypes */
#include "curl_printf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/* Supported mechanisms */
const struct {
  const char   *name;  /* Name */
  size_t        len;   /* Name length */
  unsigned int  bit;   /* Flag bit */
} mechtable[] = {
  { "LOGIN",      5,  SASL_MECH_LOGIN },
  { "PLAIN",      5,  SASL_MECH_PLAIN },
  { "CRAM-MD5",   8,  SASL_MECH_CRAM_MD5 },
  { "DIGEST-MD5", 10, SASL_MECH_DIGEST_MD5 },
  { "GSSAPI",     6,  SASL_MECH_GSSAPI },
  { "EXTERNAL",   8,  SASL_MECH_EXTERNAL },
  { "NTLM",       4,  SASL_MECH_NTLM },
  { "XOAUTH2",    7,  SASL_MECH_XOAUTH2 },
  { ZERO_NULL,    0,  0 }
};

#if !defined(CURL_DISABLE_CRYPTO_AUTH) && !defined(USE_WINDOWS_SSPI)
#define DIGEST_QOP_VALUE_AUTH             (1 << 0)
#define DIGEST_QOP_VALUE_AUTH_INT         (1 << 1)
#define DIGEST_QOP_VALUE_AUTH_CONF        (1 << 2)

#define DIGEST_QOP_VALUE_STRING_AUTH      "auth"
#define DIGEST_QOP_VALUE_STRING_AUTH_INT  "auth-int"
#define DIGEST_QOP_VALUE_STRING_AUTH_CONF "auth-conf"

/* The CURL_OUTPUT_DIGEST_CONV macro below is for non-ASCII machines.
   It converts digest text to ASCII so the MD5 will be correct for
   what ultimately goes over the network.
*/
#define CURL_OUTPUT_DIGEST_CONV(a, b) \
  result = Curl_convert_to_network(a, (char *)b, strlen((const char*)b)); \
  if(result) { \
    free(b); \
    return result; \
  }

#endif

#if !defined(CURL_DISABLE_CRYPTO_AUTH)
/*
 * Returns 0 on success and then the buffers are filled in fine.
 *
 * Non-zero means failure to parse.
 */
int Curl_sasl_digest_get_pair(const char *str, char *value, char *content,
                              const char **endptr)
{
  int c;
  bool starts_with_quote = FALSE;
  bool escape = FALSE;

  for(c = DIGEST_MAX_VALUE_LENGTH - 1; (*str && (*str != '=') && c--); )
    *value++ = *str++;
  *value = 0;

  if('=' != *str++)
    /* eek, no match */
    return 1;

  if('\"' == *str) {
    /* this starts with a quote so it must end with one as well! */
    str++;
    starts_with_quote = TRUE;
  }

  for(c = DIGEST_MAX_CONTENT_LENGTH - 1; *str && c--; str++) {
    switch(*str) {
    case '\\':
      if(!escape) {
        /* possibly the start of an escaped quote */
        escape = TRUE;
        *content++ = '\\'; /* even though this is an escape character, we still
                              store it as-is in the target buffer */
        continue;
      }
      break;
    case ',':
      if(!starts_with_quote) {
        /* this signals the end of the content if we didn't get a starting
           quote and then we do "sloppy" parsing */
        c = 0; /* the end */
        continue;
      }
      break;
    case '\r':
    case '\n':
      /* end of string */
      c = 0;
      continue;
    case '\"':
      if(!escape && starts_with_quote) {
        /* end of string */
        c = 0;
        continue;
      }
      break;
    }
    escape = FALSE;
    *content++ = *str;
  }
  *content = 0;

  *endptr = str;

  return 0; /* all is fine! */
}
#endif

#if !defined(CURL_DISABLE_CRYPTO_AUTH) && !defined(USE_WINDOWS_SSPI)
/* Convert md5 chunk to RFC2617 (section 3.1.3) -suitable ascii string*/
static void sasl_digest_md5_to_ascii(unsigned char *source, /* 16 bytes */
                                     unsigned char *dest) /* 33 bytes */
{
  int i;
  for(i = 0; i < 16; i++)
    snprintf((char *)&dest[i*2], 3, "%02x", source[i]);
}

/* Perform quoted-string escaping as described in RFC2616 and its errata */
static char *sasl_digest_string_quoted(const char *source)
{
  char *dest, *d;
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
    s = source;
    d = dest;
    while(*s) {
      if(*s == '"' || *s == '\\') {
        *d++ = '\\';
      }
      *d++ = *s++;
    }
    *d = 0;
  }

  return dest;
}

/* Retrieves the value for a corresponding key from the challenge string
 * returns TRUE if the key could be found, FALSE if it does not exists
 */
static bool sasl_digest_get_key_value(const char *chlg,
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

static CURLcode sasl_digest_get_qop_values(const char *options, int *value)
{
  char *tmp;
  char *token;
  char *tok_buf;

  /* Initialise the output */
  *value = 0;

  /* Tokenise the list of qop values. Use a temporary clone of the buffer since
     strtok_r() ruins it. */
  tmp = strdup(options);
  if(!tmp)
    return CURLE_OUT_OF_MEMORY;

  token = strtok_r(tmp, ",", &tok_buf);
  while(token != NULL) {
    if(Curl_raw_equal(token, DIGEST_QOP_VALUE_STRING_AUTH))
      *value |= DIGEST_QOP_VALUE_AUTH;
    else if(Curl_raw_equal(token, DIGEST_QOP_VALUE_STRING_AUTH_INT))
      *value |= DIGEST_QOP_VALUE_AUTH_INT;
    else if(Curl_raw_equal(token, DIGEST_QOP_VALUE_STRING_AUTH_CONF))
      *value |= DIGEST_QOP_VALUE_AUTH_CONF;

    token = strtok_r(NULL, ",", &tok_buf);
  }

  free(tmp);

  return CURLE_OK;
}
#endif /* !CURL_DISABLE_CRYPTO_AUTH && !USE_WINDOWS_SSPI */

#if !defined(USE_WINDOWS_SSPI)
/*
 * Curl_sasl_build_spn()
 *
 * This is used to build a SPN string in the format service/instance.
 *
 * Parameters:
 *
 * service  [in] - The service type such as www, smtp, pop or imap.
 * instance [in] - The host name or realm.
 *
 * Returns a pointer to the newly allocated SPN.
 */
char *Curl_sasl_build_spn(const char *service, const char *instance)
{
  /* Generate and return our SPN */
  return aprintf("%s/%s", service, instance);
}
#endif

/*
 * sasl_create_plain_message()
 *
 * This is used to generate an already encoded PLAIN message ready
 * for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The user name.
 * passdwp [in]     - The user's password.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode sasl_create_plain_message(struct SessionHandle *data,
                                          const char *userp,
                                          const char *passwdp,
                                          char **outptr, size_t *outlen)
{
  CURLcode result;
  char *plainauth;
  size_t ulen;
  size_t plen;

  ulen = strlen(userp);
  plen = strlen(passwdp);

  plainauth = malloc(2 * ulen + plen + 2);
  if(!plainauth) {
    *outlen = 0;
    *outptr = NULL;
    return CURLE_OUT_OF_MEMORY;
  }

  /* Calculate the reply */
  memcpy(plainauth, userp, ulen);
  plainauth[ulen] = '\0';
  memcpy(plainauth + ulen + 1, userp, ulen);
  plainauth[2 * ulen + 1] = '\0';
  memcpy(plainauth + 2 * ulen + 2, passwdp, plen);

  /* Base64 encode the reply */
  result = Curl_base64_encode(data, plainauth, 2 * ulen + plen + 2, outptr,
                              outlen);
  free(plainauth);
  return result;
}

/*
 * sasl_create_login_message()
 *
 * This is used to generate an already encoded LOGIN message containing the
 * user name or password ready for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * valuep  [in]     - The user name or user's password.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode sasl_create_login_message(struct SessionHandle *data,
                                          const char *valuep, char **outptr,
                                          size_t *outlen)
{
  size_t vlen = strlen(valuep);

  if(!vlen) {
    /* Calculate an empty reply */
    *outptr = strdup("=");
    if(*outptr) {
      *outlen = (size_t) 1;
      return CURLE_OK;
    }

    *outlen = 0;
    return CURLE_OUT_OF_MEMORY;
  }

  /* Base64 encode the value */
  return Curl_base64_encode(data, valuep, vlen, outptr, outlen);
}

/*
 * sasl_create_external_message()
 *
 * This is used to generate an already encoded EXTERNAL message containing
 * the user name ready for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * user    [in]     - The user name.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode sasl_create_external_message(struct SessionHandle *data,
                                             const char *user, char **outptr,
                                             size_t *outlen)
{
  /* This is the same formatting as the login message. */
  return sasl_create_login_message(data, user, outptr, outlen);
}

#ifndef CURL_DISABLE_CRYPTO_AUTH
 /*
 * sasl_decode_cram_md5_message()
 *
 * This is used to decode an already encoded CRAM-MD5 challenge message.
 *
 * Parameters:
 *
 * chlg64  [in]     - The base64 encoded challenge message.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode sasl_decode_cram_md5_message(const char *chlg64, char **outptr,
                                             size_t *outlen)
{
  CURLcode result = CURLE_OK;
  size_t chlg64len = strlen(chlg64);

  *outptr = NULL;
  *outlen = 0;

  /* Decode the challenge if necessary */
  if(chlg64len && *chlg64 != '=')
    result = Curl_base64_decode(chlg64, (unsigned char **) outptr, outlen);

    return result;
 }

 /*
 * sasl_create_cram_md5_message()
 *
 * This is used to generate an already encoded CRAM-MD5 response message ready
 * for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * chlg    [in]     - The challenge.
 * userp   [in]     - The user name.
 * passdwp [in]     - The user's password.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode sasl_create_cram_md5_message(struct SessionHandle *data,
                                             const char *chlg,
                                             const char *userp,
                                             const char *passwdp,
                                             char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  size_t chlglen = 0;
  HMAC_context *ctxt;
  unsigned char digest[MD5_DIGEST_LEN];
  char *response;

  if(chlg)
    chlglen = strlen(chlg);

  /* Compute the digest using the password as the key */
  ctxt = Curl_HMAC_init(Curl_HMAC_MD5,
                        (const unsigned char *) passwdp,
                        curlx_uztoui(strlen(passwdp)));
  if(!ctxt)
    return CURLE_OUT_OF_MEMORY;

  /* Update the digest with the given challenge */
  if(chlglen > 0)
    Curl_HMAC_update(ctxt, (const unsigned char *) chlg,
                     curlx_uztoui(chlglen));

  /* Finalise the digest */
  Curl_HMAC_final(ctxt, digest);

  /* Generate the response */
  response = aprintf(
      "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           userp, digest[0], digest[1], digest[2], digest[3], digest[4],
           digest[5], digest[6], digest[7], digest[8], digest[9], digest[10],
           digest[11], digest[12], digest[13], digest[14], digest[15]);
  if(!response)
    return CURLE_OUT_OF_MEMORY;

  /* Base64 encode the response */
  result = Curl_base64_encode(data, response, 0, outptr, outlen);

  free(response);

  return result;
}

#ifndef USE_WINDOWS_SSPI
/*
 * sasl_decode_digest_md5_message()
 *
 * This is used internally to decode an already encoded DIGEST-MD5 challenge
 * message into the seperate attributes.
 *
 * Parameters:
 *
 * chlg64  [in]     - The base64 encoded challenge message.
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
static CURLcode sasl_decode_digest_md5_message(const char *chlg64,
                                               char *nonce, size_t nlen,
                                               char *realm, size_t rlen,
                                               char *alg, size_t alen,
                                               char *qop, size_t qlen)
{
  CURLcode result = CURLE_OK;
  unsigned char *chlg = NULL;
  size_t chlglen = 0;
  size_t chlg64len = strlen(chlg64);

  /* Decode the base-64 encoded challenge message */
  if(chlg64len && *chlg64 != '=') {
    result = Curl_base64_decode(chlg64, &chlg, &chlglen);
    if(result)
      return result;
  }

  /* Ensure we have a valid challenge message */
  if(!chlg)
    return CURLE_BAD_CONTENT_ENCODING;

  /* Retrieve nonce string from the challenge */
  if(!sasl_digest_get_key_value((char *)chlg, "nonce=\"", nonce, nlen, '\"')) {
    free(chlg);
    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Retrieve realm string from the challenge */
  if(!sasl_digest_get_key_value((char *)chlg, "realm=\"", realm, rlen, '\"')) {
    /* Challenge does not have a realm, set empty string [RFC2831] page 6 */
    strcpy(realm, "");
  }

  /* Retrieve algorithm string from the challenge */
  if(!sasl_digest_get_key_value((char *)chlg, "algorithm=", alg, alen, ',')) {
    free(chlg);
    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Retrieve qop-options string from the challenge */
  if(!sasl_digest_get_key_value((char *)chlg, "qop=\"", qop, qlen, '\"')) {
    free(chlg);
    return CURLE_BAD_CONTENT_ENCODING;
  }

  free(chlg);

  return CURLE_OK;
}

/*
 * Curl_sasl_create_digest_md5_message()
 *
 * This is used to generate an already encoded DIGEST-MD5 response message
 * ready for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * chlg64  [in]     - The base64 encoded challenge message.
 * userp   [in]     - The user name.
 * passdwp [in]     - The user's password.
 * service [in]     - The service type such as www, smtp, pop or imap.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_digest_md5_message(struct SessionHandle *data,
                                             const char *chlg64,
                                             const char *userp,
                                             const char *passwdp,
                                             const char *service,
                                             char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  size_t i;
  MD5_context *ctxt;
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
  unsigned int entropy[4];
  char nonceCount[] = "00000001";
  char method[]     = "AUTHENTICATE";
  char qop[]        = DIGEST_QOP_VALUE_STRING_AUTH;
  char *spn         = NULL;

  /* Decode the challange message */
  result = sasl_decode_digest_md5_message(chlg64, nonce, sizeof(nonce),
                                          realm, sizeof(realm),
                                          algorithm, sizeof(algorithm),
                                          qop_options, sizeof(qop_options));
  if(result)
    return result;

  /* We only support md5 sessions */
  if(strcmp(algorithm, "md5-sess") != 0)
    return CURLE_BAD_CONTENT_ENCODING;

  /* Get the qop-values from the qop-options */
  result = sasl_digest_get_qop_values(qop_options, &qop_values);
  if(result)
    return result;

  /* We only support auth quality-of-protection */
  if(!(qop_values & DIGEST_QOP_VALUE_AUTH))
    return CURLE_BAD_CONTENT_ENCODING;

  /* Generate 16 bytes of random data */
  entropy[0] = Curl_rand(data);
  entropy[1] = Curl_rand(data);
  entropy[2] = Curl_rand(data);
  entropy[3] = Curl_rand(data);

  /* Convert the random data into a 32 byte hex string */
  snprintf(cnonce, sizeof(cnonce), "%08x%08x%08x%08x",
           entropy[0], entropy[1], entropy[2], entropy[3]);

  /* So far so good, now calculate A1 and H(A1) according to RFC 2831 */
  ctxt = Curl_MD5_init(Curl_DIGEST_MD5);
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

  ctxt = Curl_MD5_init(Curl_DIGEST_MD5);
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
    snprintf(&HA1_hex[2 * i], 3, "%02x", digest[i]);

  /* Generate our SPN */
  spn = Curl_sasl_build_spn(service, realm);
  if(!spn)
    return CURLE_OUT_OF_MEMORY;

  /* Calculate H(A2) */
  ctxt = Curl_MD5_init(Curl_DIGEST_MD5);
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
    snprintf(&HA2_hex[2 * i], 3, "%02x", digest[i]);

  /* Now calculate the response hash */
  ctxt = Curl_MD5_init(Curl_DIGEST_MD5);
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
    snprintf(&resp_hash_hex[2 * i], 3, "%02x", digest[i]);

  /* Generate the response */
  response = aprintf("username=\"%s\",realm=\"%s\",nonce=\"%s\","
                     "cnonce=\"%s\",nc=\"%s\",digest-uri=\"%s\",response=%s,"
                     "qop=%s",
                     userp, realm, nonce,
                     cnonce, nonceCount, spn, resp_hash_hex, qop);
  free(spn);
  if(!response)
    return CURLE_OUT_OF_MEMORY;

  /* Base64 encode the response */
  result = Curl_base64_encode(data, response, 0, outptr, outlen);

  free(response);

  return result;
}

/*
 * Curl_sasl_decode_digest_http_message()
 *
 * This is used to decode a HTTP DIGEST challenge message into the seperate
 * attributes.
 *
 * Parameters:
 *
 * chlg    [in]     - The challenge message.
 * digest  [in/out] - The digest data struct being used and modified.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_decode_digest_http_message(const char *chlg,
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
  Curl_sasl_digest_cleanup(digest);

  for(;;) {
    char value[DIGEST_MAX_VALUE_LENGTH];
    char content[DIGEST_MAX_CONTENT_LENGTH];

    /* Pass all additional spaces here */
    while(*chlg && ISSPACE(*chlg))
      chlg++;

    /* Extract a value=content pair */
    if(!Curl_sasl_digest_get_pair(chlg, value, content, &chlg)) {
      if(Curl_raw_equal(value, "nonce")) {
        digest->nonce = strdup(content);
        if(!digest->nonce)
          return CURLE_OUT_OF_MEMORY;
      }
      else if(Curl_raw_equal(value, "stale")) {
        if(Curl_raw_equal(content, "true")) {
          digest->stale = TRUE;
          digest->nc = 1; /* we make a new nonce now */
        }
      }
      else if(Curl_raw_equal(value, "realm")) {
        digest->realm = strdup(content);
        if(!digest->realm)
          return CURLE_OUT_OF_MEMORY;
      }
      else if(Curl_raw_equal(value, "opaque")) {
        digest->opaque = strdup(content);
        if(!digest->opaque)
          return CURLE_OUT_OF_MEMORY;
      }
      else if(Curl_raw_equal(value, "qop")) {
        char *tok_buf;
        /* Tokenize the list and choose auth if possible, use a temporary
            clone of the buffer since strtok_r() ruins it */
        tmp = strdup(content);
        if(!tmp)
          return CURLE_OUT_OF_MEMORY;

        token = strtok_r(tmp, ",", &tok_buf);
        while(token != NULL) {
          if(Curl_raw_equal(token, DIGEST_QOP_VALUE_STRING_AUTH)) {
            foundAuth = TRUE;
          }
          else if(Curl_raw_equal(token, DIGEST_QOP_VALUE_STRING_AUTH_INT)) {
            foundAuthInt = TRUE;
          }
          token = strtok_r(NULL, ",", &tok_buf);
        }

        free(tmp);

        /* Select only auth or auth-int. Otherwise, ignore */
        if(foundAuth) {
          digest->qop = strdup(DIGEST_QOP_VALUE_STRING_AUTH);
          if(!digest->qop)
            return CURLE_OUT_OF_MEMORY;
        }
        else if(foundAuthInt) {
          digest->qop = strdup(DIGEST_QOP_VALUE_STRING_AUTH_INT);
          if(!digest->qop)
            return CURLE_OUT_OF_MEMORY;
        }
      }
      else if(Curl_raw_equal(value, "algorithm")) {
        digest->algorithm = strdup(content);
        if(!digest->algorithm)
          return CURLE_OUT_OF_MEMORY;

        if(Curl_raw_equal(content, "MD5-sess"))
          digest->algo = CURLDIGESTALGO_MD5SESS;
        else if(Curl_raw_equal(content, "MD5"))
          digest->algo = CURLDIGESTALGO_MD5;
        else
          return CURLE_BAD_CONTENT_ENCODING;
      }
      else {
        /* unknown specifier, ignore it! */
      }
    }
    else
      break; /* we're done here */

    /* Pass all additional spaces here */
    while(*chlg && ISSPACE(*chlg))
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

  /* We got this header without a nonce, that's a bad Digest line! */
  if(!digest->nonce)
    return CURLE_BAD_CONTENT_ENCODING;

  return CURLE_OK;
}

/*
 * Curl_sasl_create_digest_http_message()
 *
 * This is used to generate a HTTP DIGEST response message ready for sending
 * to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The user name.
 * passdwp [in]     - The user's password.
 * request [in]     - The HTTP request.
 * uripath [in]     - The path of the HTTP uri.
 * digest  [in/out] - The digest data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_digest_http_message(struct SessionHandle *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const unsigned char *request,
                                              const unsigned char *uripath,
                                              struct digestdata *digest,
                                              char **outptr, size_t *outlen)
{
  CURLcode result;
  unsigned char md5buf[16]; /* 16 bytes/128 bits */
  unsigned char request_digest[33];
  unsigned char *md5this;
  unsigned char ha1[33];/* 32 digits and 1 zero byte */
  unsigned char ha2[33];/* 32 digits and 1 zero byte */
  char cnoncebuf[33];
  char *cnonce = NULL;
  size_t cnonce_sz = 0;
  char *userp_quoted;
  char *response = NULL;
  char *tmp = NULL;

  if(!digest->nc)
    digest->nc = 1;

  if(!digest->cnonce) {
    snprintf(cnoncebuf, sizeof(cnoncebuf), "%08x%08x%08x%08x",
             Curl_rand(data), Curl_rand(data),
             Curl_rand(data), Curl_rand(data));

    result = Curl_base64_encode(data, cnoncebuf, strlen(cnoncebuf),
                                &cnonce, &cnonce_sz);
    if(result)
      return result;

    digest->cnonce = cnonce;
  }

  /*
    if the algorithm is "MD5" or unspecified (which then defaults to MD5):

    A1 = unq(username-value) ":" unq(realm-value) ":" passwd

    if the algorithm is "MD5-sess" then:

    A1 = H( unq(username-value) ":" unq(realm-value) ":" passwd )
         ":" unq(nonce-value) ":" unq(cnonce-value)
  */

  md5this = (unsigned char *)
    aprintf("%s:%s:%s", userp, digest->realm, passwdp);
  if(!md5this)
    return CURLE_OUT_OF_MEMORY;

  CURL_OUTPUT_DIGEST_CONV(data, md5this); /* convert on non-ASCII machines */
  Curl_md5it(md5buf, md5this);
  free(md5this);
  sasl_digest_md5_to_ascii(md5buf, ha1);

  if(digest->algo == CURLDIGESTALGO_MD5SESS) {
    /* nonce and cnonce are OUTSIDE the hash */
    tmp = aprintf("%s:%s:%s", ha1, digest->nonce, digest->cnonce);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;

    CURL_OUTPUT_DIGEST_CONV(data, tmp); /* convert on non-ASCII machines */
    Curl_md5it(md5buf, (unsigned char *)tmp);
    free(tmp);
    sasl_digest_md5_to_ascii(md5buf, ha1);
  }

  /*
    If the "qop" directive's value is "auth" or is unspecified, then A2 is:

      A2       = Method ":" digest-uri-value

          If the "qop" value is "auth-int", then A2 is:

      A2       = Method ":" digest-uri-value ":" H(entity-body)

    (The "Method" value is the HTTP request method as specified in section
    5.1.1 of RFC 2616)
  */

  md5this = (unsigned char *)aprintf("%s:%s", request, uripath);

  if(digest->qop && Curl_raw_equal(digest->qop, "auth-int")) {
    /* We don't support auth-int for PUT or POST at the moment.
       TODO: replace md5 of empty string with entity-body for PUT/POST */
    unsigned char *md5this2 = (unsigned char *)
      aprintf("%s:%s", md5this, "d41d8cd98f00b204e9800998ecf8427e");
    free(md5this);
    md5this = md5this2;
  }

  if(!md5this)
    return CURLE_OUT_OF_MEMORY;

  CURL_OUTPUT_DIGEST_CONV(data, md5this); /* convert on non-ASCII machines */
  Curl_md5it(md5buf, md5this);
  free(md5this);
  sasl_digest_md5_to_ascii(md5buf, ha2);

  if(digest->qop) {
    md5this = (unsigned char *)aprintf("%s:%s:%08x:%s:%s:%s",
                                       ha1,
                                       digest->nonce,
                                       digest->nc,
                                       digest->cnonce,
                                       digest->qop,
                                       ha2);
  }
  else {
    md5this = (unsigned char *)aprintf("%s:%s:%s",
                                       ha1,
                                       digest->nonce,
                                       ha2);
  }

  if(!md5this)
    return CURLE_OUT_OF_MEMORY;

  CURL_OUTPUT_DIGEST_CONV(data, md5this); /* convert on non-ASCII machines */
  Curl_md5it(md5buf, md5this);
  free(md5this);
  sasl_digest_md5_to_ascii(md5buf, request_digest);

  /* for test case 64 (snooped from a Mozilla 1.3a request)

    Authorization: Digest username="testuser", realm="testrealm", \
    nonce="1053604145", uri="/64", response="c55f7f30d83d774a3d2dcacf725abaca"

    Digest parameters are all quoted strings.  Username which is provided by
    the user will need double quotes and backslashes within it escaped.  For
    the other fields, this shouldn't be an issue.  realm, nonce, and opaque
    are copied as is from the server, escapes and all.  cnonce is generated
    with web-safe characters.  uri is already percent encoded.  nc is 8 hex
    characters.  algorithm and qop with standard values only contain web-safe
    chracters.
  */
  userp_quoted = sasl_digest_string_quoted(userp);
  if(!userp_quoted)
    return CURLE_OUT_OF_MEMORY;

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
                       digest->realm,
                       digest->nonce,
                       uripath,
                       digest->cnonce,
                       digest->nc,
                       digest->qop,
                       request_digest);

    if(Curl_raw_equal(digest->qop, "auth"))
      digest->nc++; /* The nc (from RFC) has to be a 8 hex digit number 0
                       padded which tells to the server how many times you are
                       using the same nonce in the qop=auth mode */
  }
  else {
    response = aprintf("username=\"%s\", "
                       "realm=\"%s\", "
                       "nonce=\"%s\", "
                       "uri=\"%s\", "
                       "response=\"%s\"",
                       userp_quoted,
                       digest->realm,
                       digest->nonce,
                       uripath,
                       request_digest);
  }
  free(userp_quoted);
  if(!response)
    return CURLE_OUT_OF_MEMORY;

  /* Add the optional fields */
  if(digest->opaque) {
    /* Append the opaque */
    tmp = aprintf("%s, opaque=\"%s\"", response, digest->opaque);
    free(response);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;

    response = tmp;
  }

  if(digest->algorithm) {
    /* Append the algorithm */
    tmp = aprintf("%s, algorithm=\"%s\"", response, digest->algorithm);
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
 * Curl_sasl_digest_cleanup()
 *
 * This is used to clean up the digest specific data.
 *
 * Parameters:
 *
 * digest    [in/out] - The digest data struct being cleaned up.
 *
 */
void Curl_sasl_digest_cleanup(struct digestdata *digest)
{
  Curl_safefree(digest->nonce);
  Curl_safefree(digest->cnonce);
  Curl_safefree(digest->realm);
  Curl_safefree(digest->opaque);
  Curl_safefree(digest->qop);
  Curl_safefree(digest->algorithm);

  digest->nc = 0;
  digest->algo = CURLDIGESTALGO_MD5; /* default algorithm */
  digest->stale = FALSE; /* default means normal, not stale */
}
#endif  /* !USE_WINDOWS_SSPI */

#endif  /* CURL_DISABLE_CRYPTO_AUTH */

#if defined(USE_NTLM) && !defined(USE_WINDOWS_SSPI)
/*
 * Curl_sasl_ntlm_cleanup()
 *
 * This is used to clean up the ntlm specific data.
 *
 * Parameters:
 *
 * ntlm    [in/out] - The ntlm data struct being cleaned up.
 *
 */
void Curl_sasl_ntlm_cleanup(struct ntlmdata *ntlm)
{
  /* Free the target info */
  Curl_safefree(ntlm->target_info);

  /* Reset any variables */
  ntlm->target_info_len = 0;
}
#endif /* USE_NTLM && !USE_WINDOWS_SSPI*/

/*
 * sasl_create_xoauth2_message()
 *
 * This is used to generate an already encoded OAuth 2.0 message ready for
 * sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * user    [in]     - The user name.
 * bearer  [in]     - The bearer token.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode sasl_create_xoauth2_message(struct SessionHandle *data,
                                            const char *user,
                                            const char *bearer,
                                            char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  char *xoauth = NULL;

  /* Generate the message */
  xoauth = aprintf("user=%s\1auth=Bearer %s\1\1", user, bearer);
  if(!xoauth)
    return CURLE_OUT_OF_MEMORY;

  /* Base64 encode the reply */
  result = Curl_base64_encode(data, xoauth, strlen(xoauth), outptr, outlen);

  free(xoauth);

  return result;
}

/*
 * Curl_sasl_cleanup()
 *
 * This is used to cleanup any libraries or curl modules used by the sasl
 * functions.
 *
 * Parameters:
 *
 * conn     [in]     - The connection data.
 * authused [in]     - The authentication mechanism used.
 */
void Curl_sasl_cleanup(struct connectdata *conn, unsigned int authused)
{
#if defined(USE_KERBEROS5)
  /* Cleanup the gssapi structure */
  if(authused == SASL_MECH_GSSAPI) {
    Curl_sasl_gssapi_cleanup(&conn->krb5);
  }
#endif

#if defined(USE_NTLM)
  /* Cleanup the ntlm structure */
  if(authused == SASL_MECH_NTLM) {
    Curl_sasl_ntlm_cleanup(&conn->ntlm);
  }
#endif

#if !defined(USE_KERBEROS5) && !defined(USE_NTLM)
  /* Reserved for future use */
  (void)conn;
  (void)authused;
#endif
}

/*
 * Curl_sasl_decode_mech()
 *
 * Convert a SASL mechanism name into a token.
 *
 * Parameters:
 *
 * ptr    [in]     - The mechanism string.
 * maxlen [in]     - Maximum mechanism string length.
 * len    [out]    - If not NULL, effective name length.
 *
 * Returns the SASL mechanism token or 0 if no match.
 */
unsigned int Curl_sasl_decode_mech(const char *ptr, size_t maxlen, size_t *len)
{
  unsigned int i;
  char c;

  for(i = 0; mechtable[i].name; i++) {
    if(maxlen >= mechtable[i].len &&
       !memcmp(ptr, mechtable[i].name, mechtable[i].len)) {
      if(len)
        *len = mechtable[i].len;

      if(maxlen == mechtable[i].len)
        return mechtable[i].bit;

      c = ptr[mechtable[i].len];
      if(!ISUPPER(c) && !ISDIGIT(c) && c != '-' && c != '_')
        return mechtable[i].bit;
    }
  }

  return 0;
}

/*
 * Curl_sasl_parse_url_auth_option()
 *
 * Parse the URL login options.
 */
CURLcode Curl_sasl_parse_url_auth_option(struct SASL *sasl,
                                         const char *value, size_t len)
{
  CURLcode result = CURLE_OK;
  unsigned int mechbit;
  size_t mechlen;

  if(!len)
    return CURLE_URL_MALFORMAT;

    if(sasl->resetprefs) {
      sasl->resetprefs = FALSE;
      sasl->prefmech = SASL_AUTH_NONE;
    }

    if(strnequal(value, "*", len))
      sasl->prefmech = SASL_AUTH_DEFAULT;
    else if((mechbit = Curl_sasl_decode_mech(value, len, &mechlen)) &&
            mechlen == len)
      sasl->prefmech |= mechbit;
    else
      result = CURLE_URL_MALFORMAT;

  return result;
}

/*
 * Curl_sasl_init()
 *
 * Initializes the SASL structure.
 */
void Curl_sasl_init(struct SASL *sasl, const struct SASLproto *params)
{
  sasl->params = params;           /* Set protocol dependent parameters */
  sasl->state = SASL_STOP;         /* Not yet running */
  sasl->authmechs = SASL_AUTH_NONE; /* No known authentication mechanism yet */
  sasl->prefmech = SASL_AUTH_DEFAULT; /* Prefer all mechanisms */
  sasl->authused = SASL_AUTH_NONE; /* No the authentication mechanism used */
  sasl->resetprefs = TRUE;         /* Reset prefmech upon AUTH parsing. */
  sasl->mutual_auth = FALSE;       /* No mutual authentication (GSSAPI only) */
  sasl->force_ir = FALSE;          /* Respect external option */
}

/*
 * state()
 *
 * This is the ONLY way to change SASL state!
 */
static void state(struct SASL *sasl, struct connectdata *conn,
                  saslstate newstate)
{
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char * const names[]={
    "STOP",
    "PLAIN",
    "LOGIN",
    "LOGIN_PASSWD",
    "EXTERNAL",
    "CRAMMD5",
    "DIGESTMD5",
    "DIGESTMD5_RESP",
    "NTLM",
    "NTLM_TYPE2MSG",
    "GSSAPI",
    "GSSAPI_TOKEN",
    "GSSAPI_NO_DATA",
    "XOAUTH2",
    "CANCEL",
    "FINAL",
    /* LAST */
  };

  if(sasl->state != newstate)
    infof(conn->data, "SASL %p state change from %s to %s\n",
          (void *)sasl, names[sasl->state], names[newstate]);
#else
  (void) conn;
#endif

  sasl->state = newstate;
}

/*
 * Curl_sasl_can_authenticate()
 *
 * Check if we have enough auth data and capabilities to authenticate.
 */
bool Curl_sasl_can_authenticate(struct SASL *sasl, struct connectdata *conn)
{
  /* Have credentials been provided? */
  if(conn->bits.user_passwd)
    return TRUE;

  /* EXTERNAL can authenticate without a user name and/or password */
  if(sasl->authmechs & sasl->prefmech & SASL_MECH_EXTERNAL)
    return TRUE;

  return FALSE;
}

/*
 * Curl_sasl_start()
 *
 * Calculate the required login details for SASL authentication.
 */
CURLcode Curl_sasl_start(struct SASL *sasl, struct connectdata *conn,
                         bool force_ir, saslprogress *progress)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  unsigned int enabledmechs;
  const char *mech = NULL;
  char *resp = NULL;
  size_t len = 0;
  saslstate state1 = SASL_STOP;
  saslstate state2 = SASL_FINAL;

  sasl->force_ir = force_ir;    /* Latch for future use */
  sasl->authused = 0;           /* No mechanism used yet */
  enabledmechs = sasl->authmechs & sasl->prefmech;
  *progress = SASL_IDLE;

  /* Calculate the supported authentication mechanism, by decreasing order of
     security, as well as the initial response where appropriate */
  if((enabledmechs & SASL_MECH_EXTERNAL) && !conn->passwd[0]) {
    mech = SASL_MECH_STRING_EXTERNAL;
    state1 = SASL_EXTERNAL;
    sasl->authused = SASL_MECH_EXTERNAL;

    if(force_ir || data->set.sasl_ir)
      result = sasl_create_external_message(data, conn->user, &resp, &len);
  }
  else if(conn->bits.user_passwd) {
#if defined(USE_KERBEROS5)
    if(enabledmechs & SASL_MECH_GSSAPI) {
      sasl->mutual_auth = FALSE; /* TODO: Calculate mutual authentication */
      mech = SASL_MECH_STRING_GSSAPI;
      state1 = SASL_GSSAPI;
      state2 = SASL_GSSAPI_TOKEN;
      sasl->authused = SASL_MECH_GSSAPI;

      if(force_ir || data->set.sasl_ir)
        result = Curl_sasl_create_gssapi_user_message(data, conn->user,
                                                      conn->passwd,
                                                      sasl->params->service,
                                                      sasl->mutual_auth,
                                                      NULL, &conn->krb5,
                                                      &resp, &len);
    }
    else
#endif
#ifndef CURL_DISABLE_CRYPTO_AUTH
    if(enabledmechs & SASL_MECH_DIGEST_MD5) {
      mech = SASL_MECH_STRING_DIGEST_MD5;
      state1 = SASL_DIGESTMD5;
      sasl->authused = SASL_MECH_DIGEST_MD5;
    }
    else if(enabledmechs & SASL_MECH_CRAM_MD5) {
      mech = SASL_MECH_STRING_CRAM_MD5;
      state1 = SASL_CRAMMD5;
      sasl->authused = SASL_MECH_CRAM_MD5;
    }
    else
#endif
#ifdef USE_NTLM
    if(enabledmechs & SASL_MECH_NTLM) {
      mech = SASL_MECH_STRING_NTLM;
      state1 = SASL_NTLM;
      state2 = SASL_NTLM_TYPE2MSG;
      sasl->authused = SASL_MECH_NTLM;

      if(force_ir || data->set.sasl_ir)
        result = Curl_sasl_create_ntlm_type1_message(conn->user, conn->passwd,
                                                     &conn->ntlm, &resp, &len);
      }
    else
#endif
    if((enabledmechs & SASL_MECH_XOAUTH2) || conn->xoauth2_bearer) {
      mech = SASL_MECH_STRING_XOAUTH2;
      state1 = SASL_XOAUTH2;
      sasl->authused = SASL_MECH_XOAUTH2;

      if(force_ir || data->set.sasl_ir)
        result = sasl_create_xoauth2_message(data, conn->user,
                                             conn->xoauth2_bearer,
                                             &resp, &len);
    }
    else if(enabledmechs & SASL_MECH_LOGIN) {
      mech = SASL_MECH_STRING_LOGIN;
      state1 = SASL_LOGIN;
      state2 = SASL_LOGIN_PASSWD;
      sasl->authused = SASL_MECH_LOGIN;

      if(force_ir || data->set.sasl_ir)
        result = sasl_create_login_message(data, conn->user, &resp, &len);
    }
    else if(enabledmechs & SASL_MECH_PLAIN) {
      mech = SASL_MECH_STRING_PLAIN;
      state1 = SASL_PLAIN;
      sasl->authused = SASL_MECH_PLAIN;

      if(force_ir || data->set.sasl_ir)
        result = sasl_create_plain_message(data, conn->user, conn->passwd,
                                           &resp, &len);
    }
  }

  if(!result) {
    if(resp && sasl->params->maxirlen &&
       strlen(mech) + len > sasl->params->maxirlen) {
      free(resp);
      resp = NULL;
    }

    if(mech) {
      result = sasl->params->sendauth(conn, mech, resp);
      if(!result) {
        *progress = SASL_INPROGRESS;
        state(sasl, conn, resp? state2: state1);
      }
    }
  }

  free(resp);

  return result;
}

/*
 * Curl_sasl_continue()
 *
 * Continue the authentication.
 */
CURLcode Curl_sasl_continue(struct SASL *sasl, struct connectdata *conn,
                            int code, saslprogress *progress)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  saslstate newstate = SASL_FINAL;
  char *resp = NULL;
#if !defined(CURL_DISABLE_CRYPTO_AUTH)
  char *serverdata;
  char *chlg = NULL;
  size_t chlglen = 0;
#endif
  size_t len = 0;

  *progress = SASL_INPROGRESS;

  if(sasl->state == SASL_FINAL) {
    if(code != sasl->params->finalcode)
      result = CURLE_LOGIN_DENIED;
    *progress = SASL_DONE;
    state(sasl, conn, SASL_STOP);
    return result;
  }

  if(sasl->state != SASL_CANCEL && code != sasl->params->contcode) {
    *progress = SASL_DONE;
    state(sasl, conn, SASL_STOP);
    return CURLE_LOGIN_DENIED;
  }

  switch(sasl->state) {
  case SASL_STOP:
    *progress = SASL_DONE;
    return result;
  case SASL_PLAIN:
    result = sasl_create_plain_message(data, conn->user, conn->passwd, &resp,
                                       &len);
    break;
  case SASL_LOGIN:
    result = sasl_create_login_message(data, conn->user, &resp, &len);
    newstate = SASL_LOGIN_PASSWD;
    break;
  case SASL_LOGIN_PASSWD:
    result = sasl_create_login_message(data, conn->passwd, &resp, &len);
    break;
  case SASL_EXTERNAL:
    result = sasl_create_external_message(data, conn->user, &resp, &len);
    break;

#ifndef CURL_DISABLE_CRYPTO_AUTH
  case SASL_CRAMMD5:
    sasl->params->getmessage(data->state.buffer, &serverdata);
    result = sasl_decode_cram_md5_message(serverdata, &chlg, &chlglen);
    if(!result)
      result = sasl_create_cram_md5_message(data, chlg, conn->user,
                                            conn->passwd, &resp, &len);
    free(chlg);
    break;
  case SASL_DIGESTMD5:
    sasl->params->getmessage(data->state.buffer, &serverdata);
    result = Curl_sasl_create_digest_md5_message(data, serverdata,
                                                 conn->user, conn->passwd,
                                                 sasl->params->service,
                                                 &resp, &len);
    newstate = SASL_DIGESTMD5_RESP;
    break;
  case SASL_DIGESTMD5_RESP:
    if(!(resp = strdup("")))
      result = CURLE_OUT_OF_MEMORY;
    break;
#endif

#ifdef USE_NTLM
  case SASL_NTLM:
    /* Create the type-1 message */
    result = Curl_sasl_create_ntlm_type1_message(conn->user, conn->passwd,
                                                 &conn->ntlm, &resp, &len);
    newstate = SASL_NTLM_TYPE2MSG;
    break;
  case SASL_NTLM_TYPE2MSG:
    /* Decode the type-2 message */
    sasl->params->getmessage(data->state.buffer, &serverdata);
    result = Curl_sasl_decode_ntlm_type2_message(data, serverdata,
                                                 &conn->ntlm);
    if(!result)
      result = Curl_sasl_create_ntlm_type3_message(data, conn->user,
                                                   conn->passwd, &conn->ntlm,
                                                   &resp, &len);
    break;
#endif

#if defined(USE_KERBEROS5)
  case SASL_GSSAPI:
    result = Curl_sasl_create_gssapi_user_message(data, conn->user,
                                                  conn->passwd,
                                                  sasl->params->service,
                                                  sasl->mutual_auth, NULL,
                                                  &conn->krb5,
                                                  &resp, &len);
    newstate = SASL_GSSAPI_TOKEN;
    break;
  case SASL_GSSAPI_TOKEN:
    sasl->params->getmessage(data->state.buffer, &serverdata);
    if(sasl->mutual_auth) {
      /* Decode the user token challenge and create the optional response
         message */
      result = Curl_sasl_create_gssapi_user_message(data, NULL, NULL, NULL,
                                                    sasl->mutual_auth,
                                                    serverdata, &conn->krb5,
                                                    &resp, &len);
      newstate = SASL_GSSAPI_NO_DATA;
    }
    else
      /* Decode the security challenge and create the response message */
      result = Curl_sasl_create_gssapi_security_message(data, serverdata,
                                                        &conn->krb5,
                                                        &resp, &len);
    break;
  case SASL_GSSAPI_NO_DATA:
    sasl->params->getmessage(data->state.buffer, &serverdata);
    /* Decode the security challenge and create the response message */
    result = Curl_sasl_create_gssapi_security_message(data, serverdata,
                                                      &conn->krb5,
                                                      &resp, &len);
    break;
#endif

  case SASL_XOAUTH2:
    /* Create the authorisation message */
    result = sasl_create_xoauth2_message(data, conn->user,
                                         conn->xoauth2_bearer, &resp, &len);
    break;
  case SASL_CANCEL:
    /* Remove the offending mechanism from the supported list */
    sasl->authmechs ^= sasl->authused;

    /* Start an alternative SASL authentication */
    result = Curl_sasl_start(sasl, conn, sasl->force_ir, progress);
    newstate = sasl->state;   /* Use state from Curl_sasl_start() */
    break;
  default:
    failf(data, "Unsupported SASL authentication mechanism");
    result = CURLE_UNSUPPORTED_PROTOCOL;  /* Should not happen */
    break;
  }

  switch(result) {
  case CURLE_BAD_CONTENT_ENCODING:
    /* Cancel dialog */
    result = sasl->params->sendcont(conn, "*");
    newstate = SASL_CANCEL;
    break;
  case CURLE_OK:
    if(resp)
      result = sasl->params->sendcont(conn, resp);
    break;
  default:
    newstate = SASL_STOP;    /* Stop on error */
    *progress = SASL_DONE;
    break;
  }

  free(resp);

  state(sasl, conn, newstate);

  return result;
}
