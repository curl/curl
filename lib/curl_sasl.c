/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "sslgen.h"
#include "curl_hmac.h"
#include "curl_ntlm_msgs.h"
#include "curl_sasl.h"
#include "warnless.h"
#include "curl_memory.h"

#ifdef USE_NSS
#include "nssg.h" /* for Curl_nss_force_init() */
#endif

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

#ifndef CURL_DISABLE_CRYPTO_AUTH
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
#endif

/*
 * Curl_sasl_create_plain_message()
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
CURLcode Curl_sasl_create_plain_message(struct SessionHandle *data,
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
  Curl_safefree(plainauth);
  return result;
}

/*
 * Curl_sasl_create_login_message()
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
CURLcode Curl_sasl_create_login_message(struct SessionHandle *data,
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

#ifndef CURL_DISABLE_CRYPTO_AUTH
 /*
 * Curl_sasl_decode_cram_md5_message()
 *
 * This is used to decode an already encoded CRAM-MD5 challenge message.
 *
 * Parameters:
 *
 * chlg64  [in]     - Pointer to the base64 encoded challenge message.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_decode_cram_md5_message(const char *chlg64, char **outptr,
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
 * Curl_sasl_create_cram_md5_message()
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
CURLcode Curl_sasl_create_cram_md5_message(struct SessionHandle *data,
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

  Curl_safefree(response);

  return result;
}

/*
 * Curl_sasl_decode_digest_md5_message()
 *
 * This is used to decode an already encoded DIGEST-MD5 challenge message.
 *
 * Parameters:
 *
 * chlg64  [in]     - Pointer to the base64 encoded challenge message.
 * nonce   [in/out] - The buffer where the nonce will be stored.
 * nlen    [in]     - The length of the nonce buffer.
 * realm   [in/out] - The buffer where the realm will be stored.
 * rlen    [in]     - The length of the realm buffer.
 * alg     [in/out] - The buffer where the algorithm will be stored.
 * alen    [in]     - The length of the algorithm buffer.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_decode_digest_md5_message(const char *chlg64,
                                             char *nonce, size_t nlen,
                                             char *realm, size_t rlen,
                                             char *alg, size_t alen)
{
  CURLcode result = CURLE_OK;
  unsigned char *chlg = NULL;
  size_t chlglen = 0;
  size_t chlg64len = strlen(chlg64);

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
    Curl_safefree(chlg);
    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Retrieve realm string from the challenge */
  if(!sasl_digest_get_key_value((char *)chlg, "realm=\"", realm, rlen, '\"')) {
    /* Challenge does not have a realm, set empty string [RFC2831] page 6 */
    strcpy(realm, "");
  }

  /* Retrieve algorithm string from the challenge */
  if(!sasl_digest_get_key_value((char *)chlg, "algorithm=", alg, alen, ',')) {
    Curl_safefree(chlg);
    return CURLE_BAD_CONTENT_ENCODING;
  }

  Curl_safefree(chlg);

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
 * nonce   [in]     - The nonce.
 * realm   [in]     - The realm.
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
                                             const char *nonce,
                                             const char *realm,
                                             const char *userp,
                                             const char *passwdp,
                                             const char *service,
                                             char **outptr, size_t *outlen)
{
#ifndef DEBUGBUILD
  static const char table16[] = "0123456789abcdef";
#endif
  CURLcode result = CURLE_OK;
  size_t i;
  MD5_context *ctxt;
  char *response = NULL;
  unsigned char digest[MD5_DIGEST_LEN];
  char HA1_hex[2 * MD5_DIGEST_LEN + 1];
  char HA2_hex[2 * MD5_DIGEST_LEN + 1];
  char resp_hash_hex[2 * MD5_DIGEST_LEN + 1];

  char nonceCount[] = "00000001";
  char cnonce[]     = "12345678"; /* will be changed */
  char method[]     = "AUTHENTICATE";
  char qop[]        = "auth";
  char uri[128];

#ifndef DEBUGBUILD
  /* Generate 64 bits of random data */
  for(i = 0; i < 8; i++)
    cnonce[i] = table16[Curl_rand(data)%16];
#endif

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

  /* Prepare the URL string */
  snprintf(uri, sizeof(uri), "%s/%s", service, realm);

  /* Calculate H(A2) */
  ctxt = Curl_MD5_init(Curl_DIGEST_MD5);
  if(!ctxt)
    return CURLE_OUT_OF_MEMORY;

  Curl_MD5_update(ctxt, (const unsigned char *) method,
                  curlx_uztoui(strlen(method)));
  Curl_MD5_update(ctxt, (const unsigned char *) ":", 1);
  Curl_MD5_update(ctxt, (const unsigned char *) uri,
                  curlx_uztoui(strlen(uri)));
  Curl_MD5_final(ctxt, digest);

  for(i = 0; i < MD5_DIGEST_LEN; i++)
    snprintf(&HA2_hex[2 * i], 3, "%02x", digest[i]);

  /* Now calculate the response hash */
  ctxt = Curl_MD5_init(Curl_DIGEST_MD5);
  if(!ctxt)
    return CURLE_OUT_OF_MEMORY;

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
                     "cnonce=\"%s\",nc=\"%s\",digest-uri=\"%s\",response=%s",
                     userp, realm, nonce,
                     cnonce, nonceCount, uri, resp_hash_hex);
  if(!response)
    return CURLE_OUT_OF_MEMORY;

  /* Base64 encode the response */
  result = Curl_base64_encode(data, response, 0, outptr, outlen);

  Curl_safefree(response);

  return result;
}
#endif

#ifdef USE_NTLM
/*
 * Curl_sasl_create_ntlm_type1_message()
 *
 * This is used to generate an already encoded NTLM type-1 message ready for
 * sending to the recipient.
 *
 * Note: This is a simple wrapper of the NTLM function which means that any
 * SASL based protocols don't have to include the NTLM functions directly.
 *
 * Parameters:
 *
 * userp   [in]     - The user name in the format User or Domain\User.
 * passdwp [in]     - The user's password.
 * ntlm    [in/out] - The ntlm data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_ntlm_type1_message(const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen)
{
  return Curl_ntlm_create_type1_message(userp, passwdp, ntlm, outptr, outlen);
}

/*
 * Curl_sasl_decode_ntlm_type2_message()
 *
 * This is used to decode an already encoded NTLM type-2 message.
 *
 * Parameters:
 *
 * data     [in]     - Pointer to session handle.
 * type2msg [in]     - Pointer to the base64 encoded type-2 message.
 * ntlm     [in/out] - The ntlm data struct being used and modified.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_decode_ntlm_type2_message(struct SessionHandle *data,
                                             const char *type2msg,
                                             struct ntlmdata *ntlm)
{
#ifdef USE_NSS
  CURLcode result;

  /* make sure the crypto backend is initialized */
  result = Curl_nss_force_init(data);
  if(result)
    return result;
#endif

  return Curl_ntlm_decode_type2_message(data, type2msg, ntlm);
}

/*
 * Curl_sasl_create_ntlm_type3_message()
 *
 * This is used to generate an already encoded NTLM type-3 message ready for
 * sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - Pointer to session handle.
 * userp   [in]     - The user name in the format User or Domain\User.
 * passdwp [in]     - The user's password.
 * ntlm    [in/out] - The ntlm data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_ntlm_type3_message(struct SessionHandle *data,
                                             const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen)
{
  return Curl_ntlm_create_type3_message(data, userp, passwdp, ntlm, outptr,
                                        outlen);
}
#endif /* USE_NTLM */

/*
 * Curl_sasl_create_xoauth2_message()
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
CURLcode Curl_sasl_create_xoauth2_message(struct SessionHandle *data,
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

  Curl_safefree(xoauth);

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
 * conn     [in]     - Pointer to the connection data.
 * authused [in]     - The authentication mechanism used.
 */
void Curl_sasl_cleanup(struct connectdata *conn, unsigned int authused)
{
#ifdef USE_NTLM
  /* Cleanup the ntlm structure */
  if(authused == SASL_MECH_NTLM) {
    Curl_ntlm_sspi_cleanup(&conn->ntlm);
  }
  (void)conn;
#else
  /* Reserved for future use */
  (void)conn;
  (void)authused;
#endif
}
