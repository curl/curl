/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * RFC4616 PLAIN authentication
 *
 ***************************************************************************/

#include "setup.h"

#include <curl/curl.h>
#include "urldata.h"

#include "curl_base64.h"
#include "curl_md5.h"
#include "curl_rand.h"
#include "curl_hmac.h"
#include "curl_ntlm_msgs.h"
#include "curl_sasl.h"
#include "warnless.h"
#include "curl_memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

#ifndef CURL_DISABLE_CRYPTO_AUTH
/* Retrieves the value for a corresponding key from the challenge string
 * returns TRUE if the key could be found, FALSE if it does not exists
 */
static bool sasl_digest_get_key_value(const unsigned char *chlg,
                                      const char *key,
                                      char *value,
                                      size_t max_val_len,
                                      char end_char)
{
  char *find_pos;
  size_t i;

  find_pos = strstr((const char *) chlg, key);
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
                                        const char* userp,
                                        const char* passwdp,
                                        char **outptr, size_t *outlen)
{
  char plainauth[2 * MAX_CURL_USER_LENGTH + MAX_CURL_PASSWORD_LENGTH];
  size_t ulen;
  size_t plen;

  ulen = strlen(userp);
  plen = strlen(passwdp);

  if(2 * ulen + plen + 2 > sizeof(plainauth)) {
    *outlen = 0;
    *outptr = NULL;

    /* Plainauth too small */
    return CURLE_OUT_OF_MEMORY;
  }

  /* Calculate the reply */
  memcpy(plainauth, userp, ulen);
  plainauth[ulen] = '\0';
  memcpy(plainauth + ulen + 1, userp, ulen);
  plainauth[2 * ulen + 1] = '\0';
  memcpy(plainauth + 2 * ulen + 2, passwdp, plen);

  /* Base64 encode the reply */
  return Curl_base64_encode(data, plainauth, 2 * ulen + plen + 2, outptr,
                            outlen);
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
                                        const char* valuep, char **outptr,
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
 * Curl_sasl_create_cram_md5_message()
 *
 * This is used to generate an already encoded CRAM-MD5 response message ready
 * for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * chlg64  [in]     - Pointer to the base64 encoded challenge buffer.
 * userp   [in]     - The user name.
 * passdwp [in]     - The user's password.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_cram_md5_message(struct SessionHandle *data,
                                           const char* chlg64,
                                           const char* userp,
                                           const char* passwdp,
                                           char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  size_t chlg64len = strlen(chlg64);
  unsigned char *chlg = (unsigned char *) NULL;
  size_t chlglen = 0;
  HMAC_context *ctxt;
  unsigned char digest[MD5_DIGEST_LEN];
  char response[MAX_CURL_USER_LENGTH + 2 * MD5_DIGEST_LEN + 1];

  /* Decode the challenge if necessary */
  if(chlg64len && *chlg64 != '=') {
    result = Curl_base64_decode(chlg64, &chlg, &chlglen);

    if(result)
      return result;
  }

  /* Compute the digest using the password as the key */
  ctxt = Curl_HMAC_init(Curl_HMAC_MD5,
                        (const unsigned char *) passwdp,
                        curlx_uztoui(strlen(passwdp)));

  if(!ctxt) {
    Curl_safefree(chlg);
    return CURLE_OUT_OF_MEMORY;
  }

  /* Update the digest with the given challenge */
  if(chlglen > 0)
    Curl_HMAC_update(ctxt, chlg, curlx_uztoui(chlglen));

  Curl_safefree(chlg);

  /* Finalise the digest */
  Curl_HMAC_final(ctxt, digest);

  /* Prepare the response */
  snprintf(response, sizeof(response),
      "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           userp, digest[0], digest[1], digest[2], digest[3], digest[4],
           digest[5], digest[6], digest[7], digest[8], digest[9], digest[10],
           digest[11], digest[12], digest[13], digest[14], digest[15]);

  /* Base64 encode the reply */
  return Curl_base64_encode(data, response, 0, outptr, outlen);
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
 * chlg64  [in]     - Pointer to the base64 encoded challenge buffer.
 * userp   [in]     - The user name.
 * passdwp [in]     - The user's password.
 * service [in]     - The service type such as www, smtp or pop
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_digest_md5_message(struct SessionHandle *data,
                                             const char* chlg64,
                                             const char* userp,
                                             const char* passwdp,
                                             const char* service,
                                             char **outptr, size_t *outlen)
{
  static const char table16[] = "0123456789abcdef";

  CURLcode result = CURLE_OK;
  unsigned char *chlg = (unsigned char *) NULL;
  size_t chlglen = 0;
  size_t i;
  MD5_context *ctxt;
  unsigned char digest[MD5_DIGEST_LEN];
  char HA1_hex[2 * MD5_DIGEST_LEN + 1];
  char HA2_hex[2 * MD5_DIGEST_LEN + 1];
  char resp_hash_hex[2 * MD5_DIGEST_LEN + 1];

  char nonce[64];
  char realm[128];
  char alg[64];
  char nonceCount[] = "00000001";
  char cnonce[]     = "12345678"; /* will be changed */
  char method[]     = "AUTHENTICATE";
  char qop[]        = "auth";
  char uri[128];
  char response[512];

  result = Curl_base64_decode(chlg64, &chlg, &chlglen);

  if(result)
    return result;

  /* Retrieve nonce string from the challenge */
  if(!sasl_digest_get_key_value(chlg, "nonce=\"", nonce,
                                sizeof(nonce), '\"')) {
    Curl_safefree(chlg);
    return CURLE_LOGIN_DENIED;
  }

  /* Retrieve realm string from the challenge */
  if(!sasl_digest_get_key_value(chlg, "realm=\"", realm,
                                sizeof(realm), '\"')) {
    /* Challenge does not have a realm, set empty string [RFC2831] page 6 */
    strcpy(realm, "");
  }

  /* Retrieve algorithm string from the challenge */
  if(!sasl_digest_get_key_value(chlg, "algorithm=", alg, sizeof(alg), ',')) {
    Curl_safefree(chlg);
    return CURLE_LOGIN_DENIED;
  }

  Curl_safefree(chlg);

  /* We do not support other algorithms */
  if(strcmp(alg, "md5-sess") != 0)
    return CURLE_LOGIN_DENIED;

  /* Generate 64 bits of random data */
  for(i = 0; i < 8; i++)
    cnonce[i] = table16[Curl_rand()%16];

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
  strcpy(uri, service);
  strcat(uri, "/");
  strcat(uri, realm);

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

  strcpy(response, "username=\"");
  strcat(response, userp);
  strcat(response, "\",realm=\"");
  strcat(response, realm);
  strcat(response, "\",nonce=\"");
  strcat(response, nonce);
  strcat(response, "\",cnonce=\"");
  strcat(response, cnonce);
  strcat(response, "\",nc=");
  strcat(response, nonceCount);
  strcat(response, ",digest-uri=\"");
  strcat(response, uri);
  strcat(response, "\",response=");
  strcat(response, resp_hash_hex);

  /* Base64 encode the reply */
  return Curl_base64_encode(data, response, 0, outptr, outlen);
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
  return Curl_ntlm_create_type1_message(userp, passwdp, ntlm, outptr,
                                        outlen);
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
 * header  [in]     - Pointer to the base64 encoded type-2 message buffer.
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
                                             const char *header,
                                             const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen)
{
  CURLcode result = Curl_ntlm_decode_type2_message(data, header, ntlm);

  if(!result)
    result = Curl_ntlm_create_type3_message(data, userp, passwdp, ntlm,
                                            outptr, outlen);

  return result;
}
#endif /* USE_NTLM */

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
