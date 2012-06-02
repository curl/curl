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
 * RFC4616 PLAIN authentication
 *
 ***************************************************************************/

#include "setup.h"

#include <curl/curl.h>
#include "urldata.h"

#include "curl_base64.h"
#include "curl_ntlm_msgs.h"
#include "curl_sasl.h"

/* The last #include file should be: */
#include "memdebug.h"

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
    return CURLE_OUT_OF_MEMORY; /* plainauth too small */
  }

  memcpy(plainauth, userp, ulen);
  plainauth[ulen] = '\0';
  memcpy(plainauth + ulen + 1, userp, ulen);
  plainauth[2 * ulen + 1] = '\0';
  memcpy(plainauth + 2 * ulen + 2, passwdp, plen);

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
 * userp   [in]     - The user name.
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
    *outptr = strdup("=");
    if(*outptr) {
      *outlen = (size_t) 1;
      return CURLE_OK;
    }

    *outlen = 0;
    return CURLE_OUT_OF_MEMORY;
  }

  return Curl_base64_encode(data, valuep, vlen, outptr, outlen);
}

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
 * Curl_sasl_decode_ntlm_type2_message()
 *
 * This is used to decode a ntlm type-2 message received from a recipient and
 * generate the already encoded NTLM type-3 message ready for sending back.
 *
 * Parameters:
 *
 * data    [in]     - Pointer to session handle.
 * header  [in]     - Pointer to the input buffer.
 * userp   [in]     - The user name in the format User or Domain\User.
 * passdwp [in]     - The user's password.
 * ntlm    [in/out] - The ntlm data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_decode_ntlm_type2_message(struct SessionHandle *data,
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
  if(authused == SASL_AUTH_NTLM) {
    Curl_ntlm_sspi_cleanup(&conn->ntlm);
  }
#else
  /* Reserved for future use */
  (void)conn;
  (void)authused;
#endif
}