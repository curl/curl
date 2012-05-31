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
#include "curl_sasl.h"

/* The last #include file should be: */
#include "memdebug.h"

/*
 * Curl_sasl_create_plain_message()
 *
 * This is used to generate an already encoded plain message ready
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
 * This is used to generate an already encoded login message containing the
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
