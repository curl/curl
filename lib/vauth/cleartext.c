/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * RFC4616 PLAIN authentication
 * Draft   LOGIN SASL Mechanism <draft-murchison-sasl-login-00.txt>
 *
 ***************************************************************************/

#include "curl_setup.h"

#if !defined(CURL_DISABLE_IMAP) || !defined(CURL_DISABLE_SMTP) ||       \
  !defined(CURL_DISABLE_POP3)

#include <curl/curl.h>
#include "urldata.h"

#include "vauth/vauth.h"
#include "curl_base64.h"
#include "curl_md5.h"
#include "warnless.h"
#include "strtok.h"
#include "sendf.h"
#include "curl_printf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Curl_auth_create_plain_message()
 *
 * This is used to generate an already encoded PLAIN message ready
 * for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * authzid [in]     - The authorization identity.
 * authcid [in]     - The authentication identity.
 * passwd  [in]     - The password.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_plain_message(struct Curl_easy *data,
                                        const char *authzid,
                                        const char *authcid,
                                        const char *passwd,
                                        char **outptr, size_t *outlen)
{
  CURLcode result;
  char *plainauth;
  size_t zlen;
  size_t clen;
  size_t plen;
  size_t plainlen;

  *outlen = 0;
  *outptr = NULL;
  zlen = (authzid == NULL ? 0 : strlen(authzid));
  clen = strlen(authcid);
  plen = strlen(passwd);

  /* Compute binary message length. Check for overflows. */
  if((zlen > SIZE_T_MAX/4) || (clen > SIZE_T_MAX/4) ||
     (plen > (SIZE_T_MAX/2 - 2)))
    return CURLE_OUT_OF_MEMORY;
  plainlen = zlen + clen + plen + 2;

  plainauth = malloc(plainlen);
  if(!plainauth)
    return CURLE_OUT_OF_MEMORY;

  /* Calculate the reply */
  if(zlen != 0)
    memcpy(plainauth, authzid, zlen);
  plainauth[zlen] = '\0';
  memcpy(plainauth + zlen + 1, authcid, clen);
  plainauth[zlen + clen + 1] = '\0';
  memcpy(plainauth + zlen + clen + 2, passwd, plen);

  /* Base64 encode the reply */
  result = Curl_base64_encode(data, plainauth, plainlen, outptr, outlen);
  free(plainauth);

  return result;
}

/*
 * Curl_auth_create_login_message()
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
CURLcode Curl_auth_create_login_message(struct Curl_easy *data,
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
 * Curl_auth_create_external_message()
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
CURLcode Curl_auth_create_external_message(struct Curl_easy *data,
                                           const char *user, char **outptr,
                                           size_t *outlen)
{
  /* This is the same formatting as the login message */
  return Curl_auth_create_login_message(data, user, outptr, outlen);
}

#endif /* if no users */
