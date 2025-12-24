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
 * RFC4616 PLAIN authentication
 * Draft   LOGIN SASL Mechanism <draft-murchison-sasl-login-00.txt>
 *
 ***************************************************************************/

#include "../curl_setup.h"

#if !defined(CURL_DISABLE_IMAP) || !defined(CURL_DISABLE_SMTP) || \
  !defined(CURL_DISABLE_POP3) ||                                  \
  (!defined(CURL_DISABLE_LDAP) && defined(USE_OPENLDAP))

#include "vauth.h"

/*
 * Curl_auth_create_plain_message()
 *
 * This is used to generate an already encoded PLAIN message ready
 * for sending to the recipient.
 *
 * Parameters:
 *
 * authzid [in]     - The authorization identity.
 * authcid [in]     - The authentication identity.
 * passwd  [in]     - The password.
 * out     [out]    - The result storage.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_plain_message(const char *authzid,
                                        const char *authcid,
                                        const char *passwd,
                                        struct bufref *out)
{
  size_t len;
  char *auth;

  size_t zlen = (authzid == NULL ? 0 : strlen(authzid));
  size_t clen = strlen(authcid);
  size_t plen = strlen(passwd);

  if((zlen > CURL_MAX_INPUT_LENGTH) || (clen > CURL_MAX_INPUT_LENGTH) ||
     (plen > CURL_MAX_INPUT_LENGTH))
    return CURLE_TOO_LARGE;

  len = zlen + clen + plen + 2;

  auth = curl_maprintf("%s%c%s%c%s", authzid ? authzid : "", '\0',
                       authcid, '\0', passwd);
  if(!auth)
    return CURLE_OUT_OF_MEMORY;
  Curl_bufref_set(out, auth, len, curl_free);
  return CURLE_OK;
}

/*
 * Curl_auth_create_login_message()
 *
 * This is used to generate an already encoded LOGIN message containing the
 * username or password ready for sending to the recipient.
 *
 * Parameters:
 *
 * valuep  [in]     - The username or user's password.
 * out     [out]    - The result storage.
 *
 * Returns void.
 */
void Curl_auth_create_login_message(const char *valuep, struct bufref *out)
{
  Curl_bufref_set(out, valuep, strlen(valuep), NULL);
}

/*
 * Curl_auth_create_external_message()
 *
 * This is used to generate an already encoded EXTERNAL message containing
 * the username ready for sending to the recipient.
 *
 * Parameters:
 *
 * user    [in]     - The username.
 * out     [out]    - The result storage.
 *
 * Returns void.
 */
void Curl_auth_create_external_message(const char *user, struct bufref *out)
{
  /* This is the same formatting as the login message */
  Curl_auth_create_login_message(user, out);
}

#endif /* if no users */
