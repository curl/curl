/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * RFC6749 OAuth 2.0 Authorization Framework
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>
#include "urldata.h"

#include "vauth/vauth.h"
#include "curl_base64.h"
#include "warnless.h"
#include "curl_printf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Curl_auth_create_oauth_bearer_message()
 *
 * This is used to generate an already encoded OAuth 2.0 message ready for
 * sending to the recipient.
 *
 * Parameters:
 *
 * data[in]         - The session handle.
 * user[in]         - The user name.
 * host[in]         - The host name(for OAUTHBEARER).
 * port[in]         - The port(for OAUTHBEARER when not Port 80).
 * bearer[in]       - The bearer token.
 * outptr[in / out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen[out]      - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_oauth_bearer_message(struct SessionHandle *data,
                                               const char *user,
                                               const char *host,
                                               const long port,
                                               const char *bearer,
                                               char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  char *oauth = NULL;

  /* Generate the message */
  if(host == NULL && (port == 0 || port == 80))
    oauth = aprintf("user=%s\1auth=Bearer %s\1\1", user, bearer);
  else if(port == 0 || port == 80)
    oauth = aprintf("user=%s\1host=%s\1auth=Bearer %s\1\1", user, host,
                    bearer);
  else
    oauth = aprintf("user=%s\1host=%s\1port=%ld\1auth=Bearer %s\1\1", user,
                    host, port, bearer);
  if(!oauth)
    return CURLE_OUT_OF_MEMORY;

  /* Base64 encode the reply */
  result = Curl_base64_encode(data, oauth, strlen(oauth), outptr, outlen);

  free(oauth);

  return result;
}
