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
 * SPDX-License-Identifier: fetch
 *
 * RFC2195 CRAM-MD5 authentication
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifndef FETCH_DISABLE_DIGEST_AUTH

#include <fetch/fetch.h>
#include "urldata.h"

#include "vauth/vauth.h"
#include "fetch_hmac.h"
#include "fetch_md5.h"
#include "warnless.h"
#include "fetch_printf.h"

/* The last #include files should be: */
#include "fetch_memory.h"
#include "memdebug.h"

/*
 * Curl_auth_create_cram_md5_message()
 *
 * This is used to generate a CRAM-MD5 response message ready for sending to
 * the recipient.
 *
 * Parameters:
 *
 * chlg    [in]     - The challenge.
 * userp   [in]     - The username.
 * passwdp [in]     - The user's password.
 * out     [out]    - The result storage.
 *
 * Returns FETCHE_OK on success.
 */
FETCHcode Curl_auth_create_cram_md5_message(const struct bufref *chlg,
                                            const char *userp,
                                            const char *passwdp,
                                            struct bufref *out)
{
  struct HMAC_context *ctxt;
  unsigned char digest[MD5_DIGEST_LEN];
  char *response;

  /* Compute the digest using the password as the key */
  ctxt = Curl_HMAC_init(&Curl_HMAC_MD5,
                        (const unsigned char *)passwdp,
                        fetchx_uztoui(strlen(passwdp)));
  if (!ctxt)
    return FETCHE_OUT_OF_MEMORY;

  /* Update the digest with the given challenge */
  if (Curl_bufref_len(chlg))
    Curl_HMAC_update(ctxt, Curl_bufref_ptr(chlg),
                     fetchx_uztoui(Curl_bufref_len(chlg)));

  /* Finalise the digest */
  Curl_HMAC_final(ctxt, digest);

  /* Generate the response */
  response = aprintf(
      "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
      userp, digest[0], digest[1], digest[2], digest[3], digest[4],
      digest[5], digest[6], digest[7], digest[8], digest[9], digest[10],
      digest[11], digest[12], digest[13], digest[14], digest[15]);
  if (!response)
    return FETCHE_OUT_OF_MEMORY;

  Curl_bufref_set(out, response, strlen(response), fetch_free);
  return FETCHE_OK;
}

#endif /* !FETCH_DISABLE_DIGEST_AUTH */
