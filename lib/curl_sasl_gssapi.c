/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014, Steve Holme, <steve_holme@hotmail.com>.
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
 * RFC4752 The Kerberos V5 ("GSSAPI") SASL Mechanism
 *
 ***************************************************************************/

#include "curl_setup.h"

#if defined(HAVE_GSSAPI) && defined(USE_KERBEROS5)

#include <curl/curl.h>

#include "curl_sasl.h"
#include "urldata.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/*
* Curl_sasl_build_gssapi_spn()
*
* This is used to build a SPN string in the format service@host.
*
* Parameters:
*
* serivce  [in] - The service type such as www, smtp, pop or imap.
* host     [in] - The host name or realm.
*
* Returns a pointer to the newly allocated SPN.
*/
static char *Curl_sasl_build_gssapi_spn(const char *service, const char *host)
{
  /* Generate and return our SPN */
  return aprintf("%s@%s", service, host);
}

/*
 * Curl_sasl_create_gssapi_user_message()
 *
 * This is used to generate an already encoded GSSAPI (Kerberos V5) user token
 * message ready for sending to the recipient.
 *
 * Parameters:
 *
 * data        [in]     - The session handle.
 * userp       [in]     - The user name.
 * passdwp     [in]     - The user's password.
 * service     [in]     - The service type such as www, smtp, pop or imap.
 * mutual_auth [in]     - Flag specifing whether or not mutual authentication
 *                        is enabled.
 * chlg64      [in]     - Pointer to the optional base64 encoded challenge
 *                        message.
 * krb5        [in/out] - The gssapi data struct being used and modified.
 * outptr      [in/out] - The address where a pointer to newly allocated memory
 *                        holding the result will be stored upon completion.
 * outlen      [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_gssapi_user_message(struct SessionHandle *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const char *service,
                                              const bool mutual_auth,
                                              const char *chlg64,
                                              struct kerberos5data *krb5,
                                              char **outptr, size_t *outlen)
{
  (void) data;
  (void) userp;
  (void) passwdp;
  (void) service;
  (void) mutual_auth;
  (void) chlg64;
  (void) krb5;
  (void) outptr;
  (void) outlen;

  return CURLE_NOT_BUILT_IN;
}

/*
 * Curl_sasl_create_gssapi_security_message()
 *
 * This is used to generate an already encoded GSSAPI (Kerberos V5) security
 * token message ready for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * chlg64  [in]     - Pointer to the optional base64 encoded challenge message.
 * krb5    [in/out] - The gssapi data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_gssapi_security_message(struct SessionHandle *data,
                                                  const char *chlg64,
                                                  struct kerberos5data *krb5,
                                                  char **outptr,
                                                  size_t *outlen)
{
  (void) data;
  (void) chlg64;
  (void) krb5;
  (void) outptr;
  (void) outlen;

  return CURLE_NOT_BUILT_IN;
}

void Curl_sasl_gssapi_cleanup(struct kerberos5data *krb5)
{
  OM_uint32 minor_status;

  /* Free our security context */
  if(krb5->context != GSS_C_NO_CONTEXT) {
    gss_delete_sec_context(&minor_status, &krb5->context, GSS_C_NO_BUFFER);
    krb5->context = GSS_C_NO_CONTEXT;
  }

  /* Free the SPN */
  if(krb5->spn != GSS_C_NO_NAME) {
    gss_release_name(&minor_status, &krb5->spn);
    krb5->spn = GSS_C_NO_NAME;
  }
}

#endif /* HAVE_GSSAPI && USE_KERBEROS5 */
