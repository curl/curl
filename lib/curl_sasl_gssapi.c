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

#ifdef HAVE_OLD_GSSMIT
#define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#define NCOMPAT 1
#endif

#include <curl/curl.h>

#include "curl_sasl.h"
#include "urldata.h"
#include "curl_base64.h"
#include "curl_gssapi.h"
#include "curl_memory.h"
#include "sendf.h"

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
  CURLcode result = CURLE_OK;
  size_t chlglen = 0;
  unsigned char *chlg = NULL;
  OM_uint32 gss_status;
  OM_uint32 gss_major_status;
  OM_uint32 gss_minor_status;
  gss_buffer_desc spn_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

  (void) userp;
  (void) passwdp;

  if(krb5->context == GSS_C_NO_CONTEXT) {
    /* Generate our SPN */
    char *spn = Curl_sasl_build_gssapi_spn(service,
                                           data->easy_conn->host.name);
    if(!spn)
      return CURLE_OUT_OF_MEMORY;

    /* Populate the SPN structure */
    spn_token.value = spn;
    spn_token.length = strlen(spn);

    /* Import the SPN */
    gss_major_status = gss_import_name(&gss_minor_status, &spn_token,
                                       gss_nt_service_name, &krb5->spn);

    if(GSS_ERROR(gss_major_status)) {
      Curl_gss_log_error(data, gss_minor_status, "gss_import_name() failed: ");

      return CURLE_OUT_OF_MEMORY;
    }
  }
  else {
    /* Decode the base-64 encoded challenge message */
    if(strlen(chlg64) && *chlg64 != '=') {
      result = Curl_base64_decode(chlg64, &chlg, &chlglen);
      if(result)
        return result;
    }

    /* Ensure we have a valid challenge message */
    if(!chlg) {
      infof(data, "GSSAPI handshake failure (empty challenge message)\n");

      return CURLE_BAD_CONTENT_ENCODING;
    }

    /* Setup the challenge "input" security buffer */
    input_token.value = chlg;
    input_token.length = chlglen;
  }

  gss_major_status = Curl_gss_init_sec_context(data,
                                               &gss_minor_status,
                                               &krb5->context,
                                               krb5->spn,
                                               &Curl_krb5_mech_oid,
                                               GSS_C_NO_CHANNEL_BINDINGS,
                                               &input_token,
                                               &output_token,
                                               mutual_auth,
                                               NULL);

  Curl_safefree(input_token.value);

  if(GSS_ERROR(gss_major_status)) {
    if(output_token.value)
      gss_release_buffer(&gss_status, &output_token);

    Curl_gss_log_error(data, gss_minor_status,
                       "gss_init_sec_context() failed: ");

    return CURLE_RECV_ERROR;
  }

  if(output_token.value && output_token.length) {
    /* Base64 encode the response */
    result = Curl_base64_encode(data, (char *) output_token.value,
                                output_token.length, outptr, outlen);

    gss_release_buffer(&gss_status, &output_token);
  }

  return result;
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
