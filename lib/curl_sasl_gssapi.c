/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014 - 2015, Steve Holme, <steve_holme@hotmail.com>.
 * Copyright (C) 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
char *Curl_sasl_build_gssapi_spn(const char *service, const char *host)
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
                                       GSS_C_NT_HOSTBASED_SERVICE, &krb5->spn);
    if(GSS_ERROR(gss_major_status)) {
      Curl_gss_log_error(data, gss_minor_status, "gss_import_name() failed: ");

      Curl_safefree(spn);

      return CURLE_OUT_OF_MEMORY;
    }

    Curl_safefree(spn);
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
  CURLcode result = CURLE_OK;
  size_t chlglen = 0;
  size_t messagelen = 0;
  unsigned char *chlg = NULL;
  unsigned char *message = NULL;
  OM_uint32 gss_status;
  OM_uint32 gss_major_status;
  OM_uint32 gss_minor_status;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  unsigned int indata = 0;
  unsigned int outdata = 0;
  gss_qop_t qop = GSS_C_QOP_DEFAULT;
  unsigned int sec_layer = 0;
  unsigned int max_size = 0;
  gss_name_t username = GSS_C_NO_NAME;
  gss_buffer_desc username_token;

  /* Decode the base-64 encoded input message */
  if(strlen(chlg64) && *chlg64 != '=') {
    result = Curl_base64_decode(chlg64, &chlg, &chlglen);
    if(result)
      return result;
  }

  /* Ensure we have a valid challenge message */
  if(!chlg) {
    infof(data, "GSSAPI handshake failure (empty security message)\n");

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Get the fully qualified username back from the context */
  gss_major_status = gss_inquire_context(&gss_minor_status, krb5->context,
                                         &username, NULL, NULL, NULL, NULL,
                                         NULL, NULL);
  if(GSS_ERROR(gss_major_status)) {
    Curl_gss_log_error(data, gss_minor_status,
                       "gss_inquire_context() failed: ");

    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Convert the username from internal format to a displayable token */
  gss_major_status = gss_display_name(&gss_minor_status, username,
                                      &username_token, NULL);
  if(GSS_ERROR(gss_major_status)) {
    Curl_gss_log_error(data, gss_minor_status, "gss_display_name() failed: ");

    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Setup the challenge "input" security buffer */
  input_token.value = chlg;
  input_token.length = chlglen;

  /* Decrypt the inbound challenge and obtain the qop */
  gss_major_status = gss_unwrap(&gss_minor_status, krb5->context, &input_token,
                                &output_token, NULL, &qop);
  if(GSS_ERROR(gss_major_status)) {
    Curl_gss_log_error(data, gss_minor_status, "gss_unwrap() failed: ");

    gss_release_buffer(&gss_status, &username_token);
    Curl_safefree(chlg);

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Not 4 octets long so fail as per RFC4752 Section 3.1 */
  if(output_token.length != 4) {
    infof(data, "GSSAPI handshake failure (invalid security data)\n");

    gss_release_buffer(&gss_status, &username_token);
    Curl_safefree(chlg);

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Copy the data out and free the challenge as it is not required anymore */
  memcpy(&indata, output_token.value, 4);
  gss_release_buffer(&gss_status, &output_token);
  Curl_safefree(chlg);

  /* Extract the security layer */
  sec_layer = indata & 0x000000FF;
  if(!(sec_layer & GSSAUTH_P_NONE)) {
    infof(data, "GSSAPI handshake failure (invalid security layer)\n");

    gss_release_buffer(&gss_status, &username_token);

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Extract the maximum message size the server can receive */
  max_size = ntohl(indata & 0xFFFFFF00);
  if(max_size > 0) {
    /* The server has told us it supports a maximum receive buffer, however, as
       we don't require one unless we are encrypting data, we tell the server
       our receive buffer is zero. */
    max_size = 0;
  }

  /* Allocate our message */
  messagelen = sizeof(outdata) + username_token.length + 1;
  message = malloc(messagelen);
  if(!message) {
    gss_release_buffer(&gss_status, &username_token);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Populate the message with the security layer, client supported receive
     message size and authorization identity including the 0x00 based
     terminator. Note: Dispite RFC4752 Section 3.1 stating "The authorization
     identity is not terminated with the zero-valued (%x00) octet." it seems
     necessary to include it. */
  outdata = htonl(max_size) | sec_layer;
  memcpy(message, &outdata, sizeof(outdata));
  memcpy(message + sizeof(outdata), username_token.value,
         username_token.length);
  message[messagelen - 1] = '\0';

  /* Free the username token as it is not required anymore */
  gss_release_buffer(&gss_status, &username_token);

  /* Setup the "authentication data" security buffer */
  input_token.value = message;
  input_token.length = messagelen;

  /* Encrypt the data */
  gss_major_status = gss_wrap(&gss_minor_status, krb5->context, 0,
                              GSS_C_QOP_DEFAULT, &input_token, NULL,
                              &output_token);
  if(GSS_ERROR(gss_major_status)) {
    Curl_gss_log_error(data, gss_minor_status, "gss_wrap() failed: ");

    Curl_safefree(message);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Base64 encode the response */
  result = Curl_base64_encode(data, (char *) output_token.value,
                              output_token.length, outptr, outlen);

  /* Free the output buffer */
  gss_release_buffer(&gss_status, &output_token);

  /* Free the message buffer */
  Curl_safefree(message);

  return result;
}

/*
 * Curl_sasl_gssapi_cleanup()
 *
 * This is used to clean up the gssapi specific data.
 *
 * Parameters:
 *
 * krb5     [in/out] - The kerberos 5 data struct being cleaned up.
 *
 */
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
