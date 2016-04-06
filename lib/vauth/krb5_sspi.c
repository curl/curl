/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014 - 2016, Steve Holme, <steve_holme@hotmail.com>.
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
 * RFC4752 The Kerberos V5 ("GSSAPI") SASL Mechanism
 *
 ***************************************************************************/

#include "curl_setup.h"

#if defined(USE_WINDOWS_SSPI) && defined(USE_KERBEROS5)

#include <curl/curl.h>

#include "vauth/vauth.h"
#include "urldata.h"
#include "curl_base64.h"
#include "warnless.h"
#include "curl_multibyte.h"
#include "sendf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Curl_auth_create_gssapi_user_message()
 *
 * This is used to generate an already encoded GSSAPI (Kerberos V5) user token
 * message ready for sending to the recipient.
 *
 * Parameters:
 *
 * data        [in]     - The session handle.
 * userp       [in]     - The user name in the format User or Domain\User.
 * passdwp     [in]     - The user's password.
 * service     [in]     - The service type such as http, smtp, pop or imap.
 * host        [in]     - The host name.
 * mutual_auth [in]     - Flag specifing whether or not mutual authentication
 *                        is enabled.
 * chlg64      [in]     - The optional base64 encoded challenge message.
 * krb5        [in/out] - The Kerberos 5 data struct being used and modified.
 * outptr      [in/out] - The address where a pointer to newly allocated memory
 *                        holding the result will be stored upon completion.
 * outlen      [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_gssapi_user_message(struct SessionHandle *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const char *service,
                                              const char *host,
                                              const bool mutual_auth,
                                              const char *chlg64,
                                              struct kerberos5data *krb5,
                                              char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  size_t chlglen = 0;
  unsigned char *chlg = NULL;
  CtxtHandle context;
  PSecPkgInfo SecurityPackage;
  SecBuffer chlg_buf;
  SecBuffer resp_buf;
  SecBufferDesc chlg_desc;
  SecBufferDesc resp_desc;
  SECURITY_STATUS status;
  unsigned long attrs;
  TimeStamp expiry; /* For Windows 9x compatibility of SSPI calls */

  if(!krb5->spn) {
    /* Generate our SPN */
    krb5->spn = Curl_auth_build_spn(service, host, NULL);
    if(!krb5->spn)
      return CURLE_OUT_OF_MEMORY;
  }

  if(!krb5->output_token) {
    /* Query the security package for Kerberos */
    status = s_pSecFn->QuerySecurityPackageInfo((TCHAR *)
                                                TEXT(SP_NAME_KERBEROS),
                                                &SecurityPackage);
    if(status != SEC_E_OK) {
      return CURLE_NOT_BUILT_IN;
    }

    krb5->token_max = SecurityPackage->cbMaxToken;

    /* Release the package buffer as it is not required anymore */
    s_pSecFn->FreeContextBuffer(SecurityPackage);

    /* Allocate our response buffer */
    krb5->output_token = malloc(krb5->token_max);
    if(!krb5->output_token)
      return CURLE_OUT_OF_MEMORY;
  }

  if(!krb5->credentials) {
    /* Do we have credientials to use or are we using single sign-on? */
    if(userp && *userp) {
      /* Populate our identity structure */
      result = Curl_create_sspi_identity(userp, passwdp, &krb5->identity);
      if(result)
        return result;

      /* Allow proper cleanup of the identity structure */
      krb5->p_identity = &krb5->identity;
    }
    else
      /* Use the current Windows user */
      krb5->p_identity = NULL;

    /* Allocate our credentials handle */
    krb5->credentials = malloc(sizeof(CredHandle));
    if(!krb5->credentials)
      return CURLE_OUT_OF_MEMORY;

    memset(krb5->credentials, 0, sizeof(CredHandle));

    /* Acquire our credentials handle */
    status = s_pSecFn->AcquireCredentialsHandle(NULL,
                                                (TCHAR *)
                                                TEXT(SP_NAME_KERBEROS),
                                                SECPKG_CRED_OUTBOUND, NULL,
                                                krb5->p_identity, NULL, NULL,
                                                krb5->credentials, &expiry);
    if(status != SEC_E_OK)
      return CURLE_LOGIN_DENIED;

    /* Allocate our new context handle */
    krb5->context = malloc(sizeof(CtxtHandle));
    if(!krb5->context)
      return CURLE_OUT_OF_MEMORY;

    memset(krb5->context, 0, sizeof(CtxtHandle));
  }

  if(chlg64 && *chlg64) {
    /* Decode the base-64 encoded challenge message */
    if(*chlg64 != '=') {
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
    chlg_desc.ulVersion = SECBUFFER_VERSION;
    chlg_desc.cBuffers  = 1;
    chlg_desc.pBuffers  = &chlg_buf;
    chlg_buf.BufferType = SECBUFFER_TOKEN;
    chlg_buf.pvBuffer   = chlg;
    chlg_buf.cbBuffer   = curlx_uztoul(chlglen);
  }

  /* Setup the response "output" security buffer */
  resp_desc.ulVersion = SECBUFFER_VERSION;
  resp_desc.cBuffers  = 1;
  resp_desc.pBuffers  = &resp_buf;
  resp_buf.BufferType = SECBUFFER_TOKEN;
  resp_buf.pvBuffer   = krb5->output_token;
  resp_buf.cbBuffer   = curlx_uztoul(krb5->token_max);

  /* Generate our challenge-response message */
  status = s_pSecFn->InitializeSecurityContext(krb5->credentials,
                                               chlg ? krb5->context : NULL,
                                               krb5->spn,
                                               (mutual_auth ?
                                                ISC_REQ_MUTUAL_AUTH : 0),
                                               0, SECURITY_NATIVE_DREP,
                                               chlg ? &chlg_desc : NULL, 0,
                                               &context,
                                               &resp_desc, &attrs,
                                               &expiry);

  /* Free the decoded challenge as it is not required anymore */
  free(chlg);

  if(status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
    return CURLE_RECV_ERROR;
  }

  if(memcmp(&context, krb5->context, sizeof(context))) {
    s_pSecFn->DeleteSecurityContext(krb5->context);

    memcpy(krb5->context, &context, sizeof(context));
  }

  if(resp_buf.cbBuffer) {
    /* Base64 encode the response */
    result = Curl_base64_encode(data, (char *) resp_buf.pvBuffer,
                                resp_buf.cbBuffer, outptr, outlen);
  }
  else if(mutual_auth) {
    *outptr = strdup("");
    if(!*outptr)
      result = CURLE_OUT_OF_MEMORY;
  }

  return result;
}

/*
 * Curl_auth_create_gssapi_security_message()
 *
 * This is used to generate an already encoded GSSAPI (Kerberos V5) security
 * token message ready for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * chlg64  [in]     - The optional base64 encoded challenge message.
 * krb5    [in/out] - The Kerberos 5 data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_gssapi_security_message(struct SessionHandle *data,
                                                  const char *chlg64,
                                                  struct kerberos5data *krb5,
                                                  char **outptr,
                                                  size_t *outlen)
{
  CURLcode result = CURLE_OK;
  size_t offset = 0;
  size_t chlglen = 0;
  size_t messagelen = 0;
  size_t appdatalen = 0;
  unsigned char *chlg = NULL;
  unsigned char *trailer = NULL;
  unsigned char *message = NULL;
  unsigned char *padding = NULL;
  unsigned char *appdata = NULL;
  SecBuffer input_buf[2];
  SecBuffer wrap_buf[3];
  SecBufferDesc input_desc;
  SecBufferDesc wrap_desc;
  unsigned long indata = 0;
  unsigned long outdata = 0;
  unsigned long qop = 0;
  unsigned long sec_layer = 0;
  unsigned long max_size = 0;
  SecPkgContext_Sizes sizes;
  SecPkgCredentials_Names names;
  SECURITY_STATUS status;
  char *user_name;

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

  /* Get our response size information */
  status = s_pSecFn->QueryContextAttributes(krb5->context,
                                            SECPKG_ATTR_SIZES,
                                            &sizes);
  if(status != SEC_E_OK) {
    free(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Get the fully qualified username back from the context */
  status = s_pSecFn->QueryCredentialsAttributes(krb5->credentials,
                                                SECPKG_CRED_ATTR_NAMES,
                                                &names);
  if(status != SEC_E_OK) {
    free(chlg);

    return CURLE_RECV_ERROR;
  }

  /* Setup the "input" security buffer */
  input_desc.ulVersion = SECBUFFER_VERSION;
  input_desc.cBuffers = 2;
  input_desc.pBuffers = input_buf;
  input_buf[0].BufferType = SECBUFFER_STREAM;
  input_buf[0].pvBuffer = chlg;
  input_buf[0].cbBuffer = curlx_uztoul(chlglen);
  input_buf[1].BufferType = SECBUFFER_DATA;
  input_buf[1].pvBuffer = NULL;
  input_buf[1].cbBuffer = 0;

  /* Decrypt the inbound challenge and obtain the qop */
  status = s_pSecFn->DecryptMessage(krb5->context, &input_desc, 0, &qop);
  if(status != SEC_E_OK) {
    infof(data, "GSSAPI handshake failure (empty security message)\n");

    free(chlg);

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Not 4 octets long so fail as per RFC4752 Section 3.1 */
  if(input_buf[1].cbBuffer != 4) {
    infof(data, "GSSAPI handshake failure (invalid security data)\n");

    free(chlg);

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Copy the data out and free the challenge as it is not required anymore */
  memcpy(&indata, input_buf[1].pvBuffer, 4);
  s_pSecFn->FreeContextBuffer(input_buf[1].pvBuffer);
  free(chlg);

  /* Extract the security layer */
  sec_layer = indata & 0x000000FF;
  if(!(sec_layer & KERB_WRAP_NO_ENCRYPT)) {
    infof(data, "GSSAPI handshake failure (invalid security layer)\n");

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

  /* Allocate the trailer */
  trailer = malloc(sizes.cbSecurityTrailer);
  if(!trailer)
    return CURLE_OUT_OF_MEMORY;

  /* Convert the user name to UTF8 when operating with Unicode */
  user_name = Curl_convert_tchar_to_UTF8(names.sUserName);
  if(!user_name) {
    free(trailer);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Allocate our message */
  messagelen = sizeof(outdata) + strlen(user_name) + 1;
  message = malloc(messagelen);
  if(!message) {
    free(trailer);
    Curl_unicodefree(user_name);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Populate the message with the security layer, client supported receive
     message size and authorization identity including the 0x00 based
     terminator. Note: Despite RFC4752 Section 3.1 stating "The authorization
     identity is not terminated with the zero-valued (%x00) octet." it seems
     necessary to include it. */
  outdata = htonl(max_size) | sec_layer;
  memcpy(message, &outdata, sizeof(outdata));
  strcpy((char *) message + sizeof(outdata), user_name);
  Curl_unicodefree(user_name);

  /* Allocate the padding */
  padding = malloc(sizes.cbBlockSize);
  if(!padding) {
    free(message);
    free(trailer);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Setup the "authentication data" security buffer */
  wrap_desc.ulVersion    = SECBUFFER_VERSION;
  wrap_desc.cBuffers     = 3;
  wrap_desc.pBuffers     = wrap_buf;
  wrap_buf[0].BufferType = SECBUFFER_TOKEN;
  wrap_buf[0].pvBuffer   = trailer;
  wrap_buf[0].cbBuffer   = sizes.cbSecurityTrailer;
  wrap_buf[1].BufferType = SECBUFFER_DATA;
  wrap_buf[1].pvBuffer   = message;
  wrap_buf[1].cbBuffer   = curlx_uztoul(messagelen);
  wrap_buf[2].BufferType = SECBUFFER_PADDING;
  wrap_buf[2].pvBuffer   = padding;
  wrap_buf[2].cbBuffer   = sizes.cbBlockSize;

  /* Encrypt the data */
  status = s_pSecFn->EncryptMessage(krb5->context, KERB_WRAP_NO_ENCRYPT,
                                    &wrap_desc, 0);
  if(status != SEC_E_OK) {
    free(padding);
    free(message);
    free(trailer);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Allocate the encryption (wrap) buffer */
  appdatalen = wrap_buf[0].cbBuffer + wrap_buf[1].cbBuffer +
               wrap_buf[2].cbBuffer;
  appdata = malloc(appdatalen);
  if(!appdata) {
    free(padding);
    free(message);
    free(trailer);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Populate the encryption buffer */
  memcpy(appdata, wrap_buf[0].pvBuffer, wrap_buf[0].cbBuffer);
  offset += wrap_buf[0].cbBuffer;
  memcpy(appdata + offset, wrap_buf[1].pvBuffer, wrap_buf[1].cbBuffer);
  offset += wrap_buf[1].cbBuffer;
  memcpy(appdata + offset, wrap_buf[2].pvBuffer, wrap_buf[2].cbBuffer);

  /* Base64 encode the response */
  result = Curl_base64_encode(data, (char *) appdata, appdatalen, outptr,
                              outlen);

  /* Free all of our local buffers */
  free(appdata);
  free(padding);
  free(message);
  free(trailer);

  return result;
}

/*
 * Curl_auth_gssapi_cleanup()
 *
 * This is used to clean up the GSSAPI (Kerberos V5) specific data.
 *
 * Parameters:
 *
 * krb5     [in/out] - The Kerberos 5 data struct being cleaned up.
 *
 */
void Curl_auth_gssapi_cleanup(struct kerberos5data *krb5)
{
  /* Free our security context */
  if(krb5->context) {
    s_pSecFn->DeleteSecurityContext(krb5->context);
    free(krb5->context);
    krb5->context = NULL;
  }

  /* Free our credentials handle */
  if(krb5->credentials) {
    s_pSecFn->FreeCredentialsHandle(krb5->credentials);
    free(krb5->credentials);
    krb5->credentials = NULL;
  }

  /* Free our identity */
  Curl_sspi_free_identity(krb5->p_identity);
  krb5->p_identity = NULL;

  /* Free the SPN and output token */
  Curl_safefree(krb5->spn);
  Curl_safefree(krb5->output_token);

  /* Reset any variables */
  krb5->token_max = 0;
}

#endif /* USE_WINDOWS_SSPI && USE_KERBEROS5*/
