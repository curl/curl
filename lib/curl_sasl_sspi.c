/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014, Steve Holme, <steve_holme@hotmail.com>.
 * Copyright (C) 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * RFC2831 DIGEST-MD5 authentication
 * RFC4422 Simple Authentication and Security Layer (SASL)
 * RFC4752 The Kerberos V5 ("GSSAPI") SASL Mechanism
 *
 ***************************************************************************/

#include "curl_setup.h"

#if defined(USE_WINDOWS_SSPI)

#include <curl/curl.h>

#include "curl_sasl.h"
#include "urldata.h"
#include "curl_base64.h"
#include "warnless.h"
#include "curl_memory.h"
#include "curl_multibyte.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

void Curl_sasl_gssapi_cleanup(struct kerberos5data *krb5);

/*
 * Curl_sasl_build_spn()
 *
 * This is used to build a SPN string in the format service/host.
 *
 * Parameters:
 *
 * serivce  [in] - The service type such as www, smtp, pop or imap.
 * instance [in] - The instance name such as the host nme or realm.
 *
 * Returns a pointer to the newly allocated SPN.
 */
TCHAR *Curl_sasl_build_spn(const char *service, const char *host)
{
  char *utf8_spn = NULL;
  TCHAR *tchar_spn = NULL;

  /* Note: We could use DsMakeSPN() or DsClientMakeSpnForTargetServer() rather
     than doing this ourselves but the first is only available in Windows XP
     and Windows Server 2003 and the latter is only available in Windows 2000
     but not Windows95/98/ME or Windows NT4.0 unless the Active Directory
     Client Extensions are installed. As such it is far simpler for us to
     formulate the SPN instead. */

  /* Allocate our UTF8 based SPN */
  utf8_spn = aprintf("%s/%s", service, host);
  if(!utf8_spn) {
    return NULL;
  }

  /* Allocate our TCHAR based SPN */
  tchar_spn = Curl_convert_UTF8_to_tchar(utf8_spn);
  if(!tchar_spn) {
    Curl_safefree(utf8_spn);

    return NULL;
  }

  /* Release the UTF8 variant when operating with Unicode */
  if(utf8_spn != tchar_spn)
    Curl_safefree(utf8_spn);

  /* Return our newly allocated SPN */
  return tchar_spn;
}

#if !defined(CURL_DISABLE_CRYPTO_AUTH)
/*
 * Curl_sasl_create_digest_md5_message()
 *
 * This is used to generate an already encoded DIGEST-MD5 response message
 * ready for sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * chlg64  [in]     - Pointer to the base64 encoded challenge message.
 * userp   [in]     - The user name.
 * passdwp [in]     - The user's password.
 * service [in]     - The service type such as www, smtp, pop or imap.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_digest_md5_message(struct SessionHandle *data,
                                             const char *chlg64,
                                             const char *userp,
                                             const char *passwdp,
                                             const char *service,
                                             char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  TCHAR *spn = NULL;
  size_t chlglen = 0;
  size_t resp_max = 0;
  unsigned char *chlg = NULL;
  unsigned char *resp = NULL;
  CredHandle handle;
  CtxtHandle ctx;
  PSecPkgInfo SecurityPackage;
  SEC_WINNT_AUTH_IDENTITY identity;
  SecBuffer chlg_buf;
  SecBuffer resp_buf;
  SecBufferDesc chlg_desc;
  SecBufferDesc resp_desc;
  SECURITY_STATUS status;
  unsigned long attrs;
  TimeStamp tsDummy; /* For Windows 9x compatibility of SSPI calls */

  /* Decode the base-64 encoded challenge message */
  if(strlen(chlg64) && *chlg64 != '=') {
    result = Curl_base64_decode(chlg64, &chlg, &chlglen);
    if(result)
      return result;
  }

  /* Ensure we have a valid challenge message */
  if(!chlg)
    return CURLE_BAD_CONTENT_ENCODING;

  /* Ensure we have some login credientials as DigestSSP cannot use the current
     Windows user like NTLMSSP can */
  if(!userp || !*userp) {
    Curl_safefree(chlg);
    return CURLE_LOGIN_DENIED;
  }

  /* Query the security package for DigestSSP */
  status = s_pSecFn->QuerySecurityPackageInfo((TCHAR *) TEXT("WDigest"),
                                              &SecurityPackage);
  if(status != SEC_E_OK) {
    Curl_safefree(chlg);

    return CURLE_NOT_BUILT_IN;
  }

  resp_max = SecurityPackage->cbMaxToken;

  /* Release the package buffer as it is not required anymore */
  s_pSecFn->FreeContextBuffer(SecurityPackage);

  /* Allocate our response buffer */
  resp = malloc(resp_max);
  if(!resp) {
    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Generate our SPN */
  spn = Curl_sasl_build_spn(service, data->easy_conn->host.name);
  if(!spn) {
    Curl_safefree(resp);
    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Populate our identity structure */
  result = Curl_create_sspi_identity(userp, passwdp, &identity);
  if(result) {
    Curl_safefree(spn);
    Curl_safefree(resp);
    Curl_safefree(chlg);

    return result;
  }

  /* Acquire our credientials handle */
  status = s_pSecFn->AcquireCredentialsHandle(NULL,
                                              (TCHAR *) TEXT("WDigest"),
                                              SECPKG_CRED_OUTBOUND, NULL,
                                              &identity, NULL, NULL,
                                              &handle, &tsDummy);

  if(status != SEC_E_OK) {
    Curl_sspi_free_identity(&identity);
    Curl_safefree(spn);
    Curl_safefree(resp);
    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Setup the challenge "input" security buffer */
  chlg_desc.ulVersion = SECBUFFER_VERSION;
  chlg_desc.cBuffers  = 1;
  chlg_desc.pBuffers  = &chlg_buf;
  chlg_buf.BufferType = SECBUFFER_TOKEN;
  chlg_buf.pvBuffer   = chlg;
  chlg_buf.cbBuffer   = curlx_uztoul(chlglen);

  /* Setup the response "output" security buffer */
  resp_desc.ulVersion = SECBUFFER_VERSION;
  resp_desc.cBuffers  = 1;
  resp_desc.pBuffers  = &resp_buf;
  resp_buf.BufferType = SECBUFFER_TOKEN;
  resp_buf.pvBuffer   = resp;
  resp_buf.cbBuffer   = curlx_uztoul(resp_max);

  /* Generate our challenge-response message */
  status = s_pSecFn->InitializeSecurityContext(&handle, NULL, spn, 0, 0, 0,
                                               &chlg_desc, 0, &ctx,
                                               &resp_desc, &attrs, &tsDummy);

  if(status == SEC_I_COMPLETE_AND_CONTINUE ||
     status == SEC_I_CONTINUE_NEEDED)
    s_pSecFn->CompleteAuthToken(&handle, &resp_desc);
  else if(status != SEC_E_OK) {
    s_pSecFn->FreeCredentialsHandle(&handle);
    Curl_sspi_free_identity(&identity);
    Curl_safefree(spn);
    Curl_safefree(resp);
    Curl_safefree(chlg);

    return CURLE_RECV_ERROR;
  }

  /* Base64 encode the response */
  result = Curl_base64_encode(data, (char *)resp, resp_buf.cbBuffer, outptr,
                              outlen);

  /* Free our handles */
  s_pSecFn->DeleteSecurityContext(&ctx);
  s_pSecFn->FreeCredentialsHandle(&handle);

  /* Free the identity structure */
  Curl_sspi_free_identity(&identity);

  /* Free the SPN */
  Curl_safefree(spn);

  /* Free the response buffer */
  Curl_safefree(resp);

  /* Free the decoeded challenge message */
  Curl_safefree(chlg);

  return result;
}

#endif /* !CURL_DISABLE_CRYPTO_AUTH */

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
  CtxtHandle context;
  PSecPkgInfo SecurityPackage;
  SecBuffer chlg_buf;
  SecBuffer resp_buf;
  SecBufferDesc chlg_desc;
  SecBufferDesc resp_desc;
  SECURITY_STATUS status;
  unsigned long attrs;
  TimeStamp tsDummy; /* For Windows 9x compatibility of SSPI calls */

  if(!krb5->credentials) {
    /* Query the security package for Kerberos */
    status = s_pSecFn->QuerySecurityPackageInfo((TCHAR *) TEXT("Kerberos"),
                                                &SecurityPackage);
    if(status != SEC_E_OK) {
      return CURLE_NOT_BUILT_IN;
    }

    krb5->token_max = SecurityPackage->cbMaxToken;

    /* Release the package buffer as it is not required anymore */
    s_pSecFn->FreeContextBuffer(SecurityPackage);

    /* Generate our SPN */
    krb5->spn = Curl_sasl_build_spn(service, data->easy_conn->host.name);
    if(!krb5->spn)
      return CURLE_OUT_OF_MEMORY;

    if(userp && *userp) {
      /* Populate our identity structure */
      result = Curl_create_sspi_identity(userp, passwdp, &krb5->identity);
      if(result)
        return result;

      /* Allow proper cleanup of the identity structure */
      krb5->p_identity = &krb5->identity;

      /* Allocate our response buffer */
      krb5->output_token = malloc(krb5->token_max);
      if(!krb5->output_token)
        return CURLE_OUT_OF_MEMORY;
    }
    else
      /* Use the current Windows user */
      krb5->p_identity = NULL;

    /* Allocate our credentials handle */
    krb5->credentials = malloc(sizeof(CredHandle));
    if(!krb5->credentials)
      return CURLE_OUT_OF_MEMORY;

    memset(krb5->credentials, 0, sizeof(CredHandle));

    /* Acquire our credientials handle */
    status = s_pSecFn->AcquireCredentialsHandle(NULL,
                                                (TCHAR *) TEXT("Kerberos"),
                                                SECPKG_CRED_OUTBOUND, NULL,
                                                krb5->p_identity, NULL, NULL,
                                                krb5->credentials, &tsDummy);
    if(status != SEC_E_OK)
      return CURLE_OUT_OF_MEMORY;

    /* Allocate our new context handle */
    krb5->context = malloc(sizeof(CtxtHandle));
    if(!krb5->context)
      return CURLE_OUT_OF_MEMORY;

    memset(krb5->context, 0, sizeof(CtxtHandle));
  }
  else {
    /* Decode the base-64 encoded challenge message */
    if(strlen(chlg64) && *chlg64 != '=') {
      result = Curl_base64_decode(chlg64, &chlg, &chlglen);
      if(result)
        return result;
    }

    /* Ensure we have a valid challenge message */
    if(!chlg)
      return CURLE_BAD_CONTENT_ENCODING;

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
                                               &tsDummy);

  if(status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
    Curl_safefree(chlg);

    return CURLE_RECV_ERROR;
  }

  if(memcmp(&context, krb5->context, sizeof(context))) {
    s_pSecFn->DeleteSecurityContext(krb5->context);

    memcpy(krb5->context, &context, sizeof(context));
  }

  if(resp_buf.cbBuffer) {
    /* Base64 encode the response */
    result = Curl_base64_encode(data, (char *)resp_buf.pvBuffer,
                                resp_buf.cbBuffer, outptr, outlen);
  }

  /* Free the decoded challenge */
  Curl_safefree(chlg);

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

  /* TODO: Verify the unicodeness of this function */

  /* Decode the base-64 encoded input message */
  if(strlen(chlg64) && *chlg64 != '=') {
    result = Curl_base64_decode(chlg64, &chlg, &chlglen);
    if(result)
      return result;
  }

  /* Ensure we have a valid challenge message */
  if(!chlg)
    return CURLE_BAD_CONTENT_ENCODING;

  /* Get our response size information */
  status = s_pSecFn->QueryContextAttributes(krb5->context,
                                            SECPKG_ATTR_SIZES,
                                            &sizes);
  if(status != SEC_E_OK) {
    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Get the fully qualified username back from the context */
  status = s_pSecFn->QueryCredentialsAttributes(krb5->credentials,
                                                SECPKG_CRED_ATTR_NAMES,
                                                &names);
  if(status != SEC_E_OK) {
    Curl_safefree(chlg);

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

  /* Decrypt in the inbound challenge obtaining the qop */
  status = s_pSecFn->DecryptMessage(krb5->context, &input_desc, 0, &qop);
  if(status != SEC_E_OK) {
    Curl_safefree(chlg);

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Not 4 octets long to fail as per RFC4752 Section 3.1 */
  if(input_buf[1].cbBuffer != 4) {
    Curl_safefree(chlg);

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Copy the data out into a coinput_bufnvenient variable and free the SSPI
     allocated buffer as it is not required anymore */
  memcpy(&indata, input_buf[1].pvBuffer, 4);
  s_pSecFn->FreeContextBuffer(input_buf[1].pvBuffer);

  /* Extract the security layer */
  sec_layer = indata & 0x000000FF;
  if(!(sec_layer & KERB_WRAP_NO_ENCRYPT)) {
    Curl_safefree(chlg);

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Extract the maximum message size the server can receive */
  max_size = ntohl(indata & 0xFFFFFF00);
  if(max_size > 0) {
    /* The server has told us it supports a maximum receive buffer, however, as
       we don't require one unless we are encrypting data we, tell the server
       our receive buffer is zero. */
    max_size = 0;
  }

  outdata = htonl(max_size) | sec_layer;

  /* Allocate the trailer */
  trailer = malloc(sizes.cbSecurityTrailer);
  if(!trailer) {
    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Allocate our message */
  messagelen = 4 + strlen(names.sUserName) + 1;
  message = malloc(messagelen);
  if(!message) {
    Curl_safefree(trailer);
    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Populate the message with the security layer, client supported receive
     message size and authorization identity including the 0x00 based
     terminator. Note: Dispite RFC4752 Section 3.1 stating "The authorization
     identity is not terminated with the zero-valued (%x00) octet." it seems
     necessary to include it. */
  memcpy(message, &outdata, 4);
  strcpy((char *)message + 4, names.sUserName);

  /* Allocate the padding */
  padding = malloc(sizes.cbBlockSize);
  if(!padding) {
    Curl_safefree(message);
    Curl_safefree(trailer);
    Curl_safefree(chlg);

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
    Curl_safefree(padding);
    Curl_safefree(message);
    Curl_safefree(trailer);
    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Allocate the encryption (wrap) buffer */
  appdatalen = wrap_buf[0].cbBuffer + wrap_buf[1].cbBuffer +
               wrap_buf[2].cbBuffer;
  appdata = malloc(appdatalen);
  if(!appdata) {
    Curl_safefree(padding);
    Curl_safefree(message);
    Curl_safefree(trailer);
    Curl_safefree(chlg);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Populate the encryption buffer */
  memcpy(appdata, wrap_buf[0].pvBuffer, wrap_buf[0].cbBuffer);
  offset += wrap_buf[0].cbBuffer;
  memcpy(appdata + offset, wrap_buf[1].pvBuffer, wrap_buf[1].cbBuffer);
  offset += wrap_buf[1].cbBuffer;
  memcpy(appdata + offset, wrap_buf[2].pvBuffer, wrap_buf[2].cbBuffer);

  /* Base64 encode the response */
  result = Curl_base64_encode(data, (char *)appdata, appdatalen, outptr,
                              outlen);

  /* Free all of our local buffers */
  Curl_safefree(appdata);
  Curl_safefree(padding);
  Curl_safefree(message);
  Curl_safefree(trailer);
  Curl_safefree(chlg);

  return result;
}

void Curl_sasl_gssapi_cleanup(struct kerberos5data *krb5)
{
  /* Free  the context */
  if(krb5->context) {
    s_pSecFn->DeleteSecurityContext(krb5->context);
    free(krb5->context);
    krb5->context = NULL;
  }

  /* Free the credientials handle */
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

#endif /* USE_WINDOWS_SSPI */
