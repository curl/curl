/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) 2014 - 2015, Steve Holme, <steve_holme@hotmail.com>.
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
 * RFC2617 Basic and Digest Access Authentication
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
#include "curl_multibyte.h"
#include "sendf.h"
#include "strdup.h"
#include "curl_printf.h"
#include "rawstr.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Curl_sasl_build_spn()
 *
 * This is used to build a SPN string in the format service/instance.
 *
 * Parameters:
 *
 * serivce  [in] - The service type such as www, smtp, pop or imap.
 * instance [in] - The host name or realm.
 *
 * Returns a pointer to the newly allocated SPN.
 */
TCHAR *Curl_sasl_build_spn(const char *service, const char *instance)
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
  utf8_spn = aprintf("%s/%s", service, instance);
  if(!utf8_spn) {
    return NULL;
  }

  /* Allocate our TCHAR based SPN */
  tchar_spn = Curl_convert_UTF8_to_tchar(utf8_spn);
  if(!tchar_spn) {
    free(utf8_spn);

    return NULL;
  }

  /* Release the UTF8 variant when operating with Unicode */
  Curl_unicodefree(utf8_spn);

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
 * chlg64  [in]     - The base64 encoded challenge message.
 * userp   [in]     - The user name in the format User or Domain\User.
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
  size_t token_max = 0;
  unsigned char *input_token = NULL;
  unsigned char *output_token = NULL;
  CredHandle credentials;
  CtxtHandle context;
  PSecPkgInfo SecurityPackage;
  SEC_WINNT_AUTH_IDENTITY identity;
  SEC_WINNT_AUTH_IDENTITY *p_identity;
  SecBuffer chlg_buf;
  SecBuffer resp_buf;
  SecBufferDesc chlg_desc;
  SecBufferDesc resp_desc;
  SECURITY_STATUS status;
  unsigned long attrs;
  TimeStamp expiry; /* For Windows 9x compatibility of SSPI calls */

  /* Decode the base-64 encoded challenge message */
  if(strlen(chlg64) && *chlg64 != '=') {
    result = Curl_base64_decode(chlg64, &input_token, &chlglen);
    if(result)
      return result;
  }

  /* Ensure we have a valid challenge message */
  if(!input_token) {
    infof(data, "DIGEST-MD5 handshake failure (empty challenge message)\n");

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Query the security package for DigestSSP */
  status = s_pSecFn->QuerySecurityPackageInfo((TCHAR *) TEXT(SP_NAME_DIGEST),
                                              &SecurityPackage);
  if(status != SEC_E_OK) {
    free(input_token);

    return CURLE_NOT_BUILT_IN;
  }

  token_max = SecurityPackage->cbMaxToken;

  /* Release the package buffer as it is not required anymore */
  s_pSecFn->FreeContextBuffer(SecurityPackage);

  /* Allocate our response buffer */
  output_token = malloc(token_max);
  if(!output_token) {
    free(input_token);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Generate our SPN */
  spn = Curl_sasl_build_spn(service, data->easy_conn->host.name);
  if(!spn) {
    free(output_token);
    free(input_token);

    return CURLE_OUT_OF_MEMORY;
  }

  if(userp && *userp) {
    /* Populate our identity structure */
    result = Curl_create_sspi_identity(userp, passwdp, &identity);
    if(result) {
      free(spn);
      free(output_token);
      free(input_token);

      return result;
    }

    /* Allow proper cleanup of the identity structure */
    p_identity = &identity;
  }
  else
    /* Use the current Windows user */
    p_identity = NULL;

  /* Acquire our credentials handle */
  status = s_pSecFn->AcquireCredentialsHandle(NULL,
                                              (TCHAR *) TEXT(SP_NAME_DIGEST),
                                              SECPKG_CRED_OUTBOUND, NULL,
                                              p_identity, NULL, NULL,
                                              &credentials, &expiry);

  if(status != SEC_E_OK) {
    Curl_sspi_free_identity(p_identity);
    free(spn);
    free(output_token);
    free(input_token);

    return CURLE_LOGIN_DENIED;
  }

  /* Setup the challenge "input" security buffer */
  chlg_desc.ulVersion = SECBUFFER_VERSION;
  chlg_desc.cBuffers  = 1;
  chlg_desc.pBuffers  = &chlg_buf;
  chlg_buf.BufferType = SECBUFFER_TOKEN;
  chlg_buf.pvBuffer   = input_token;
  chlg_buf.cbBuffer   = curlx_uztoul(chlglen);

  /* Setup the response "output" security buffer */
  resp_desc.ulVersion = SECBUFFER_VERSION;
  resp_desc.cBuffers  = 1;
  resp_desc.pBuffers  = &resp_buf;
  resp_buf.BufferType = SECBUFFER_TOKEN;
  resp_buf.pvBuffer   = output_token;
  resp_buf.cbBuffer   = curlx_uztoul(token_max);

  /* Generate our response message */
  status = s_pSecFn->InitializeSecurityContext(&credentials, NULL, spn,
                                               0, 0, 0, &chlg_desc, 0,
                                               &context, &resp_desc, &attrs,
                                               &expiry);

  if(status == SEC_I_COMPLETE_NEEDED ||
     status == SEC_I_COMPLETE_AND_CONTINUE)
    s_pSecFn->CompleteAuthToken(&credentials, &resp_desc);
  else if(status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
    s_pSecFn->FreeCredentialsHandle(&credentials);
    Curl_sspi_free_identity(p_identity);
    free(spn);
    free(output_token);
    free(input_token);

    return CURLE_RECV_ERROR;
  }

  /* Base64 encode the response */
  result = Curl_base64_encode(data, (char *) output_token, resp_buf.cbBuffer,
                              outptr, outlen);

  /* Free our handles */
  s_pSecFn->DeleteSecurityContext(&context);
  s_pSecFn->FreeCredentialsHandle(&credentials);

  /* Free the identity structure */
  Curl_sspi_free_identity(p_identity);

  /* Free the SPN */
  free(spn);

  /* Free the response buffer */
  free(output_token);

  /* Free the decoded challenge message */
  free(input_token);

  return result;
}

/*
* Curl_override_sspi_http_realm()
*
* This is used to populate the domain in a SSPI identity structure
* The realm is extracted from the challenge message and used as the
* domain if it is not already explicitly set.
*
* Parameters:
*
* chlg     [in]     - The challenge message.
* identity [in/out] - The identity structure.
*
* Returns CURLE_OK on success.
*/
CURLcode Curl_override_sspi_http_realm(const char *chlg,
                                       SEC_WINNT_AUTH_IDENTITY *identity)
{
  xcharp_u domain, dup_domain;

  /* If domain is blank or unset, check challenge message for realm */
  if(!identity->Domain || !identity->DomainLength) {
    for(;;) {
      char value[DIGEST_MAX_VALUE_LENGTH];
      char content[DIGEST_MAX_CONTENT_LENGTH];

      /* Pass all additional spaces here */
      while(*chlg && ISSPACE(*chlg))
        chlg++;

      /* Extract a value=content pair */
      if(!Curl_sasl_digest_get_pair(chlg, value, content, &chlg)) {
        if(Curl_raw_equal(value, "realm")) {

          /* Setup identity's domain and length */
          domain.tchar_ptr = Curl_convert_UTF8_to_tchar((char *)content);
          if(!domain.tchar_ptr)
            return CURLE_OUT_OF_MEMORY;
          dup_domain.tchar_ptr = _tcsdup(domain.tchar_ptr);
          if(!dup_domain.tchar_ptr) {
            Curl_unicodefree(domain.tchar_ptr);
            return CURLE_OUT_OF_MEMORY;
          }
          free(identity->Domain);
          identity->Domain = dup_domain.tbyte_ptr;
          identity->DomainLength = curlx_uztoul(_tcslen(dup_domain.tchar_ptr));
          dup_domain.tchar_ptr = NULL;

          Curl_unicodefree(domain.tchar_ptr);
        }
        else {
          /* unknown specifier, ignore it! */
        }
      }
      else
        break; /* we're done here */

      /* Pass all additional spaces here */
      while(*chlg && ISSPACE(*chlg))
        chlg++;

      /* Allow the list to be comma-separated */
      if(',' == *chlg)
        chlg++;
    }
  }

  return CURLE_OK;
}

/*
 * Curl_sasl_decode_digest_http_message()
 *
 * This is used to decode a HTTP DIGEST challenge message into the seperate
 * attributes.
 *
 * Parameters:
 *
 * chlg    [in]     - The challenge message.
 * digest  [in/out] - The digest data struct being used and modified.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_decode_digest_http_message(const char *chlg,
                                              struct digestdata *digest)
{
  size_t chlglen = strlen(chlg);

  /* We had an input token before and we got another one now. This means we
  provided bad credentials in the previous request. */
  if(digest->input_token)
    return CURLE_BAD_CONTENT_ENCODING;

  /* Simply store the challenge for use later */
  digest->input_token = (BYTE *) Curl_memdup(chlg, chlglen);
  if(!digest->input_token)
    return CURLE_OUT_OF_MEMORY;

  digest->input_token_len = chlglen;

  return CURLE_OK;
}

/*
 * Curl_sasl_create_digest_http_message()
 *
 * This is used to generate a HTTP DIGEST response message ready for sending
 * to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The user name in the format User or Domain\User.
 * passdwp [in]     - The user's password.
 * request [in]     - The HTTP request.
 * uripath [in]     - The path of the HTTP uri.
 * digest  [in/out] - The digest data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_sasl_create_digest_http_message(struct SessionHandle *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const unsigned char *request,
                                              const unsigned char *uripath,
                                              struct digestdata *digest,
                                              char **outptr, size_t *outlen)
{
  size_t token_max;
  CredHandle credentials;
  CtxtHandle context;
  char *resp;
  BYTE *output_token;
  PSecPkgInfo SecurityPackage;
  SEC_WINNT_AUTH_IDENTITY identity;
  SEC_WINNT_AUTH_IDENTITY *p_identity;
  SecBuffer chlg_buf[3];
  SecBuffer resp_buf;
  SecBufferDesc chlg_desc;
  SecBufferDesc resp_desc;
  SECURITY_STATUS status;
  unsigned long attrs;
  TimeStamp expiry; /* For Windows 9x compatibility of SSPI calls */
  TCHAR *spn;

  (void) data;

  /* Query the security package for DigestSSP */
  status = s_pSecFn->QuerySecurityPackageInfo((TCHAR *) TEXT(SP_NAME_DIGEST),
                                              &SecurityPackage);
  if(status != SEC_E_OK)
    return CURLE_NOT_BUILT_IN;

  token_max = SecurityPackage->cbMaxToken;

  /* Release the package buffer as it is not required anymore */
  s_pSecFn->FreeContextBuffer(SecurityPackage);

  /* Allocate the output buffer according to the max token size as indicated
     by the security package */
  output_token = malloc(token_max);
  if(!output_token)
    return CURLE_OUT_OF_MEMORY;

  if(userp && *userp) {
    /* Populate our identity structure */
    if(Curl_create_sspi_identity(userp, passwdp, &identity))
      return CURLE_OUT_OF_MEMORY;

    /* Populate our identity domain */
    if(Curl_override_sspi_http_realm((const char*)digest->input_token,
                                     &identity))
      return CURLE_OUT_OF_MEMORY;

    /* Allow proper cleanup of the identity structure */
    p_identity = &identity;
  }
  else
    /* Use the current Windows user */
    p_identity = NULL;

  /* Acquire our credentials handle */
  status = s_pSecFn->AcquireCredentialsHandle(NULL,
                                              (TCHAR *) TEXT(SP_NAME_DIGEST),
                                              SECPKG_CRED_OUTBOUND, NULL,
                                              p_identity, NULL, NULL,
                                              &credentials, &expiry);
  if(status != SEC_E_OK) {
    Curl_sspi_free_identity(p_identity);
    free(output_token);

    return CURLE_LOGIN_DENIED;
  }

  /* Setup the challenge "input" security buffer if present */
  chlg_desc.ulVersion    = SECBUFFER_VERSION;
  chlg_desc.cBuffers     = 3;
  chlg_desc.pBuffers     = chlg_buf;
  chlg_buf[0].BufferType = SECBUFFER_TOKEN;
  chlg_buf[0].pvBuffer   = digest->input_token;
  chlg_buf[0].cbBuffer   = curlx_uztoul(digest->input_token_len);
  chlg_buf[1].BufferType = SECBUFFER_PKG_PARAMS;
  chlg_buf[1].pvBuffer   = (void *)request;
  chlg_buf[1].cbBuffer   = curlx_uztoul(strlen((const char *) request));
  chlg_buf[2].BufferType = SECBUFFER_PKG_PARAMS;
  chlg_buf[2].pvBuffer   = NULL;
  chlg_buf[2].cbBuffer   = 0;

  /* Setup the response "output" security buffer */
  resp_desc.ulVersion = SECBUFFER_VERSION;
  resp_desc.cBuffers  = 1;
  resp_desc.pBuffers  = &resp_buf;
  resp_buf.BufferType = SECBUFFER_TOKEN;
  resp_buf.pvBuffer   = output_token;
  resp_buf.cbBuffer   = curlx_uztoul(token_max);

  spn = Curl_convert_UTF8_to_tchar((char *) uripath);
  if(!spn) {
    Curl_sspi_free_identity(p_identity);
    free(output_token);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Generate our reponse message */
  status = s_pSecFn->InitializeSecurityContext(&credentials, NULL,
                                               spn,
                                               ISC_REQ_USE_HTTP_STYLE, 0, 0,
                                               &chlg_desc, 0, &context,
                                               &resp_desc, &attrs, &expiry);
  Curl_unicodefree(spn);

  if(status == SEC_I_COMPLETE_NEEDED ||
     status == SEC_I_COMPLETE_AND_CONTINUE)
    s_pSecFn->CompleteAuthToken(&credentials, &resp_desc);
  else if(status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
    s_pSecFn->FreeCredentialsHandle(&credentials);

    Curl_sspi_free_identity(p_identity);
    free(output_token);

    return CURLE_OUT_OF_MEMORY;
  }

  resp = malloc(resp_buf.cbBuffer + 1);
  if(!resp) {
    s_pSecFn->DeleteSecurityContext(&context);
    s_pSecFn->FreeCredentialsHandle(&credentials);

    Curl_sspi_free_identity(p_identity);
    free(output_token);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Copy the generated reponse */
  memcpy(resp, resp_buf.pvBuffer, resp_buf.cbBuffer);
  resp[resp_buf.cbBuffer] = 0x00;

  /* Return the response */
  *outptr = resp;
  *outlen = resp_buf.cbBuffer;

  /* Free our handles */
  s_pSecFn->DeleteSecurityContext(&context);
  s_pSecFn->FreeCredentialsHandle(&credentials);

  /* Free the identity structure */
  Curl_sspi_free_identity(p_identity);

  /* Free the response buffer */
  free(output_token);

  return CURLE_OK;
}

/*
 * Curl_sasl_digest_cleanup()
 *
 * This is used to clean up the digest specific data.
 *
 * Parameters:
 *
 * digest    [in/out] - The digest data struct being cleaned up.
 *
 */
void Curl_sasl_digest_cleanup(struct digestdata *digest)
{
  /* Free the input token */
  Curl_safefree(digest->input_token);

  /* Reset any variables */
  digest->input_token_len = 0;
}
#endif /* !CURL_DISABLE_CRYPTO_AUTH */

#if defined USE_NTLM
/*
* Curl_sasl_create_ntlm_type1_message()
*
* This is used to generate an already encoded NTLM type-1 message ready for
* sending to the recipient.
*
* Parameters:
*
* userp   [in]     - The user name in the format User or Domain\User.
* passdwp [in]     - The user's password.
* ntlm    [in/out] - The ntlm data struct being used and modified.
* outptr  [in/out] - The address where a pointer to newly allocated memory
*                    holding the result will be stored upon completion.
* outlen  [out]    - The length of the output message.
*
* Returns CURLE_OK on success.
*/
CURLcode Curl_sasl_create_ntlm_type1_message(const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen)
{
  PSecPkgInfo SecurityPackage;
  SecBuffer type_1_buf;
  SecBufferDesc type_1_desc;
  SECURITY_STATUS status;
  unsigned long attrs;
  TimeStamp expiry; /* For Windows 9x compatibility of SSPI calls */

  /* Clean up any former leftovers and initialise to defaults */
  Curl_sasl_ntlm_cleanup(ntlm);

  /* Query the security package for NTLM */
  status = s_pSecFn->QuerySecurityPackageInfo((TCHAR *) TEXT(SP_NAME_NTLM),
                                              &SecurityPackage);
  if(status != SEC_E_OK)
    return CURLE_NOT_BUILT_IN;

  ntlm->token_max = SecurityPackage->cbMaxToken;

  /* Release the package buffer as it is not required anymore */
  s_pSecFn->FreeContextBuffer(SecurityPackage);

  /* Allocate our output buffer */
  ntlm->output_token = malloc(ntlm->token_max);
  if(!ntlm->output_token)
    return CURLE_OUT_OF_MEMORY;

  if(userp && *userp) {
    CURLcode result;

    /* Populate our identity structure */
    result = Curl_create_sspi_identity(userp, passwdp, &ntlm->identity);
    if(result)
      return result;

    /* Allow proper cleanup of the identity structure */
    ntlm->p_identity = &ntlm->identity;
  }
  else
    /* Use the current Windows user */
    ntlm->p_identity = NULL;

  /* Allocate our credentials handle */
  ntlm->credentials = malloc(sizeof(CredHandle));
  if(!ntlm->credentials)
    return CURLE_OUT_OF_MEMORY;

  memset(ntlm->credentials, 0, sizeof(CredHandle));

  /* Acquire our credentials handle */
  status = s_pSecFn->AcquireCredentialsHandle(NULL,
                                              (TCHAR *) TEXT(SP_NAME_NTLM),
                                              SECPKG_CRED_OUTBOUND, NULL,
                                              ntlm->p_identity, NULL, NULL,
                                              ntlm->credentials, &expiry);
  if(status != SEC_E_OK)
    return CURLE_LOGIN_DENIED;

  /* Allocate our new context handle */
  ntlm->context = malloc(sizeof(CtxtHandle));
  if(!ntlm->context)
    return CURLE_OUT_OF_MEMORY;

  memset(ntlm->context, 0, sizeof(CtxtHandle));

  /* Setup the type-1 "output" security buffer */
  type_1_desc.ulVersion = SECBUFFER_VERSION;
  type_1_desc.cBuffers  = 1;
  type_1_desc.pBuffers  = &type_1_buf;
  type_1_buf.BufferType = SECBUFFER_TOKEN;
  type_1_buf.pvBuffer   = ntlm->output_token;
  type_1_buf.cbBuffer   = curlx_uztoul(ntlm->token_max);

  /* Generate our type-1 message */
  status = s_pSecFn->InitializeSecurityContext(ntlm->credentials, NULL,
                                               (TCHAR *) TEXT(""),
                                               0, 0, SECURITY_NETWORK_DREP,
                                               NULL, 0,
                                               ntlm->context, &type_1_desc,
                                               &attrs, &expiry);
  if(status == SEC_I_COMPLETE_NEEDED ||
    status == SEC_I_COMPLETE_AND_CONTINUE)
    s_pSecFn->CompleteAuthToken(ntlm->context, &type_1_desc);
  else if(status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED)
    return CURLE_RECV_ERROR;

  /* Base64 encode the response */
  return Curl_base64_encode(NULL, (char *) ntlm->output_token,
                            type_1_buf.cbBuffer, outptr, outlen);
}

/*
* Curl_sasl_decode_ntlm_type2_message()
*
* This is used to decode an already encoded NTLM type-2 message.
*
* Parameters:
*
* data     [in]     - The session handle.
* type2msg [in]     - The base64 encoded type-2 message.
* ntlm     [in/out] - The ntlm data struct being used and modified.
*
* Returns CURLE_OK on success.
*/
CURLcode Curl_sasl_decode_ntlm_type2_message(struct SessionHandle *data,
                                             const char *type2msg,
                                             struct ntlmdata *ntlm)
{
  CURLcode result = CURLE_OK;
  unsigned char *type2 = NULL;
  size_t type2_len = 0;

#if defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void) data;
#endif

  /* Decode the base-64 encoded type-2 message */
  if(strlen(type2msg) && *type2msg != '=') {
    result = Curl_base64_decode(type2msg, &type2, &type2_len);
    if(result)
      return result;
  }

  /* Ensure we have a valid type-2 message */
  if(!type2) {
    infof(data, "NTLM handshake failure (empty type-2 message)\n");

    return CURLE_BAD_CONTENT_ENCODING;
  }

  /* Simply store the challenge for use later */
  ntlm->input_token = type2;
  ntlm->input_token_len = type2_len;

  return result;
}

/*
* Curl_sasl_create_ntlm_type3_message()
*
* This is used to generate an already encoded NTLM type-3 message ready for
* sending to the recipient.
*
* Parameters:
*
* data    [in]     - The session handle.
* userp   [in]     - The user name in the format User or Domain\User.
* passdwp [in]     - The user's password.
* ntlm    [in/out] - The ntlm data struct being used and modified.
* outptr  [in/out] - The address where a pointer to newly allocated memory
*                    holding the result will be stored upon completion.
* outlen  [out]    - The length of the output message.
*
* Returns CURLE_OK on success.
*/
CURLcode Curl_sasl_create_ntlm_type3_message(struct SessionHandle *data,
                                             const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  SecBuffer type_2_buf;
  SecBuffer type_3_buf;
  SecBufferDesc type_2_desc;
  SecBufferDesc type_3_desc;
  SECURITY_STATUS status;
  unsigned long attrs;
  TimeStamp expiry; /* For Windows 9x compatibility of SSPI calls */

  (void) passwdp;
  (void) userp;

  /* Setup the type-2 "input" security buffer */
  type_2_desc.ulVersion = SECBUFFER_VERSION;
  type_2_desc.cBuffers  = 1;
  type_2_desc.pBuffers  = &type_2_buf;
  type_2_buf.BufferType = SECBUFFER_TOKEN;
  type_2_buf.pvBuffer   = ntlm->input_token;
  type_2_buf.cbBuffer   = curlx_uztoul(ntlm->input_token_len);

  /* Setup the type-3 "output" security buffer */
  type_3_desc.ulVersion = SECBUFFER_VERSION;
  type_3_desc.cBuffers  = 1;
  type_3_desc.pBuffers  = &type_3_buf;
  type_3_buf.BufferType = SECBUFFER_TOKEN;
  type_3_buf.pvBuffer   = ntlm->output_token;
  type_3_buf.cbBuffer   = curlx_uztoul(ntlm->token_max);

  /* Generate our type-3 message */
  status = s_pSecFn->InitializeSecurityContext(ntlm->credentials,
                                               ntlm->context,
                                               (TCHAR *) TEXT(""),
                                               0, 0, SECURITY_NETWORK_DREP,
                                               &type_2_desc,
                                               0, ntlm->context,
                                               &type_3_desc,
                                               &attrs, &expiry);
  if(status != SEC_E_OK) {
    infof(data, "NTLM handshake failure (type-3 message): Status=%x\n",
          status);

    return CURLE_RECV_ERROR;
  }

  /* Base64 encode the response */
  result = Curl_base64_encode(data, (char *) ntlm->output_token,
                              type_3_buf.cbBuffer, outptr, outlen);

  Curl_sasl_ntlm_cleanup(ntlm);

  return result;
}

/*
 * Curl_sasl_ntlm_cleanup()
 *
 * This is used to clean up the ntlm specific data.
 *
 * Parameters:
 *
 * ntlm    [in/out] - The ntlm data struct being cleaned up.
 *
 */
void Curl_sasl_ntlm_cleanup(struct ntlmdata *ntlm)
{
  /* Free our security context */
  if(ntlm->context) {
    s_pSecFn->DeleteSecurityContext(ntlm->context);
    free(ntlm->context);
    ntlm->context = NULL;
  }

  /* Free our credentials handle */
  if(ntlm->credentials) {
    s_pSecFn->FreeCredentialsHandle(ntlm->credentials);
    free(ntlm->credentials);
    ntlm->credentials = NULL;
  }

  /* Free our identity */
  Curl_sspi_free_identity(ntlm->p_identity);
  ntlm->p_identity = NULL;

  /* Free the input and output tokens */
  Curl_safefree(ntlm->input_token);
  Curl_safefree(ntlm->output_token);

  /* Reset any variables */
  ntlm->token_max = 0;
}
#endif /* USE_NTLM */

#if defined(USE_KERBEROS5)
/*
 * Curl_sasl_create_gssapi_user_message()
 *
 * This is used to generate an already encoded GSSAPI (Kerberos V5) user token
 * message ready for sending to the recipient.
 *
 * Parameters:
 *
 * data        [in]     - The session handle.
 * userp       [in]     - The user name in the format User or Domain\User.
 * passdwp     [in]     - The user's password.
 * service     [in]     - The service type such as www, smtp, pop or imap.
 * mutual_auth [in]     - Flag specifing whether or not mutual authentication
 *                        is enabled.
 * chlg64      [in]     - The optional base64 encoded challenge message.
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
  TimeStamp expiry; /* For Windows 9x compatibility of SSPI calls */

  if(!krb5->credentials) {
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

  if(status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
    free(chlg);

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
  free(chlg);

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
 * chlg64  [in]     - The optional base64 encoded challenge message.
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
     terminator. Note: Dispite RFC4752 Section 3.1 stating "The authorization
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
  result = Curl_base64_encode(data, (char *)appdata, appdatalen, outptr,
                              outlen);

  /* Free all of our local buffers */
  free(appdata);
  free(padding);
  free(message);
  free(trailer);

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
#endif /* USE_KERBEROS5 */

#endif /* USE_WINDOWS_SSPI */
