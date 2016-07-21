/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014 - 2016, Steve Holme, <steve_holme@hotmail.com>.
 * Copyright (C) 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * RFC2831 DIGEST-MD5 authentication
 *
 ***************************************************************************/

#include "curl_setup.h"

#if defined(USE_WINDOWS_SSPI) && !defined(CURL_DISABLE_CRYPTO_AUTH)

#include <curl/curl.h>

#include "vauth/vauth.h"
#include "vauth/digest.h"
#include "urldata.h"
#include "curl_base64.h"
#include "warnless.h"
#include "curl_multibyte.h"
#include "sendf.h"
#include "strdup.h"
#include "rawstr.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Curl_auth_create_digest_md5_message()
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
 * service [in]     - The service type such as http, smtp, pop or imap.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_digest_md5_message(struct Curl_easy *data,
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
  spn = Curl_auth_build_spn(service, data->easy_conn->host.name, NULL);
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
      if(Curl_auth_digest_get_pair(chlg, value, content, &chlg)) {
        if(Curl_raw_equal(value, "realm")) {

          /* Setup identity's domain and length */
          domain.tchar_ptr = Curl_convert_UTF8_to_tchar((char *) content);
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
          /* Unknown specifier, ignore it! */
        }
      }
      else
        break; /* We're done here */

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
 * Curl_auth_decode_digest_http_message()
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
CURLcode Curl_auth_decode_digest_http_message(const char *chlg,
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
 * Curl_auth_create_digest_http_message()
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
CURLcode Curl_auth_create_digest_http_message(struct Curl_easy *data,
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

  if(userp && *userp) {
    /* Populate our identity structure */
    if(Curl_create_sspi_identity(userp, passwdp, &identity))
      return CURLE_OUT_OF_MEMORY;

    /* Populate our identity domain */
    if(Curl_override_sspi_http_realm((const char*) digest->input_token,
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

    return CURLE_LOGIN_DENIED;
  }

  /* Allocate the output buffer according to the max token size as indicated
     by the security package */
  output_token = malloc(token_max);
  if(!output_token) {
    s_pSecFn->FreeCredentialsHandle(&credentials);

    Curl_sspi_free_identity(p_identity);

    return CURLE_OUT_OF_MEMORY;
  }

  /* Setup the challenge "input" security buffer if present */
  chlg_desc.ulVersion    = SECBUFFER_VERSION;
  chlg_desc.cBuffers     = 3;
  chlg_desc.pBuffers     = chlg_buf;
  chlg_buf[0].BufferType = SECBUFFER_TOKEN;
  chlg_buf[0].pvBuffer   = digest->input_token;
  chlg_buf[0].cbBuffer   = curlx_uztoul(digest->input_token_len);
  chlg_buf[1].BufferType = SECBUFFER_PKG_PARAMS;
  chlg_buf[1].pvBuffer   = (void *) request;
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
    s_pSecFn->FreeCredentialsHandle(&credentials);

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
 * Curl_auth_digest_cleanup()
 *
 * This is used to clean up the digest specific data.
 *
 * Parameters:
 *
 * digest    [in/out] - The digest data struct being cleaned up.
 *
 */
void Curl_auth_digest_cleanup(struct digestdata *digest)
{
  /* Free the input token */
  Curl_safefree(digest->input_token);

  /* Reset any variables */
  digest->input_token_len = 0;
}

#endif /* USE_WINDOWS_SSPI && !CURL_DISABLE_CRYPTO_AUTH */
