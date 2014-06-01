/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
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
 *
 ***************************************************************************/

#include "curl_setup.h"

#if defined(USE_WINDOWS_SSPI) && !defined(CURL_DISABLE_CRYPTO_AUTH)

#include <curl/curl.h>

#include "curl_sasl.h"
#include "urldata.h"
#include "curl_base64.h"
#include "warnless.h"
#include "curl_memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

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
  char *spn = NULL;
  size_t chlglen = 0;
  unsigned char *chlg = NULL;
  unsigned char resp[1024];
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

  /* Calculate our SPN */
  spn = aprintf("%s/%s", service, data->easy_conn->host.name);
  if(!spn)
    return CURLE_OUT_OF_MEMORY;

  /* Populate our identity structure */
  result = Curl_create_sspi_identity(userp, passwdp, &identity);
  if(result) {
    Curl_safefree(spn);
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
  resp_buf.cbBuffer   = sizeof(resp);

  /* Generate our challenge-response message */
  status = s_pSecFn->InitializeSecurityContext(&handle,
                                               NULL,
                                               (TCHAR *) spn,
                                               0, 0, 0,
                                               &chlg_desc,
                                               0, &ctx,
                                               &resp_desc,
                                               &attrs, &tsDummy);

  if(status == SEC_I_COMPLETE_AND_CONTINUE ||
     status == SEC_I_CONTINUE_NEEDED)
    s_pSecFn->CompleteAuthToken(&handle, &resp_desc);
  else if(status != SEC_E_OK) {
    s_pSecFn->FreeCredentialsHandle(&handle);
    Curl_sspi_free_identity(&identity);
    Curl_safefree(spn);
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

  /* Free the decoeded challenge message */
  Curl_safefree(chlg);

  return result;
}

#endif /* USE_WINDOWS_SSPI && !CURL_DISABLE_CRYPTO_AUTH */
