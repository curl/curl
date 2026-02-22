/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Markus Moeller, <markus_moeller@compuserve.com>
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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"

#if defined(USE_WINDOWS_SSPI) && !defined(CURL_DISABLE_PROXY)

#include "urldata.h"
#include "curl_trc.h"
#include "cfilters.h"
#include "connect.h"
#include "strerror.h"
#include "curlx/nonblock.h"
#include "socks.h"
#include "curl_sspi.h"
#include "curlx/multibyte.h"

/*
 * Helper sspi error functions.
 */
static int check_sspi_err(struct Curl_easy *data,
                          SECURITY_STATUS status,
                          const char *function)
{
  if(status != SEC_E_OK &&
     status != SEC_I_COMPLETE_AND_CONTINUE &&
     status != SEC_I_COMPLETE_NEEDED &&
     status != SEC_I_CONTINUE_NEEDED) {
    char buffer[STRERROR_LEN];
    failf(data, "SSPI error: %s failed: %s", function,
          Curl_sspi_strerror(status, buffer, sizeof(buffer)));
    return 1;
  }
  return 0;
}

/* This is the SSPI-using version of this function */
static CURLcode socks5_sspi_setup(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  CredHandle *cred_handle,
                                  char **service_namep)
{
  struct connectdata *conn = cf->conn;
  const char *service = data->set.str[STRING_PROXY_SERVICE_NAME] ?
    data->set.str[STRING_PROXY_SERVICE_NAME] : "rcmd";
  SECURITY_STATUS status;

  /* prepare service name */
  if(strchr(service, '/'))
    *service_namep = curlx_strdup(service);
  else
    *service_namep = curl_maprintf("%s/%s",
                                   service, conn->socks_proxy.host.name);
  if(!*service_namep)
    return CURLE_OUT_OF_MEMORY;

  status =
    Curl_pSecFn->AcquireCredentialsHandle(NULL,
                                       (TCHAR *)CURL_UNCONST(TEXT("Kerberos")),
                                          SECPKG_CRED_OUTBOUND,
                                          NULL, NULL, NULL, NULL,
                                          cred_handle, NULL);

  if(check_sspi_err(data, status, "AcquireCredentialsHandle")) {
    failf(data, "Failed to acquire credentials.");
    return CURLE_COULDNT_CONNECT;
  }

  return CURLE_OK;
}

static CURLcode socks5_free_token(SecBuffer *send_token,
                                  CURLcode result)
{
  if(send_token->pvBuffer) {
    Curl_pSecFn->FreeContextBuffer(send_token->pvBuffer);
    send_token->pvBuffer = NULL;
  }
  return result;
}

static CURLcode socks5_sspi_loop(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 CredHandle *cred_handle,
                                 CtxtHandle *sspi_context,
                                 char *service_name,
                                 unsigned long *sspi_ret_flagsp)
{
  struct connectdata *conn = cf->conn;
  curl_socket_t sock = conn->sock[cf->sockindex];
  CURLcode result = CURLE_OK;
  CURLcode code;
  SECURITY_STATUS status;
  SecBuffer sspi_send_token, sspi_recv_token;
  SecBufferDesc input_desc, output_desc;
  PCtxtHandle context_handle = NULL;
  unsigned short us_length;
  size_t actualread;
  size_t written;
  unsigned char socksreq[4];

  input_desc.cBuffers = 1;
  input_desc.pBuffers = &sspi_recv_token;
  input_desc.ulVersion = SECBUFFER_VERSION;

  sspi_recv_token.BufferType = SECBUFFER_TOKEN;
  sspi_recv_token.cbBuffer = 0;
  sspi_recv_token.pvBuffer = NULL;

  output_desc.cBuffers = 1;
  output_desc.pBuffers = &sspi_send_token;
  output_desc.ulVersion = SECBUFFER_VERSION;

  sspi_send_token.BufferType = SECBUFFER_TOKEN;
  sspi_send_token.cbBuffer = 0;
  sspi_send_token.pvBuffer = NULL;

  (void)curlx_nonblock(sock, FALSE);

  for(;;) {
    TCHAR *sname = curlx_convert_UTF8_to_tchar(service_name);
    if(!sname) {
      curlx_free(sspi_recv_token.pvBuffer);
      return socks5_free_token(&sspi_send_token, CURLE_OUT_OF_MEMORY);
    }

    status =
      Curl_pSecFn->InitializeSecurityContext(cred_handle, context_handle,
                                             sname,
                                             ISC_REQ_MUTUAL_AUTH |
                                             ISC_REQ_ALLOCATE_MEMORY |
                                             ISC_REQ_CONFIDENTIALITY |
                                             ISC_REQ_REPLAY_DETECT,
                                             0, SECURITY_NATIVE_DREP,
                                             &input_desc, 0,
                                             sspi_context,
                                             &output_desc,
                                             sspi_ret_flagsp, NULL);

    curlx_free(sname);
    Curl_safefree(sspi_recv_token.pvBuffer);
    sspi_recv_token.cbBuffer = 0;

    if(check_sspi_err(data, status, "InitializeSecurityContext")) {
      failf(data, "Failed to initialise security context.");
      return socks5_free_token(&sspi_send_token, CURLE_COULDNT_CONNECT);
    }

    if(sspi_send_token.cbBuffer) {
      socksreq[0] = 1; /* GSS-API subnegotiation version */
      socksreq[1] = 1; /* authentication message type */
      if(sspi_send_token.cbBuffer > 0xffff) {
        /* needs to fit in an unsigned 16-bit field */
        return socks5_free_token(&sspi_send_token, CURLE_COULDNT_CONNECT);
      }
      us_length = htons((unsigned short)sspi_send_token.cbBuffer);
      memcpy(socksreq + 2, &us_length, sizeof(short));

      code = Curl_conn_cf_send(cf->next, data, socksreq, 4, FALSE, &written);
      if(code || (written != 4)) {
        failf(data, "Failed to send SSPI authentication request.");
        return socks5_free_token(&sspi_send_token, CURLE_COULDNT_CONNECT);
      }

      code = Curl_conn_cf_send(cf->next, data,
                               sspi_send_token.pvBuffer,
                               sspi_send_token.cbBuffer, FALSE, &written);
      if(code || (sspi_send_token.cbBuffer != written)) {
        failf(data, "Failed to send SSPI authentication token.");
        return socks5_free_token(&sspi_send_token, CURLE_COULDNT_CONNECT);
      }
    }

    if(sspi_send_token.pvBuffer)
      socks5_free_token(&sspi_send_token, CURLE_OK);
    sspi_send_token.cbBuffer = 0;

    Curl_safefree(sspi_recv_token.pvBuffer);
    sspi_recv_token.cbBuffer = 0;

    if(status != SEC_I_CONTINUE_NEEDED)
      break;

    result = Curl_blockread_all(cf, data, (char *)socksreq, 4, &actualread);
    if(result || (actualread != 4)) {
      failf(data, "Failed to receive SSPI authentication response.");
      return result ? result : CURLE_COULDNT_CONNECT;
    }

    if(socksreq[1] == 255) {
      failf(data, "User was rejected by the SOCKS5 server (%u %u).",
            (unsigned int)socksreq[0], (unsigned int)socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    }

    if(socksreq[1] != 1) {
      failf(data, "Invalid SSPI authentication response type (%u %u).",
            (unsigned int)socksreq[0], (unsigned int)socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    }

    memcpy(&us_length, socksreq + 2, sizeof(short));
    us_length = ntohs(us_length);

    sspi_recv_token.cbBuffer = us_length;
    sspi_recv_token.pvBuffer = curlx_malloc(us_length);

    if(!sspi_recv_token.pvBuffer)
      return CURLE_OUT_OF_MEMORY;

    result = Curl_blockread_all(cf, data, (char *)sspi_recv_token.pvBuffer,
                                sspi_recv_token.cbBuffer, &actualread);

    if(result || (actualread != us_length)) {
      failf(data, "Failed to receive SSPI authentication token.");
      curlx_free(sspi_recv_token.pvBuffer);
      return result ? result : CURLE_COULDNT_CONNECT;
    }

    context_handle = sspi_context;
  }

  return CURLE_OK;
}

static CURLcode socks5_free(SecBuffer *sspi_w_token,
                            CURLcode result)
{
  Curl_safefree(sspi_w_token[0].pvBuffer);
  Curl_safefree(sspi_w_token[1].pvBuffer);
  Curl_safefree(sspi_w_token[2].pvBuffer);
  return result;
}

static CURLcode socks5_sspi_encrypt(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    CtxtHandle *sspi_context,
                                    unsigned long sspi_ret_flags)
{
  CURLcode result = CURLE_OK;
  CURLcode code;
  SECURITY_STATUS status;
  unsigned char gss_enc;
  SecBuffer sspi_w_token[3];
  SecBufferDesc wrap_desc;
  SecPkgContext_Sizes sspi_sizes;
  unsigned short us_length;
  unsigned long qop;
  unsigned char socksreq[4];
  uint8_t *etbuf = NULL;
  size_t etbuf_size = 0;
  size_t actualread;
  size_t written;

  gss_enc = 0;
  if(sspi_ret_flags & ISC_REQ_CONFIDENTIALITY)
    gss_enc = 2;
  else if(sspi_ret_flags & ISC_REQ_INTEGRITY)
    gss_enc = 1;

  infof(data, "SOCKS5 server supports GSS-API %s data protection.",
        (gss_enc == 0) ? "no" :
        ((gss_enc == 1) ? "integrity" : "confidentiality") );

  sspi_w_token[0].pvBuffer =
    sspi_w_token[1].pvBuffer =
    sspi_w_token[2].pvBuffer = NULL;

  wrap_desc.cBuffers = 3;
  wrap_desc.pBuffers = sspi_w_token;
  wrap_desc.ulVersion = SECBUFFER_VERSION;

  socksreq[0] = 1;
  socksreq[1] = 2;

  if(data->set.socks5_gssapi_nec) {
    us_length = htons((unsigned short)1);
    memcpy(socksreq + 2, &us_length, sizeof(short));
  }
  else {
    status = Curl_pSecFn->QueryContextAttributes(sspi_context,
                                                 SECPKG_ATTR_SIZES,
                                                 &sspi_sizes);
    if(check_sspi_err(data, status, "QueryContextAttributes")) {
      failf(data, "Failed to query security context attributes.");
      return CURLE_COULDNT_CONNECT;
    }

    sspi_w_token[0].cbBuffer = sspi_sizes.cbSecurityTrailer;
    sspi_w_token[0].BufferType = SECBUFFER_TOKEN;
    sspi_w_token[0].pvBuffer = curlx_malloc(sspi_sizes.cbSecurityTrailer);

    if(!sspi_w_token[0].pvBuffer)
      return CURLE_OUT_OF_MEMORY;

    sspi_w_token[1].cbBuffer = 1;
    sspi_w_token[1].BufferType = SECBUFFER_DATA;
    sspi_w_token[1].pvBuffer = curlx_malloc(1);
    if(!sspi_w_token[1].pvBuffer)
      return socks5_free(sspi_w_token, CURLE_OUT_OF_MEMORY);

    memcpy(sspi_w_token[1].pvBuffer, &gss_enc, 1);
    sspi_w_token[2].BufferType = SECBUFFER_PADDING;
    sspi_w_token[2].cbBuffer = sspi_sizes.cbBlockSize;
    sspi_w_token[2].pvBuffer = curlx_malloc(sspi_sizes.cbBlockSize);
    if(!sspi_w_token[2].pvBuffer)
      return socks5_free(sspi_w_token, CURLE_OUT_OF_MEMORY);

    status = Curl_pSecFn->EncryptMessage(sspi_context,
                                         KERB_WRAP_NO_ENCRYPT,
                                         &wrap_desc, 0);
    if(check_sspi_err(data, status, "EncryptMessage"))
      return socks5_free(sspi_w_token, CURLE_COULDNT_CONNECT);

    etbuf_size = sspi_w_token[0].cbBuffer + sspi_w_token[1].cbBuffer +
      sspi_w_token[2].cbBuffer;
    if(etbuf_size > 0xffff)
      return socks5_free(sspi_w_token, CURLE_COULDNT_CONNECT);

    etbuf = curlx_malloc(etbuf_size);
    if(!etbuf)
      return socks5_free(sspi_w_token, CURLE_OUT_OF_MEMORY);

    memcpy(etbuf, sspi_w_token[0].pvBuffer, sspi_w_token[0].cbBuffer);
    memcpy(etbuf + sspi_w_token[0].cbBuffer,
           sspi_w_token[1].pvBuffer, sspi_w_token[1].cbBuffer);
    memcpy(etbuf + sspi_w_token[0].cbBuffer + sspi_w_token[1].cbBuffer,
           sspi_w_token[2].pvBuffer, sspi_w_token[2].cbBuffer);

    (void)socks5_free(sspi_w_token, CURLE_OK);

    us_length = htons((unsigned short)etbuf_size);
    memcpy(socksreq + 2, &us_length, sizeof(short));
  }

  code = Curl_conn_cf_send(cf->next, data, socksreq, 4, FALSE, &written);
  if(code || (written != 4)) {
    failf(data, "Failed to send SSPI encryption request.");
    curlx_free(etbuf);
    return CURLE_COULDNT_CONNECT;
  }

  if(data->set.socks5_gssapi_nec) {
    memcpy(socksreq, &gss_enc, 1);
    code = Curl_conn_cf_send(cf->next, data, socksreq, 1, FALSE, &written);
    if(code || (written != 1)) {
      failf(data, "Failed to send SSPI encryption type.");
      return CURLE_COULDNT_CONNECT;
    }
  }
  else {
    code = Curl_conn_cf_send(cf->next, data, etbuf, etbuf_size, FALSE,
                             &written);
    curlx_free(etbuf);
    if(code || (etbuf_size != written)) {
      failf(data, "Failed to send SSPI encryption type.");
      return CURLE_COULDNT_CONNECT;
    }
  }

  result = Curl_blockread_all(cf, data, (char *)socksreq, 4, &actualread);
  if(result || (actualread != 4)) {
    failf(data, "Failed to receive SSPI encryption response.");
    return result ? result : CURLE_COULDNT_CONNECT;
  }

  if(socksreq[1] == 255) {
    failf(data, "User was rejected by the SOCKS5 server (%u %u).",
          (unsigned int)socksreq[0], (unsigned int)socksreq[1]);
    return CURLE_COULDNT_CONNECT;
  }

  if(socksreq[1] != 2) {
    failf(data, "Invalid SSPI encryption response type (%u %u).",
          (unsigned int)socksreq[0], (unsigned int)socksreq[1]);
    return CURLE_COULDNT_CONNECT;
  }

  memcpy(&us_length, socksreq + 2, sizeof(short));
  us_length = ntohs(us_length);

  sspi_w_token[0].cbBuffer = us_length;
  sspi_w_token[0].pvBuffer = curlx_malloc(us_length);
  if(!sspi_w_token[0].pvBuffer)
    return CURLE_OUT_OF_MEMORY;

  result = Curl_blockread_all(cf, data, (char *)sspi_w_token[0].pvBuffer,
                              sspi_w_token[0].cbBuffer, &actualread);

  if(result || (actualread != us_length)) {
    failf(data, "Failed to receive SSPI encryption type.");
    curlx_free(sspi_w_token[0].pvBuffer);
    return result ? result : CURLE_COULDNT_CONNECT;
  }

  if(!data->set.socks5_gssapi_nec) {
    wrap_desc.cBuffers = 2;
    sspi_w_token[0].BufferType = SECBUFFER_STREAM;
    sspi_w_token[1].BufferType = SECBUFFER_DATA;
    sspi_w_token[1].cbBuffer = 0;
    sspi_w_token[1].pvBuffer = NULL;

    status = Curl_pSecFn->DecryptMessage(sspi_context, &wrap_desc,
                                         0, &qop);

    if(check_sspi_err(data, status, "DecryptMessage")) {
      if(sspi_w_token[1].pvBuffer)
        Curl_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
      curlx_free(sspi_w_token[0].pvBuffer);
      return CURLE_COULDNT_CONNECT;
    }

    if(sspi_w_token[1].cbBuffer != 1) {
      failf(data, "Invalid SSPI encryption response length (%lu).",
            (unsigned long)sspi_w_token[1].cbBuffer);
      if(sspi_w_token[1].pvBuffer)
        Curl_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
      curlx_free(sspi_w_token[0].pvBuffer);
      return CURLE_COULDNT_CONNECT;
    }

    memcpy(socksreq, sspi_w_token[1].pvBuffer, sspi_w_token[1].cbBuffer);
    Curl_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
  }
  else {
    if(sspi_w_token[0].cbBuffer != 1) {
      failf(data, "Invalid SSPI encryption response length (%lu).",
            (unsigned long)sspi_w_token[0].cbBuffer);
      curlx_free(sspi_w_token[0].pvBuffer);
      return CURLE_COULDNT_CONNECT;
    }
    memcpy(socksreq, sspi_w_token[0].pvBuffer, sspi_w_token[0].cbBuffer);
  }
  curlx_free(sspi_w_token[0].pvBuffer);

  infof(data, "SOCKS5 access with%s protection granted BUT NOT USED.",
        (socksreq[0] == 0) ? "out GSS-API data" :
        ((socksreq[0] == 1) ? " GSS-API integrity" :
         " GSS-API confidentiality"));

  return CURLE_OK;
}

CURLcode Curl_SOCKS5_gssapi_negotiate(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct connectdata *conn = cf->conn;
  curl_socket_t sock = conn->sock[cf->sockindex];
  CURLcode result;
  SECURITY_STATUS status;
  CredHandle cred_handle;
  CtxtHandle sspi_context;
  SecPkgCredentials_Names names;
  char *service_name = NULL;
  unsigned long sspi_ret_flags = 0;

  memset(&cred_handle, 0, sizeof(cred_handle));
  memset(&sspi_context, 0, sizeof(sspi_context));
  names.sUserName = NULL;

  result = socks5_sspi_setup(cf, data, &cred_handle, &service_name);
  if(result)
    goto error;

  result = socks5_sspi_loop(cf, data, &cred_handle, &sspi_context,
                            service_name, &sspi_ret_flags);
  if(result)
    goto error;

  Curl_safefree(service_name);

  status = Curl_pSecFn->QueryCredentialsAttributes(&cred_handle,
                                                   SECPKG_CRED_ATTR_NAMES,
                                                   &names);
  if(check_sspi_err(data, status, "QueryCredentialAttributes")) {
    failf(data, "Failed to determine username.");
    result = CURLE_COULDNT_CONNECT;
    goto error;
  }
  else {
    VERBOSE(char *user_utf8 = curlx_convert_tchar_to_UTF8(names.sUserName));
    infof(data, "SOCKS5 server authenticated user %s with GSS-API.",
          (user_utf8 ? user_utf8 : "(unknown)"));
    VERBOSE(curlx_free(user_utf8));
    Curl_pSecFn->FreeContextBuffer(names.sUserName);
    names.sUserName = NULL;
  }

  result = socks5_sspi_encrypt(cf, data, &sspi_context, sspi_ret_flags);
  if(result)
    goto error;

  (void)curlx_nonblock(sock, TRUE);
  Curl_pSecFn->DeleteSecurityContext(&sspi_context);
  Curl_pSecFn->FreeCredentialsHandle(&cred_handle);
  return CURLE_OK;

error:
  (void)curlx_nonblock(sock, TRUE);
  curlx_free(service_name);
  Curl_pSecFn->DeleteSecurityContext(&sspi_context);
  Curl_pSecFn->FreeCredentialsHandle(&cred_handle);
  if(names.sUserName)
    Curl_pSecFn->FreeContextBuffer(names.sUserName);
  return result;
}
#endif
