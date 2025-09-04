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
#include "sendf.h"
#include "cfilters.h"
#include "connect.h"
#include "strerror.h"
#include "curlx/timeval.h"
#include "socks.h"
#include "curl_sspi.h"
#include "curlx/multibyte.h"
#include "curlx/warnless.h"
#include "strdup.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

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
CURLcode Curl_SOCKS5_gssapi_negotiate(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct connectdata *conn = cf->conn;
  curl_socket_t sock = conn->sock[cf->sockindex];
  CURLcode code;
  size_t actualread;
  size_t written;
  CURLcode result;
  int err;
  /* Needs GSS-API authentication */
  SECURITY_STATUS status;
  unsigned long sspi_ret_flags = 0;
  unsigned char gss_enc;
  SecBuffer sspi_send_token, sspi_recv_token, sspi_w_token[3];
  SecBufferDesc input_desc, output_desc, wrap_desc;
  SecPkgContext_Sizes sspi_sizes;
  CredHandle cred_handle;
  CtxtHandle sspi_context;
  PCtxtHandle context_handle = NULL;
  SecPkgCredentials_Names names;
  char *service_name = NULL;
  unsigned short us_length;
  unsigned long qop;
  unsigned char socksreq[4]; /* room for GSS-API exchange header only */
  const char *service = data->set.str[STRING_PROXY_SERVICE_NAME] ?
    data->set.str[STRING_PROXY_SERVICE_NAME]  : "rcmd";
  char *etbuf;
  size_t etbuf_size;

  /*   GSS-API request looks like
   * +----+------+-----+----------------+
   * |VER | MTYP | LEN |     TOKEN      |
   * +----+------+----------------------+
   * | 1  |  1   |  2  | up to 2^16 - 1 |
   * +----+------+-----+----------------+
   */

  /* prepare service name */
  if(strchr(service, '/'))
    service_name = strdup(service);
  else
    service_name = aprintf("%s/%s", service, conn->socks_proxy.host.name);
  if(!service_name)
    return CURLE_OUT_OF_MEMORY;

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

  sspi_w_token[0].pvBuffer =
    sspi_w_token[1].pvBuffer =
    sspi_w_token[2].pvBuffer = NULL;

  wrap_desc.cBuffers = 3;
  wrap_desc.pBuffers = sspi_w_token;
  wrap_desc.ulVersion = SECBUFFER_VERSION;

  memset(&cred_handle, 0, sizeof(cred_handle));
  memset(&sspi_context, 0, sizeof(sspi_context));

  names.sUserName = NULL;

  etbuf = NULL;
  etbuf_size = 0;

  status =
    Curl_pSecFn->AcquireCredentialsHandle(NULL,
                                       (TCHAR *)CURL_UNCONST(TEXT("Kerberos")),
                                          SECPKG_CRED_OUTBOUND,
                                          NULL, NULL, NULL, NULL,
                                          &cred_handle, NULL);

  if(check_sspi_err(data, status, "AcquireCredentialsHandle")) {
    failf(data, "Failed to acquire credentials.");
    result = CURLE_COULDNT_CONNECT;
    goto error;
  }

  (void)curlx_nonblock(sock, FALSE);

  /* As long as we need to keep sending some context info, and there is no  */
  /* errors, keep sending it...                                            */
  for(;;) {
    TCHAR *sname;

    sname = curlx_convert_UTF8_to_tchar(service_name);
    if(!sname) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }

    status =
      Curl_pSecFn->InitializeSecurityContext(&cred_handle, context_handle,
                                             sname,
                                             ISC_REQ_MUTUAL_AUTH |
                                             ISC_REQ_ALLOCATE_MEMORY |
                                             ISC_REQ_CONFIDENTIALITY |
                                             ISC_REQ_REPLAY_DETECT,
                                             0, SECURITY_NATIVE_DREP,
                                             &input_desc, 0,
                                             &sspi_context,
                                             &output_desc,
                                             &sspi_ret_flags, NULL);

    curlx_unicodefree(sname);

    Curl_safefree(sspi_recv_token.pvBuffer);
    sspi_recv_token.cbBuffer = 0;

    if(check_sspi_err(data, status, "InitializeSecurityContext")) {
      failf(data, "Failed to initialise security context.");
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }

    if(sspi_send_token.cbBuffer) {
      socksreq[0] = 1;    /* GSS-API subnegotiation version */
      socksreq[1] = 1;    /* authentication message type */
      us_length = htons((unsigned short)sspi_send_token.cbBuffer);
      memcpy(socksreq + 2, &us_length, sizeof(short));

      code = Curl_conn_cf_send(cf->next, data, (char *)socksreq, 4, FALSE,
                               &written);
      if(code || (written != 4)) {
        failf(data, "Failed to send SSPI authentication request.");
        result = CURLE_COULDNT_CONNECT;
        goto error;
      }

      code = Curl_conn_cf_send(cf->next, data,
                               (char *)sspi_send_token.pvBuffer,
                               sspi_send_token.cbBuffer, FALSE, &written);
      if(code || (sspi_send_token.cbBuffer != written)) {
        failf(data, "Failed to send SSPI authentication token.");
        result = CURLE_COULDNT_CONNECT;
        goto error;
      }
    }

    if(sspi_send_token.pvBuffer) {
      Curl_pSecFn->FreeContextBuffer(sspi_send_token.pvBuffer);
      sspi_send_token.pvBuffer = NULL;
    }
    sspi_send_token.cbBuffer = 0;

    Curl_safefree(sspi_recv_token.pvBuffer);
    sspi_recv_token.cbBuffer = 0;

    if(status != SEC_I_CONTINUE_NEEDED)
      break;

    /* analyse response */

    /*   GSS-API response looks like
     * +----+------+-----+----------------+
     * |VER | MTYP | LEN |     TOKEN      |
     * +----+------+----------------------+
     * | 1  |  1   |  2  | up to 2^16 - 1 |
     * +----+------+-----+----------------+
     */

    err = Curl_blockread_all(cf, data, (char *)socksreq, 4, &actualread);
    if(err || (actualread != 4)) {
      failf(data, "Failed to receive SSPI authentication response.");
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }

    /* ignore the first (VER) byte */
    if(socksreq[1] == 255) { /* status / message type */
      failf(data, "User was rejected by the SOCKS5 server (%u %u).",
            (unsigned int)socksreq[0], (unsigned int)socksreq[1]);
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }

    if(socksreq[1] != 1) { /* status / message type */
      failf(data, "Invalid SSPI authentication response type (%u %u).",
            (unsigned int)socksreq[0], (unsigned int)socksreq[1]);
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }

    memcpy(&us_length, socksreq + 2, sizeof(short));
    us_length = ntohs(us_length);

    sspi_recv_token.cbBuffer = us_length;
    sspi_recv_token.pvBuffer = malloc(us_length);

    if(!sspi_recv_token.pvBuffer) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
    err = Curl_blockread_all(cf, data, (char *)sspi_recv_token.pvBuffer,
                             sspi_recv_token.cbBuffer, &actualread);

    if(err || (actualread != us_length)) {
      failf(data, "Failed to receive SSPI authentication token.");
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }

    context_handle = &sspi_context;
  }

  Curl_safefree(service_name);

  /* Everything is good so far, user was authenticated! */
  status = Curl_pSecFn->QueryCredentialsAttributes(&cred_handle,
                                                   SECPKG_CRED_ATTR_NAMES,
                                                   &names);
  if(check_sspi_err(data, status, "QueryCredentialAttributes")) {
    failf(data, "Failed to determine username.");
    result = CURLE_COULDNT_CONNECT;
    goto error;
  }
  else {
#ifndef CURL_DISABLE_VERBOSE_STRINGS
    char *user_utf8 = curlx_convert_tchar_to_UTF8(names.sUserName);
    infof(data, "SOCKS5 server authenticated user %s with GSS-API.",
          (user_utf8 ? user_utf8 : "(unknown)"));
    curlx_unicodefree(user_utf8);
#endif
    Curl_pSecFn->FreeContextBuffer(names.sUserName);
    names.sUserName = NULL;
  }

  /* Do encryption */
  socksreq[0] = 1;    /* GSS-API subnegotiation version */
  socksreq[1] = 2;    /* encryption message type */

  gss_enc = 0; /* no data protection */
  /* do confidentiality protection if supported */
  if(sspi_ret_flags & ISC_REQ_CONFIDENTIALITY)
    gss_enc = 2;
  /* else do integrity protection */
  else if(sspi_ret_flags & ISC_REQ_INTEGRITY)
    gss_enc = 1;

  infof(data, "SOCKS5 server supports GSS-API %s data protection.",
        (gss_enc == 0) ? "no" :
        ((gss_enc == 1) ? "integrity":"confidentiality") );
  /* force to no data protection, avoid encryption/decryption for now */
  gss_enc = 0;
  /*
   * Sending the encryption type in clear seems wrong. It should be
   * protected with gss_seal()/gss_wrap(). See RFC1961 extract below
   * The NEC reference implementations on which this is based is
   * therefore at fault
   *
   *  +------+------+------+.......................+
   *  + ver  | mtyp | len  |   token               |
   *  +------+------+------+.......................+
   *  + 0x01 | 0x02 | 0x02 | up to 2^16 - 1 octets |
   *  +------+------+------+.......................+
   *
   *   Where:
   *
   *  - "ver" is the protocol version number, here 1 to represent the
   *    first version of the SOCKS/GSS-API protocol
   *
   *  - "mtyp" is the message type, here 2 to represent a protection
   *    -level negotiation message
   *
   *  - "len" is the length of the "token" field in octets
   *
   *  - "token" is the GSS-API encapsulated protection level
   *
   * The token is produced by encapsulating an octet containing the
   * required protection level using gss_seal()/gss_wrap() with conf_req
   * set to FALSE. The token is verified using gss_unseal()/
   * gss_unwrap().
   *
   */

  if(data->set.socks5_gssapi_nec) {
    us_length = htons((unsigned short)1);
    memcpy(socksreq + 2, &us_length, sizeof(short));
  }
  else {
    status = Curl_pSecFn->QueryContextAttributes(&sspi_context,
                                                 SECPKG_ATTR_SIZES,
                                                 &sspi_sizes);
    if(check_sspi_err(data, status, "QueryContextAttributes")) {
      failf(data, "Failed to query security context attributes.");
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }

    sspi_w_token[0].cbBuffer = sspi_sizes.cbSecurityTrailer;
    sspi_w_token[0].BufferType = SECBUFFER_TOKEN;
    sspi_w_token[0].pvBuffer = malloc(sspi_sizes.cbSecurityTrailer);

    if(!sspi_w_token[0].pvBuffer) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }

    sspi_w_token[1].cbBuffer = 1;
    sspi_w_token[1].pvBuffer = malloc(1);
    if(!sspi_w_token[1].pvBuffer) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }

    memcpy(sspi_w_token[1].pvBuffer, &gss_enc, 1);
    sspi_w_token[2].BufferType = SECBUFFER_PADDING;
    sspi_w_token[2].cbBuffer = sspi_sizes.cbBlockSize;
    sspi_w_token[2].pvBuffer = malloc(sspi_sizes.cbBlockSize);
    if(!sspi_w_token[2].pvBuffer) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
    status = Curl_pSecFn->EncryptMessage(&sspi_context,
                                         KERB_WRAP_NO_ENCRYPT,
                                         &wrap_desc, 0);
    if(check_sspi_err(data, status, "EncryptMessage")) {
      failf(data, "Failed to query security context attributes.");
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }

    etbuf_size = sspi_w_token[0].cbBuffer +
                 sspi_w_token[1].cbBuffer +
                 sspi_w_token[2].cbBuffer;
    etbuf = malloc(etbuf_size);
    if(!etbuf) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }

    memcpy(etbuf, sspi_w_token[0].pvBuffer, sspi_w_token[0].cbBuffer);
    memcpy(etbuf + sspi_w_token[0].cbBuffer,
           sspi_w_token[1].pvBuffer, sspi_w_token[1].cbBuffer);
    memcpy(etbuf + sspi_w_token[0].cbBuffer + sspi_w_token[1].cbBuffer,
           sspi_w_token[2].pvBuffer, sspi_w_token[2].cbBuffer);

    Curl_safefree(sspi_w_token[0].pvBuffer);
    sspi_w_token[0].cbBuffer = 0;
    Curl_safefree(sspi_w_token[1].pvBuffer);
    sspi_w_token[1].cbBuffer = 0;
    Curl_safefree(sspi_w_token[2].pvBuffer);
    sspi_w_token[2].cbBuffer = 0;

    us_length = htons((unsigned short)etbuf_size);
    memcpy(socksreq + 2, &us_length, sizeof(short));
  }

  code = Curl_conn_cf_send(cf->next, data, (char *)socksreq, 4, FALSE,
                           &written);
  if(code || (written != 4)) {
    failf(data, "Failed to send SSPI encryption request.");
    result = CURLE_COULDNT_CONNECT;
    goto error;
  }

  if(data->set.socks5_gssapi_nec) {
    memcpy(socksreq, &gss_enc, 1);
    code = Curl_conn_cf_send(cf->next, data, (char *)socksreq, 1, FALSE,
                             &written);
    if(code || (written != 1)) {
      failf(data, "Failed to send SSPI encryption type.");
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }
  }
  else {
    code = Curl_conn_cf_send(cf->next, data, etbuf, etbuf_size,
                             FALSE, &written);
    if(code || (etbuf_size != written)) {
      failf(data, "Failed to send SSPI encryption type.");
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }
    Curl_safefree(etbuf);
  }

  err = Curl_blockread_all(cf, data, (char *)socksreq, 4, &actualread);
  if(err || (actualread != 4)) {
    failf(data, "Failed to receive SSPI encryption response.");
    result = CURLE_COULDNT_CONNECT;
    goto error;
  }

  /* ignore the first (VER) byte */
  if(socksreq[1] == 255) { /* status / message type */
    failf(data, "User was rejected by the SOCKS5 server (%u %u).",
          (unsigned int)socksreq[0], (unsigned int)socksreq[1]);
    result = CURLE_COULDNT_CONNECT;
    goto error;
  }

  if(socksreq[1] != 2) { /* status / message type */
    failf(data, "Invalid SSPI encryption response type (%u %u).",
          (unsigned int)socksreq[0], (unsigned int)socksreq[1]);
    result = CURLE_COULDNT_CONNECT;
    goto error;
  }

  memcpy(&us_length, socksreq + 2, sizeof(short));
  us_length = ntohs(us_length);

  sspi_w_token[0].cbBuffer = us_length;
  sspi_w_token[0].pvBuffer = malloc(us_length);
  if(!sspi_w_token[0].pvBuffer) {
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  err = Curl_blockread_all(cf, data, (char *)sspi_w_token[0].pvBuffer,
                           sspi_w_token[0].cbBuffer, &actualread);

  if(err || (actualread != us_length)) {
    failf(data, "Failed to receive SSPI encryption type.");
    result = CURLE_COULDNT_CONNECT;
    goto error;
  }


  if(!data->set.socks5_gssapi_nec) {
    wrap_desc.cBuffers = 2;
    sspi_w_token[0].BufferType = SECBUFFER_STREAM;
    sspi_w_token[1].BufferType = SECBUFFER_DATA;
    sspi_w_token[1].cbBuffer = 0;
    sspi_w_token[1].pvBuffer = NULL;

    status = Curl_pSecFn->DecryptMessage(&sspi_context, &wrap_desc,
                                         0, &qop);

    /* since sspi_w_token[1].pvBuffer is allocated by the SSPI in this case, it
       must be freed in this block using FreeContextBuffer() instead of
       potentially in error cleanup using free(). */

    if(check_sspi_err(data, status, "DecryptMessage")) {
      failf(data, "Failed to query security context attributes.");
      if(sspi_w_token[1].pvBuffer) {
        Curl_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
        sspi_w_token[1].pvBuffer = NULL;
      }
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }

    if(sspi_w_token[1].cbBuffer != 1) {
      failf(data, "Invalid SSPI encryption response length (%lu).",
            (unsigned long)sspi_w_token[1].cbBuffer);
      if(sspi_w_token[1].pvBuffer) {
        Curl_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
        sspi_w_token[1].pvBuffer = NULL;
      }
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }

    memcpy(socksreq, sspi_w_token[1].pvBuffer, sspi_w_token[1].cbBuffer);
    Curl_safefree(sspi_w_token[0].pvBuffer);
    sspi_w_token[0].cbBuffer = 0;
    Curl_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
    sspi_w_token[1].pvBuffer = NULL;
    sspi_w_token[1].cbBuffer = 0;
  }
  else {
    if(sspi_w_token[0].cbBuffer != 1) {
      failf(data, "Invalid SSPI encryption response length (%lu).",
            (unsigned long)sspi_w_token[0].cbBuffer);
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }
    memcpy(socksreq, sspi_w_token[0].pvBuffer, sspi_w_token[0].cbBuffer);
    Curl_safefree(sspi_w_token[0].pvBuffer);
    sspi_w_token[0].cbBuffer = 0;
  }
  (void)curlx_nonblock(sock, TRUE);

  infof(data, "SOCKS5 access with%s protection granted.",
        (socksreq[0] == 0) ? "out GSS-API data":
        ((socksreq[0] == 1) ? " GSS-API integrity" :
         " GSS-API confidentiality"));

  /* For later use if encryption is required
     conn->socks5_gssapi_enctype = socksreq[0];
     if(socksreq[0] != 0)
       conn->socks5_sspi_context = sspi_context;
     else {
       Curl_pSecFn->DeleteSecurityContext(&sspi_context);
       conn->socks5_sspi_context = sspi_context;
     }
  */

  Curl_pSecFn->DeleteSecurityContext(&sspi_context);
  Curl_pSecFn->FreeCredentialsHandle(&cred_handle);
  return CURLE_OK;
error:
  (void)curlx_nonblock(sock, TRUE);
  free(service_name);
  Curl_pSecFn->DeleteSecurityContext(&sspi_context);
  Curl_pSecFn->FreeCredentialsHandle(&cred_handle);
  free(sspi_recv_token.pvBuffer);
  if(sspi_send_token.pvBuffer)
    Curl_pSecFn->FreeContextBuffer(sspi_send_token.pvBuffer);
  if(names.sUserName)
    Curl_pSecFn->FreeContextBuffer(names.sUserName);
  free(sspi_w_token[0].pvBuffer);
  free(sspi_w_token[1].pvBuffer);
  free(sspi_w_token[2].pvBuffer);
  free(etbuf);
  return result;
}
#endif
