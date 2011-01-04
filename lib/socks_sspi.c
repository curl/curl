/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2009, 2011, Markus Moeller, <markus_moeller@compuserve.com>
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
 ***************************************************************************/


#include "setup.h"

#ifdef USE_WINDOWS_SSPI

#include <string.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "connect.h"
#include "timeval.h"
#include "socks.h"
#include "curl_sspi.h"

#define _MPRINTF_REPLACE /* use the internal *printf() functions */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/*
 * Definitions required from ntsecapi.h are directly provided below this point
 * to avoid including ntsecapi.h due to a conflict with OpenSSL's safestack.h
 */
#define KERB_WRAP_NO_ENCRYPT 0x80000001

/*
 * Helper sspi error functions.
 */
static int check_sspi_err(struct SessionHandle *data,
                          SECURITY_STATUS major_status,
                          SECURITY_STATUS minor_status,
                          const char* function)
{
  const char *txt;
  (void)minor_status;

  if(major_status != SEC_E_OK &&
     major_status != SEC_I_COMPLETE_AND_CONTINUE &&
     major_status != SEC_I_COMPLETE_NEEDED &&
     major_status != SEC_I_CONTINUE_NEEDED) {
    failf(data, "SSPI error: %s failed: %d\n", function, major_status);
    switch (major_status) {
    case SEC_I_COMPLETE_AND_CONTINUE:
      txt="SEC_I_COMPLETE_AND_CONTINUE";
      break;
    case SEC_I_COMPLETE_NEEDED:
      txt="SEC_I_COMPLETE_NEEDED";
      break;
    case SEC_I_CONTINUE_NEEDED:
      txt="SEC_I_CONTINUE_NEEDED";
      break;
    case SEC_I_CONTEXT_EXPIRED:
      txt="SEC_I_CONTEXT_EXPIRED";
      break;
    case SEC_I_INCOMPLETE_CREDENTIALS:
      txt="SEC_I_INCOMPLETE_CREDENTIALS";
      break;
    case SEC_I_RENEGOTIATE:
      txt="SEC_I_RENEGOTIATE";
      break;
    case SEC_E_BUFFER_TOO_SMALL:
      txt="SEC_E_BUFFER_TOO_SMALL";
      break;
    case SEC_E_CONTEXT_EXPIRED:
      txt="SEC_E_CONTEXT_EXPIRED";
      break;
    case SEC_E_CRYPTO_SYSTEM_INVALID:
      txt="SEC_E_CRYPTO_SYSTEM_INVALID";
      break;
    case SEC_E_INCOMPLETE_MESSAGE:
      txt="SEC_E_INCOMPLETE_MESSAGE";
      break;
    case SEC_E_INSUFFICIENT_MEMORY:
      txt="SEC_E_INSUFFICIENT_MEMORY";
      break;
    case SEC_E_INTERNAL_ERROR:
      txt="SEC_E_INTERNAL_ERROR";
      break;
    case SEC_E_INVALID_HANDLE:
      txt="SEC_E_INVALID_HANDLE";
      break;
    case SEC_E_INVALID_TOKEN:
      txt="SEC_E_INVALID_TOKEN";
      break;
    case SEC_E_LOGON_DENIED:
      txt="SEC_E_LOGON_DENIED";
      break;
    case SEC_E_MESSAGE_ALTERED:
      txt="SEC_E_MESSAGE_ALTERED";
      break;
    case SEC_E_NO_AUTHENTICATING_AUTHORITY:
      txt="SEC_E_NO_AUTHENTICATING_AUTHORITY";
      break;
    case SEC_E_NO_CREDENTIALS:
      txt="SEC_E_NO_CREDENTIALS";
      break;
    case SEC_E_NOT_OWNER:
      txt="SEC_E_NOT_OWNER";
      break;
    case SEC_E_OUT_OF_SEQUENCE:
      txt="SEC_E_OUT_OF_SEQUENCE";
      break;
    case SEC_E_QOP_NOT_SUPPORTED:
      txt="SEC_E_QOP_NOT_SUPPORTED";
      break;
    case SEC_E_SECPKG_NOT_FOUND:
      txt="SEC_E_SECPKG_NOT_FOUND";
      break;
    case SEC_E_TARGET_UNKNOWN:
      txt="SEC_E_TARGET_UNKNOWN";
      break;
    case SEC_E_UNKNOWN_CREDENTIALS:
      txt="SEC_E_UNKNOWN_CREDENTIALS";
      break;
    case SEC_E_UNSUPPORTED_FUNCTION:
      txt="SEC_E_UNSUPPORTED_FUNCTION";
      break;
    case SEC_E_WRONG_PRINCIPAL:
      txt="SEC_E_WRONG_PRINCIPAL";
      break;
    default:
      txt="Unknown error";

    }
    failf(data, "SSPI error: %s failed: %s\n", function, txt);
    return 1;
  }
  return 0;
}

/* This is the SSPI-using version of this function */
CURLcode Curl_SOCKS5_gssapi_negotiate(int sockindex,
                                      struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  curl_socket_t sock = conn->sock[sockindex];
  CURLcode code;
  ssize_t actualread;
  ssize_t written;
  int result;
  long timeout;
  /* Needs GSSAPI authentication */
  SECURITY_STATUS sspi_major_status, sspi_minor_status=0;
  unsigned long sspi_ret_flags=0;
  int gss_enc;
  SecBuffer sspi_send_token, sspi_recv_token, sspi_w_token[3];
  SecBufferDesc input_desc, output_desc, wrap_desc;
  SecPkgContext_Sizes sspi_sizes;
  CredHandle cred_handle;
  CtxtHandle sspi_context;
  PCtxtHandle context_handle = NULL;
  SecPkgCredentials_Names names;
  TimeStamp expiry;
  char *service_name=NULL;
  u_short us_length;
  ULONG qop;
  unsigned char socksreq[4]; /* room for gssapi exchange header only */
  char *service = data->set.str[STRING_SOCKS5_GSSAPI_SERVICE];

  /* get timeout */
  timeout = Curl_timeleft(data, NULL, TRUE);

  /*   GSSAPI request looks like
   * +----+------+-----+----------------+
   * |VER | MTYP | LEN |     TOKEN      |
   * +----+------+----------------------+
   * | 1  |  1   |  2  | up to 2^16 - 1 |
   * +----+------+-----+----------------+
   */

  /* prepare service name */
  if (strchr(service, '/')) {
    service_name = malloc(strlen(service));
    if(!service_name)
      return CURLE_OUT_OF_MEMORY;
    memcpy(service_name, service, strlen(service));
  }
  else {
    service_name = malloc(strlen(service) + strlen(conn->proxy.name) + 2);
    if(!service_name)
      return CURLE_OUT_OF_MEMORY;
    snprintf(service_name,strlen(service) +strlen(conn->proxy.name)+2,"%s/%s",
             service,conn->proxy.name);
  }

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

  wrap_desc.cBuffers = 3;
  wrap_desc.pBuffers = sspi_w_token;
  wrap_desc.ulVersion = SECBUFFER_VERSION;

  cred_handle.dwLower = 0;
  cred_handle.dwUpper = 0;

  sspi_major_status = s_pSecFn->AcquireCredentialsHandleA( NULL,
                                                           (char *)"Kerberos",
                                                           SECPKG_CRED_OUTBOUND,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           &cred_handle,
                                                           &expiry);

  if(check_sspi_err(data, sspi_major_status,sspi_minor_status,
                    "AcquireCredentialsHandleA") ) {
    failf(data, "Failed to acquire credentials.");
    free(service_name);
    service_name=NULL;
    s_pSecFn->FreeCredentialsHandle(&cred_handle);
    return CURLE_COULDNT_CONNECT;
  }

  /* As long as we need to keep sending some context info, and there's no  */
  /* errors, keep sending it...                                            */
  for(;;) {

    sspi_major_status = s_pSecFn->InitializeSecurityContextA(
                                    &cred_handle,
                                    context_handle,
                                    service_name,
                                    ISC_REQ_MUTUAL_AUTH |
                                    ISC_REQ_ALLOCATE_MEMORY |
                                    ISC_REQ_CONFIDENTIALITY |
                                    ISC_REQ_REPLAY_DETECT,
                                    0,
                                    SECURITY_NATIVE_DREP,
                                    &input_desc,
                                    0,
                                    &sspi_context,
                                    &output_desc,
                                    &sspi_ret_flags,
                                    &expiry);

    if(sspi_recv_token.pvBuffer) {
      s_pSecFn->FreeContextBuffer(sspi_recv_token.pvBuffer);
      sspi_recv_token.pvBuffer = NULL;
      sspi_recv_token.cbBuffer = 0;
    }

    if(check_sspi_err(data,sspi_major_status,sspi_minor_status,
                      "InitializeSecurityContextA") ){
      free(service_name);
      service_name=NULL;
      s_pSecFn->FreeCredentialsHandle(&cred_handle);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      s_pSecFn->FreeContextBuffer(sspi_recv_token.pvBuffer);
      failf(data, "Failed to initialise security context.");
      return CURLE_COULDNT_CONNECT;
    }

    if(sspi_send_token.cbBuffer != 0) {
      socksreq[0] = 1;    /* gssapi subnegotiation version */
      socksreq[1] = 1;    /* authentication message type */
      us_length = htons((short)sspi_send_token.cbBuffer);
      memcpy(socksreq+2, &us_length, sizeof(short));

      code = Curl_write_plain(conn, sock, (char *)socksreq, 4, &written);
      if((code != CURLE_OK) || (4 != written)) {
        failf(data, "Failed to send SSPI authentication request.");
        free(service_name);
        service_name=NULL;
        s_pSecFn->FreeContextBuffer(sspi_send_token.pvBuffer);
        s_pSecFn->FreeContextBuffer(sspi_recv_token.pvBuffer);
        s_pSecFn->FreeCredentialsHandle(&cred_handle);
        s_pSecFn->DeleteSecurityContext(&sspi_context);
        return CURLE_COULDNT_CONNECT;
      }

      code = Curl_write_plain(conn, sock, (char *)sspi_send_token.pvBuffer,
                              sspi_send_token.cbBuffer, &written);
      if((code != CURLE_OK) || (sspi_send_token.cbBuffer != (size_t)written)) {
        failf(data, "Failed to send SSPI authentication token.");
        free(service_name);
        service_name=NULL;
        s_pSecFn->FreeContextBuffer(sspi_send_token.pvBuffer);
        s_pSecFn->FreeContextBuffer(sspi_recv_token.pvBuffer);
        s_pSecFn->FreeCredentialsHandle(&cred_handle);
        s_pSecFn->DeleteSecurityContext(&sspi_context);
        return CURLE_COULDNT_CONNECT;
      }

    }

    s_pSecFn->FreeContextBuffer(sspi_send_token.pvBuffer);
    sspi_send_token.pvBuffer = NULL;
    sspi_send_token.cbBuffer = 0;
    s_pSecFn->FreeContextBuffer(sspi_recv_token.pvBuffer);
    sspi_recv_token.pvBuffer = NULL;
    sspi_recv_token.cbBuffer = 0;
    if(sspi_major_status != SEC_I_CONTINUE_NEEDED)  break;

    /* analyse response */

    /*   GSSAPI response looks like
     * +----+------+-----+----------------+
     * |VER | MTYP | LEN |     TOKEN      |
     * +----+------+----------------------+
     * | 1  |  1   |  2  | up to 2^16 - 1 |
     * +----+------+-----+----------------+
     */

    result=Curl_blockread_all(conn, sock, (char *)socksreq, 4,
                              &actualread, timeout);
    if(result != CURLE_OK || actualread != 4) {
      failf(data, "Failed to receive SSPI authentication response.");
      free(service_name);
      service_name=NULL;
      s_pSecFn->FreeCredentialsHandle(&cred_handle);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_COULDNT_CONNECT;
    }

    /* ignore the first (VER) byte */
    if(socksreq[1] == 255) { /* status / message type */
      failf(data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      free(service_name);
      service_name=NULL;
      s_pSecFn->FreeCredentialsHandle(&cred_handle);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_COULDNT_CONNECT;
    }

    if(socksreq[1] != 1) { /* status / messgae type */
      failf(data, "Invalid SSPI authentication response type (%d %d).",
            socksreq[0], socksreq[1]);
      free(service_name);
      service_name=NULL;
      s_pSecFn->FreeCredentialsHandle(&cred_handle);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_COULDNT_CONNECT;
    }

    memcpy(&us_length, socksreq+2, sizeof(short));
    us_length = ntohs(us_length);

    sspi_recv_token.cbBuffer = us_length;
    sspi_recv_token.pvBuffer = malloc(us_length);

    if(!sspi_recv_token.pvBuffer) {
      free(service_name);
      service_name=NULL;
      s_pSecFn->FreeCredentialsHandle(&cred_handle);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_blockread_all(conn, sock, (char *)sspi_recv_token.pvBuffer,
                                sspi_recv_token.cbBuffer,
                                &actualread, timeout);

    if(result != CURLE_OK || actualread != us_length) {
      failf(data, "Failed to receive SSPI authentication token.");
      free(service_name);
      service_name=NULL;
      s_pSecFn->FreeContextBuffer(sspi_recv_token.pvBuffer);
      s_pSecFn->FreeCredentialsHandle(&cred_handle);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_COULDNT_CONNECT;
    }

    context_handle = &sspi_context;
  }

  free(service_name);
  service_name=NULL;

  /* Everything is good so far, user was authenticated! */
  sspi_major_status = s_pSecFn->QueryCredentialsAttributes( &cred_handle,
                                                            SECPKG_CRED_ATTR_NAMES,
                                                            &names);
  s_pSecFn->FreeCredentialsHandle(&cred_handle);
  if(check_sspi_err(data,sspi_major_status,sspi_minor_status,
                    "QueryCredentialAttributes") ){
    s_pSecFn->DeleteSecurityContext(&sspi_context);
    s_pSecFn->FreeContextBuffer(names.sUserName);
    failf(data, "Failed to determine user name.");
    return CURLE_COULDNT_CONNECT;
  }
  infof(data, "SOCKS5 server authencticated user %s with gssapi.\n",
        names.sUserName);
  s_pSecFn->FreeContextBuffer(names.sUserName);

  /* Do encryption */
  socksreq[0] = 1;    /* gssapi subnegotiation version */
  socksreq[1] = 2;    /* encryption message type */

  gss_enc = 0; /* no data protection */
  /* do confidentiality protection if supported */
  if(sspi_ret_flags & ISC_REQ_CONFIDENTIALITY)
    gss_enc = 2;
  /* else do integrity protection */
  else if(sspi_ret_flags & ISC_REQ_INTEGRITY)
    gss_enc = 1;

  infof(data, "SOCKS5 server supports gssapi %s data protection.\n",
        (gss_enc==0)?"no":((gss_enc==1)?"integrity":"confidentiality") );
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
   * set to FALSE.  The token is verified using gss_unseal()/
   * gss_unwrap().
   *
   */

  if(data->set.socks5_gssapi_nec) {
    us_length = htons((short)1);
    memcpy(socksreq+2, &us_length, sizeof(short));
  }
  else {
    sspi_major_status = s_pSecFn->QueryContextAttributesA( &sspi_context,
                                                           SECPKG_ATTR_SIZES,
                                                           &sspi_sizes);
    if(check_sspi_err(data,sspi_major_status,sspi_minor_status,
                      "QueryContextAttributesA")) {
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      failf(data, "Failed to query security context attributes.");
      return CURLE_COULDNT_CONNECT;
    }

    sspi_w_token[0].cbBuffer = sspi_sizes.cbSecurityTrailer;
    sspi_w_token[0].BufferType = SECBUFFER_TOKEN;
    sspi_w_token[0].pvBuffer = malloc(sspi_sizes.cbSecurityTrailer);

    if(!sspi_w_token[0].pvBuffer) {
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_OUT_OF_MEMORY;
    }

    sspi_w_token[1].cbBuffer = 1;
    sspi_w_token[1].pvBuffer = malloc(1);
    if(!sspi_w_token[1].pvBuffer){
      s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_OUT_OF_MEMORY;
    }

    memcpy(sspi_w_token[1].pvBuffer,&gss_enc,1);
    sspi_w_token[2].BufferType = SECBUFFER_PADDING;
    sspi_w_token[2].cbBuffer = sspi_sizes.cbBlockSize;
    sspi_w_token[2].pvBuffer = malloc(sspi_sizes.cbBlockSize);
    if(!sspi_w_token[2].pvBuffer) {
      s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
      s_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_OUT_OF_MEMORY;
    }
    sspi_major_status = s_pSecFn->EncryptMessage( &sspi_context,
                                                  KERB_WRAP_NO_ENCRYPT,
                                                  &wrap_desc,
                                                  0);
    if(check_sspi_err(data,sspi_major_status,sspi_minor_status,
                      "EncryptMessage") ) {
      s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
      s_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
      s_pSecFn->FreeContextBuffer(sspi_w_token[2].pvBuffer);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      failf(data, "Failed to query security context attributes.");
      return CURLE_COULDNT_CONNECT;
    }
    sspi_send_token.cbBuffer = sspi_w_token[0].cbBuffer
      + sspi_w_token[1].cbBuffer
      + sspi_w_token[2].cbBuffer;
    sspi_send_token.pvBuffer = malloc(sspi_send_token.cbBuffer);
    if(!sspi_send_token.pvBuffer) {
      s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
      s_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
      s_pSecFn->FreeContextBuffer(sspi_w_token[2].pvBuffer);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_OUT_OF_MEMORY;
    }

    memcpy(sspi_send_token.pvBuffer, sspi_w_token[0].pvBuffer,
           sspi_w_token[0].cbBuffer);
    memcpy((PUCHAR) sspi_send_token.pvBuffer +(int)sspi_w_token[0].cbBuffer,
           sspi_w_token[1].pvBuffer, sspi_w_token[1].cbBuffer);
    memcpy((PUCHAR) sspi_send_token.pvBuffer
           +sspi_w_token[0].cbBuffer
           +sspi_w_token[1].cbBuffer,
           sspi_w_token[2].pvBuffer, sspi_w_token[2].cbBuffer);

    s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
    sspi_w_token[0].pvBuffer = NULL;
    sspi_w_token[0].cbBuffer = 0;
    s_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
    sspi_w_token[1].pvBuffer = NULL;
    sspi_w_token[1].cbBuffer = 0;
    s_pSecFn->FreeContextBuffer(sspi_w_token[2].pvBuffer);
    sspi_w_token[2].pvBuffer = NULL;
    sspi_w_token[2].cbBuffer = 0;

    us_length = htons((short)sspi_send_token.cbBuffer);
    memcpy(socksreq+2,&us_length,sizeof(short));
  }

  code = Curl_write_plain(conn, sock, (char *)socksreq, 4, &written);
  if((code != CURLE_OK) || (4 != written)) {
    failf(data, "Failed to send SSPI encryption request.");
    s_pSecFn->FreeContextBuffer(sspi_send_token.pvBuffer);
    s_pSecFn->DeleteSecurityContext(&sspi_context);
    return CURLE_COULDNT_CONNECT;
  }

  if(data->set.socks5_gssapi_nec) {
    memcpy(socksreq,&gss_enc,1);
    code = Curl_write_plain(conn, sock, (char *)socksreq, 1, &written);
    if((code != CURLE_OK) || (1 != written)) {
      failf(data, "Failed to send SSPI encryption type.");
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_COULDNT_CONNECT;
    }
  } else {
    code = Curl_write_plain(conn, sock, (char *)sspi_send_token.pvBuffer,
                            sspi_send_token.cbBuffer, &written);
    if((code != CURLE_OK) || (sspi_send_token.cbBuffer != (size_t)written)) {
      failf(data, "Failed to send SSPI encryption type.");
      s_pSecFn->FreeContextBuffer(sspi_send_token.pvBuffer);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_COULDNT_CONNECT;
    }
    s_pSecFn->FreeContextBuffer(sspi_send_token.pvBuffer);
  }

  result=Curl_blockread_all(conn, sock, (char *)socksreq, 4,
                            &actualread, timeout);
  if(result != CURLE_OK || actualread != 4) {
    failf(data, "Failed to receive SSPI encryption response.");
    s_pSecFn->DeleteSecurityContext(&sspi_context);
    return CURLE_COULDNT_CONNECT;
  }

  /* ignore the first (VER) byte */
  if(socksreq[1] == 255) { /* status / message type */
    failf(data, "User was rejected by the SOCKS5 server (%d %d).",
          socksreq[0], socksreq[1]);
    s_pSecFn->DeleteSecurityContext(&sspi_context);
    return CURLE_COULDNT_CONNECT;
  }

  if(socksreq[1] != 2) { /* status / message type */
    failf(data, "Invalid SSPI encryption response type (%d %d).",
          socksreq[0], socksreq[1]);
    s_pSecFn->DeleteSecurityContext(&sspi_context);
    return CURLE_COULDNT_CONNECT;
  }

  memcpy(&us_length, socksreq+2, sizeof(short));
  us_length = ntohs(us_length);

  sspi_w_token[0].cbBuffer = us_length;
  sspi_w_token[0].pvBuffer = malloc(us_length);
  if(!sspi_w_token[0].pvBuffer) {
    s_pSecFn->DeleteSecurityContext(&sspi_context);
    return CURLE_OUT_OF_MEMORY;
  }

  result=Curl_blockread_all(conn, sock, (char *)sspi_w_token[0].pvBuffer,
                            sspi_w_token[0].cbBuffer,
                            &actualread, timeout);

  if(result != CURLE_OK || actualread != us_length) {
    failf(data, "Failed to receive SSPI encryption type.");
    s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
    s_pSecFn->DeleteSecurityContext(&sspi_context);
    return CURLE_COULDNT_CONNECT;
  }


  if(!data->set.socks5_gssapi_nec) {
    wrap_desc.cBuffers = 2;
    sspi_w_token[0].BufferType = SECBUFFER_STREAM;
    sspi_w_token[1].BufferType = SECBUFFER_DATA;
    sspi_w_token[1].cbBuffer = 0;
    sspi_w_token[1].pvBuffer = NULL;

    sspi_major_status = s_pSecFn->DecryptMessage( &sspi_context,
                                                  &wrap_desc,
                                                  0,
                                                  &qop);

    if(check_sspi_err(data,sspi_major_status,sspi_minor_status,
                      "DecryptMessage")) {
      s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
      s_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      failf(data, "Failed to query security context attributes.");
      return CURLE_COULDNT_CONNECT;
    }

    if(sspi_w_token[1].cbBuffer != 1) {
      failf(data, "Invalid SSPI encryption response length (%d).",
            sspi_w_token[1].cbBuffer);
      s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
      s_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_COULDNT_CONNECT;
    }

    memcpy(socksreq,sspi_w_token[1].pvBuffer,sspi_w_token[1].cbBuffer);
    s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
    s_pSecFn->FreeContextBuffer(sspi_w_token[1].pvBuffer);
  } else {
    if(sspi_w_token[0].cbBuffer != 1) {
      failf(data, "Invalid SSPI encryption response length (%d).",
            sspi_w_token[0].cbBuffer);
      s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
      s_pSecFn->DeleteSecurityContext(&sspi_context);
      return CURLE_COULDNT_CONNECT;
    }
    memcpy(socksreq,sspi_w_token[0].pvBuffer,sspi_w_token[0].cbBuffer);
    s_pSecFn->FreeContextBuffer(sspi_w_token[0].pvBuffer);
  }

  infof(data, "SOCKS5 access with%s protection granted.\n",
        (socksreq[0]==0)?"out gssapi data":
        ((socksreq[0]==1)?" gssapi integrity":" gssapi confidentiality"));

  /* For later use if encryption is required
     conn->socks5_gssapi_enctype = socksreq[0];
     if (socksreq[0] != 0)
     conn->socks5_sspi_context = sspi_context;
     else {
     s_pSecFn->DeleteSecurityContext(&sspi_context);
     conn->socks5_sspi_context = sspi_context;
     }
  */
  return CURLE_OK;
}
#endif
