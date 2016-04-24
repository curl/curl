/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2015, Marc Hoersken, <info@marc-hoersken.de>
 * Copyright (C) 2012, Mark Salisbury, <mark.salisbury@hp.com>
 * Copyright (C) 2012 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

/*
 * Source file for all SChannel-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

/*
 * Based upon the PolarSSL implementation in polarssl.c and polarssl.h:
 *   Copyright (C) 2010, 2011, Hoi-Ho Chan, <hoiho.chan@gmail.com>
 *
 * Based upon the CyaSSL implementation in cyassl.c and cyassl.h:
 *   Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * Thanks for code and inspiration!
 */

#include "curl_setup.h"

#ifdef USE_SCHANNEL

#ifndef USE_WINDOWS_SSPI
#  error "Can't compile SCHANNEL support without SSPI."
#endif

#include "curl_sspi.h"
#include "schannel.h"
#include "vtls.h"
#include "sendf.h"
#include "connect.h" /* for the connect timeout */
#include "strerror.h"
#include "select.h" /* for the socket readyness */
#include "inet_pton.h" /* for IP addr SNI check */
#include "curl_multibyte.h"
#include "warnless.h"
#include "curl_printf.h"
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Uncomment to force verbose output
 * #define infof(x, y, ...) printf(y, __VA_ARGS__)
 * #define failf(x, y, ...) printf(y, __VA_ARGS__)
 */

static Curl_recv schannel_recv;
static Curl_send schannel_send;

#ifdef _WIN32_WCE
static CURLcode verify_certificate(struct connectdata *conn, int sockindex);
#endif

static void InitSecBuffer(SecBuffer *buffer, unsigned long BufType,
                          void *BufDataPtr, unsigned long BufByteSize)
{
  buffer->cbBuffer = BufByteSize;
  buffer->BufferType = BufType;
  buffer->pvBuffer = BufDataPtr;
}

static void InitSecBufferDesc(SecBufferDesc *desc, SecBuffer *BufArr,
                              unsigned long NumArrElem)
{
  desc->ulVersion = SECBUFFER_VERSION;
  desc->pBuffers = BufArr;
  desc->cBuffers = NumArrElem;
}

static CURLcode
schannel_connect_step1(struct connectdata *conn, int sockindex)
{
  ssize_t written = -1;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  SecBuffer outbuf;
  SecBufferDesc outbuf_desc;
  SCHANNEL_CRED schannel_cred;
  SECURITY_STATUS sspi_status = SEC_E_OK;
  struct curl_schannel_cred *old_cred = NULL;
  struct in_addr addr;
#ifdef ENABLE_IPV6
  struct in6_addr addr6;
#endif
  TCHAR *host_name;
  CURLcode result;

  infof(data, "schannel: SSL/TLS connection with %s port %hu (step 1/3)\n",
        conn->host.name, conn->remote_port);

  /* check for an existing re-usable credential handle */
  if(!Curl_ssl_getsessionid(conn, (void **)&old_cred, NULL)) {
    connssl->cred = old_cred;
    infof(data, "schannel: re-using existing credential handle\n");
  }
  else {
    /* setup Schannel API options */
    memset(&schannel_cred, 0, sizeof(schannel_cred));
    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;

    if(data->set.ssl.verifypeer) {
#ifdef _WIN32_WCE
      /* certificate validation on CE doesn't seem to work right; we'll
         do it following a more manual process. */
      schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION |
        SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
        SCH_CRED_IGNORE_REVOCATION_OFFLINE;
#else
      schannel_cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION;
      if(data->set.ssl_no_revoke)
        schannel_cred.dwFlags |= SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
                                 SCH_CRED_IGNORE_REVOCATION_OFFLINE;
      else
        schannel_cred.dwFlags |= SCH_CRED_REVOCATION_CHECK_CHAIN;
#endif
      if(data->set.ssl_no_revoke)
        infof(data, "schannel: disabled server certificate revocation "
                    "checks\n");
      else
        infof(data, "schannel: checking server certificate revocation\n");
    }
    else {
      schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION |
        SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
        SCH_CRED_IGNORE_REVOCATION_OFFLINE;
      infof(data, "schannel: disabled server certificate revocation checks\n");
    }

    if(!data->set.ssl.verifyhost) {
      schannel_cred.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK;
      infof(data, "schannel: verifyhost setting prevents Schannel from "
            "comparing the supplied target name with the subject "
            "names in server certificates. Also disables SNI.\n");
    }

    switch(data->set.ssl.version) {
    default:
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT |
        SP_PROT_TLS1_1_CLIENT |
        SP_PROT_TLS1_2_CLIENT;
      break;
    case CURL_SSLVERSION_TLSv1_0:
      schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT;
      break;
    case CURL_SSLVERSION_TLSv1_1:
      schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT;
      break;
    case CURL_SSLVERSION_TLSv1_2:
      schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
      break;
    case CURL_SSLVERSION_SSLv3:
      schannel_cred.grbitEnabledProtocols = SP_PROT_SSL3_CLIENT;
      break;
    case CURL_SSLVERSION_SSLv2:
      schannel_cred.grbitEnabledProtocols = SP_PROT_SSL2_CLIENT;
      break;
    }

    /* allocate memory for the re-usable credential handle */
    connssl->cred = (struct curl_schannel_cred *)
      malloc(sizeof(struct curl_schannel_cred));
    if(!connssl->cred) {
      failf(data, "schannel: unable to allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }
    memset(connssl->cred, 0, sizeof(struct curl_schannel_cred));

    /* https://msdn.microsoft.com/en-us/library/windows/desktop/aa374716.aspx
       */
    sspi_status =
      s_pSecFn->AcquireCredentialsHandle(NULL, (TCHAR *)UNISP_NAME,
                                         SECPKG_CRED_OUTBOUND, NULL,
                                         &schannel_cred, NULL, NULL,
                                         &connssl->cred->cred_handle,
                                         &connssl->cred->time_stamp);

    if(sspi_status != SEC_E_OK) {
      if(sspi_status == SEC_E_WRONG_PRINCIPAL)
        failf(data, "schannel: SNI or certificate check failed: %s",
              Curl_sspi_strerror(conn, sspi_status));
      else
        failf(data, "schannel: AcquireCredentialsHandle failed: %s",
              Curl_sspi_strerror(conn, sspi_status));
      Curl_safefree(connssl->cred);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Warn if SNI is disabled due to use of an IP address */
  if(Curl_inet_pton(AF_INET, conn->host.name, &addr)
#ifdef ENABLE_IPV6
     || Curl_inet_pton(AF_INET6, conn->host.name, &addr6)
#endif
    ) {
    infof(data, "schannel: using IP address, SNI is not supported by OS.\n");
  }

  /* setup output buffer */
  InitSecBuffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
  InitSecBufferDesc(&outbuf_desc, &outbuf, 1);

  /* setup request flags */
  connssl->req_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
    ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
    ISC_REQ_STREAM;

  /* allocate memory for the security context handle */
  connssl->ctxt = (struct curl_schannel_ctxt *)
    malloc(sizeof(struct curl_schannel_ctxt));
  if(!connssl->ctxt) {
    failf(data, "schannel: unable to allocate memory");
    return CURLE_OUT_OF_MEMORY;
  }
  memset(connssl->ctxt, 0, sizeof(struct curl_schannel_ctxt));

  host_name = Curl_convert_UTF8_to_tchar(conn->host.name);
  if(!host_name)
    return CURLE_OUT_OF_MEMORY;

  /* https://msdn.microsoft.com/en-us/library/windows/desktop/aa375924.aspx */

  sspi_status = s_pSecFn->InitializeSecurityContext(
    &connssl->cred->cred_handle, NULL, host_name,
    connssl->req_flags, 0, 0, NULL, 0, &connssl->ctxt->ctxt_handle,
    &outbuf_desc, &connssl->ret_flags, &connssl->ctxt->time_stamp);

  Curl_unicodefree(host_name);

  if(sspi_status != SEC_I_CONTINUE_NEEDED) {
    if(sspi_status == SEC_E_WRONG_PRINCIPAL)
      failf(data, "schannel: SNI or certificate check failed: %s",
            Curl_sspi_strerror(conn, sspi_status));
    else
      failf(data, "schannel: initial InitializeSecurityContext failed: %s",
            Curl_sspi_strerror(conn, sspi_status));
    Curl_safefree(connssl->ctxt);
    return CURLE_SSL_CONNECT_ERROR;
  }

  infof(data, "schannel: sending initial handshake data: "
        "sending %lu bytes...\n", outbuf.cbBuffer);

  /* send initial handshake data which is now stored in output buffer */
  result = Curl_write_plain(conn, conn->sock[sockindex], outbuf.pvBuffer,
                            outbuf.cbBuffer, &written);
  s_pSecFn->FreeContextBuffer(outbuf.pvBuffer);
  if((result != CURLE_OK) || (outbuf.cbBuffer != (size_t) written)) {
    failf(data, "schannel: failed to send initial handshake data: "
          "sent %zd of %lu bytes", written, outbuf.cbBuffer);
    return CURLE_SSL_CONNECT_ERROR;
  }

  infof(data, "schannel: sent initial handshake data: "
        "sent %zd bytes\n", written);

  connssl->recv_unrecoverable_err = CURLE_OK;
  connssl->recv_sspi_close_notify = false;
  connssl->recv_connection_closed = false;

  /* continue to second handshake step */
  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode
schannel_connect_step2(struct connectdata *conn, int sockindex)
{
  int i;
  ssize_t nread = -1, written = -1;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  unsigned char *reallocated_buffer;
  size_t reallocated_length;
  SecBuffer outbuf[3];
  SecBufferDesc outbuf_desc;
  SecBuffer inbuf[2];
  SecBufferDesc inbuf_desc;
  SECURITY_STATUS sspi_status = SEC_E_OK;
  TCHAR *host_name;
  CURLcode result;
  bool doread;

  doread = (connssl->connecting_state != ssl_connect_2_writing) ? TRUE : FALSE;

  infof(data, "schannel: SSL/TLS connection with %s port %hu (step 2/3)\n",
        conn->host.name, conn->remote_port);

  if(!connssl->cred || !connssl->ctxt)
    return CURLE_SSL_CONNECT_ERROR;

  /* buffer to store previously received and decrypted data */
  if(connssl->decdata_buffer == NULL) {
    connssl->decdata_offset = 0;
    connssl->decdata_length = CURL_SCHANNEL_BUFFER_INIT_SIZE;
    connssl->decdata_buffer = malloc(connssl->decdata_length);
    if(connssl->decdata_buffer == NULL) {
      failf(data, "schannel: unable to allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* buffer to store previously received and encrypted data */
  if(connssl->encdata_buffer == NULL) {
    connssl->encdata_offset = 0;
    connssl->encdata_length = CURL_SCHANNEL_BUFFER_INIT_SIZE;
    connssl->encdata_buffer = malloc(connssl->encdata_length);
    if(connssl->encdata_buffer == NULL) {
      failf(data, "schannel: unable to allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* if we need a bigger buffer to read a full message, increase buffer now */
  if(connssl->encdata_length - connssl->encdata_offset <
     CURL_SCHANNEL_BUFFER_FREE_SIZE) {
    /* increase internal encrypted data buffer */
    reallocated_length = connssl->encdata_offset +
      CURL_SCHANNEL_BUFFER_FREE_SIZE;
    reallocated_buffer = realloc(connssl->encdata_buffer,
                                 reallocated_length);

    if(reallocated_buffer == NULL) {
      failf(data, "schannel: unable to re-allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }
    else {
      connssl->encdata_buffer = reallocated_buffer;
      connssl->encdata_length = reallocated_length;
    }
  }

  for(;;) {
    if(doread) {
      /* read encrypted handshake data from socket */
      result = Curl_read_plain(conn->sock[sockindex],
                               (char *) (connssl->encdata_buffer +
                                         connssl->encdata_offset),
                               connssl->encdata_length -
                               connssl->encdata_offset,
                               &nread);
      if(result == CURLE_AGAIN) {
        if(connssl->connecting_state != ssl_connect_2_writing)
          connssl->connecting_state = ssl_connect_2_reading;
        infof(data, "schannel: failed to receive handshake, "
              "need more data\n");
        return CURLE_OK;
      }
      else if((result != CURLE_OK) || (nread == 0)) {
        failf(data, "schannel: failed to receive handshake, "
              "SSL/TLS connection failed");
        return CURLE_SSL_CONNECT_ERROR;
      }

      /* increase encrypted data buffer offset */
      connssl->encdata_offset += nread;
    }

    infof(data, "schannel: encrypted data buffer: offset %zu length %zu\n",
          connssl->encdata_offset, connssl->encdata_length);

    /* setup input buffers */
    InitSecBuffer(&inbuf[0], SECBUFFER_TOKEN, malloc(connssl->encdata_offset),
                  curlx_uztoul(connssl->encdata_offset));
    InitSecBuffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
    InitSecBufferDesc(&inbuf_desc, inbuf, 2);

    /* setup output buffers */
    InitSecBuffer(&outbuf[0], SECBUFFER_TOKEN, NULL, 0);
    InitSecBuffer(&outbuf[1], SECBUFFER_ALERT, NULL, 0);
    InitSecBuffer(&outbuf[2], SECBUFFER_EMPTY, NULL, 0);
    InitSecBufferDesc(&outbuf_desc, outbuf, 3);

    if(inbuf[0].pvBuffer == NULL) {
      failf(data, "schannel: unable to allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }

    /* copy received handshake data into input buffer */
    memcpy(inbuf[0].pvBuffer, connssl->encdata_buffer,
           connssl->encdata_offset);

    host_name = Curl_convert_UTF8_to_tchar(conn->host.name);
    if(!host_name)
      return CURLE_OUT_OF_MEMORY;

    /* https://msdn.microsoft.com/en-us/library/windows/desktop/aa375924.aspx
       */
    sspi_status = s_pSecFn->InitializeSecurityContext(
      &connssl->cred->cred_handle, &connssl->ctxt->ctxt_handle,
      host_name, connssl->req_flags, 0, 0, &inbuf_desc, 0, NULL,
      &outbuf_desc, &connssl->ret_flags, &connssl->ctxt->time_stamp);

    Curl_unicodefree(host_name);

    /* free buffer for received handshake data */
    Curl_safefree(inbuf[0].pvBuffer);

    /* check if the handshake was incomplete */
    if(sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
      connssl->connecting_state = ssl_connect_2_reading;
      infof(data, "schannel: received incomplete message, need more data\n");
      return CURLE_OK;
    }

    /* If the server has requested a client certificate, attempt to continue
       the handshake without one. This will allow connections to servers which
       request a client certificate but do not require it. */
    if(sspi_status == SEC_I_INCOMPLETE_CREDENTIALS &&
       !(connssl->req_flags & ISC_REQ_USE_SUPPLIED_CREDS)) {
      connssl->req_flags |= ISC_REQ_USE_SUPPLIED_CREDS;
      connssl->connecting_state = ssl_connect_2_writing;
      infof(data, "schannel: a client certificate has been requested\n");
      return CURLE_OK;
    }

    /* check if the handshake needs to be continued */
    if(sspi_status == SEC_I_CONTINUE_NEEDED || sspi_status == SEC_E_OK) {
      for(i = 0; i < 3; i++) {
        /* search for handshake tokens that need to be send */
        if(outbuf[i].BufferType == SECBUFFER_TOKEN && outbuf[i].cbBuffer > 0) {
          infof(data, "schannel: sending next handshake data: "
                "sending %lu bytes...\n", outbuf[i].cbBuffer);

          /* send handshake token to server */
          result = Curl_write_plain(conn, conn->sock[sockindex],
                                    outbuf[i].pvBuffer, outbuf[i].cbBuffer,
                                    &written);
          if((result != CURLE_OK) ||
             (outbuf[i].cbBuffer != (size_t) written)) {
            failf(data, "schannel: failed to send next handshake data: "
                  "sent %zd of %lu bytes", written, outbuf[i].cbBuffer);
            return CURLE_SSL_CONNECT_ERROR;
          }
        }

        /* free obsolete buffer */
        if(outbuf[i].pvBuffer != NULL) {
          s_pSecFn->FreeContextBuffer(outbuf[i].pvBuffer);
        }
      }
    }
    else {
      if(sspi_status == SEC_E_WRONG_PRINCIPAL)
        failf(data, "schannel: SNI or certificate check failed: %s",
              Curl_sspi_strerror(conn, sspi_status));
      else
        failf(data, "schannel: next InitializeSecurityContext failed: %s",
              Curl_sspi_strerror(conn, sspi_status));
      return CURLE_SSL_CONNECT_ERROR;
    }

    /* check if there was additional remaining encrypted data */
    if(inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer > 0) {
      infof(data, "schannel: encrypted data length: %lu\n", inbuf[1].cbBuffer);
      /*
        There are two cases where we could be getting extra data here:
        1) If we're renegotiating a connection and the handshake is already
        complete (from the server perspective), it can encrypted app data
        (not handshake data) in an extra buffer at this point.
        2) (sspi_status == SEC_I_CONTINUE_NEEDED) We are negotiating a
        connection and this extra data is part of the handshake.
        We should process the data immediately; waiting for the socket to
        be ready may fail since the server is done sending handshake data.
      */
      /* check if the remaining data is less than the total amount
         and therefore begins after the already processed data */
      if(connssl->encdata_offset > inbuf[1].cbBuffer) {
        memmove(connssl->encdata_buffer,
                (connssl->encdata_buffer + connssl->encdata_offset) -
                inbuf[1].cbBuffer, inbuf[1].cbBuffer);
        connssl->encdata_offset = inbuf[1].cbBuffer;
        if(sspi_status == SEC_I_CONTINUE_NEEDED) {
          doread = FALSE;
          continue;
        }
      }
    }
    else {
      connssl->encdata_offset = 0;
    }
    break;
  }

  /* check if the handshake needs to be continued */
  if(sspi_status == SEC_I_CONTINUE_NEEDED) {
    connssl->connecting_state = ssl_connect_2_reading;
    return CURLE_OK;
  }

  /* check if the handshake is complete */
  if(sspi_status == SEC_E_OK) {
    connssl->connecting_state = ssl_connect_3;
    infof(data, "schannel: SSL/TLS handshake complete\n");
  }

#ifdef _WIN32_WCE
  /* Windows CE doesn't do any server certificate validation.
     We have to do it manually. */
  if(data->set.ssl.verifypeer)
    return verify_certificate(conn, sockindex);
#endif

  return CURLE_OK;
}

static CURLcode
schannel_connect_step3(struct connectdata *conn, int sockindex)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct curl_schannel_cred *old_cred = NULL;
  bool incache;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  infof(data, "schannel: SSL/TLS connection with %s port %hu (step 3/3)\n",
        conn->host.name, conn->remote_port);

  if(!connssl->cred)
    return CURLE_SSL_CONNECT_ERROR;

  /* check if the required context attributes are met */
  if(connssl->ret_flags != connssl->req_flags) {
    if(!(connssl->ret_flags & ISC_RET_SEQUENCE_DETECT))
      failf(data, "schannel: failed to setup sequence detection");
    if(!(connssl->ret_flags & ISC_RET_REPLAY_DETECT))
      failf(data, "schannel: failed to setup replay detection");
    if(!(connssl->ret_flags & ISC_RET_CONFIDENTIALITY))
      failf(data, "schannel: failed to setup confidentiality");
    if(!(connssl->ret_flags & ISC_RET_ALLOCATED_MEMORY))
      failf(data, "schannel: failed to setup memory allocation");
    if(!(connssl->ret_flags & ISC_RET_STREAM))
      failf(data, "schannel: failed to setup stream orientation");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* increment the reference counter of the credential/session handle */
  if(connssl->cred && connssl->ctxt) {
    connssl->cred->refcount++;
    infof(data, "schannel: incremented credential handle refcount = %d\n",
          connssl->cred->refcount);
  }

  /* save the current session data for possible re-use */
  incache = !(Curl_ssl_getsessionid(conn, (void **)&old_cred, NULL));
  if(incache) {
    if(old_cred != connssl->cred) {
      infof(data, "schannel: old credential handle is stale, removing\n");
      Curl_ssl_delsessionid(conn, (void *)old_cred);
      incache = FALSE;
    }
  }

  if(!incache) {
    result = Curl_ssl_addsessionid(conn, (void *)connssl->cred,
                                   sizeof(struct curl_schannel_cred));
    if(result) {
      failf(data, "schannel: failed to store credential handle");
      return result;
    }
    else {
      connssl->cred->cached = TRUE;
      infof(data, "schannel: stored credential handle in session cache\n");
    }
  }

  connssl->connecting_state = ssl_connect_done;

  return CURLE_OK;
}

static CURLcode
schannel_connect_common(struct connectdata *conn, int sockindex,
                        bool nonblocking, bool *done)
{
  CURLcode result;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    /* check out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL/TLS connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = schannel_connect_step1(conn, sockindex);
    if(result)
      return result;
  }

  while(ssl_connect_2 == connssl->connecting_state ||
        ssl_connect_2_reading == connssl->connecting_state ||
        ssl_connect_2_writing == connssl->connecting_state) {

    /* check out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL/TLS connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* if ssl is expecting something, check if it's available. */
    if(connssl->connecting_state == ssl_connect_2_reading
       || connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing ==
        connssl->connecting_state ? sockfd : CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading ==
        connssl->connecting_state ? sockfd : CURL_SOCKET_BAD;

      what = Curl_socket_ready(readfd, writefd, nonblocking ? 0 : timeout_ms);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL/TLS socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          /* timeout */
          failf(data, "SSL/TLS connection timeout");
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      /* socket is readable or writable */
    }

    /* Run transaction, and return to the caller if it failed or if
     * this connection is part of a multi handle and this loop would
     * execute again. This permits the owner of a multi handle to
     * abort a connection attempt before step2 has completed while
     * ensuring that a client using select() or epoll() will always
     * have a valid fdset to wait on.
     */
    result = schannel_connect_step2(conn, sockindex);
    if(result || (nonblocking &&
                  (ssl_connect_2 == connssl->connecting_state ||
                   ssl_connect_2_reading == connssl->connecting_state ||
                   ssl_connect_2_writing == connssl->connecting_state)))
      return result;

  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    result = schannel_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = schannel_recv;
    conn->send[sockindex] = schannel_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* reset our connection state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

static ssize_t
schannel_send(struct connectdata *conn, int sockindex,
              const void *buf, size_t len, CURLcode *err)
{
  ssize_t written = -1;
  size_t data_len = 0;
  unsigned char *data = NULL;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  SecBuffer outbuf[4];
  SecBufferDesc outbuf_desc;
  SECURITY_STATUS sspi_status = SEC_E_OK;
  CURLcode result;

  /* check if the maximum stream sizes were queried */
  if(connssl->stream_sizes.cbMaximumMessage == 0) {
    sspi_status = s_pSecFn->QueryContextAttributes(
      &connssl->ctxt->ctxt_handle,
      SECPKG_ATTR_STREAM_SIZES,
      &connssl->stream_sizes);
    if(sspi_status != SEC_E_OK) {
      *err = CURLE_SEND_ERROR;
      return -1;
    }
  }

  /* check if the buffer is longer than the maximum message length */
  if(len > connssl->stream_sizes.cbMaximumMessage) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  /* calculate the complete message length and allocate a buffer for it */
  data_len = connssl->stream_sizes.cbHeader + len +
    connssl->stream_sizes.cbTrailer;
  data = (unsigned char *) malloc(data_len);
  if(data == NULL) {
    *err = CURLE_OUT_OF_MEMORY;
    return -1;
  }

  /* setup output buffers (header, data, trailer, empty) */
  InitSecBuffer(&outbuf[0], SECBUFFER_STREAM_HEADER,
                data, connssl->stream_sizes.cbHeader);
  InitSecBuffer(&outbuf[1], SECBUFFER_DATA,
                data + connssl->stream_sizes.cbHeader, curlx_uztoul(len));
  InitSecBuffer(&outbuf[2], SECBUFFER_STREAM_TRAILER,
                data + connssl->stream_sizes.cbHeader + len,
                connssl->stream_sizes.cbTrailer);
  InitSecBuffer(&outbuf[3], SECBUFFER_EMPTY, NULL, 0);
  InitSecBufferDesc(&outbuf_desc, outbuf, 4);

  /* copy data into output buffer */
  memcpy(outbuf[1].pvBuffer, buf, len);

  /* https://msdn.microsoft.com/en-us/library/windows/desktop/aa375390.aspx */
  sspi_status = s_pSecFn->EncryptMessage(&connssl->ctxt->ctxt_handle, 0,
                                         &outbuf_desc, 0);

  /* check if the message was encrypted */
  if(sspi_status == SEC_E_OK) {
    written = 0;

    /* send the encrypted message including header, data and trailer */
    len = outbuf[0].cbBuffer + outbuf[1].cbBuffer + outbuf[2].cbBuffer;

    /*
      It's important to send the full message which includes the header,
      encrypted payload, and trailer.  Until the client receives all the
      data a coherent message has not been delivered and the client
      can't read any of it.

      If we wanted to buffer the unwritten encrypted bytes, we would
      tell the client that all data it has requested to be sent has been
      sent. The unwritten encrypted bytes would be the first bytes to
      send on the next invocation.
      Here's the catch with this - if we tell the client that all the
      bytes have been sent, will the client call this method again to
      send the buffered data?  Looking at who calls this function, it
      seems the answer is NO.
    */

    /* send entire message or fail */
    while(len > (size_t)written) {
      ssize_t this_write;
      long timeleft;
      int what;

      this_write = 0;

      timeleft = Curl_timeleft(conn->data, NULL, FALSE);
      if(timeleft < 0) {
        /* we already got the timeout */
        failf(conn->data, "schannel: timed out sending data "
              "(bytes sent: %zd)", written);
        *err = CURLE_OPERATION_TIMEDOUT;
        written = -1;
        break;
      }

      what = Curl_socket_ready(CURL_SOCKET_BAD, conn->sock[sockindex],
                               timeleft);
      if(what < 0) {
        /* fatal error */
        failf(conn->data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        *err = CURLE_SEND_ERROR;
        written = -1;
        break;
      }
      else if(0 == what) {
        failf(conn->data, "schannel: timed out sending data "
              "(bytes sent: %zd)", written);
        *err = CURLE_OPERATION_TIMEDOUT;
        written = -1;
        break;
      }
      /* socket is writable */

      result = Curl_write_plain(conn, conn->sock[sockindex], data + written,
                                len - written, &this_write);
      if(result == CURLE_AGAIN)
        continue;
      else if(result != CURLE_OK) {
        *err = result;
        written = -1;
        break;
      }

      written += this_write;
    }
  }
  else if(sspi_status == SEC_E_INSUFFICIENT_MEMORY) {
    *err = CURLE_OUT_OF_MEMORY;
  }
  else{
    *err = CURLE_SEND_ERROR;
  }

  Curl_safefree(data);

  if(len == (size_t)written)
    /* Encrypted message including header, data and trailer entirely sent.
       The return value is the number of unencrypted bytes that were sent. */
    written = outbuf[1].cbBuffer;

  return written;
}

static ssize_t
schannel_recv(struct connectdata *conn, int sockindex,
              char *buf, size_t len, CURLcode *err)
{
  size_t size = 0;
  ssize_t nread = -1;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  unsigned char *reallocated_buffer;
  size_t reallocated_length;
  bool done = FALSE;
  SecBuffer inbuf[4];
  SecBufferDesc inbuf_desc;
  SECURITY_STATUS sspi_status = SEC_E_OK;
  /* we want the length of the encrypted buffer to be at least large enough
     that it can hold all the bytes requested and some TLS record overhead. */
  size_t min_encdata_length = len + CURL_SCHANNEL_BUFFER_FREE_SIZE;

  /****************************************************************************
   * Don't return or set connssl->recv_unrecoverable_err unless in the cleanup.
   * The pattern for return error is set *err, optional infof, goto cleanup.
   *
   * Our priority is to always return as much decrypted data to the caller as
   * possible, even if an error occurs. The state of the decrypted buffer must
   * always be valid. Transfer of decrypted data to the caller's buffer is
   * handled in the cleanup.
   */

  infof(data, "schannel: client wants to read %zu bytes\n", len);
  *err = CURLE_OK;

  if(len && len <= connssl->decdata_offset) {
    infof(data, "schannel: enough decrypted data is already available\n");
    goto cleanup;
  }
  else if(connssl->recv_unrecoverable_err) {
    *err = connssl->recv_unrecoverable_err;
    infof(data, "schannel: an unrecoverable error occurred in a prior call\n");
    goto cleanup;
  }
  else if(connssl->recv_sspi_close_notify) {
    /* once a server has indicated shutdown there is no more encrypted data */
    infof(data, "schannel: server indicated shutdown in a prior call\n");
    goto cleanup;
  }
  else if(!len) {
    /* It's debatable what to return when !len. Regardless we can't return
    immediately because there may be data to decrypt (in the case we want to
    decrypt all encrypted cached data) so handle !len later in cleanup.
    */
    ; /* do nothing */
  }
  else if(!connssl->recv_connection_closed) {
    /* increase enc buffer in order to fit the requested amount of data */
    size = connssl->encdata_length - connssl->encdata_offset;
    if(size < CURL_SCHANNEL_BUFFER_FREE_SIZE ||
       connssl->encdata_length < min_encdata_length) {
      reallocated_length = connssl->encdata_offset +
                           CURL_SCHANNEL_BUFFER_FREE_SIZE;
      if(reallocated_length < min_encdata_length) {
        reallocated_length = min_encdata_length;
      }
      reallocated_buffer = realloc(connssl->encdata_buffer,
                                   reallocated_length);
      if(reallocated_buffer == NULL) {
        *err = CURLE_OUT_OF_MEMORY;
        failf(data, "schannel: unable to re-allocate memory");
        goto cleanup;
      }

      connssl->encdata_buffer = reallocated_buffer;
      connssl->encdata_length = reallocated_length;
      size = connssl->encdata_length - connssl->encdata_offset;
      infof(data, "schannel: encdata_buffer resized %zu\n",
            connssl->encdata_length);
    }

    infof(data, "schannel: encrypted data buffer: offset %zu length %zu\n",
          connssl->encdata_offset, connssl->encdata_length);

    /* read encrypted data from socket */
    *err = Curl_read_plain(conn->sock[sockindex],
                           (char *)(connssl->encdata_buffer +
                                    connssl->encdata_offset),
                           size, &nread);
    if(*err) {
      nread = -1;
      if(*err == CURLE_AGAIN)
        infof(data, "schannel: Curl_read_plain returned CURLE_AGAIN\n");
      else if(*err == CURLE_RECV_ERROR)
        infof(data, "schannel: Curl_read_plain returned CURLE_RECV_ERROR\n");
      else
        infof(data, "schannel: Curl_read_plain returned error %d\n", *err);
    }
    else if(nread == 0) {
      connssl->recv_connection_closed = true;
      infof(data, "schannel: server closed the connection\n");
    }
    else if(nread > 0) {
      connssl->encdata_offset += (size_t)nread;
      infof(data, "schannel: encrypted data got %zd\n", nread);
    }
  }

  infof(data, "schannel: encrypted data buffer: offset %zu length %zu\n",
        connssl->encdata_offset, connssl->encdata_length);

  /* decrypt loop */
  while(connssl->encdata_offset > 0 && sspi_status == SEC_E_OK &&
        (!len || connssl->decdata_offset < len ||
         connssl->recv_connection_closed)) {
    /* prepare data buffer for DecryptMessage call */
    InitSecBuffer(&inbuf[0], SECBUFFER_DATA, connssl->encdata_buffer,
                  curlx_uztoul(connssl->encdata_offset));

    /* we need 3 more empty input buffers for possible output */
    InitSecBuffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
    InitSecBuffer(&inbuf[2], SECBUFFER_EMPTY, NULL, 0);
    InitSecBuffer(&inbuf[3], SECBUFFER_EMPTY, NULL, 0);
    InitSecBufferDesc(&inbuf_desc, inbuf, 4);

    /* https://msdn.microsoft.com/en-us/library/windows/desktop/aa375348.aspx
       */
    sspi_status = s_pSecFn->DecryptMessage(&connssl->ctxt->ctxt_handle,
                                           &inbuf_desc, 0, NULL);

    /* check if everything went fine (server may want to renegotiate
       or shutdown the connection context) */
    if(sspi_status == SEC_E_OK || sspi_status == SEC_I_RENEGOTIATE ||
       sspi_status == SEC_I_CONTEXT_EXPIRED) {
      /* check for successfully decrypted data, even before actual
         renegotiation or shutdown of the connection context */
      if(inbuf[1].BufferType == SECBUFFER_DATA) {
        infof(data, "schannel: decrypted data length: %lu\n",
              inbuf[1].cbBuffer);

        /* increase buffer in order to fit the received amount of data */
        size = inbuf[1].cbBuffer > CURL_SCHANNEL_BUFFER_FREE_SIZE ?
               inbuf[1].cbBuffer : CURL_SCHANNEL_BUFFER_FREE_SIZE;
        if(connssl->decdata_length - connssl->decdata_offset < size ||
           connssl->decdata_length < len) {
          /* increase internal decrypted data buffer */
          reallocated_length = connssl->decdata_offset + size;
          /* make sure that the requested amount of data fits */
          if(reallocated_length < len) {
            reallocated_length = len;
          }
          reallocated_buffer = realloc(connssl->decdata_buffer,
                                       reallocated_length);
          if(reallocated_buffer == NULL) {
            *err = CURLE_OUT_OF_MEMORY;
            failf(data, "schannel: unable to re-allocate memory");
            goto cleanup;
          }
          connssl->decdata_buffer = reallocated_buffer;
          connssl->decdata_length = reallocated_length;
        }

        /* copy decrypted data to internal buffer */
        size = inbuf[1].cbBuffer;
        if(size) {
          memcpy(connssl->decdata_buffer + connssl->decdata_offset,
                 inbuf[1].pvBuffer, size);
          connssl->decdata_offset += size;
        }

        infof(data, "schannel: decrypted data added: %zu\n", size);
        infof(data, "schannel: decrypted data cached: offset %zu length %zu\n",
              connssl->decdata_offset, connssl->decdata_length);
      }

      /* check for remaining encrypted data */
      if(inbuf[3].BufferType == SECBUFFER_EXTRA && inbuf[3].cbBuffer > 0) {
        infof(data, "schannel: encrypted data length: %lu\n",
              inbuf[3].cbBuffer);

        /* check if the remaining data is less than the total amount
         * and therefore begins after the already processed data
         */
        if(connssl->encdata_offset > inbuf[3].cbBuffer) {
          /* move remaining encrypted data forward to the beginning of
             buffer */
          memmove(connssl->encdata_buffer,
                  (connssl->encdata_buffer + connssl->encdata_offset) -
                  inbuf[3].cbBuffer, inbuf[3].cbBuffer);
          connssl->encdata_offset = inbuf[3].cbBuffer;
        }

        infof(data, "schannel: encrypted data cached: offset %zu length %zu\n",
              connssl->encdata_offset, connssl->encdata_length);
      }
      else {
        /* reset encrypted buffer offset, because there is no data remaining */
        connssl->encdata_offset = 0;
      }

      /* check if server wants to renegotiate the connection context */
      if(sspi_status == SEC_I_RENEGOTIATE) {
        infof(data, "schannel: remote party requests renegotiation\n");
        if(*err && *err != CURLE_AGAIN) {
          infof(data, "schannel: can't renogotiate, an error is pending\n");
          goto cleanup;
        }
        if(connssl->encdata_offset) {
          *err = CURLE_RECV_ERROR;
          infof(data, "schannel: can't renogotiate, "
                      "encrypted data available\n");
          goto cleanup;
        }
        /* begin renegotiation */
        infof(data, "schannel: renegotiating SSL/TLS connection\n");
        connssl->state = ssl_connection_negotiating;
        connssl->connecting_state = ssl_connect_2_writing;
        *err = schannel_connect_common(conn, sockindex, FALSE, &done);
        if(*err) {
          infof(data, "schannel: renegotiation failed\n");
          goto cleanup;
        }
        /* now retry receiving data */
        sspi_status = SEC_E_OK;
        infof(data, "schannel: SSL/TLS connection renegotiated\n");
        continue;
      }
      /* check if the server closed the connection */
      else if(sspi_status == SEC_I_CONTEXT_EXPIRED) {
        /* In Windows 2000 SEC_I_CONTEXT_EXPIRED (close_notify) is not
           returned so we have to work around that in cleanup. */
        connssl->recv_sspi_close_notify = true;
        if(!connssl->recv_connection_closed) {
          connssl->recv_connection_closed = true;
          infof(data, "schannel: server closed the connection\n");
        }
        goto cleanup;
      }
    }
    else if(sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
      if(!*err)
        *err = CURLE_AGAIN;
      infof(data, "schannel: failed to decrypt data, need more data\n");
      goto cleanup;
    }
    else {
      *err = CURLE_RECV_ERROR;
      infof(data, "schannel: failed to read data from server: %s\n",
            Curl_sspi_strerror(conn, sspi_status));
      goto cleanup;
    }
  }

  infof(data, "schannel: encrypted data buffer: offset %zu length %zu\n",
        connssl->encdata_offset, connssl->encdata_length);

  infof(data, "schannel: decrypted data buffer: offset %zu length %zu\n",
        connssl->decdata_offset, connssl->decdata_length);

cleanup:
  /* Warning- there is no guarantee the encdata state is valid at this point */
  infof(data, "schannel: schannel_recv cleanup\n");

  /* Error if the connection has closed without a close_notify.
  Behavior here is a matter of debate. We don't want to be vulnerable to a
  truncation attack however there's some browser precedent for ignoring the
  close_notify for compatibility reasons.
  Additionally, Windows 2000 (v5.0) is a special case since it seems it doesn't
  return close_notify. In that case if the connection was closed we assume it
  was graceful (close_notify) since there doesn't seem to be a way to tell.
  */
  if(len && !connssl->decdata_offset && connssl->recv_connection_closed &&
     !connssl->recv_sspi_close_notify) {
    bool isWin2k = FALSE;

#if !defined(_WIN32_WINNT) || !defined(_WIN32_WINNT_WIN2K) || \
    (_WIN32_WINNT < _WIN32_WINNT_WIN2K)
    OSVERSIONINFO osver;

    memset(&osver, 0, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);

    /* Find out the Windows version */
    if(GetVersionEx(&osver)) {
      /* Verify the version number is 5.0 */
      if(osver.dwMajorVersion == 5 && osver.dwMinorVersion == 0)
        isWin2k = TRUE;
    }
#else
    ULONGLONG cm;
    OSVERSIONINFOEX osver;

    memset(&osver, 0, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);
    osver.dwMajorVersion = 5;

    cm = VerSetConditionMask(0, VER_MAJORVERSION, VER_EQUAL);
    cm = VerSetConditionMask(cm, VER_MINORVERSION, VER_EQUAL);
    cm = VerSetConditionMask(cm, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
    cm = VerSetConditionMask(cm, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL);

    if(VerifyVersionInfo(&osver, (VER_MAJORVERSION | VER_MINORVERSION |
                                  VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR),
                         cm))
      isWin2k = TRUE;
#endif

    if(isWin2k && sspi_status == SEC_E_OK)
      connssl->recv_sspi_close_notify = true;
    else {
      *err = CURLE_RECV_ERROR;
      infof(data, "schannel: server closed abruptly (missing close_notify)\n");
    }
  }

  /* Any error other than CURLE_AGAIN is an unrecoverable error. */
  if(*err && *err != CURLE_AGAIN)
      connssl->recv_unrecoverable_err = *err;

  size = len < connssl->decdata_offset ? len : connssl->decdata_offset;
  if(size) {
    memcpy(buf, connssl->decdata_buffer, size);
    memmove(connssl->decdata_buffer, connssl->decdata_buffer + size,
            connssl->decdata_offset - size);
    connssl->decdata_offset -= size;

    infof(data, "schannel: decrypted data returned %zu\n", size);
    infof(data, "schannel: decrypted data buffer: offset %zu length %zu\n",
          connssl->decdata_offset, connssl->decdata_length);
    *err = CURLE_OK;
    return (ssize_t)size;
  }

  if(!*err && !connssl->recv_connection_closed)
      *err = CURLE_AGAIN;

  /* It's debatable what to return when !len. We could return whatever error we
  got from decryption but instead we override here so the return is consistent.
  */
  if(!len)
    *err = CURLE_OK;

  return *err ? -1 : 0;
}

CURLcode
Curl_schannel_connect_nonblocking(struct connectdata *conn, int sockindex,
                                  bool *done)
{
  return schannel_connect_common(conn, sockindex, TRUE, done);
}

CURLcode
Curl_schannel_connect(struct connectdata *conn, int sockindex)
{
  CURLcode result;
  bool done = FALSE;

  result = schannel_connect_common(conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

bool Curl_schannel_data_pending(const struct connectdata *conn, int sockindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->use) /* SSL/TLS is in use */
    return (connssl->encdata_offset > 0 ||
            connssl->decdata_offset > 0 ) ? TRUE : FALSE;
  else
    return FALSE;
}

void Curl_schannel_close(struct connectdata *conn, int sockindex)
{
  if(conn->ssl[sockindex].use)
    /* if the SSL/TLS channel hasn't been shut down yet, do that now. */
    Curl_ssl_shutdown(conn, sockindex);
}

int Curl_schannel_shutdown(struct connectdata *conn, int sockindex)
{
  /* See https://msdn.microsoft.com/en-us/library/windows/desktop/aa380138.aspx
   * Shutting Down an Schannel Connection
   */
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  infof(data, "schannel: shutting down SSL/TLS connection with %s port %hu\n",
        conn->host.name, conn->remote_port);

  if(connssl->cred && connssl->ctxt) {
    SecBufferDesc BuffDesc;
    SecBuffer Buffer;
    SECURITY_STATUS sspi_status;
    SecBuffer outbuf;
    SecBufferDesc outbuf_desc;
    CURLcode result;
    TCHAR *host_name;
    DWORD dwshut = SCHANNEL_SHUTDOWN;

    InitSecBuffer(&Buffer, SECBUFFER_TOKEN, &dwshut, sizeof(dwshut));
    InitSecBufferDesc(&BuffDesc, &Buffer, 1);

    sspi_status = s_pSecFn->ApplyControlToken(&connssl->ctxt->ctxt_handle,
                                              &BuffDesc);

    if(sspi_status != SEC_E_OK)
      failf(data, "schannel: ApplyControlToken failure: %s",
            Curl_sspi_strerror(conn, sspi_status));

    host_name = Curl_convert_UTF8_to_tchar(conn->host.name);
    if(!host_name)
      return CURLE_OUT_OF_MEMORY;

    /* setup output buffer */
    InitSecBuffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
    InitSecBufferDesc(&outbuf_desc, &outbuf, 1);

    sspi_status = s_pSecFn->InitializeSecurityContext(
      &connssl->cred->cred_handle,
      &connssl->ctxt->ctxt_handle,
      host_name,
      connssl->req_flags,
      0,
      0,
      NULL,
      0,
      &connssl->ctxt->ctxt_handle,
      &outbuf_desc,
      &connssl->ret_flags,
      &connssl->ctxt->time_stamp);

    Curl_unicodefree(host_name);

    if((sspi_status == SEC_E_OK) || (sspi_status == SEC_I_CONTEXT_EXPIRED)) {
      /* send close message which is in output buffer */
      ssize_t written;
      result = Curl_write_plain(conn, conn->sock[sockindex], outbuf.pvBuffer,
                                outbuf.cbBuffer, &written);

      s_pSecFn->FreeContextBuffer(outbuf.pvBuffer);
      if((result != CURLE_OK) || (outbuf.cbBuffer != (size_t) written)) {
        infof(data, "schannel: failed to send close msg: %s"
              " (bytes written: %zd)\n", curl_easy_strerror(result), written);
      }
    }
  }

  /* free SSPI Schannel API security context handle */
  if(connssl->ctxt) {
    infof(data, "schannel: clear security context handle\n");
    s_pSecFn->DeleteSecurityContext(&connssl->ctxt->ctxt_handle);
    Curl_safefree(connssl->ctxt);
  }

  /* free SSPI Schannel API credential handle */
  if(connssl->cred) {
    /* decrement the reference counter of the credential/session handle */
    if(connssl->cred->refcount > 0) {
      connssl->cred->refcount--;
      infof(data, "schannel: decremented credential handle refcount = %d\n",
            connssl->cred->refcount);
    }

    /* if the handle was not cached and the refcount is zero */
    if(!connssl->cred->cached && connssl->cred->refcount == 0) {
      infof(data, "schannel: clear credential handle\n");
      s_pSecFn->FreeCredentialsHandle(&connssl->cred->cred_handle);
      Curl_safefree(connssl->cred);
    }
  }

  /* free internal buffer for received encrypted data */
  if(connssl->encdata_buffer != NULL) {
    Curl_safefree(connssl->encdata_buffer);
    connssl->encdata_length = 0;
    connssl->encdata_offset = 0;
  }

  /* free internal buffer for received decrypted data */
  if(connssl->decdata_buffer != NULL) {
    Curl_safefree(connssl->decdata_buffer);
    connssl->decdata_length = 0;
    connssl->decdata_offset = 0;
  }

  return CURLE_OK;
}

void Curl_schannel_session_free(void *ptr)
{
  struct curl_schannel_cred *cred = ptr;

  if(cred && cred->cached) {
    if(cred->refcount == 0) {
      s_pSecFn->FreeCredentialsHandle(&cred->cred_handle);
      Curl_safefree(cred);
    }
    else {
      cred->cached = FALSE;
    }
  }
}

int Curl_schannel_init(void)
{
  return (Curl_sspi_global_init() == CURLE_OK ? 1 : 0);
}

void Curl_schannel_cleanup(void)
{
  Curl_sspi_global_cleanup();
}

size_t Curl_schannel_version(char *buffer, size_t size)
{
  size = snprintf(buffer, size, "WinSSL");

  return size;
}

int Curl_schannel_random(unsigned char *entropy, size_t length)
{
  HCRYPTPROV hCryptProv = 0;

  if(!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL,
                          CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return 1;

  if(!CryptGenRandom(hCryptProv, (DWORD)length, entropy)) {
    CryptReleaseContext(hCryptProv, 0UL);
    return 1;
  }

  CryptReleaseContext(hCryptProv, 0UL);
  return 0;
}

#ifdef _WIN32_WCE
static CURLcode verify_certificate(struct connectdata *conn, int sockindex)
{
  SECURITY_STATUS status;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  CURLcode result = CURLE_OK;
  CERT_CONTEXT *pCertContextServer = NULL;
  const CERT_CHAIN_CONTEXT *pChainContext = NULL;

  status = s_pSecFn->QueryContextAttributes(&connssl->ctxt->ctxt_handle,
                                            SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                            &pCertContextServer);

  if((status != SEC_E_OK) || (pCertContextServer == NULL)) {
    failf(data, "schannel: Failed to read remote certificate context: %s",
          Curl_sspi_strerror(conn, status));
    result = CURLE_PEER_FAILED_VERIFICATION;
  }

  if(result == CURLE_OK) {
    CERT_CHAIN_PARA ChainPara;
    memset(&ChainPara, 0, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);

    if(!CertGetCertificateChain(NULL,
                                pCertContextServer,
                                NULL,
                                pCertContextServer->hCertStore,
                                &ChainPara,
                                (data->set.ssl_no_revoke ? 0 :
                                 CERT_CHAIN_REVOCATION_CHECK_CHAIN),
                                NULL,
                                &pChainContext)) {
      failf(data, "schannel: CertGetCertificateChain failed: %s",
            Curl_sspi_strerror(conn, GetLastError()));
      pChainContext = NULL;
      result = CURLE_PEER_FAILED_VERIFICATION;
    }

    if(result == CURLE_OK) {
      CERT_SIMPLE_CHAIN *pSimpleChain = pChainContext->rgpChain[0];
      DWORD dwTrustErrorMask = ~(DWORD)(CERT_TRUST_IS_NOT_TIME_NESTED);
      dwTrustErrorMask &= pSimpleChain->TrustStatus.dwErrorStatus;
      if(dwTrustErrorMask) {
        if(dwTrustErrorMask & CERT_TRUST_IS_REVOKED)
          failf(data, "schannel: CertGetCertificateChain trust error"
                " CERT_TRUST_IS_REVOKED");
        else if(dwTrustErrorMask & CERT_TRUST_IS_PARTIAL_CHAIN)
          failf(data, "schannel: CertGetCertificateChain trust error"
                " CERT_TRUST_IS_PARTIAL_CHAIN");
        else if(dwTrustErrorMask & CERT_TRUST_IS_UNTRUSTED_ROOT)
          failf(data, "schannel: CertGetCertificateChain trust error"
                " CERT_TRUST_IS_UNTRUSTED_ROOT");
        else if(dwTrustErrorMask & CERT_TRUST_IS_NOT_TIME_VALID)
          failf(data, "schannel: CertGetCertificateChain trust error"
                " CERT_TRUST_IS_NOT_TIME_VALID");
        else
          failf(data, "schannel: CertGetCertificateChain error mask: 0x%08x",
                dwTrustErrorMask);
        result = CURLE_PEER_FAILED_VERIFICATION;
      }
    }
  }

  if(result == CURLE_OK) {
    if(data->set.ssl.verifyhost) {
      TCHAR cert_hostname_buff[128];
      xcharp_u hostname;
      xcharp_u cert_hostname;
      DWORD len;

      cert_hostname.const_tchar_ptr = cert_hostname_buff;
      hostname.tchar_ptr = Curl_convert_UTF8_to_tchar(conn->host.name);

      /* TODO: Fix this for certificates with multiple alternative names.
      Right now we're only asking for the first preferred alternative name.
      Instead we'd need to do all via CERT_NAME_SEARCH_ALL_NAMES_FLAG
      (if WinCE supports that?) and run this section in a loop for each.
      https://msdn.microsoft.com/en-us/library/windows/desktop/aa376086.aspx
      curl: (51) schannel: CertGetNameString() certificate hostname
      (.google.com) did not match connection (google.com)
      */
      len = CertGetNameString(pCertContextServer,
                              CERT_NAME_DNS_TYPE,
                              0,
                              NULL,
                              cert_hostname.tchar_ptr,
                              128);
      if(len > 0 && *cert_hostname.tchar_ptr == '*') {
        /* this is a wildcard cert.  try matching the last len - 1 chars */
        int hostname_len = strlen(conn->host.name);
        cert_hostname.tchar_ptr++;
        if(_tcsicmp(cert_hostname.const_tchar_ptr,
                    hostname.const_tchar_ptr + hostname_len - len + 2) != 0)
          result = CURLE_PEER_FAILED_VERIFICATION;
      }
      else if(len == 0 || _tcsicmp(hostname.const_tchar_ptr,
                                   cert_hostname.const_tchar_ptr) != 0) {
        result = CURLE_PEER_FAILED_VERIFICATION;
      }
      if(result == CURLE_PEER_FAILED_VERIFICATION) {
        char *_cert_hostname;
        _cert_hostname = Curl_convert_tchar_to_UTF8(cert_hostname.tchar_ptr);
        failf(data, "schannel: CertGetNameString() certificate hostname "
              "(%s) did not match connection (%s)",
              _cert_hostname, conn->host.name);
        Curl_unicodefree(_cert_hostname);
      }
      Curl_unicodefree(hostname.tchar_ptr);
    }
  }

  if(pChainContext)
    CertFreeCertificateChain(pChainContext);

  if(pCertContextServer)
    CertFreeCertificateContext(pCertContextServer);

  return result;
}
#endif /* _WIN32_WCE */

#endif /* USE_SCHANNEL */
