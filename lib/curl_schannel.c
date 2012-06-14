/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012, Marc Hoersken, <info@marc-hoersken.de>, et al.
 * Copyright (C) 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
 * Source file for all SChannel-specific code for the TLS/SSL layer. No code
 * but sslgen.c should ever call or use these functions.
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

/*
 * TODO list for TLS/SSL implementation:
 * - implement write buffering
 * - implement SSL/TLS shutdown
 * - implement client certificate authentication
 * - implement custom server certificate validation
 * - implement cipher/algorithm option
 *
 * Related articles on MSDN:
 * - Getting a Certificate for Schannel
 *   http://msdn.microsoft.com/en-us/library/windows/desktop/aa375447.aspx
 * - Specifying Schannel Ciphers and Cipher Strengths
 *   http://msdn.microsoft.com/en-us/library/windows/desktop/aa380161.aspx
 */

#include "setup.h"

#ifdef USE_SCHANNEL

#ifndef USE_WINDOWS_SSPI
#  error "Can't compile SCHANNEL support without SSPI."
#endif

#include "curl_sspi.h"
#include "curl_schannel.h"
#include "sslgen.h"
#include "sendf.h"
#include "connect.h" /* for the connect timeout */
#include "strerror.h"
#include "select.h" /* for the socket readyness */
#include "inet_pton.h" /* for IP addr SNI check */

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Uncomment to force verbose output
 * #define infof(x, y, ...) printf(y, __VA_ARGS__)
 * #define failf(x, y, ...) printf(y, __VA_ARGS__)
 */

static Curl_recv schannel_recv;
static Curl_send schannel_send;

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

  infof(data, "schannel: connecting to %s:%d (step 1/3)\n",
        conn->host.name, conn->remote_port);

  /* check for an existing re-usable credential handle */
  if(!Curl_ssl_getsessionid(conn, (void**)&old_cred, NULL)) {
    connssl->cred = old_cred;
    infof(data, "schannel: re-using existing credential handle\n");
  }
  else {
    /* setup Schannel API options */
    memset(&schannel_cred, 0, sizeof(schannel_cred));
    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;

    if(data->set.ssl.verifypeer) {
      schannel_cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION |
                              SCH_CRED_REVOCATION_CHECK_CHAIN;
      infof(data, "schannel: checking server certificate revocation\n");
    }
    else {
      schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION |
                              SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
                              SCH_CRED_IGNORE_REVOCATION_OFFLINE;
      infof(data, "schannel: disable server certificate revocation checks\n");
    }

    if(Curl_inet_pton(AF_INET, conn->host.name, &addr) ||
#ifdef ENABLE_IPV6
       Curl_inet_pton(AF_INET6, conn->host.name, &addr6) ||
#endif
       data->set.ssl.verifyhost < 2) {
      schannel_cred.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK;
      infof(data, "schannel: using IP address, disable SNI servername "
            "check\n");
    }

    switch(data->set.ssl.version) {
      case CURL_SSLVERSION_TLSv1:
        schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT |
                                              SP_PROT_TLS1_1_CLIENT |
                                              SP_PROT_TLS1_2_CLIENT;
        break;
      case CURL_SSLVERSION_SSLv3:
        schannel_cred.grbitEnabledProtocols = SP_PROT_SSL3_CLIENT;
        break;
      case CURL_SSLVERSION_SSLv2:
        schannel_cred.grbitEnabledProtocols = SP_PROT_SSL2_CLIENT;
        break;
    }

    /* allocate memory for the re-usable credential handle */
    connssl->cred = malloc(sizeof(struct curl_schannel_cred));
    if(!connssl->cred) {
      failf(data, "schannel: unable to allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }
    memset(connssl->cred, 0, sizeof(struct curl_schannel_cred));

    /* http://msdn.microsoft.com/en-us/library/windows/desktop/aa374716.aspx */
    sspi_status = s_pSecFn->AcquireCredentialsHandle(NULL, (void *)UNISP_NAME,
      SECPKG_CRED_OUTBOUND, NULL, &schannel_cred, NULL, NULL,
      &connssl->cred->cred_handle, &connssl->cred->time_stamp);

    if(sspi_status != SEC_E_OK) {
      if(sspi_status == SEC_E_WRONG_PRINCIPAL)
        failf(data, "schannel: SNI or certificate check failed: %s\n",
              Curl_sspi_strerror(conn, sspi_status));
      else
        failf(data, "schannel: AcquireCredentialsHandleA failed: %s\n",
              Curl_sspi_strerror(conn, sspi_status));
      free(connssl->cred);
      connssl->cred = NULL;
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* setup output buffer */
  outbuf.pvBuffer = NULL;
  outbuf.cbBuffer = 0;
  outbuf.BufferType = SECBUFFER_EMPTY;

  outbuf_desc.pBuffers = &outbuf;
  outbuf_desc.cBuffers = 1;
  outbuf_desc.ulVersion = SECBUFFER_VERSION;

  /* setup request flags */
  connssl->req_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                       ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                       ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

  /* allocate memory for the security context handle */
  connssl->ctxt = malloc(sizeof(struct curl_schannel_ctxt));
  if(!connssl->ctxt) {
    failf(data, "schannel: unable to allocate memory");
    return CURLE_OUT_OF_MEMORY;
  }
  memset(connssl->ctxt, 0, sizeof(struct curl_schannel_ctxt));

  /* http://msdn.microsoft.com/en-us/library/windows/desktop/aa375924.aspx */
  sspi_status = s_pSecFn->InitializeSecurityContext(
    &connssl->cred->cred_handle, NULL, conn->host.name,
    connssl->req_flags, 0, 0, NULL, 0, &connssl->ctxt->ctxt_handle,
    &outbuf_desc, &connssl->ret_flags, &connssl->ctxt->time_stamp);

  if(sspi_status != SEC_I_CONTINUE_NEEDED) {
    if(sspi_status == SEC_E_WRONG_PRINCIPAL)
      failf(data, "schannel: SNI or certificate check failed: %s\n",
            Curl_sspi_strerror(conn, sspi_status));
    else
      failf(data, "schannel: initial InitializeSecurityContextA failed: %s\n",
            Curl_sspi_strerror(conn, sspi_status));
    free(connssl->ctxt);
    connssl->ctxt = NULL;
    return CURLE_SSL_CONNECT_ERROR;
  }

  infof(data, "schannel: sending initial handshake data: %d ...\n",
        outbuf.cbBuffer);

  /* send initial handshake data which is now stored in output buffer */
  written = swrite(conn->sock[sockindex], outbuf.pvBuffer, outbuf.cbBuffer);
  s_pSecFn->FreeContextBuffer(outbuf.pvBuffer);
  if(outbuf.cbBuffer != (size_t)written) {
    failf(data, "schannel: failed to send initial handshake data: %d\n",
          written);
    return CURLE_SSL_CONNECT_ERROR;
  }

  infof(data, "schannel: sent initial handshake data: %d\n", written);

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
  SecBuffer outbuf[2];
  SecBufferDesc outbuf_desc;
  SecBuffer inbuf[2];
  SecBufferDesc inbuf_desc;
  SECURITY_STATUS sspi_status = SEC_E_OK;

  infof(data, "schannel: connecting to %s:%d (step 2/3)\n",
        conn->host.name, conn->remote_port);

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

  /* read encrypted handshake data from socket */
  nread = sread(conn->sock[sockindex],
                connssl->encdata_buffer + connssl->encdata_offset,
                connssl->encdata_length - connssl->encdata_offset);
  if(nread > 0) {
    /* increase encrypted data buffer offset */
    connssl->encdata_offset += nread;
  }
  else if(connssl->connecting_state != ssl_connect_2_writing) {
    if(nread < 0) {
      connssl->connecting_state = ssl_connect_2_reading;
      infof(data, "schannel: failed to receive handshake, need more data\n");
      return CURLE_OK;
    }
    else if(nread == 0) {
      failf(data, "schannel: failed to receive handshake, connection "
            "failed\n");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  infof(data, "schannel: encrypted data buffer %d/%d\n",
    connssl->encdata_offset, connssl->encdata_length);

  /* setup input buffers */
  inbuf[0].pvBuffer = malloc(connssl->encdata_offset);
  inbuf[0].cbBuffer = connssl->encdata_offset;
  inbuf[0].BufferType = SECBUFFER_TOKEN;

  inbuf[1].pvBuffer = NULL;
  inbuf[1].cbBuffer = 0;
  inbuf[1].BufferType = SECBUFFER_EMPTY;

  inbuf_desc.pBuffers = &inbuf[0];
  inbuf_desc.cBuffers = 2;
  inbuf_desc.ulVersion = SECBUFFER_VERSION;

  /* setup output buffers */
  outbuf[0].pvBuffer = NULL;
  outbuf[0].cbBuffer = 0;
  outbuf[0].BufferType = SECBUFFER_TOKEN;

  outbuf[1].pvBuffer = NULL;
  outbuf[1].cbBuffer = 0;
  outbuf[1].BufferType = SECBUFFER_ALERT;

  outbuf_desc.pBuffers = &outbuf[0];
  outbuf_desc.cBuffers = 2;
  outbuf_desc.ulVersion = SECBUFFER_VERSION;

  if(inbuf[0].pvBuffer == NULL) {
    failf(data, "schannel: unable to allocate memory");
    return CURLE_OUT_OF_MEMORY;
  }

  /* copy received handshake data into input buffer */
  memcpy(inbuf[0].pvBuffer, connssl->encdata_buffer, connssl->encdata_offset);

  /* http://msdn.microsoft.com/en-us/library/windows/desktop/aa375924.aspx */
  sspi_status = s_pSecFn->InitializeSecurityContext(
    &connssl->cred->cred_handle, &connssl->ctxt->ctxt_handle,
    conn->host.name, connssl->req_flags, 0, 0, &inbuf_desc, 0, NULL,
    &outbuf_desc, &connssl->ret_flags, &connssl->ctxt->time_stamp);

  /* free buffer for received handshake data */
  free(inbuf[0].pvBuffer);

  /* check if the handshake was incomplete */
  if(sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
    connssl->connecting_state = ssl_connect_2_reading;
    infof(data, "schannel: received incomplete message, need more data\n");
    return CURLE_OK;
  }

  /* check if the handshake needs to be continued */
  if(sspi_status == SEC_I_CONTINUE_NEEDED || sspi_status == SEC_E_OK) {
    for(i = 0; i < 2; i++) {
      /* search for handshake tokens that need to be send */
      if(outbuf[i].BufferType == SECBUFFER_TOKEN && outbuf[i].cbBuffer > 0) {
        infof(data, "schannel: sending next handshake data: %d ...\n",
              outbuf[i].cbBuffer);

        /* send handshake token to server */
        written = swrite(conn->sock[sockindex],
                         outbuf[i].pvBuffer, outbuf[i].cbBuffer);
        if(outbuf[i].cbBuffer != (size_t)written) {
          failf(data, "schannel: failed to send next handshake data: %d\n",
                written);
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
      failf(data, "schannel: SNI or certificate check failed: %s\n",
            Curl_sspi_strerror(conn, sspi_status));
    else
      failf(data, "schannel: next InitializeSecurityContextA failed: %s\n",
            Curl_sspi_strerror(conn, sspi_status));
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* check if there was additional remaining encrypted data */
  if(inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer > 0) {
    infof(data, "schannel: encrypted data length: %d\n", inbuf[1].cbBuffer);

    /* check if the remaining data is less than the total amount
     * and therefore begins after the already processed data
     */
    if(connssl->encdata_offset > inbuf[1].cbBuffer) {
      memmove(connssl->encdata_buffer,
              (connssl->encdata_buffer + connssl->encdata_offset) -
                inbuf[1].cbBuffer, inbuf[1].cbBuffer);
      connssl->encdata_offset = inbuf[1].cbBuffer;
    }
  }
  else {
    connssl->encdata_offset = 0;
  }

  /* check if the handshake needs to be continued */
  if(sspi_status == SEC_I_CONTINUE_NEEDED) {
    connssl->connecting_state = ssl_connect_2_reading;
    return CURLE_OK;
  }

  /* check if the handshake is complete */
  if(sspi_status == SEC_E_OK) {
    connssl->connecting_state = ssl_connect_3;
    infof(data, "schannel: handshake complete\n");
  }

  return CURLE_OK;
}

static CURLcode
schannel_connect_step3(struct connectdata *conn, int sockindex)
{
  CURLcode retcode = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct curl_schannel_cred *old_cred = NULL;
  int incache;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  infof(data, "schannel: connecting to %s:%d (step 3/3)\n",
        conn->host.name, conn->remote_port);

  /* check if the required context attributes are met */
  if(connssl->ret_flags != connssl->req_flags) {
    if(!(connssl->ret_flags & ISC_RET_SEQUENCE_DETECT))
      failf(data, "schannel: failed to setup sequence detection\n");
    if(!(connssl->ret_flags & ISC_RET_REPLAY_DETECT))
      failf(data, "schannel: failed to setup replay detection\n");
    if(!(connssl->ret_flags & ISC_RET_CONFIDENTIALITY))
      failf(data, "schannel: failed to setup confidentiality\n");
    if(!(connssl->ret_flags & ISC_RET_EXTENDED_ERROR))
      failf(data, "schannel: failed to setup extended errors\n");
    if(!(connssl->ret_flags & ISC_RET_ALLOCATED_MEMORY))
      failf(data, "schannel: failed to setup memory allocation\n");
    if(!(connssl->ret_flags & ISC_RET_STREAM))
      failf(data, "schannel: failed to setup stream orientation\n");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* save the current session data for possible re-use */
  incache = !(Curl_ssl_getsessionid(conn, (void**)&old_cred, NULL));
  if(incache) {
    if(old_cred != connssl->cred) {
      infof(data, "schannel: old credential handle is stale, removing\n");
      Curl_ssl_delsessionid(conn, (void*)old_cred);
      incache = FALSE;
    }
  }
  if(!incache) {
    retcode = Curl_ssl_addsessionid(conn, (void*)connssl->cred,
                                    sizeof(struct curl_schannel_cred));
    if(retcode) {
      failf(data, "schannel: failed to store credential handle\n");
      return retcode;
    }
    else {
      infof(data, "schannel: stored crendential handle\n");
    }
  }

  connssl->connecting_state = ssl_connect_done;

  return CURLE_OK;
}

static CURLcode
schannel_connect_common(struct connectdata *conn, int sockindex,
                        bool nonblocking, bool *done)
{
  CURLcode retcode;
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
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    retcode = schannel_connect_step1(conn, sockindex);
    if(retcode)
      return retcode;
  }

  while(ssl_connect_2 == connssl->connecting_state ||
        ssl_connect_2_reading == connssl->connecting_state ||
        ssl_connect_2_writing == connssl->connecting_state) {

    /* check out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
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
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          /* timeout */
          failf(data, "SSL connection timeout");
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
    retcode = schannel_connect_step2(conn, sockindex);
    if(retcode || (nonblocking &&
                   (ssl_connect_2 == connssl->connecting_state ||
                    ssl_connect_2_reading == connssl->connecting_state ||
                    ssl_connect_2_writing == connssl->connecting_state)))
      return retcode;

  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    retcode = schannel_connect_step3(conn, sockindex);
    if(retcode)
      return retcode;
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
  data = (unsigned char*) malloc(data_len);
  if(data == NULL) {
    *err = CURLE_OUT_OF_MEMORY;
    return -1;
  }

  /* setup output buffers (header, data, trailer, empty) */
  outbuf[0].pvBuffer = data;
  outbuf[0].cbBuffer = connssl->stream_sizes.cbHeader;
  outbuf[0].BufferType = SECBUFFER_STREAM_HEADER;

  outbuf[1].pvBuffer = data + connssl->stream_sizes.cbHeader;
  outbuf[1].cbBuffer = len;
  outbuf[1].BufferType = SECBUFFER_DATA;

  outbuf[2].pvBuffer = data + connssl->stream_sizes.cbHeader + len;
  outbuf[2].cbBuffer = connssl->stream_sizes.cbTrailer;
  outbuf[2].BufferType = SECBUFFER_STREAM_TRAILER;

  outbuf[3].pvBuffer = NULL;
  outbuf[3].cbBuffer = 0;
  outbuf[3].BufferType = SECBUFFER_EMPTY;

  outbuf_desc.pBuffers = &outbuf[0];
  outbuf_desc.cBuffers = 4;
  outbuf_desc.ulVersion = SECBUFFER_VERSION;

  /* copy data into output buffer */
  memcpy(outbuf[1].pvBuffer, buf, len);

  /* http://msdn.microsoft.com/en-us/library/windows/desktop/aa375390.aspx */
  sspi_status = s_pSecFn->EncryptMessage(&connssl->ctxt->ctxt_handle, 0,
                                         &outbuf_desc, 0);

  /* check if the message was encrypted */
  if(sspi_status == SEC_E_OK) {
    /* send the encrypted message including header, data and trailer */
    len = outbuf[0].cbBuffer + outbuf[1].cbBuffer + outbuf[2].cbBuffer;
    written = swrite(conn->sock[sockindex], data, len);
    /* TODO: implement write buffering */
  }
  else if(sspi_status == SEC_E_INSUFFICIENT_MEMORY) {
    *err = CURLE_OUT_OF_MEMORY;
  }
  else{
    *err = CURLE_SEND_ERROR;
  }

  free(data);

  return written;
}

static ssize_t
schannel_recv(struct connectdata *conn, int sockindex,
              char *buf, size_t len, CURLcode *err)
{
  size_t size = 0;
  ssize_t nread = 0, ret = -1;
  CURLcode retcode;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  bool done = FALSE;
  SecBuffer inbuf[4];
  SecBufferDesc inbuf_desc;
  SECURITY_STATUS sspi_status = SEC_E_OK;

  infof(data, "schannel: client wants to read %d\n", len);
  *err = CURLE_OK;

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

  /* increase buffer in order to fit the requested amount of data */
  while(connssl->encdata_length - connssl->encdata_offset <
        CURL_SCHANNEL_BUFFER_STEP_SIZE || connssl->encdata_length < len) {
    /* increase internal encrypted data buffer */
    connssl->encdata_length += CURL_SCHANNEL_BUFFER_STEP_SIZE;
    connssl->encdata_buffer = realloc(connssl->encdata_buffer,
                                      connssl->encdata_length);
    if(connssl->encdata_buffer == NULL) {
      failf(data, "schannel: unable to re-allocate memory");
      *err = CURLE_OUT_OF_MEMORY;
      return -1;
    }
  }

  /* read encrypted data from socket */
  infof(data, "schannel: encrypted data buffer %d/%d\n",
        connssl->encdata_offset, connssl->encdata_length);
  size = connssl->encdata_length - connssl->encdata_offset;
  if(size > 0) {
    nread = sread(conn->sock[sockindex],
                  connssl->encdata_buffer + connssl->encdata_offset, size);
    infof(data, "schannel: encrypted data received %d\n", nread);

    /* check for received data */
    if(nread > 0) {
      /* increase encrypted data buffer offset */
      connssl->encdata_offset += nread;
    }
    else if(connssl->encdata_offset == 0) {
      if(nread == 0)
        ret = 0;
      else
        *err = CURLE_AGAIN;
    }
  }

  infof(data, "schannel: encrypted data buffer %d/%d\n",
    connssl->encdata_offset, connssl->encdata_length);

  /* check if we still have some data in our buffers */
  while(connssl->encdata_offset > 0 && sspi_status == SEC_E_OK) {
    /* prepare data buffer for DecryptMessage call */
    inbuf[0].pvBuffer = connssl->encdata_buffer;
    inbuf[0].cbBuffer = connssl->encdata_offset;
    inbuf[0].BufferType = SECBUFFER_DATA;

    /* we need 3 more empty input buffers for possible output */
    inbuf[1].pvBuffer = NULL;
    inbuf[1].cbBuffer = 0;
    inbuf[1].BufferType = SECBUFFER_EMPTY;

    inbuf[2].pvBuffer = NULL;
    inbuf[2].cbBuffer = 0;
    inbuf[2].BufferType = SECBUFFER_EMPTY;

    inbuf[3].pvBuffer = NULL;
    inbuf[3].cbBuffer = 0;
    inbuf[3].BufferType = SECBUFFER_EMPTY;

    inbuf_desc.pBuffers = &inbuf[0];
    inbuf_desc.cBuffers = 4;
    inbuf_desc.ulVersion = SECBUFFER_VERSION;

    /* http://msdn.microsoft.com/en-us/library/windows/desktop/aa375348.aspx */
    sspi_status = s_pSecFn->DecryptMessage(&connssl->ctxt->ctxt_handle,
                                           &inbuf_desc, 0, NULL);

    /* check if we need more data */
    if(sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
      infof(data, "schannel: failed to decrypt data, need more data\n");
      *err = CURLE_AGAIN;
      return -1;
    }

    /* check if everything went fine (server may want to renegotiate
       context) */
    if(sspi_status == SEC_E_OK || sspi_status == SEC_I_RENEGOTIATE ||
                                  sspi_status == SEC_I_CONTEXT_EXPIRED) {
      /* check for successfully decrypted data */
      if(inbuf[1].BufferType == SECBUFFER_DATA) {
        infof(data, "schannel: decrypted data length: %d\n",
              inbuf[1].cbBuffer);

        /* increase buffer in order to fit the received amount of data */
        size = inbuf[1].cbBuffer > CURL_SCHANNEL_BUFFER_STEP_SIZE ?
               inbuf[1].cbBuffer : CURL_SCHANNEL_BUFFER_STEP_SIZE;
        while(connssl->decdata_length - connssl->decdata_offset < size ||
              connssl->decdata_length < len) {
          /* increase internal decrypted data buffer */
          connssl->decdata_length += size;
          connssl->decdata_buffer = realloc(connssl->decdata_buffer,
                                            connssl->decdata_length);
          if(connssl->decdata_buffer == NULL) {
            failf(data, "schannel: unable to re-allocate memory");
            *err = CURLE_OUT_OF_MEMORY;
            return -1;
          }
        }

        /* copy decrypted data to internal buffer */
        size = inbuf[1].cbBuffer;
        if(size > 0) {
          memcpy(connssl->decdata_buffer + connssl->decdata_offset,
                 inbuf[1].pvBuffer, size);
          connssl->decdata_offset += size;
        }

        infof(data, "schannel: decrypted data added: %d\n", size);
        infof(data, "schannel: decrypted data cached: %d/%d\n",
              connssl->decdata_offset, connssl->decdata_length);
      }

      /* check for remaining encrypted data */
      if(inbuf[3].BufferType == SECBUFFER_EXTRA && inbuf[3].cbBuffer > 0) {
        infof(data, "schannel: encrypted data length: %d\n",
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

        infof(data, "schannel: encrypted data cached: %d/%d\n",
              connssl->encdata_offset, connssl->encdata_length);
      }
      else{
        /* reset encrypted buffer offset, because there is no data remaining */
        connssl->encdata_offset = 0;
      }
    }

    /* check if server wants to renegotiate the connection context */
    if(sspi_status == SEC_I_RENEGOTIATE) {
      infof(data, "schannel: client needs to renegotiate with server\n");

      /* begin renegotiation */
      connssl->state = ssl_connection_negotiating;
      connssl->connecting_state = ssl_connect_2_writing;
      retcode = schannel_connect_common(conn, sockindex, FALSE, &done);
      if(retcode)
        *err = retcode;
      else /* now retry receiving data */
        return schannel_recv(conn, sockindex, buf, len, err);
    }
  }

  /* copy requested decrypted data to supplied buffer */
  size = len < connssl->decdata_offset ? len : connssl->decdata_offset;
  if(size > 0) {
    memcpy(buf, connssl->decdata_buffer, size);
    ret = size;

    /* move remaining decrypted data forward to the beginning of buffer */
    memmove(connssl->decdata_buffer, connssl->decdata_buffer + size,
            connssl->decdata_offset - size);
    connssl->decdata_offset -= size;
  }

  /* reduce internal buffer length to reduce memory usage */
  if(connssl->encdata_length > CURL_SCHANNEL_BUFFER_INIT_SIZE) {
    connssl->encdata_length =
      connssl->encdata_offset > CURL_SCHANNEL_BUFFER_INIT_SIZE ?
      connssl->encdata_offset : CURL_SCHANNEL_BUFFER_INIT_SIZE;
    connssl->encdata_buffer = realloc(connssl->encdata_buffer,
                                      connssl->encdata_length);
  }
  if(connssl->decdata_length > CURL_SCHANNEL_BUFFER_INIT_SIZE) {
    connssl->decdata_length =
      connssl->decdata_offset > CURL_SCHANNEL_BUFFER_INIT_SIZE ?
      connssl->decdata_offset : CURL_SCHANNEL_BUFFER_INIT_SIZE;
    connssl->decdata_buffer = realloc(connssl->decdata_buffer,
                                      connssl->decdata_length);
  }

  /* check if the server closed the connection */
  if(ret <= 0 && ( /* special check for Windows 2000 Professional */
      sspi_status == SEC_I_CONTEXT_EXPIRED || (sspi_status == SEC_E_OK &&
        connssl->encdata_offset > 0 && connssl->encdata_buffer[0] == 0x15))) {
    infof(data, "schannel: server closed the connection\n");
    *err = CURLE_OK;
    return 0;
  }

  /* check if something went wrong and we need to return an error */
  if(ret < 0 && sspi_status != SEC_E_OK) {
    infof(data, "schannel: failed to read data from server: %s\n",
          Curl_sspi_strerror(conn, sspi_status));
    *err = CURLE_RECV_ERROR;
    return -1;
  }

  return ret;
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
  CURLcode retcode;
  bool done = FALSE;

  retcode = schannel_connect_common(conn, sockindex, FALSE, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}

bool Curl_schannel_data_pending(const struct connectdata *conn, int sockindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->use) /* SSL is in use */
    return (connssl->encdata_offset > 0 ||
            connssl->decdata_offset > 0 ) ? TRUE : FALSE;
  else
    return FALSE;
}

void Curl_schannel_close(struct connectdata *conn, int sockindex)
{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  infof(data, "schannel: Closing connection with %s:%d\n",
        conn->host.name, conn->remote_port);

  /* free SSPI Schannel API security context handle */
  if(connssl->ctxt) {
    s_pSecFn->DeleteSecurityContext(&connssl->ctxt->ctxt_handle);
    free(connssl->ctxt);
    connssl->ctxt = NULL;
  }

  /* free internal buffer for received encrypted data */
  if(connssl->encdata_buffer != NULL) {
    free(connssl->encdata_buffer);
    connssl->encdata_buffer = NULL;
    connssl->encdata_length = 0;
    connssl->encdata_offset = 0;
  }

  /* free internal buffer for received decrypted data */
  if(connssl->decdata_buffer != NULL) {
    free(connssl->decdata_buffer);
    connssl->decdata_buffer = NULL;
    connssl->decdata_length = 0;
    connssl->decdata_offset = 0;
  }
}

int Curl_schannel_shutdown(struct connectdata *conn, int sockindex)
{
  return CURLE_NOT_BUILT_IN; /* TODO: implement SSL/TLS shutdown */
}

void Curl_schannel_session_free(void *ptr)
{
  struct curl_schannel_cred *cred = ptr;

  if(cred) {
    s_pSecFn->FreeCredentialsHandle(&cred->cred_handle);
    free(cred);
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
  size = snprintf(buffer, size, "SSL-Windows-native");

  return size;
}

#endif /* USE_SCHANNEL */
