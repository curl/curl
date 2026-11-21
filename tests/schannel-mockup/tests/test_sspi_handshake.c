/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "sspi.h"
#include "schannel.h"
#include "windows.h"
#include "wincrypt.h"

static void generate_test_cert_and_key(X509 **out_cert, EVP_PKEY **out_pkey)
{
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY *pkey = NULL;
  X509 *cert;
  X509_NAME *name;
  assert(pctx != NULL);
  assert(EVP_PKEY_keygen_init(pctx) > 0);
  assert(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0);
  assert(EVP_PKEY_keygen(pctx, &pkey) > 0);
  EVP_PKEY_CTX_free(pctx);

  cert = X509_new();
  assert(cert != NULL);
  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 3600);
  X509_set_pubkey(cert, pkey);

  name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (const unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(cert, name);
  X509_sign(cert, pkey, EVP_sha256());

  *out_cert = cert;
  *out_pkey = pkey;
}

static int server_alpn_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg)
{
  unsigned int i = 0;
  (void)ssl;
  (void)arg;
  while(i < inlen) {
    unsigned char len = in[i++];
    if(i + len <= inlen) {
      if(len == 2 && in[i] == 'h' && in[i + 1] == '2') {
        *out = &in[i];
        *outlen = 2;
        return SSL_TLSEXT_ERR_OK;
      }
      i += len;
    }
  }
  return SSL_TLSEXT_ERR_NOACK;
}

static void build_alpn_buffer(unsigned char *buf, size_t *out_len)
{
  const unsigned char wire_protos[] = "\x02h2\x08http/1.1";
  unsigned short list_len = (unsigned short)(sizeof(wire_protos) - 1);
  unsigned int ext_len =
    (unsigned int)(list_len + sizeof(unsigned int) + sizeof(unsigned short));
  unsigned int ext_type = SecApplicationProtocolNegotiationExt_ALPN;

  size_t cur = 0;
  memcpy(buf + cur, &ext_len, sizeof(ext_len));
  cur += sizeof(ext_len);

  memcpy(buf + cur, &ext_type, sizeof(ext_type));
  cur += sizeof(ext_type);

  memcpy(buf + cur, &list_len, sizeof(list_len));
  cur += sizeof(list_len);

  memcpy(buf + cur, wire_protos, list_len);
  cur += list_len;

  *out_len = cur;
}

int main(void)
{
  SECURITY_STATUS status;
  PSecurityFunctionTableA sspi_a = InitSecurityInterfaceA();
  PSecurityFunctionTableW sspi_w;
  CredHandle cred_handle = { 0, 0 };
  TimeStamp expiry;
  SecBuffer out_token_buf;
  BIO *server_rbio;
  BIO *server_wbio;
  SSL *server_ssl = NULL;
  SSL_CTX *server_ctx = NULL;
  X509 *server_cert = NULL;
  EVP_PKEY *server_pkey = NULL;
  unsigned char *server_flight;
  CtxtHandle ctxt_handle = { 0, 0 };
  char target_name[] = "localhost";
  unsigned long req_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
    ISC_REQ_CONFIDENTIALITY | ISC_REQ_SEQUENCE_DETECT |
    ISC_REQ_REPLAY_DETECT;
  unsigned long ret_flags = 0;
  int server_bytes;
  unsigned char *flight_with_extra = NULL;
  SecBuffer in_leg2[2];
  SecBufferDesc in_leg2_desc;
  SecBuffer out_leg2[3];
  SecBufferDesc out_leg2_desc;
  SecBufferDesc out_desc;

  assert(sspi_a != NULL);
  sspi_w = InitSecurityInterfaceW();
  assert(sspi_w != NULL);

  printf("Schannel Mockup Handshake Engine Tests\n\n");

  /* 1. Setup OpenSSL test server with in-memory cert and ALPN */
  printf("1. Setting up in-memory OpenSSL TLS test server\n");
  {
    generate_test_cert_and_key(&server_cert, &server_pkey);

    server_ctx = SSL_CTX_new(TLS_server_method());
    assert(server_ctx != NULL);
    assert(SSL_CTX_use_certificate(server_ctx, server_cert) > 0);
    assert(SSL_CTX_use_PrivateKey(server_ctx, server_pkey) > 0);
    SSL_CTX_set_alpn_select_cb(server_ctx, server_alpn_cb, NULL);

    server_ssl = SSL_new(server_ctx);
    assert(server_ssl != NULL);
    server_rbio = BIO_new(BIO_s_mem());
    server_wbio = BIO_new(BIO_s_mem());
    assert(server_rbio && server_wbio);
    BIO_set_mem_eof_return(server_rbio, -1);
    BIO_set_mem_eof_return(server_wbio, -1);
    SSL_set_bio(server_ssl, server_rbio, server_wbio);
    SSL_set_accept_state(server_ssl);
  }
  printf(" PASS: Test server initialized.\n\n");

  /* 2. Acquire client credential handle */
  printf("2. Acquiring client credential handle\n");
  {
    SCH_CREDENTIALS sch_creds;
    TLS_PARAMETERS tls_params;

    memset(&sch_creds, 0, sizeof(sch_creds));
    memset(&tls_params, 0, sizeof(tls_params));
    sch_creds.dwVersion = SCH_CREDENTIALS_VERSION;
    sch_creds.dwFlags = SCH_USE_STRONG_CRYPTO |
      SCH_CRED_MANUAL_CRED_VALIDATION;
    sch_creds.cTlsParameters = 1;
    sch_creds.pTlsParameters = &tls_params;
    tls_params.grbitDisabledProtocols = ~(SP_PROT_TLS1_2_CLIENT |
                                          SP_PROT_TLS1_3_CLIENT);

    status = sspi_a->AcquireCredentialsHandleA(
      NULL, UNCONST(UNISP_NAME_A), SECPKG_CRED_OUTBOUND, NULL,
      &sch_creds, NULL, NULL, &cred_handle, &expiry);
    assert(status == SEC_E_OK);
  }
  printf(" PASS: Client credential handle acquired.\n\n");

  /* 3. Handshake Leg 1: Generate ClientHello with SNI and ALPN */
  printf("3. Testing Handshake Leg 1 (InitializeSecurityContextA)\n");
  {
    unsigned char alpn_buf[128];
    size_t alpn_len = 0;
    SecBuffer in_alpn_buf;
    SecBufferDesc in_desc;

    build_alpn_buffer(alpn_buf, &alpn_len);

    in_alpn_buf.BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
    in_alpn_buf.pvBuffer = alpn_buf;
    in_alpn_buf.cbBuffer = (unsigned long)alpn_len;

    in_desc.ulVersion = SECBUFFER_VERSION;
    in_desc.cBuffers = 1;
    in_desc.pBuffers = &in_alpn_buf;

    out_token_buf.BufferType = SECBUFFER_EMPTY;
    out_token_buf.pvBuffer = NULL;
    out_token_buf.cbBuffer = 0;

    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &out_token_buf;

    status = sspi_a->InitializeSecurityContextA(
      &cred_handle, NULL, target_name, req_flags, 0, 0,
      &in_desc, 0, &ctxt_handle, &out_desc, &ret_flags, &expiry);

    assert(status == SEC_I_CONTINUE_NEEDED);
    assert(ctxt_handle.dwLower != 0);
    assert(ctxt_handle.dwUpper == 0x4D435458); /* MOCK_MAGIC_CTXT */
    assert(out_token_buf.BufferType == SECBUFFER_TOKEN);
    assert(out_token_buf.pvBuffer != NULL);
    assert(out_token_buf.cbBuffer > 0);
  }
  printf(" PASS: Leg 1 generated ClientHello (%lu bytes).\n\n",
         out_token_buf.cbBuffer);

  /* 4. Feed ClientHello to server and get server response */
  printf("4. Processing ClientHello on server\n");
  {
    int server_ret;
    size_t server_pending;

    BIO_write(server_rbio, out_token_buf.pvBuffer,
              (int)out_token_buf.cbBuffer);
    sspi_a->FreeContextBuffer(out_token_buf.pvBuffer);
    out_token_buf.pvBuffer = NULL;

    server_ret = SSL_accept(server_ssl);
    (void)server_ret;
    server_pending = (size_t)BIO_ctrl_pending(server_wbio);
    assert(server_pending > 0);

    server_flight = (unsigned char *)malloc(server_pending);
    assert(server_flight != NULL);
    server_bytes = BIO_read(server_wbio, server_flight, (int)server_pending);
    assert(server_bytes > 0);
    printf(" PASS: Server processed ClientHello and produced response"
           " (%d bytes).\n\n", server_bytes);
  }

  /* 5. Test incomplete record detection on client */
  printf("5. Testing incomplete message detection "
         "(SEC_E_INCOMPLETE_MESSAGE)\n");
  {
    SecBuffer in_partial[2];
    SecBufferDesc in_partial_desc;
    SecBuffer out_dummy[3];
    SecBufferDesc out_dummy_desc;
    in_partial_desc.ulVersion = SECBUFFER_VERSION;
    in_partial_desc.cBuffers = 2;
    in_partial_desc.pBuffers = in_partial;

    /* Test with less than 5 bytes (incomplete TLS header) */
    in_partial[0].BufferType = SECBUFFER_TOKEN;
    in_partial[0].pvBuffer = server_flight;
    in_partial[0].cbBuffer = 3;
    in_partial[1].BufferType = SECBUFFER_EMPTY;
    in_partial[1].pvBuffer = NULL;
    in_partial[1].cbBuffer = 0;

    out_dummy_desc.ulVersion = SECBUFFER_VERSION;
    out_dummy_desc.cBuffers = 3;
    out_dummy_desc.pBuffers = out_dummy;
    out_dummy[0].BufferType = SECBUFFER_TOKEN;
    out_dummy[0].pvBuffer = NULL;
    out_dummy[0].cbBuffer = 0;
    out_dummy[1].BufferType = SECBUFFER_ALERT;
    out_dummy[1].pvBuffer = NULL;
    out_dummy[1].cbBuffer = 0;
    out_dummy[2].BufferType = SECBUFFER_EMPTY;
    out_dummy[2].pvBuffer = NULL;
    out_dummy[2].cbBuffer = 0;

    status = sspi_a->InitializeSecurityContextA(
      &cred_handle, &ctxt_handle, target_name, req_flags, 0, 0,
      &in_partial_desc, 0, NULL, &out_dummy_desc, &ret_flags, &expiry);
    assert(status == SEC_E_INCOMPLETE_MESSAGE);

    /* Test with header present but truncated payload */
    in_partial[0].cbBuffer = 10;
    status = sspi_a->InitializeSecurityContextA(
      &cred_handle, &ctxt_handle, target_name, req_flags, 0, 0,
      &in_partial_desc, 0, NULL, &out_dummy_desc, &ret_flags, &expiry);
    assert(status == SEC_E_INCOMPLETE_MESSAGE);
  }
  printf(" PASS: SEC_E_INCOMPLETE_MESSAGE returned for "
         "partial TLS records.\n\n");

  /* 6. Handshake Leg 2+: Feed server flight with extra trailing data to
     client */
  printf("6. Testing extra data (SECBUFFER_EXTRA) and handshake loopback\n");
  {
    size_t flight_with_extra_len = (size_t)server_bytes + 16;

    flight_with_extra = (unsigned char *)malloc(flight_with_extra_len);

    assert(flight_with_extra != NULL);
    memcpy(flight_with_extra, server_flight, server_bytes);
    memset(flight_with_extra + server_bytes, 0xEE, 16);

    in_leg2[0].BufferType = SECBUFFER_TOKEN;
    in_leg2[0].pvBuffer = flight_with_extra;
    in_leg2[0].cbBuffer = (unsigned long)flight_with_extra_len;
    in_leg2[1].BufferType = SECBUFFER_EMPTY;
    in_leg2[1].pvBuffer = NULL;
    in_leg2[1].cbBuffer = 0;

    in_leg2_desc.ulVersion = SECBUFFER_VERSION;
    in_leg2_desc.cBuffers = 2;
    in_leg2_desc.pBuffers = in_leg2;

    out_leg2[0].BufferType = SECBUFFER_TOKEN;
    out_leg2[0].pvBuffer = NULL;
    out_leg2[0].cbBuffer = 0;
    out_leg2[1].BufferType = SECBUFFER_ALERT;
    out_leg2[1].pvBuffer = NULL;
    out_leg2[1].cbBuffer = 0;
    out_leg2[2].BufferType = SECBUFFER_EMPTY;
    out_leg2[2].pvBuffer = NULL;
    out_leg2[2].cbBuffer = 0;

    out_leg2_desc.ulVersion = SECBUFFER_VERSION;
    out_leg2_desc.cBuffers = 3;
    out_leg2_desc.pBuffers = out_leg2;

    status = sspi_a->InitializeSecurityContextA(
      &cred_handle, &ctxt_handle, target_name, req_flags, 0, 0,
      &in_leg2_desc, 0, NULL, &out_leg2_desc, &ret_flags, &expiry);

    assert(in_leg2[1].BufferType == SECBUFFER_EXTRA);
    assert(in_leg2[1].cbBuffer == 16);
  }
  printf(" PASS: SECBUFFER_EXTRA reported 16 extra bytes.\n");

  free(flight_with_extra);
  free(server_flight);

  while(status == SEC_I_CONTINUE_NEEDED) {
    int server_ret;
    size_t s_pending;

    if(out_leg2[0].pvBuffer && out_leg2[0].cbBuffer > 0) {
      BIO_write(server_rbio, out_leg2[0].pvBuffer, (int)out_leg2[0].cbBuffer);
      sspi_a->FreeContextBuffer(out_leg2[0].pvBuffer);
      out_leg2[0].pvBuffer = NULL;
      out_leg2[0].cbBuffer = 0;
    }

    server_ret = SSL_accept(server_ssl);
    (void)server_ret;
    s_pending = (size_t)BIO_ctrl_pending(server_wbio);
    if(s_pending > 0) {
      unsigned char *s_flight = (unsigned char *)malloc(s_pending);
      int s_read = BIO_read(server_wbio, s_flight, (int)s_pending);

      in_leg2[0].BufferType = SECBUFFER_TOKEN;
      in_leg2[0].pvBuffer = s_flight;
      in_leg2[0].cbBuffer = (unsigned long)s_read;
      in_leg2[1].BufferType = SECBUFFER_EMPTY;

      out_leg2[0].BufferType = SECBUFFER_TOKEN;
      out_leg2[0].pvBuffer = NULL;
      out_leg2[0].cbBuffer = 0;

      status = sspi_a->InitializeSecurityContextA(
        &cred_handle, &ctxt_handle, target_name, req_flags, 0, 0,
        &in_leg2_desc, 0, NULL, &out_leg2_desc, &ret_flags, &expiry);

      free(s_flight);
    }
  }

  assert(status == SEC_E_OK);
  if(out_leg2[0].pvBuffer && out_leg2[0].cbBuffer > 0) {
    BIO_write(server_rbio, out_leg2[0].pvBuffer, (int)out_leg2[0].cbBuffer);
    sspi_a->FreeContextBuffer(out_leg2[0].pvBuffer);
    out_leg2[0].pvBuffer = NULL;
    out_leg2[0].cbBuffer = 0;
  }
  SSL_accept(server_ssl);
  assert(SSL_is_init_finished(server_ssl) == 1);
  printf(" PASS: TLS Handshake complete (SEC_E_OK).\n\n");

  /* 7. QueryContextAttributes */
  printf("7. Testing QueryContextAttributes\n");
  {
    /* ALPN attribute */
    SecPkgContext_ApplicationProtocol alpn_result;
    memset(&alpn_result, 0, sizeof(alpn_result));
    status = sspi_a->QueryContextAttributesA(
      &ctxt_handle, SECPKG_ATTR_APPLICATION_PROTOCOL, &alpn_result);
    assert(status == SEC_E_OK);
    assert(alpn_result.ProtoNegoStatus ==
           SecApplicationProtocolNegotiationStatus_Success);
    assert(alpn_result.ProtoNegoExt ==
           SecApplicationProtocolNegotiationExt_ALPN);
    assert(alpn_result.ProtocolIdSize == 2);
    assert(memcmp(alpn_result.ProtocolId, "h2", 2) == 0);
  }
  printf(" PASS: ALPN negotiated protocol is 'h2'.\n");
  {
    /* Stream sizes attribute */
    SecPkgContext_StreamSizes stream_sizes;
    memset(&stream_sizes, 0, sizeof(stream_sizes));
    status = sspi_a->QueryContextAttributesA(
      &ctxt_handle, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);
    assert(status == SEC_E_OK);
    assert(stream_sizes.cbHeader == 5);
    assert(stream_sizes.cbTrailer == 64);
    assert(stream_sizes.cbMaximumMessage == 16384);
    printf(" PASS: Stream sizes: header=%lu trailer=%lu max_message=%lu.\n",
           stream_sizes.cbHeader, stream_sizes.cbTrailer,
           stream_sizes.cbMaximumMessage);
  }
  /* Remote certificate attribute */
  {
    PCCERT_CONTEXT remote_cert = NULL;
    status = sspi_a->QueryContextAttributesA(
      &ctxt_handle, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote_cert);
    assert(status == SEC_E_OK);
    assert(remote_cert != NULL);
    assert(remote_cert->pbCertEncoded != NULL);
    assert(remote_cert->cbCertEncoded > 0);
    CertFreeCertificateContext(remote_cert);
  }
  printf(" PASS: Remote peer certificate retrieved and validated.\n\n");

  /* 8. Testing ApplyControlToken & Shutdown Token */
  printf("8. Testing ApplyControlToken (SCHANNEL_SHUTDOWN)\n");
  {
    DWORD shutdown_token = SCHANNEL_SHUTDOWN;
    SecBuffer shutdown_buf;
    SecBufferDesc shutdown_desc;
    SecBuffer out_shutdown_buf;
    SecBufferDesc out_shutdown_desc;

    shutdown_buf.BufferType = SECBUFFER_TOKEN;
    shutdown_buf.pvBuffer = &shutdown_token;
    shutdown_buf.cbBuffer = sizeof(shutdown_token);
    shutdown_desc.ulVersion = SECBUFFER_VERSION;
    shutdown_desc.cBuffers = 1;
    shutdown_desc.pBuffers = &shutdown_buf;

    status = sspi_a->ApplyControlToken(&ctxt_handle, &shutdown_desc);
    assert(status == SEC_E_OK);

    out_shutdown_buf.BufferType = SECBUFFER_EMPTY;
    out_shutdown_buf.pvBuffer = NULL;
    out_shutdown_buf.cbBuffer = 0;

    out_shutdown_desc.ulVersion = SECBUFFER_VERSION;
    out_shutdown_desc.cBuffers = 1;
    out_shutdown_desc.pBuffers = &out_shutdown_buf;

    status = sspi_a->InitializeSecurityContextA(
      &cred_handle, &ctxt_handle, NULL, 0, 0, 0,
      NULL, 0, NULL, &out_shutdown_desc, &ret_flags, &expiry);
    assert(status == SEC_E_OK);
    assert(out_shutdown_buf.BufferType == SECBUFFER_TOKEN);
    assert(out_shutdown_buf.pvBuffer != NULL);
    assert(out_shutdown_buf.cbBuffer > 0);
    sspi_a->FreeContextBuffer(out_shutdown_buf.pvBuffer);
  }
  printf(" PASS: Shutdown alert token generated successfully.\n\n");

  /* 9. DeleteSecurityContext */
  printf("9. Testing DeleteSecurityContext\n");
  status = sspi_a->DeleteSecurityContext(&ctxt_handle);
  assert(status == SEC_E_OK);
  assert(ctxt_handle.dwLower == 0 && ctxt_handle.dwUpper == 0);

  status = sspi_a->DeleteSecurityContext(&ctxt_handle);
  assert(status == SEC_E_INVALID_HANDLE);
  printf(" PASS: Security context deleted and handle invalidated.\n\n");

  /* 10. Test InitializeSecurityContextW (WideChar version) */
  printf("10. Testing InitializeSecurityContextW\n");
  {
    CtxtHandle ctxt_w = { 0, 0 };
    WCHAR target_w[] = L"localhost";
    out_token_buf.BufferType = SECBUFFER_EMPTY;
    out_token_buf.pvBuffer = NULL;
    out_token_buf.cbBuffer = 0;

    status = sspi_w->InitializeSecurityContextW(
      &cred_handle, NULL, target_w, req_flags, 0, 0,
      NULL, 0, &ctxt_w, &out_desc, &ret_flags, &expiry);
    assert(status == SEC_I_CONTINUE_NEEDED);
    assert(ctxt_w.dwLower != 0);
    assert(out_token_buf.pvBuffer != NULL);
    sspi_w->FreeContextBuffer(out_token_buf.pvBuffer);
    status = sspi_w->DeleteSecurityContext(&ctxt_w);
    assert(status == SEC_E_OK);
  }
  printf(" PASS: InitializeSecurityContextW verified.\n\n");

  /* 11. Cleanup credentials & server resources */
  printf("11. Cleaning up resources\n");
  status = sspi_a->FreeCredentialsHandle(&cred_handle);
  assert(status == SEC_E_OK);

  SSL_free(server_ssl);
  SSL_CTX_free(server_ctx);
  X509_free(server_cert);
  EVP_PKEY_free(server_pkey);
  printf(" PASS: All resources freed.\n\n");

  printf("All SSPI Handshake Engine tests PASSED successfully!\n");
  return 0;
}
