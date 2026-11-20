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

static void do_handshake_loopback(
  PSecurityFunctionTableA sspi,
  CredHandle *cred_handle,
  CtxtHandle *ctxt_handle,
  SSL *server_ssl,
  BIO *server_rbio,
  BIO *server_wbio)
{
  SECURITY_STATUS status;
  SecBuffer out_token;
  SecBufferDesc out_desc;
  unsigned long req_flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                           ISC_REQ_CONFIDENTIALITY | ISC_REQ_SEQUENCE_DETECT |
                           ISC_REQ_REPLAY_DETECT;
  unsigned long ret_flags = 0;
  TimeStamp expiry;
  char target_name[] = "localhost";
  SecBuffer in_buf[2];
  SecBufferDesc in_desc;
  SecBuffer out_leg2[3];
  SecBufferDesc out_leg2_desc;
  unsigned char *s_flight;
  int s_read;

  out_token.BufferType = SECBUFFER_EMPTY;
  out_token.pvBuffer = NULL;
  out_token.cbBuffer = 0;

  out_desc.ulVersion = SECBUFFER_VERSION;
  out_desc.cBuffers = 1;
  out_desc.pBuffers = &out_token;

  /* Leg 1: ClientHello */
  status = sspi->InitializeSecurityContextA(
    cred_handle, NULL, target_name, req_flags, 0, 0,
    NULL, 0, ctxt_handle, &out_desc, &ret_flags, &expiry);
  assert(status == SEC_I_CONTINUE_NEEDED);
  assert(out_token.pvBuffer != NULL && out_token.cbBuffer > 0);

  BIO_write(server_rbio, out_token.pvBuffer, (int)out_token.cbBuffer);
  sspi->FreeContextBuffer(out_token.pvBuffer);
  out_token.pvBuffer = NULL;

  /* Server processes ClientHello */
  SSL_accept(server_ssl);
  {
    size_t s_pending = (size_t)BIO_ctrl_pending(server_wbio);
    assert(s_pending > 0);
    s_flight = (unsigned char *)malloc(s_pending);
    assert(s_flight != NULL);
    s_read = BIO_read(server_wbio, s_flight, (int)s_pending);
    assert(s_read > 0);
  }

  /* Leg 2+: Ingest server response */
  in_buf[0].BufferType = SECBUFFER_TOKEN;
  in_buf[0].pvBuffer = s_flight;
  in_buf[0].cbBuffer = (unsigned long)s_read;
  in_buf[1].BufferType = SECBUFFER_EMPTY;
  in_buf[1].pvBuffer = NULL;
  in_buf[1].cbBuffer = 0;

  in_desc.ulVersion = SECBUFFER_VERSION;
  in_desc.cBuffers = 2;
  in_desc.pBuffers = in_buf;

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

  status = sspi->InitializeSecurityContextA(
    cred_handle, ctxt_handle, target_name, req_flags, 0, 0,
    &in_desc, 0, NULL, &out_leg2_desc, &ret_flags, &expiry);

  free(s_flight);

  while(status == SEC_I_CONTINUE_NEEDED) {
    size_t pending;
    if(out_leg2[0].pvBuffer && out_leg2[0].cbBuffer > 0) {
      BIO_write(server_rbio, out_leg2[0].pvBuffer, (int)out_leg2[0].cbBuffer);
      sspi->FreeContextBuffer(out_leg2[0].pvBuffer);
      out_leg2[0].pvBuffer = NULL;
      out_leg2[0].cbBuffer = 0;
    }

    SSL_accept(server_ssl);
    pending = (size_t)BIO_ctrl_pending(server_wbio);
    if(pending > 0) {
      unsigned char *flight = (unsigned char *)malloc(pending);
      int n = BIO_read(server_wbio, flight, (int)pending);

      in_buf[0].BufferType = SECBUFFER_TOKEN;
      in_buf[0].pvBuffer = flight;
      in_buf[0].cbBuffer = (unsigned long)n;
      in_buf[1].BufferType = SECBUFFER_EMPTY;

      out_leg2[0].BufferType = SECBUFFER_TOKEN;
      out_leg2[0].pvBuffer = NULL;
      out_leg2[0].cbBuffer = 0;

      status = sspi->InitializeSecurityContextA(
        cred_handle, ctxt_handle, target_name, req_flags, 0, 0,
        &in_desc, 0, NULL, &out_leg2_desc, &ret_flags, &expiry);

      free(flight);
    }
  }

  assert(status == SEC_E_OK);
  if(out_leg2[0].pvBuffer && out_leg2[0].cbBuffer > 0) {
    BIO_write(server_rbio, out_leg2[0].pvBuffer, (int)out_leg2[0].cbBuffer);
    sspi->FreeContextBuffer(out_leg2[0].pvBuffer);
    out_leg2[0].pvBuffer = NULL;
    out_leg2[0].cbBuffer = 0;
  }
  SSL_accept(server_ssl);
  assert(SSL_is_init_finished(server_ssl) == 1);
}

int main(void)
{
  SECURITY_STATUS status;
  PSecurityFunctionTableA sspi = InitSecurityInterfaceA();
  X509 *server_cert = NULL;
  EVP_PKEY *server_pkey = NULL;
  SSL_CTX *server_ctx;
  SSL *server_ssl;
  BIO *server_rbio;
  BIO *server_wbio;

  CredHandle cred_handle = { 0, 0 };
  SCH_CREDENTIALS sch_creds;
  TLS_PARAMETERS tls_params;
  CtxtHandle ctxt_handle = { 0, 0 };
  SecPkgContext_StreamSizes stream_sizes;

  const char server_msg[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello Server!";
  size_t server_msg_len = strlen(server_msg);
  unsigned char *server_enc_data;
  size_t server_enc_len;

  SecBuffer dec_bufs[4];
  SecBufferDesc dec_desc;
  SecBufferDesc enc_desc;
  unsigned char *combined;
  size_t rec2_len;
  size_t p2_len;
  const char msg_part2[] = "Stream Chunk 2";

  assert(sspi != NULL);

  printf("Schannel Mockup Data Streaming Tests "
         "(EncryptMessage & DecryptMessage)\n\n");

  /* 1. Setup OpenSSL test server */
  printf("1. Setting up OpenSSL TLS test server\n");
  generate_test_cert_and_key(&server_cert, &server_pkey);

  server_ctx = SSL_CTX_new(TLS_server_method());
  assert(server_ctx != NULL);
  assert(SSL_CTX_use_certificate(server_ctx, server_cert) > 0);
  assert(SSL_CTX_use_PrivateKey(server_ctx, server_pkey) > 0);

  server_ssl = SSL_new(server_ctx);
  assert(server_ssl != NULL);
  server_rbio = BIO_new(BIO_s_mem());
  server_wbio = BIO_new(BIO_s_mem());
  assert(server_rbio && server_wbio);
  BIO_set_mem_eof_return(server_rbio, -1);
  BIO_set_mem_eof_return(server_wbio, -1);
  SSL_set_bio(server_ssl, server_rbio, server_wbio);
  SSL_set_accept_state(server_ssl);
  printf(" PASS: Test server initialized.\n\n");

  /* 2. Establish connection loopback */
  printf("2. Performing TLS loopback handshake\n");
  memset(&sch_creds, 0, sizeof(sch_creds));
  memset(&tls_params, 0, sizeof(tls_params));
  sch_creds.dwVersion = SCH_CREDENTIALS_VERSION;
  sch_creds.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_MANUAL_CRED_VALIDATION;
  sch_creds.cTlsParameters = 1;
  sch_creds.pTlsParameters = &tls_params;
  tls_params.grbitDisabledProtocols =
    ~(SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT);

  {
    TimeStamp expiry;
    status = sspi->AcquireCredentialsHandleA(
      NULL, UNCONST(UNISP_NAME_A), SECPKG_CRED_OUTBOUND, NULL,
      &sch_creds, NULL, NULL, &cred_handle, &expiry);
    assert(status == SEC_E_OK);
  }

  do_handshake_loopback(sspi, &cred_handle, &ctxt_handle,
                        server_ssl, server_rbio, server_wbio);
  printf(" PASS: Handshake complete and context active.\n\n");

  /* 3. Query stream sizes */
  printf("3. Querying stream sizes (QueryContextAttributesA)\n");
  memset(&stream_sizes, 0, sizeof(stream_sizes));
  status = sspi->QueryContextAttributesA(
    &ctxt_handle, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);
  assert(status == SEC_E_OK);
  assert(stream_sizes.cbHeader == 5);
  assert(stream_sizes.cbTrailer == 64);
  assert(stream_sizes.cbMaximumMessage == 16384);

  {
    SecPkgContext_Sizes sizes;
    memset(&sizes, 0, sizeof(sizes));
    status = sspi->QueryContextAttributesA(
      &ctxt_handle, SECPKG_ATTR_SIZES, &sizes);
    assert(status == SEC_E_OK);
    assert(sizes.cbMaxToken == 16384);
    assert(sizes.cbSecurityTrailer == 64);
    printf(" PASS: Stream sizes verified: header=%lu "
           "trailer=%lu max_message=%lu.\n\n",
           stream_sizes.cbHeader, stream_sizes.cbTrailer,
           stream_sizes.cbMaximumMessage);
  }

  /* 4. Test client EncryptMessage and server Decryption */
  printf("4. Testing client EncryptMessage and server decryption\n");
  {
    const char plaintext[] = "GET /resource HTTP/1.1\r\n"
      "Host: localhost\r\n\r\n";
    size_t pt_len = strlen(plaintext);
    size_t total_buf_size =
      stream_sizes.cbHeader + pt_len + stream_sizes.cbTrailer;
    unsigned char *enc_packet = (unsigned char *)malloc(total_buf_size);
    SecBuffer enc_bufs[4];
    size_t full_record_len;
    char server_recv_buf[256];
    int server_dec_len;

    assert(enc_packet != NULL);

    enc_bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    enc_bufs[0].pvBuffer = enc_packet;
    enc_bufs[0].cbBuffer = stream_sizes.cbHeader;

    enc_bufs[1].BufferType = SECBUFFER_DATA;
    enc_bufs[1].pvBuffer = enc_packet + stream_sizes.cbHeader;
    enc_bufs[1].cbBuffer = (unsigned long)pt_len;
    memcpy(enc_bufs[1].pvBuffer, plaintext, pt_len);

    enc_bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    enc_bufs[2].pvBuffer = enc_packet + stream_sizes.cbHeader + pt_len;
    enc_bufs[2].cbBuffer = stream_sizes.cbTrailer;

    enc_bufs[3].BufferType = SECBUFFER_EMPTY;
    enc_bufs[3].pvBuffer = NULL;
    enc_bufs[3].cbBuffer = 0;

    enc_desc.ulVersion = SECBUFFER_VERSION;
    enc_desc.cBuffers = 4;
    enc_desc.pBuffers = enc_bufs;

    status = sspi->EncryptMessage(&ctxt_handle, 0, &enc_desc, 0);
    assert(status == SEC_E_OK);
    assert(enc_bufs[0].cbBuffer == 5);
    assert(enc_bufs[1].cbBuffer == pt_len);
    assert(enc_bufs[2].cbBuffer > 0);

    full_record_len = enc_bufs[0].cbBuffer + enc_bufs[1].cbBuffer +
      enc_bufs[2].cbBuffer;
    printf(" PASS: EncryptMessage produced encrypted record of %u bytes"
           " (payload=%u).\n",
           (unsigned int)full_record_len, (unsigned int)pt_len);

    /* Feed encrypted record to OpenSSL server */
    BIO_write(server_rbio, enc_packet, (int)full_record_len);
    free(enc_packet);

    memset(server_recv_buf, 0, sizeof(server_recv_buf));
    server_dec_len = SSL_read(server_ssl, server_recv_buf,
                              sizeof(server_recv_buf) - 1);
    assert(server_dec_len == (int)pt_len);
    assert(memcmp(server_recv_buf, plaintext, pt_len) == 0);
    printf(" PASS: Server successfully decrypted plaintext:"
           " \"%s\"\n\n", server_recv_buf);
  }
  /* 5. Test server encryption and client DecryptMessage */
  printf("5. Testing server-to-client streaming and DecryptMessage\n");
  {
    int s_written = SSL_write(server_ssl, server_msg, (int)server_msg_len);
    int s_read_bytes;

    assert(s_written == (int)server_msg_len);

    server_enc_len = (size_t)BIO_ctrl_pending(server_wbio);
    assert(server_enc_len > 0);
    server_enc_data = (unsigned char *)malloc(server_enc_len);
    assert(server_enc_data != NULL);
    s_read_bytes = BIO_read(server_wbio, server_enc_data, (int)server_enc_len);
    assert(s_read_bytes == (int)server_enc_len);
  }

  /* 6. Test incomplete record detection in DecryptMessage */
  printf("6. Testing incomplete message handling in DecryptMessage\n");
  dec_desc.ulVersion = SECBUFFER_VERSION;
  dec_desc.cBuffers = 4;
  dec_desc.pBuffers = dec_bufs;

  /* Truncated TLS header (< 5 bytes) */
  dec_bufs[0].BufferType = SECBUFFER_DATA;
  dec_bufs[0].pvBuffer = server_enc_data;
  dec_bufs[0].cbBuffer = 3;
  dec_bufs[1].BufferType = SECBUFFER_EMPTY;
  dec_bufs[1].pvBuffer = NULL;
  dec_bufs[1].cbBuffer = 0;
  dec_bufs[2].BufferType = SECBUFFER_EMPTY;
  dec_bufs[2].pvBuffer = NULL;
  dec_bufs[2].cbBuffer = 0;
  dec_bufs[3].BufferType = SECBUFFER_EMPTY;
  dec_bufs[3].pvBuffer = NULL;
  dec_bufs[3].cbBuffer = 0;

  status = sspi->DecryptMessage(&ctxt_handle, &dec_desc, 0, NULL);
  assert(status == SEC_E_INCOMPLETE_MESSAGE);

  /* Truncated record payload */
  dec_bufs[0].cbBuffer = 10;
  status = sspi->DecryptMessage(&ctxt_handle, &dec_desc, 0, NULL);
  assert(status == SEC_E_INCOMPLETE_MESSAGE);
  printf(" PASS: SEC_E_INCOMPLETE_MESSAGE returned for partial frames.\n\n");

  /* 7. Test full DecryptMessage with stream receive loop (as libcurl does) */
  printf("7. Testing complete record decryption in DecryptMessage\n");
  {
    size_t enc_offset = server_enc_len;
    size_t total_decrypted = 0;
    char client_recv_buf[256];
    memset(client_recv_buf, 0, sizeof(client_recv_buf));

    while(enc_offset > 0) {
      dec_bufs[0].BufferType = SECBUFFER_DATA;
      dec_bufs[0].pvBuffer = server_enc_data;
      dec_bufs[0].cbBuffer = (unsigned long)enc_offset;
      dec_bufs[1].BufferType = SECBUFFER_EMPTY;
      dec_bufs[1].pvBuffer = NULL;
      dec_bufs[1].cbBuffer = 0;
      dec_bufs[2].BufferType = SECBUFFER_EMPTY;
      dec_bufs[2].pvBuffer = NULL;
      dec_bufs[2].cbBuffer = 0;
      dec_bufs[3].BufferType = SECBUFFER_EMPTY;
      dec_bufs[3].pvBuffer = NULL;
      dec_bufs[3].cbBuffer = 0;

      status = sspi->DecryptMessage(&ctxt_handle, &dec_desc, 0, NULL);
      assert(status == SEC_E_OK);

      if(dec_bufs[1].BufferType == SECBUFFER_DATA &&
         dec_bufs[1].cbBuffer > 0) {
        memcpy(client_recv_buf + total_decrypted, dec_bufs[1].pvBuffer,
               dec_bufs[1].cbBuffer);
        total_decrypted += dec_bufs[1].cbBuffer;
      }

      if(dec_bufs[3].BufferType == SECBUFFER_EXTRA &&
         dec_bufs[3].cbBuffer > 0) {
        memmove(server_enc_data, dec_bufs[3].pvBuffer, dec_bufs[3].cbBuffer);
        enc_offset = dec_bufs[3].cbBuffer;
      }
      else {
        enc_offset = 0;
      }
    }

    assert(total_decrypted == server_msg_len);
    assert(memcmp(client_recv_buf, server_msg, server_msg_len) == 0);
    printf(" PASS: DecryptMessage successfully decrypted: \"%s\"\n\n",
           client_recv_buf);
  }
  free(server_enc_data);

  /* 8. Test DecryptMessage with extra trailing data (SECBUFFER_EXTRA) */
  printf("8. Testing DecryptMessage with trailing extra data "
         "(SECBUFFER_EXTRA)\n");
  {
    const char msg_part1[] = "Stream Chunk 1";
    size_t p1_len = strlen(msg_part1);
    size_t rec1_len;
    unsigned char *rec1;
    unsigned char *rec2;
    size_t combined_len;
    p2_len = strlen(msg_part2);

    assert(SSL_write(server_ssl, msg_part1, (int)p1_len) == (int)p1_len);
    rec1_len = (size_t)BIO_ctrl_pending(server_wbio);
    rec1 = (unsigned char *)malloc(rec1_len);
    assert(rec1 != NULL);
    BIO_read(server_wbio, rec1, (int)rec1_len);

    assert(SSL_write(server_ssl, msg_part2, (int)p2_len) == (int)p2_len);
    rec2_len = (size_t)BIO_ctrl_pending(server_wbio);
    rec2 = (unsigned char *)malloc(rec2_len);
    assert(rec2 != NULL);
    BIO_read(server_wbio, rec2, (int)rec2_len);

    /* Concatenate Record 1 and Record 2 into combined buffer */
    combined_len = rec1_len + rec2_len;
    combined = (unsigned char *)malloc(combined_len);
    assert(combined != NULL);
    memcpy(combined, rec1, rec1_len);
    memcpy(combined + rec1_len, rec2, rec2_len);
    free(rec1);
    free(rec2);

    /* Decrypt Chunk 1 */
    dec_bufs[0].BufferType = SECBUFFER_DATA;
    dec_bufs[0].pvBuffer = combined;
    dec_bufs[0].cbBuffer = (unsigned long)combined_len;
    dec_bufs[1].BufferType = SECBUFFER_EMPTY;
    dec_bufs[1].pvBuffer = NULL;
    dec_bufs[1].cbBuffer = 0;
    dec_bufs[2].BufferType = SECBUFFER_EMPTY;
    dec_bufs[2].pvBuffer = NULL;
    dec_bufs[2].cbBuffer = 0;
    dec_bufs[3].BufferType = SECBUFFER_EMPTY;
    dec_bufs[3].pvBuffer = NULL;
    dec_bufs[3].cbBuffer = 0;

    status = sspi->DecryptMessage(&ctxt_handle, &dec_desc, 0, NULL);
    assert(status == SEC_E_OK);
    assert(dec_bufs[1].BufferType == SECBUFFER_DATA);
    assert(dec_bufs[1].cbBuffer == p1_len);
    assert(memcmp(dec_bufs[1].pvBuffer, msg_part1, p1_len) == 0);
    assert(dec_bufs[3].BufferType == SECBUFFER_EXTRA);
    assert(dec_bufs[3].cbBuffer == rec2_len);
  }
  printf(" PASS: First record decrypted; SECBUFFER_EXTRA "
         "reported %lu bytes remaining.\n",
         dec_bufs[3].cbBuffer);

  /* Move extra bytes forward as libcurl does and decrypt Chunk 2 */
  memmove(combined, dec_bufs[3].pvBuffer, dec_bufs[3].cbBuffer);
  dec_bufs[0].BufferType = SECBUFFER_DATA;
  dec_bufs[0].pvBuffer = combined;
  dec_bufs[0].cbBuffer = (unsigned long)rec2_len;
  dec_bufs[1].BufferType = SECBUFFER_EMPTY;
  dec_bufs[1].pvBuffer = NULL;
  dec_bufs[1].cbBuffer = 0;
  dec_bufs[2].BufferType = SECBUFFER_EMPTY;
  dec_bufs[2].pvBuffer = NULL;
  dec_bufs[2].cbBuffer = 0;
  dec_bufs[3].BufferType = SECBUFFER_EMPTY;
  dec_bufs[3].pvBuffer = NULL;
  dec_bufs[3].cbBuffer = 0;

  status = sspi->DecryptMessage(&ctxt_handle, &dec_desc, 0, NULL);
  assert(status == SEC_E_OK);
  assert(dec_bufs[1].BufferType == SECBUFFER_DATA);
  assert(dec_bufs[1].cbBuffer == p2_len);
  assert(memcmp(dec_bufs[1].pvBuffer, msg_part2, p2_len) == 0);
  assert(dec_bufs[3].BufferType == SECBUFFER_EMPTY);
  assert(dec_bufs[3].cbBuffer == 0);
  printf(" PASS: Second record decrypted; no remaining extra data.\n\n");

  free(combined);

  /* 9. Test TLS close_notify (SEC_I_CONTEXT_EXPIRED) */
  printf("9. Testing TLS close_notify alert handling "
         "(SEC_I_CONTEXT_EXPIRED)\n");
  {
    size_t close_pending;
    unsigned char *close_alert;
    SSL_shutdown(server_ssl);
    close_pending = (size_t)BIO_ctrl_pending(server_wbio);
    assert(close_pending > 0);
    close_alert = (unsigned char *)malloc(close_pending);
    assert(close_alert != NULL);
    BIO_read(server_wbio, close_alert, (int)close_pending);

    dec_bufs[0].BufferType = SECBUFFER_DATA;
    dec_bufs[0].pvBuffer = close_alert;
    dec_bufs[0].cbBuffer = (unsigned long)close_pending;
    dec_bufs[1].BufferType = SECBUFFER_EMPTY;
    dec_bufs[1].pvBuffer = NULL;
    dec_bufs[1].cbBuffer = 0;
    dec_bufs[2].BufferType = SECBUFFER_EMPTY;
    dec_bufs[2].pvBuffer = NULL;
    dec_bufs[2].cbBuffer = 0;
    dec_bufs[3].BufferType = SECBUFFER_EMPTY;
    dec_bufs[3].pvBuffer = NULL;
    dec_bufs[3].cbBuffer = 0;

    status = sspi->DecryptMessage(&ctxt_handle, &dec_desc, 0, NULL);
    assert(status == SEC_I_CONTEXT_EXPIRED);
    printf(" PASS: SEC_I_CONTEXT_EXPIRED returned upon receiving "
           "close_notify alert.\n\n");

    free(close_alert);
  }
  /* 10. Test error handling */
  printf("10. Testing error handling\n");
  {
    CtxtHandle invalid_ctxt = { 0, 0 };
    status = sspi->EncryptMessage(&invalid_ctxt, 0, &enc_desc, 0);
    assert(status == SEC_E_INVALID_HANDLE);

    status = sspi->DecryptMessage(&invalid_ctxt, &dec_desc, 0, NULL);
    assert(status == SEC_E_INVALID_HANDLE);

    status = sspi->EncryptMessage(&ctxt_handle, 0, NULL, 0);
    assert(status == SEC_E_INVALID_TOKEN);

    status = sspi->DecryptMessage(&ctxt_handle, NULL, 0, NULL);
    assert(status == SEC_E_INVALID_TOKEN);
  }
  printf(" PASS: Error cases returned expected status codes.\n\n");

  /* 11. Cleanup */
  printf("11. Cleaning up resources\n");
  sspi->DeleteSecurityContext(&ctxt_handle);
  sspi->FreeCredentialsHandle(&cred_handle);
  SSL_free(server_ssl);
  SSL_CTX_free(server_ctx);
  X509_free(server_cert);
  EVP_PKEY_free(server_pkey);
  printf(" PASS: All resources freed cleanly.\n\n");

  printf("All Data Streaming (EncryptMessage & DecryptMessage) "
         "tests PASSED successfully!\n");
  return 0;
}
