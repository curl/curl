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

#include "mock_internal.h"

/* Forward declarations for SSPI stubs implemented in subsequent phases */
static SECURITY_STATUS WINAPI mock_InitializeSecurityContextA(
  PCredHandle phCredential, PCtxtHandle phContext, LPSTR pszTargetName,
  unsigned long fContextReq, unsigned long Reserved1,
  unsigned long TargetDataRep,
  PSecBufferDesc pInput, unsigned long Reserved2, PCtxtHandle phNewContext,
  PSecBufferDesc pOutput, unsigned long *pfContextAttr, TimeStamp *ptsExpiry);

static SECURITY_STATUS WINAPI mock_InitializeSecurityContextW(
  PCredHandle phCredential, PCtxtHandle phContext, LPWSTR pszTargetName,
  unsigned long fContextReq, unsigned long Reserved1,
  unsigned long TargetDataRep,
  PSecBufferDesc pInput, unsigned long Reserved2, PCtxtHandle phNewContext,
  PSecBufferDesc pOutput, unsigned long *pfContextAttr, TimeStamp *ptsExpiry);

static SECURITY_STATUS WINAPI
mock_DeleteSecurityContext(PCtxtHandle phContext);

static SECURITY_STATUS WINAPI mock_QueryContextAttributesA(
  PCtxtHandle phContext, unsigned long ulAttribute, void *pBuffer);

static SECURITY_STATUS WINAPI mock_QueryContextAttributesW(
  PCtxtHandle phContext, unsigned long ulAttribute, void *pBuffer);

static SECURITY_STATUS WINAPI mock_EncryptMessage(
  PCtxtHandle phContext, unsigned long fQOP, PSecBufferDesc pMessage,
  unsigned long MessageSeqNo);

static SECURITY_STATUS WINAPI mock_DecryptMessage(
  PCtxtHandle phContext, PSecBufferDesc pMessage, unsigned long MessageSeqNo,
  unsigned long *pfQOP);

static SECURITY_STATUS WINAPI mock_ApplyControlToken(
  PCtxtHandle phContext, PSecBufferDesc pInput);

static void free_cred_internal(mock_cred_t *cred);

/*
 * Client certificate callback for OpenSSL
 */
static int client_cert_callback(SSL *ssl, X509 **x509, EVP_PKEY **pkey)
{
  mock_ctxt_t *ctxt = (mock_ctxt_t *)SSL_get_app_data(ssl);
  if(ctxt) {
    ctxt->client_cert_requested = true;
    if(ctxt->cred && ctxt->cred->client_cert && ctxt->cred->client_key) {
      X509_up_ref(ctxt->cred->client_cert);
      EVP_PKEY_up_ref(ctxt->cred->client_key);
      *x509 = ctxt->cred->client_cert;
      *pkey = ctxt->cred->client_key;
      return 1;
    }
  }
  return 0;
}

/*
 * AcquireCredentialsHandle Implementation
 */
static SECURITY_STATUS do_acquire_credentials(
  unsigned long fCredentialUse,
  void *pAuthData,
  PCredHandle phCredential,
  TimeStamp *ptsExpiry)
{
  mock_cred_t *cred = NULL;
  DWORD enabled_protocols = 0;
  DWORD flags = 0;
  PCCERT_CONTEXT client_cert_ctx = NULL;
  SSL_CTX *ssl_ctx = NULL;
  int min_version = 0;
  int max_version = 0;

  if(!phCredential)
    return SEC_E_INVALID_HANDLE;

  if(fCredentialUse != SECPKG_CRED_OUTBOUND &&
     fCredentialUse != SECPKG_CRED_INBOUND &&
     fCredentialUse != SECPKG_CRED_BOTH)
    return SEC_E_UNKNOWN_CREDENTIALS;

  /* Parse authentication / credential data */
  if(pAuthData) {
    DWORD *version = (DWORD *)pAuthData;
    if(*version == SCH_CREDENTIALS_VERSION) {
      PSCH_CREDENTIALS creds = (PSCH_CREDENTIALS)pAuthData;
      flags = creds->dwFlags;

      if(creds->cTlsParameters > 0 && creds->pTlsParameters)
        enabled_protocols = ~creds->pTlsParameters[0].grbitDisabledProtocols;
      else
        enabled_protocols = SP_PROT_TLS1_CLIENT;

      if(creds->cCreds > 0 && creds->paCred)
        client_cert_ctx = creds->paCred[0];
    }
    else if(*version == SCHANNEL_CRED_VERSION) {
      PSCHANNEL_CRED creds = (PSCHANNEL_CRED)pAuthData;
      flags = creds->dwFlags;
      enabled_protocols = creds->grbitEnabledProtocols;

      if(creds->cCreds > 0 && creds->paCred)
        client_cert_ctx = creds->paCred[0];
    }
    else
      return SEC_E_INVALID_TOKEN;
  }
  else
    enabled_protocols = SP_PROT_TLS1_CLIENT;

  /* Create and configure OpenSSL SSL_CTX */
  ssl_ctx = SSL_CTX_new(TLS_client_method());
  if(!ssl_ctx)
    return SEC_E_INSUFFICIENT_MEMORY;

  /* Configure TLS protocol range */
  if(enabled_protocols & SP_PROT_TLS1_0_CLIENT)
    min_version = TLS1_VERSION;
  else if(enabled_protocols & SP_PROT_TLS1_1_CLIENT)
    min_version = TLS1_1_VERSION;
  else if(enabled_protocols & SP_PROT_TLS1_2_CLIENT)
    min_version = TLS1_2_VERSION;
  else if(enabled_protocols & SP_PROT_TLS1_3_CLIENT)
    min_version = TLS1_3_VERSION;

  if(enabled_protocols & SP_PROT_TLS1_3_CLIENT)
    max_version = TLS1_3_VERSION;
  else if(enabled_protocols & SP_PROT_TLS1_2_CLIENT)
    max_version = TLS1_2_VERSION;
  else if(enabled_protocols & SP_PROT_TLS1_1_CLIENT)
    max_version = TLS1_1_VERSION;
  else if(enabled_protocols & SP_PROT_TLS1_0_CLIENT)
    max_version = TLS1_VERSION;

  if(min_version > 0)
    SSL_CTX_set_min_proto_version(ssl_ctx, min_version);
  if(max_version > 0)
    SSL_CTX_set_max_proto_version(ssl_ctx, max_version);

  /* Disable legacy SSLv2 / SSLv3 */
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

  /* Certificate verification: in Schannel, libcurl performs host and CA
   * verification manually when required (or queries remote cert context).
   * Setting SSL_VERIFY_NONE allows libcurl's verification logic to inspect
   * the certificate chain directly. */
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

  /* Set cipher list if specified / strong crypto requested */
  if(flags & SCH_USE_STRONG_CRYPTO)
    SSL_CTX_set_cipher_list(ssl_ctx, "HIGH:!aNULL:!MD5:!RC4:!3DES");

  /* Setup client certificate callback */
  SSL_CTX_set_client_cert_cb(ssl_ctx, client_cert_callback);

  /* Attach client certificate and private key if present */
  if(client_cert_ctx) {
    const mock_cert_context_t *mock_cert =
      (const mock_cert_context_t *)client_cert_ctx;
    if(mock_cert->x509) {
      if(SSL_CTX_use_certificate(ssl_ctx, mock_cert->x509) <= 0) {
        SSL_CTX_free(ssl_ctx);
        return SEC_E_UNKNOWN_CREDENTIALS;
      }
    }
    if(mock_cert->pkey) {
      if(SSL_CTX_use_PrivateKey(ssl_ctx, mock_cert->pkey) <= 0) {
        SSL_CTX_free(ssl_ctx);
        return SEC_E_UNKNOWN_CREDENTIALS;
      }
    }
  }

  /* Allocate internal credential wrapper */
  cred = (mock_cred_t *)calloc(1, sizeof(mock_cred_t));
  if(!cred) {
    SSL_CTX_free(ssl_ctx);
    return SEC_E_INSUFFICIENT_MEMORY;
  }

  cred->magic = MOCK_MAGIC_CRED;
  cred->ssl_ctx = ssl_ctx;
  cred->enabled_protocols = enabled_protocols;
  cred->flags = flags;
  cred->refcount = 1;

  if(client_cert_ctx) {
    const mock_cert_context_t *mc =
      (const mock_cert_context_t *)client_cert_ctx;
    if(mc->x509) {
      X509_up_ref(mc->x509);
      cred->client_cert = mc->x509;
    }
    if(mc->pkey) {
      EVP_PKEY_up_ref(mc->pkey);
      cred->client_key = mc->pkey;
    }
  }

  phCredential->dwLower = (uintptr_t)cred;
  phCredential->dwUpper = (uintptr_t)MOCK_MAGIC_CRED;

  if(ptsExpiry) {
    ptsExpiry->LowPart = 0xFFFFFFFF;
    ptsExpiry->HighPart = 0x7FFFFFFF;
  }

  return SEC_E_OK;
}

static bool check_package_name(const char *name)
{
  if(!name)
    return true;
  if(!strcmp(name, UNISP_NAME_A) ||
     !strcmp(name, "schannel") ||
     !strcmp(name, "Schannel") ||
     !strcmp(name, "Microsoft Unified Security Protocol Provider"))
    return true;
  return false;
}

static bool check_package_name_w(const wchar_t *name)
{
  if(!name)
    return true;
  if(!wcscmp(name, UNISP_NAME_W) ||
     !wcscmp(name, L"schannel") ||
     !wcscmp(name, L"Schannel") ||
     !wcscmp(name, L"Microsoft Unified Security Protocol Provider"))
    return true;
  return false;
}

static SECURITY_STATUS WINAPI mock_AcquireCredentialsHandleA(
  LPSTR pszPrincipal,
  LPSTR pszPackage,
  unsigned long fCredentialUse,
  void *pvLogonId,
  void *pAuthData,
  void *pGetKeyFn,
  void *pvGetKeyArgument,
  PCredHandle phCredential,
  TimeStamp *ptsExpiry)
{
  (void)pszPrincipal;
  (void)pvLogonId;
  (void)pGetKeyFn;
  (void)pvGetKeyArgument;

  if(!check_package_name(pszPackage))
    return SEC_E_SECPKG_NOT_FOUND;

  return do_acquire_credentials(fCredentialUse, pAuthData, phCredential,
                                ptsExpiry);
}

static SECURITY_STATUS WINAPI mock_AcquireCredentialsHandleW(
  LPWSTR pszPrincipal,
  LPWSTR pszPackage,
  unsigned long fCredentialUse,
  void *pvLogonId,
  void *pAuthData,
  void *pGetKeyFn,
  void *pvGetKeyArgument,
  PCredHandle phCredential,
  TimeStamp *ptsExpiry)
{
  (void)pszPrincipal;
  (void)pvLogonId;
  (void)pGetKeyFn;
  (void)pvGetKeyArgument;

  if(!check_package_name_w(pszPackage))
    return SEC_E_SECPKG_NOT_FOUND;

  return do_acquire_credentials(fCredentialUse, pAuthData, phCredential,
                                ptsExpiry);
}

/*
 * FreeCredentialsHandle Implementation
 */
static void free_cred_internal(mock_cred_t *cred)
{
  if(!cred)
    return;

  cred->refcount--;
  if(cred->refcount <= 0) {
    if(cred->ssl_ctx) {
      SSL_CTX_free(cred->ssl_ctx);
      cred->ssl_ctx = NULL;
    }
    if(cred->client_cert) {
      X509_free(cred->client_cert);
      cred->client_cert = NULL;
    }
    if(cred->client_key) {
      EVP_PKEY_free(cred->client_key);
      cred->client_key = NULL;
    }
    if(cred->cipher_list) {
      free(cred->cipher_list);
      cred->cipher_list = NULL;
    }
    cred->magic = 0;
    free(cred);
  }
}

static SECURITY_STATUS WINAPI
mock_FreeCredentialsHandle(PCredHandle phCredential)
{
  mock_cred_t *cred;
  if(!IS_VALID_CRED(phCredential))
    return SEC_E_INVALID_HANDLE;

  cred = (mock_cred_t *)phCredential->dwLower;
  phCredential->dwLower = 0;
  phCredential->dwUpper = 0;

  free_cred_internal(cred);
  return SEC_E_OK;
}

/*
 * FreeContextBuffer Implementation
 */
static SECURITY_STATUS WINAPI mock_FreeContextBuffer(void *pvContextBuffer)
{
  if(pvContextBuffer)
    free(pvContextBuffer);
  return SEC_E_OK;
}

/*
 * SSPI Function Table Instance and Initializers
 */
static SecurityFunctionTableA s_sec_fn_table_a = {
  SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION,
  NULL, /* EnumerateSecurityPackagesA */
  NULL, /* QueryCredentialsAttributesA */
  mock_AcquireCredentialsHandleA,
  mock_FreeCredentialsHandle,
  NULL, /* Reserved2 */
  mock_InitializeSecurityContextA,
  NULL, /* AcceptSecurityContext */
  NULL, /* CompleteAuthToken */
  mock_DeleteSecurityContext,
  mock_ApplyControlToken,
  mock_QueryContextAttributesA,
  NULL, /* FreeContextBuffer_dummy */
  NULL, /* MakeSignature */
  NULL, /* VerifySignature */
  mock_FreeContextBuffer,
  NULL, /* QuerySecurityPackageInfoA */
  NULL, /* Reserved3 */
  NULL, /* Reserved4 */
  NULL, /* ExportSecurityContext */
  NULL, /* ImportSecurityContextA */
  NULL, /* AddCredentialsA */
  NULL, /* Reserved8 */
  NULL, /* QuerySecurityContextToken */
  mock_EncryptMessage,
  mock_DecryptMessage,
  NULL  /* SetContextAttributesA */
};

static SecurityFunctionTableW s_sec_fn_table_w = {
  SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION,
  NULL, /* EnumerateSecurityPackagesW */
  NULL, /* QueryCredentialsAttributesW */
  mock_AcquireCredentialsHandleW,
  mock_FreeCredentialsHandle,
  NULL, /* Reserved2 */
  mock_InitializeSecurityContextW,
  NULL, /* AcceptSecurityContext */
  NULL, /* CompleteAuthToken */
  mock_DeleteSecurityContext,
  mock_ApplyControlToken,
  mock_QueryContextAttributesW,
  NULL, /* FreeContextBuffer_dummy */
  NULL, /* MakeSignature */
  NULL, /* VerifySignature */
  mock_FreeContextBuffer,
  NULL, /* QuerySecurityPackageInfoW */
  NULL, /* Reserved3 */
  NULL, /* Reserved4 */
  NULL, /* ExportSecurityContext */
  NULL, /* ImportSecurityContextW */
  NULL, /* AddCredentialsW */
  NULL, /* Reserved8 */
  NULL, /* QuerySecurityContextToken */
  mock_EncryptMessage,
  mock_DecryptMessage,
  NULL  /* SetContextAttributesW */
};

PSecurityFunctionTableA WINAPI InitSecurityInterfaceA(void)
{
  return &s_sec_fn_table_a;
}

PSecurityFunctionTableW WINAPI InitSecurityInterfaceW(void)
{
  return &s_sec_fn_table_w;
}

/*
 * Helper functions for InitializeSecurityContext
 */
static SECURITY_STATUS write_output_token(
  mock_ctxt_t *ctxt, PSecBufferDesc pOutput, size_t pending)
{
  SecBuffer *out_token = NULL;
  unsigned long i;
  if(!pOutput || pOutput->cBuffers == 0 || !pOutput->pBuffers)
    return SEC_E_OK;

  for(i = 0; i < pOutput->cBuffers; i++) {
    if(pOutput->pBuffers[i].BufferType == SECBUFFER_TOKEN ||
       pOutput->pBuffers[i].BufferType == SECBUFFER_EMPTY) {
      if(!out_token)
        out_token = &pOutput->pBuffers[i];
    }
  }

  /* Clear any other buffers in pOutput */
  for(i = 0; i < pOutput->cBuffers; i++) {
    if(&pOutput->pBuffers[i] != out_token) {
      pOutput->pBuffers[i].BufferType = SECBUFFER_EMPTY;
      pOutput->pBuffers[i].pvBuffer = NULL;
      pOutput->pBuffers[i].cbBuffer = 0;
    }
  }

  if(!out_token)
    return SEC_E_INVALID_TOKEN;

  if(pending == 0) {
    out_token->BufferType = SECBUFFER_TOKEN;
    out_token->pvBuffer = NULL;
    out_token->cbBuffer = 0;
    return SEC_E_OK;
  }

  if(out_token->pvBuffer && !(ctxt->req_flags & ISC_REQ_ALLOCATE_MEMORY)) {
    int nread;
    if(out_token->cbBuffer < pending)
      return SEC_E_INSUFFICIENT_MEMORY;
    nread = BIO_read(ctxt->wbio, out_token->pvBuffer, (int)pending);
    out_token->cbBuffer = (unsigned long)nread;
  }
  else {
    void *out_buf = malloc(pending);
    int nread;
    if(!out_buf)
      return SEC_E_INSUFFICIENT_MEMORY;
    nread = BIO_read(ctxt->wbio, out_buf, (int)pending);
    out_token->pvBuffer = out_buf;
    out_token->cbBuffer = (unsigned long)nread;
  }

  out_token->BufferType = SECBUFFER_TOKEN;
  return SEC_E_OK;
}

static void configure_alpn(SSL *ssl, PSecBufferDesc pInput)
{
  unsigned long i;
  if(!pInput || !pInput->pBuffers)
    return;

  for(i = 0; i < pInput->cBuffers; i++) {
    SecBuffer *b = &pInput->pBuffers[i];
    if(b->BufferType == SECBUFFER_APPLICATION_PROTOCOLS &&
       b->pvBuffer && b->cbBuffer >= 10) {
      const uint8_t *p = (const uint8_t *)b->pvBuffer;
      uint32_t ext_type;
      uint16_t list_len;
      memcpy(&ext_type, p + 4, sizeof(ext_type));
      memcpy(&list_len, p + 8, sizeof(list_len));
      if(ext_type == SecApplicationProtocolNegotiationExt_ALPN &&
         b->cbBuffer >= (unsigned long)(10 + list_len)) {
        SSL_set_alpn_protos(ssl, p + 10, list_len);
        break;
      }
    }
  }
}

static void finalize_handshake_state(mock_ctxt_t *ctxt)
{
  const unsigned char *alpn_proto = NULL;
  unsigned int alpn_len = 0;

  SSL_get0_alpn_selected(ctxt->ssl, &alpn_proto, &alpn_len);
  if(alpn_proto && alpn_len > 0) {
    ctxt->alpn_result.ProtoNegoStatus =
      SecApplicationProtocolNegotiationStatus_Success;
    ctxt->alpn_result.ProtoNegoExt =
      SecApplicationProtocolNegotiationExt_ALPN;
    if(alpn_len > sizeof(ctxt->alpn_result.ProtocolId))
      alpn_len = sizeof(ctxt->alpn_result.ProtocolId);
    ctxt->alpn_result.ProtocolIdSize = (unsigned char)alpn_len;
    memcpy(ctxt->alpn_result.ProtocolId, alpn_proto, alpn_len);
  }
  else {
    ctxt->alpn_result.ProtoNegoStatus =
      SecApplicationProtocolNegotiationStatus_None;
    ctxt->alpn_result.ProtoNegoExt =
      SecApplicationProtocolNegotiationExt_None;
    ctxt->alpn_result.ProtocolIdSize = 0;
  }

  if(!ctxt->remote_cert_context) {
    X509 *peer = SSL_get1_peer_certificate(ctxt->ssl);
    if(peer) {
      HCERTSTORE peer_store = NULL;
      STACK_OF(X509) *chain;
      int n;
      int i;

      chain = SSL_get_peer_cert_chain(ctxt->ssl);
      if(chain) {
        n = sk_X509_num(chain);
        peer_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
        if(peer_store) {
          mock_cert_store_t *s = (mock_cert_store_t *)peer_store;
          for(i = 0; i < n; i++) {
            X509 *cx = sk_X509_value(chain, i);
            if(cx) {
              X509_up_ref(cx);
              sk_X509_push(s->certs, cx);
              sk_EVP_PKEY_push(s->keys, NULL);
            }
          }
        }
      }
      ctxt->remote_cert_context = (CERT_CONTEXT *)
        mock_cert_context_new(peer, NULL, peer_store);
      if(!ctxt->remote_cert_context) {
        if(peer_store)
          CertCloseStore(peer_store, 0);
        X509_free(peer);
      }
    }
  }

  ctxt->stream_sizes.cbHeader = 5;
  ctxt->stream_sizes.cbTrailer = 64;
  ctxt->stream_sizes.cbMaximumMessage = 16384;
  ctxt->stream_sizes.cBuffers = 4;
  ctxt->stream_sizes.cbBlockSize = 0;
}

static SECURITY_STATUS do_initialize_security_context(
  PCredHandle phCredential,
  PCtxtHandle phContext,
  const char *target_name,
  unsigned long fContextReq,
  PSecBufferDesc pInput,
  PCtxtHandle phNewContext,
  PSecBufferDesc pOutput,
  unsigned long *pfContextAttr,
  TimeStamp *ptsExpiry)
{
  mock_ctxt_t *ctxt;
  SecBuffer *in_token = NULL;
  SecBuffer *in_extra = NULL;
  const uint8_t *in_data;
  size_t in_len;
  size_t consumed = 0;
  int ret;
  size_t unread;
  size_t total_unconsumed;
  size_t out_pending;
  SECURITY_STATUS out_status;
  int ssl_err;

  /* Leg 1: Initial context establishment */
  if(!phContext || phContext->dwLower == 0) {
    mock_cred_t *cred;
    size_t pending;
    if(!IS_VALID_CRED(phCredential))
      return SEC_E_INVALID_HANDLE;

    if(!phNewContext && !phContext)
      return SEC_E_INVALID_HANDLE;

    if(!pOutput || pOutput->cBuffers < 1 || !pOutput->pBuffers)
      return SEC_E_INVALID_TOKEN;

    cred = (mock_cred_t *)phCredential->dwLower;
    ctxt = (mock_ctxt_t *)calloc(1, sizeof(mock_ctxt_t));
    if(!ctxt)
      return SEC_E_INSUFFICIENT_MEMORY;

    ctxt->magic = MOCK_MAGIC_CTXT;
    ctxt->cred = cred;
    cred->refcount++;
    ctxt->req_flags = fContextReq;

    ctxt->stream_sizes.cbHeader = 5;
    ctxt->stream_sizes.cbTrailer = 64;
    ctxt->stream_sizes.cbMaximumMessage = 16384;
    ctxt->stream_sizes.cBuffers = 4;
    ctxt->stream_sizes.cbBlockSize = 0;

    ctxt->ssl = SSL_new(cred->ssl_ctx);
    if(!ctxt->ssl) {
      free_cred_internal(cred);
      free(ctxt);
      return SEC_E_INSUFFICIENT_MEMORY;
    }

    SSL_set_app_data(ctxt->ssl, ctxt);

    ctxt->rbio = BIO_new(BIO_s_mem());
    ctxt->wbio = BIO_new(BIO_s_mem());
    if(!ctxt->rbio || !ctxt->wbio) {
      if(ctxt->rbio)
        BIO_free(ctxt->rbio);
      if(ctxt->wbio)
        BIO_free(ctxt->wbio);
      SSL_free(ctxt->ssl);
      free_cred_internal(cred);
      free(ctxt);
      return SEC_E_INSUFFICIENT_MEMORY;
    }

    BIO_set_mem_eof_return(ctxt->rbio, -1);
    BIO_set_mem_eof_return(ctxt->wbio, -1);
    SSL_set_bio(ctxt->ssl, ctxt->rbio, ctxt->wbio);
    SSL_set_connect_state(ctxt->ssl);

    if(target_name && *target_name) {
      struct in_addr addr4;
      struct in6_addr addr6;
      ctxt->sni_hostname = strdup(target_name);
      if(inet_pton(AF_INET, target_name, &addr4) <= 0 &&
         inet_pton(AF_INET6, target_name, &addr6) <= 0) {
        SSL_set_tlsext_host_name(ctxt->ssl, target_name);
      }
    }

    configure_alpn(ctxt->ssl, pInput);

    /* Generate ClientHello */
    (void)SSL_connect(ctxt->ssl);

    pending = (size_t)BIO_ctrl_pending(ctxt->wbio);
    if(pending == 0) {
      SSL_free(ctxt->ssl);
      free_cred_internal(cred);
      if(ctxt->sni_hostname)
        free(ctxt->sni_hostname);
      free(ctxt);
      return SEC_E_INTERNAL_ERROR;
    }

    out_status = write_output_token(ctxt, pOutput, pending);
    if(out_status != SEC_E_OK) {
      SSL_free(ctxt->ssl);
      free_cred_internal(cred);
      if(ctxt->sni_hostname)
        free(ctxt->sni_hostname);
      free(ctxt);
      return out_status;
    }

    if(phNewContext) {
      phNewContext->dwLower = (uintptr_t)ctxt;
      phNewContext->dwUpper = (uintptr_t)MOCK_MAGIC_CTXT;
    }
    if(phContext) {
      phContext->dwLower = (uintptr_t)ctxt;
      phContext->dwUpper = (uintptr_t)MOCK_MAGIC_CTXT;
    }
    if(pfContextAttr)
      *pfContextAttr = ctxt->req_flags;
    if(ptsExpiry) {
      ptsExpiry->LowPart = 0xFFFFFFFF;
      ptsExpiry->HighPart = 0x7FFFFFFF;
    }
    return SEC_I_CONTINUE_NEEDED;
  }

  /* Leg 2+: Ingest server handshake flight and advance state machine */
  if(!IS_VALID_CTXT(phContext))
    return SEC_E_INVALID_HANDLE;

  ctxt = (mock_ctxt_t *)phContext->dwLower;

  if(phNewContext) {
    phNewContext->dwLower = (uintptr_t)ctxt;
    phNewContext->dwUpper = (uintptr_t)MOCK_MAGIC_CTXT;
  }

  /* Handle shutdown sequence */
  if(ctxt->shutdown_token_pending) {
    size_t pending;

    ctxt->shutdown_token_pending = false;
    ctxt->connection_closed = true;
    (void)SSL_shutdown(ctxt->ssl);

    pending = (size_t)BIO_ctrl_pending(ctxt->wbio);
    if(pending > 0 && pOutput) {
      out_status = write_output_token(ctxt, pOutput, pending);
      if(out_status != SEC_E_OK)
        return out_status;
    }
    return SEC_E_OK;
  }

  /* Locate input token and extra buffer */
  if(pInput && pInput->pBuffers) {
    unsigned long i;
    for(i = 0; i < pInput->cBuffers; i++) {
      if(pInput->pBuffers[i].BufferType == SECBUFFER_TOKEN &&
         pInput->pBuffers[i].pvBuffer && pInput->pBuffers[i].cbBuffer > 0) {
        in_token = &pInput->pBuffers[i];
      }
      else if(pInput->pBuffers[i].BufferType == SECBUFFER_EMPTY && !in_extra) {
        in_extra = &pInput->pBuffers[i];
      }
    }
  }

  if(!in_token)
    return SEC_E_INCOMPLETE_MESSAGE;
  else {
    uint16_t first_len;

    in_data = (const uint8_t *)in_token->pvBuffer;
    in_len = in_token->cbBuffer;

    if(in_len < 5)
      return SEC_E_INCOMPLETE_MESSAGE;

    first_len = (uint16_t)((in_data[3] << 8) | in_data[4]);
    if(in_len < (size_t)(5 + first_len))
      return SEC_E_INCOMPLETE_MESSAGE;

    /* Parse all contiguous complete records */
    while(consumed + 5 <= in_len) {
      uint16_t rec_len = (uint16_t)((in_data[consumed + 3] << 8) |
                                    in_data[consumed + 4]);
      if(consumed + 5 + rec_len <= in_len)
        consumed += 5 + rec_len;
      else
        break;
    }
  }

  /* Feed complete records into OpenSSL */
  BIO_write(ctxt->rbio, in_data, (int)consumed);

  /* Advance TLS handshake */
  ret = SSL_connect(ctxt->ssl);

  /* Check unread bytes remaining in rbio */
  unread = (size_t)BIO_ctrl_pending(ctxt->rbio);
  total_unconsumed = (in_len - consumed) + unread;
  if(unread > 0)
    (void)BIO_reset(ctxt->rbio);

  /* Set SECBUFFER_EXTRA if there are leftover unconsumed bytes */
  if(in_extra) {
    if(total_unconsumed > 0) {
      in_extra->BufferType = SECBUFFER_EXTRA;
      in_extra->cbBuffer = (unsigned long)total_unconsumed;
      in_extra->pvBuffer =
        (uint8_t *)in_token->pvBuffer + (in_len - total_unconsumed);
    }
    else {
      in_extra->BufferType = SECBUFFER_EMPTY;
      in_extra->cbBuffer = 0;
      in_extra->pvBuffer = NULL;
    }
  }

  /* Write any output tokens generated */
  out_pending = (size_t)BIO_ctrl_pending(ctxt->wbio);
  out_status = write_output_token(ctxt, pOutput, out_pending);
  if(out_status != SEC_E_OK)
    return out_status;

  /* Check if handshake is complete */
  if(ret == 1 || SSL_is_init_finished(ctxt->ssl)) {
    ctxt->ret_flags = ISC_RET_CONFIDENTIALITY | ISC_RET_STREAM |
      ISC_RET_SEQUENCE_DETECT | ISC_RET_REPLAY_DETECT;
    if(ctxt->req_flags & ISC_REQ_ALLOCATE_MEMORY)
      ctxt->ret_flags |= ISC_RET_ALLOCATED_MEMORY;
    if(ctxt->req_flags & ISC_REQ_USE_SUPPLIED_CREDS)
      ctxt->ret_flags |= ISC_RET_USED_SUPPLIED_CREDS;

    finalize_handshake_state(ctxt);

    if(pfContextAttr)
      *pfContextAttr = ctxt->ret_flags;
    if(ptsExpiry) {
      ptsExpiry->LowPart = 0xFFFFFFFF;
      ptsExpiry->HighPart = 0x7FFFFFFF;
    }
    return SEC_E_OK;
  }

  ssl_err = SSL_get_error(ctxt->ssl, ret);
  if(ssl_err == SSL_ERROR_WANT_READ) {
    if(pfContextAttr)
      *pfContextAttr = ctxt->req_flags;
    if(ptsExpiry) {
      ptsExpiry->LowPart = 0xFFFFFFFF;
      ptsExpiry->HighPart = 0x7FFFFFFF;
    }
    return SEC_I_CONTINUE_NEEDED;
  }

  if(ctxt->client_cert_requested &&
     !(ctxt->req_flags & ISC_REQ_USE_SUPPLIED_CREDS)) {
    return SEC_I_INCOMPLETE_CREDENTIALS;
  }
  else {
    unsigned long err = ERR_peek_error();
    if(ERR_GET_REASON(err) == SSL_R_CERTIFICATE_VERIFY_FAILED)
      return SEC_E_WRONG_PRINCIPAL;
  }

  return SEC_E_INTERNAL_ERROR;
}

static SECURITY_STATUS WINAPI mock_InitializeSecurityContextA(
  PCredHandle phCredential, PCtxtHandle phContext, LPSTR pszTargetName,
  unsigned long fContextReq, unsigned long Reserved1,
  unsigned long TargetDataRep,
  PSecBufferDesc pInput, unsigned long Reserved2, PCtxtHandle phNewContext,
  PSecBufferDesc pOutput, unsigned long *pfContextAttr, TimeStamp *ptsExpiry)
{
  (void)Reserved1;
  (void)TargetDataRep;
  (void)Reserved2;
  return do_initialize_security_context(
    phCredential, phContext, pszTargetName, fContextReq,
    pInput, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}

static SECURITY_STATUS WINAPI mock_InitializeSecurityContextW(
  PCredHandle phCredential, PCtxtHandle phContext, LPWSTR pszTargetName,
  unsigned long fContextReq, unsigned long Reserved1,
  unsigned long TargetDataRep,
  PSecBufferDesc pInput, unsigned long Reserved2, PCtxtHandle phNewContext,
  PSecBufferDesc pOutput, unsigned long *pfContextAttr, TimeStamp *ptsExpiry)
{
  char target_name_a[512] = {0};
  (void)Reserved1;
  (void)TargetDataRep;
  (void)Reserved2;
  if(pszTargetName) {
    WideCharToMultiByte(CP_UTF8, 0, pszTargetName, -1,
                        target_name_a, sizeof(target_name_a), NULL, NULL);
  }
  return do_initialize_security_context(
    phCredential, phContext, pszTargetName ? target_name_a : NULL,
    fContextReq, pInput, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}

static SECURITY_STATUS WINAPI mock_DeleteSecurityContext(PCtxtHandle phContext)
{
  mock_ctxt_t *ctxt;
  if(!IS_VALID_CTXT(phContext))
    return SEC_E_INVALID_HANDLE;

  ctxt = (mock_ctxt_t *)phContext->dwLower;
  phContext->dwLower = 0;
  phContext->dwUpper = 0;

  if(ctxt->ssl) {
    SSL_free(ctxt->ssl);
    ctxt->ssl = NULL;
    ctxt->rbio = NULL;
    ctxt->wbio = NULL;
  }

  if(ctxt->remote_cert_context) {
    if(ctxt->remote_cert_context->hCertStore) {
      CertCloseStore(ctxt->remote_cert_context->hCertStore, 0);
      ctxt->remote_cert_context->hCertStore = NULL;
    }
    CertFreeCertificateContext(ctxt->remote_cert_context);
    ctxt->remote_cert_context = NULL;
  }

  if(ctxt->sni_hostname) {
    free(ctxt->sni_hostname);
    ctxt->sni_hostname = NULL;
  }

  if(ctxt->cred) {
    free_cred_internal(ctxt->cred);
    ctxt->cred = NULL;
  }

  ctxt->magic = 0;
  free(ctxt);

  return SEC_E_OK;
}

static SECURITY_STATUS do_query_context_attributes(
  PCtxtHandle phContext, unsigned long ulAttribute, void *pBuffer)
{
  mock_ctxt_t *ctxt;
  if(!IS_VALID_CTXT(phContext))
    return SEC_E_INVALID_HANDLE;
  if(!pBuffer)
    return SEC_E_INTERNAL_ERROR;

  ctxt = (mock_ctxt_t *)phContext->dwLower;

  switch(ulAttribute) {
  case SECPKG_ATTR_STREAM_SIZES: {
    SecPkgContext_StreamSizes *sizes = (SecPkgContext_StreamSizes *)pBuffer;
    *sizes = ctxt->stream_sizes;
    return SEC_E_OK;
  }
  case SECPKG_ATTR_SIZES: {
    SecPkgContext_Sizes *sizes = (SecPkgContext_Sizes *)pBuffer;
    sizes->cbMaxToken = ctxt->stream_sizes.cbMaximumMessage;
    sizes->cbMaxSignature = ctxt->stream_sizes.cbTrailer;
    sizes->cbBlockSize = ctxt->stream_sizes.cbBlockSize;
    sizes->cbSecurityTrailer = ctxt->stream_sizes.cbTrailer;
    return SEC_E_OK;
  }
  case SECPKG_ATTR_APPLICATION_PROTOCOL: {
    SecPkgContext_ApplicationProtocol *proto =
      (SecPkgContext_ApplicationProtocol *)pBuffer;
    *proto = ctxt->alpn_result;
    return SEC_E_OK;
  }
  case SECPKG_ATTR_REMOTE_CERT_CONTEXT: {
    PCCERT_CONTEXT *ppCert = (PCCERT_CONTEXT *)pBuffer;
    if(!ctxt->remote_cert_context)
      return SEC_E_INTERNAL_ERROR;
    CertDuplicateCertificateContext(ctxt->remote_cert_context);
    *ppCert = ctxt->remote_cert_context;
    return SEC_E_OK;
  }
  default:
    return SEC_E_UNSUPPORTED_FUNCTION;
  }
}

static SECURITY_STATUS WINAPI mock_QueryContextAttributesA(
  PCtxtHandle phContext, unsigned long ulAttribute, void *pBuffer)
{
  return do_query_context_attributes(phContext, ulAttribute, pBuffer);
}

static SECURITY_STATUS WINAPI mock_QueryContextAttributesW(
  PCtxtHandle phContext, unsigned long ulAttribute, void *pBuffer)
{
  return do_query_context_attributes(phContext, ulAttribute, pBuffer);
}

static SECURITY_STATUS WINAPI mock_EncryptMessage(
  PCtxtHandle phContext, unsigned long fQOP, PSecBufferDesc pMessage,
  unsigned long MessageSeqNo)
{
  SecBuffer *hdr_buf = NULL;
  SecBuffer *data_buf = NULL;
  SecBuffer *trailer_buf = NULL;
  mock_ctxt_t *ctxt;
  unsigned long i;
  size_t data_len;
  int written;
  size_t enc_total;
  size_t trailer_len;
  unsigned char *enc_record;
  int nread;
  (void)fQOP;
  (void)MessageSeqNo;

  if(!IS_VALID_CTXT(phContext))
    return SEC_E_INVALID_HANDLE;

  if(!pMessage || pMessage->cBuffers < 3 || !pMessage->pBuffers)
    return SEC_E_INVALID_TOKEN;

  ctxt = (mock_ctxt_t *)phContext->dwLower;

  for(i = 0; i < pMessage->cBuffers; i++) {
    if(pMessage->pBuffers[i].BufferType == SECBUFFER_STREAM_HEADER)
      hdr_buf = &pMessage->pBuffers[i];
    else if(pMessage->pBuffers[i].BufferType == SECBUFFER_DATA)
      data_buf = &pMessage->pBuffers[i];
    else if(pMessage->pBuffers[i].BufferType == SECBUFFER_STREAM_TRAILER)
      trailer_buf = &pMessage->pBuffers[i];
  }

  if(!hdr_buf || !data_buf || !trailer_buf)
    return SEC_E_INVALID_TOKEN;

  if(!hdr_buf->pvBuffer || !data_buf->pvBuffer || !trailer_buf->pvBuffer)
    return SEC_E_INVALID_TOKEN;

  if(data_buf->cbBuffer > ctxt->stream_sizes.cbMaximumMessage)
    return SEC_E_BUFFER_TOO_SMALL;

  data_len = data_buf->cbBuffer;

  written = SSL_write(ctxt->ssl, data_buf->pvBuffer, (int)data_len);
  if((data_len > 0 && written <= 0) || (data_len == 0 && written < 0))
    return SEC_E_INTERNAL_ERROR;

  enc_total = (size_t)BIO_ctrl_pending(ctxt->wbio);
  if(enc_total < 5 + data_len)
    return SEC_E_INTERNAL_ERROR;

  trailer_len = enc_total - 5 - data_len;

  if(hdr_buf->cbBuffer < 5 || trailer_buf->cbBuffer < trailer_len)
    return SEC_E_BUFFER_TOO_SMALL;

  enc_record = (unsigned char *)malloc(enc_total);
  if(!enc_record)
    return SEC_E_INSUFFICIENT_MEMORY;

  nread = BIO_read(ctxt->wbio, enc_record, (int)enc_total);
  if(nread != (int)enc_total) {
    free(enc_record);
    return SEC_E_INTERNAL_ERROR;
  }

  memcpy(hdr_buf->pvBuffer, enc_record, 5);
  hdr_buf->cbBuffer = 5;

  memcpy(data_buf->pvBuffer, enc_record + 5, data_len);
  data_buf->cbBuffer = (unsigned long)data_len;

  memcpy(trailer_buf->pvBuffer, enc_record + 5 + data_len, trailer_len);
  trailer_buf->cbBuffer = (unsigned long)trailer_len;

  free(enc_record);
  return SEC_E_OK;
}

static SECURITY_STATUS WINAPI mock_DecryptMessage(
  PCtxtHandle phContext, PSecBufferDesc pMessage, unsigned long MessageSeqNo,
  unsigned long *pfQOP)
{
  mock_ctxt_t *ctxt;
  SecBuffer *in_buf;
  size_t total_len;
  const unsigned char *raw;
  uint16_t rec_len;
  size_t full_rec_len;
  int ret;
  int ssl_err;
  unsigned long i;

  (void)MessageSeqNo;

  if(!IS_VALID_CTXT(phContext))
    return SEC_E_INVALID_HANDLE;

  if(!pMessage || pMessage->cBuffers < 4 || !pMessage->pBuffers)
    return SEC_E_INVALID_TOKEN;

  ctxt = (mock_ctxt_t *)phContext->dwLower;

  in_buf = &pMessage->pBuffers[0];
  if(in_buf->BufferType != SECBUFFER_DATA || !in_buf->pvBuffer)
    return SEC_E_INVALID_TOKEN;

  total_len = in_buf->cbBuffer;
  if(total_len < 5)
    return SEC_E_INCOMPLETE_MESSAGE;

  raw = (const unsigned char *)in_buf->pvBuffer;
  rec_len = (uint16_t)((raw[3] << 8) | raw[4]);
  full_rec_len = (size_t)5 + rec_len;

  if(total_len < full_rec_len)
    return SEC_E_INCOMPLETE_MESSAGE;

  /* Check if remote party requested TLS renegotiation (HelloRequest) */
  if(raw[0] == 0x16 && rec_len > 0 && raw[5] == 0x00) {
    pMessage->pBuffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    pMessage->pBuffers[0].cbBuffer = 5;

    pMessage->pBuffers[1].BufferType = SECBUFFER_DATA;
    pMessage->pBuffers[1].pvBuffer = (unsigned char *)in_buf->pvBuffer + 5;
    pMessage->pBuffers[1].cbBuffer = 0;

    pMessage->pBuffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    pMessage->pBuffers[2].pvBuffer = (unsigned char *)in_buf->pvBuffer + 5;
    pMessage->pBuffers[2].cbBuffer = (unsigned long)rec_len;

    if(total_len > full_rec_len) {
      pMessage->pBuffers[3].BufferType = SECBUFFER_EXTRA;
      pMessage->pBuffers[3].pvBuffer =
        (unsigned char *)in_buf->pvBuffer + full_rec_len;
      pMessage->pBuffers[3].cbBuffer =
        (unsigned long)(total_len - full_rec_len);
    }
    else {
      pMessage->pBuffers[3].BufferType = SECBUFFER_EMPTY;
      pMessage->pBuffers[3].pvBuffer = NULL;
      pMessage->pBuffers[3].cbBuffer = 0;
    }

    if(pfQOP)
      *pfQOP = 0;

    return SEC_I_RENEGOTIATE;
  }

  /* Feed exactly this TLS record into read BIO */
  BIO_write(ctxt->rbio, raw, (int)full_rec_len);

  {
    unsigned char dec_buf[17408];
    ret = SSL_read(ctxt->ssl, dec_buf, sizeof(dec_buf));

    if(ret > 0) {
      size_t decrypted_len = (size_t)ret;
      memcpy((unsigned char *)in_buf->pvBuffer + 5, dec_buf, decrypted_len);

      pMessage->pBuffers[0].BufferType = SECBUFFER_STREAM_HEADER;
      pMessage->pBuffers[0].cbBuffer = 5;

      pMessage->pBuffers[1].BufferType = SECBUFFER_DATA;
      pMessage->pBuffers[1].pvBuffer = (unsigned char *)in_buf->pvBuffer + 5;
      pMessage->pBuffers[1].cbBuffer = (unsigned long)decrypted_len;

      pMessage->pBuffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
      pMessage->pBuffers[2].pvBuffer =
        (unsigned char *)in_buf->pvBuffer + 5 + decrypted_len;
      pMessage->pBuffers[2].cbBuffer =
        (unsigned long)(rec_len > decrypted_len ?
                        (rec_len - decrypted_len) : 0);

      if(total_len > full_rec_len) {
        pMessage->pBuffers[3].BufferType = SECBUFFER_EXTRA;
        pMessage->pBuffers[3].pvBuffer =
          (unsigned char *)in_buf->pvBuffer + full_rec_len;
        pMessage->pBuffers[3].cbBuffer =
          (unsigned long)(total_len - full_rec_len);
      }
      else {
        pMessage->pBuffers[3].BufferType = SECBUFFER_EMPTY;
        pMessage->pBuffers[3].pvBuffer = NULL;
        pMessage->pBuffers[3].cbBuffer = 0;
      }

      for(i = 4; i < pMessage->cBuffers; i++) {
        pMessage->pBuffers[i].BufferType = SECBUFFER_EMPTY;
        pMessage->pBuffers[i].pvBuffer = NULL;
        pMessage->pBuffers[i].cbBuffer = 0;
      }

      if(pfQOP)
        *pfQOP = 0;

      return SEC_E_OK;
    }
  }

  ssl_err = SSL_get_error(ctxt->ssl, ret);

  if(ssl_err == SSL_ERROR_ZERO_RETURN) {
    /* TLS close_notify received */
    pMessage->pBuffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    pMessage->pBuffers[0].cbBuffer = 5;

    pMessage->pBuffers[1].BufferType = SECBUFFER_DATA;
    pMessage->pBuffers[1].pvBuffer = (unsigned char *)in_buf->pvBuffer + 5;
    pMessage->pBuffers[1].cbBuffer = 0;

    pMessage->pBuffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    pMessage->pBuffers[2].pvBuffer = (unsigned char *)in_buf->pvBuffer + 5;
    pMessage->pBuffers[2].cbBuffer = (unsigned long)rec_len;

    if(total_len > full_rec_len) {
      pMessage->pBuffers[3].BufferType = SECBUFFER_EXTRA;
      pMessage->pBuffers[3].pvBuffer =
        (unsigned char *)in_buf->pvBuffer + full_rec_len;
      pMessage->pBuffers[3].cbBuffer =
        (unsigned long)(total_len - full_rec_len);
    }
    else {
      pMessage->pBuffers[3].BufferType = SECBUFFER_EMPTY;
      pMessage->pBuffers[3].pvBuffer = NULL;
      pMessage->pBuffers[3].cbBuffer = 0;
    }

    for(i = 4; i < pMessage->cBuffers; i++) {
      pMessage->pBuffers[i].BufferType = SECBUFFER_EMPTY;
      pMessage->pBuffers[i].pvBuffer = NULL;
      pMessage->pBuffers[i].cbBuffer = 0;
    }

    ctxt->connection_closed = true;
    if(pfQOP)
      *pfQOP = 0;

    return SEC_I_CONTEXT_EXPIRED;
  }

  if(ssl_err == SSL_ERROR_WANT_READ) {
    /* Non-application data record consumed */
    pMessage->pBuffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    pMessage->pBuffers[0].cbBuffer = 5;

    pMessage->pBuffers[1].BufferType = SECBUFFER_DATA;
    pMessage->pBuffers[1].pvBuffer = (unsigned char *)in_buf->pvBuffer + 5;
    pMessage->pBuffers[1].cbBuffer = 0;

    pMessage->pBuffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    pMessage->pBuffers[2].pvBuffer = (unsigned char *)in_buf->pvBuffer + 5;
    pMessage->pBuffers[2].cbBuffer = (unsigned long)rec_len;

    if(total_len > full_rec_len) {
      pMessage->pBuffers[3].BufferType = SECBUFFER_EXTRA;
      pMessage->pBuffers[3].pvBuffer =
        (unsigned char *)in_buf->pvBuffer + full_rec_len;
      pMessage->pBuffers[3].cbBuffer =
        (unsigned long)(total_len - full_rec_len);
    }
    else {
      pMessage->pBuffers[3].BufferType = SECBUFFER_EMPTY;
      pMessage->pBuffers[3].pvBuffer = NULL;
      pMessage->pBuffers[3].cbBuffer = 0;
    }

    for(i = 4; i < pMessage->cBuffers; i++) {
      pMessage->pBuffers[i].BufferType = SECBUFFER_EMPTY;
      pMessage->pBuffers[i].pvBuffer = NULL;
      pMessage->pBuffers[i].cbBuffer = 0;
    }

    if(pfQOP)
      *pfQOP = 0;

    return SEC_E_OK;
  }

  /* Any remaining bytes in rbio on failure must be drained */
  (void)BIO_reset(ctxt->rbio);
  return SEC_E_DECRYPT_FAILURE;
}

static SECURITY_STATUS WINAPI mock_ApplyControlToken(
  PCtxtHandle phContext, PSecBufferDesc pInput)
{
  mock_ctxt_t *ctxt;
  unsigned long i;
  if(!IS_VALID_CTXT(phContext))
    return SEC_E_INVALID_HANDLE;
  if(!pInput || pInput->cBuffers < 1 || !pInput->pBuffers)
    return SEC_E_INVALID_TOKEN;

  ctxt = (mock_ctxt_t *)phContext->dwLower;
  for(i = 0; i < pInput->cBuffers; i++) {
    SecBuffer *buf = &pInput->pBuffers[i];
    if(buf->pvBuffer && buf->cbBuffer >= sizeof(DWORD)) {
      DWORD token = *(DWORD *)buf->pvBuffer;
      if(token == SCHANNEL_SHUTDOWN) {
        ctxt->shutdown_token_pending = true;
      }
    }
  }
  return SEC_E_OK;
}
