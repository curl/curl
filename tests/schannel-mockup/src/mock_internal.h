#ifndef MOCK_INTERNAL_H
#define MOCK_INTERNAL_H
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
#include <stdint.h>
#include <stdbool.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/safestack.h>
#include <arpa/inet.h>

DEFINE_STACK_OF(EVP_PKEY)

/* Mock headers */
#include "windows.h"
#include "sspi.h"
#include "schannel.h"
#include "wincrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Magic numbers for handle validation */
#define MOCK_MAGIC_CRED   0x4D435244 /* "MCRD" */
#define MOCK_MAGIC_CTXT   0x4D435458 /* "MCTX" */
#define MOCK_MAGIC_STORE  0x4D535452 /* "MSTR" */
#define MOCK_MAGIC_ENGINE 0x4D454E47 /* "MENG" */
#define MOCK_MAGIC_CHAIN  0x4D43484E /* "MCHN" */

/*
 * Internal mock credential structure
 */
typedef struct mock_cred {
  uint32_t magic;
  SSL_CTX *ssl_ctx;
  DWORD enabled_protocols;
  DWORD flags;
  char *cipher_list;
  X509 *client_cert;
  EVP_PKEY *client_key;
  int refcount;
} mock_cred_t;

/*
 * Internal mock certificate context
 */
typedef struct mock_cert_context {
  CERT_CONTEXT public_context;
  CERT_INFO cert_info;
  X509 *x509;
  EVP_PKEY *pkey;
  uint8_t *der_encoded;
  size_t der_len;
  int refcount;
} mock_cert_context_t;

/*
 * Internal mock security context
 */
typedef struct mock_ctxt {
  uint32_t magic;
  SSL *ssl;
  BIO *rbio;
  BIO *wbio;
  mock_cred_t *cred;
  char *sni_hostname;
  unsigned long req_flags;
  unsigned long ret_flags;
  SecPkgContext_StreamSizes stream_sizes;
  SecPkgContext_ApplicationProtocol alpn_result;
  CERT_CONTEXT *remote_cert_context;
  bool client_cert_requested;
  bool shutdown_token_pending;
  bool connection_closed;
  bool renegotiating;
} mock_ctxt_t;

/* Handle validation helpers */
#define IS_VALID_CRED(x)                                        \
  (phCredential && phCredential->dwLower &&                     \
   (phCredential->dwUpper == (uintptr_t)MOCK_MAGIC_CRED) &&     \
   ((mock_cred_t *)phCredential->dwLower)->magic ==             \
   MOCK_MAGIC_CRED)

#define IS_VALID_CTXT(x)                                        \
  (phContext && phContext->dwLower &&                           \
   (phContext->dwUpper == (uintptr_t)MOCK_MAGIC_CTXT) &&        \
   ((mock_ctxt_t *)phContext->dwLower)->magic ==                \
   MOCK_MAGIC_CTXT)

/*
 * Internal mock certificate store
 */
typedef struct mock_cert_store {
  uint32_t magic;
  STACK_OF(X509) *certs;
  STACK_OF(EVP_PKEY) *keys;
  int refcount;
} mock_cert_store_t;

/*
 * Internal mock chain engine
 */
typedef struct mock_chain_engine {
  uint32_t magic;
  X509_STORE *x509_store;
} mock_chain_engine_t;

/*
 * Internal mock chain context
 */
typedef struct mock_chain_context {
  uint32_t magic;
  CERT_CHAIN_CONTEXT public_ctx;
  CERT_SIMPLE_CHAIN simple_chain;
  PCERT_SIMPLE_CHAIN chain_ptr;
  PCERT_CHAIN_ELEMENT *element_ptrs;
  CERT_CHAIN_ELEMENT *elements;
  DWORD num_elements;
} mock_chain_context_t;

/*
 * Helper functions for cert context management
 */
mock_cert_context_t *mock_cert_context_new(X509 *x509, EVP_PKEY *pkey,
                                           HCERTSTORE store_handle);
void mock_cert_context_free_extensions(CERT_INFO *ci);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_INTERNAL_H */
