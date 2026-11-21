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

/*
 * mock_crypto.c - CryptoAPI certificate store and chain mocks.
 *
 * Implements:
 *   mock_cert_context_new, mock_cert_context_free_extensions
 *   CertOpenStore, CertCloseStore
 *   CertAddCertificateContextToStore
 *   CertEnumCertificatesInStore, CertFindCertificateInStore
 *   CryptQueryObject
 *   PFXImportCertStore
 *   CryptStringToBinaryA, CryptStringToBinaryW
 *   CertCreateCertificateChainEngine, CertFreeCertificateChainEngine
 *   CertGetCertificateChain, CertFreeCertificateChain
 */

#include "mock_internal.h"

void mock_cert_context_free_extensions(CERT_INFO *ci)
{
  DWORD i;
  if(!ci || !ci->rgExtension)
    return;
  for(i = 0; i < ci->cExtension; i++) {
    free(ci->rgExtension[i].pszObjId);
    free(ci->rgExtension[i].Value.pbData);
  }
  free(ci->rgExtension);
  ci->rgExtension = NULL;
  ci->cExtension = 0;
}

mock_cert_context_t *mock_cert_context_new(X509 *x509, EVP_PKEY *pkey,
                                           HCERTSTORE store_handle)
{
  mock_cert_context_t *mc;
  unsigned char *der_buf = NULL;
  int der_len;
  int ext_count;
  int i;

  mc = calloc(1, sizeof(mock_cert_context_t));
  if(!mc)
    return NULL;

  der_len = i2d_X509(x509, &der_buf);
  if(der_len < 0) {
    free(mc);
    return NULL;
  }

  mc->x509 = x509;
  mc->pkey = pkey;
  mc->der_encoded = der_buf;
  mc->der_len = (size_t)der_len;
  mc->refcount = 1;

  mc->public_context.dwCertEncodingType =
    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
  mc->public_context.pbCertEncoded = mc->der_encoded;
  mc->public_context.cbCertEncoded = (DWORD)mc->der_len;
  mc->public_context.pCertInfo = &mc->cert_info;
  mc->public_context.hCertStore = store_handle;

  ext_count = X509_get_ext_count(x509);
  mc->cert_info.cExtension = 0;
  mc->cert_info.rgExtension = NULL;

  if(ext_count > 0) {
    CERT_EXTENSION *exts;
    int valid = 0;

    exts = calloc((size_t)ext_count, sizeof(CERT_EXTENSION));
    if(exts) {
      for(i = 0; i < ext_count; i++) {
        X509_EXTENSION *xe = X509_get_ext(x509, i);
        ASN1_OBJECT *obj;
        ASN1_OCTET_STRING *val;
        char oid_buf[64];
        char *oid_str;
        const unsigned char *val_data;
        int val_len;

        if(!xe)
          continue;
        obj = X509_EXTENSION_get_object(xe);
        val = X509_EXTENSION_get_data(xe);
        if(!obj || !val)
          continue;

        OBJ_obj2txt(oid_buf, (int)sizeof(oid_buf), obj, 1);
        oid_str = strdup(oid_buf);
        if(!oid_str)
          continue;

        val_data = ASN1_STRING_get0_data(val);
        val_len = ASN1_STRING_length(val);

        exts[valid].pszObjId = oid_str;
        exts[valid].fCritical = X509_EXTENSION_get_critical(xe) ? TRUE : FALSE;
        if(val_len > 0) {
          BYTE *vbuf = malloc((size_t)val_len);
          if(vbuf) {
            memcpy(vbuf, val_data, (size_t)val_len);
            exts[valid].Value.pbData = vbuf;
            exts[valid].Value.cbData = (DWORD)val_len;
          }
        }
        valid++;
      }
      mc->cert_info.cExtension = (DWORD)valid;
      mc->cert_info.rgExtension = exts;
    }
  }

  return mc;
}

HCERTSTORE WINAPI CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType,
                                HCRYPTPROV hCryptProv, DWORD dwFlags,
                                const void *pvPara)
{
  mock_cert_store_t *store;
  (void)dwEncodingType;
  (void)hCryptProv;
  (void)dwFlags;
  (void)pvPara;

  if(lpszStoreProvider != CERT_STORE_PROV_MEMORY) {
    SetLastError(ERROR_NOT_SUPPORTED);
    return NULL;
  }

  store = calloc(1, sizeof(mock_cert_store_t));
  if(!store) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  store->certs = sk_X509_new_null();
  store->keys = sk_EVP_PKEY_new_null();
  if(!store->certs || !store->keys) {
    if(store->certs) {
      sk_X509_free(store->certs);
    }
    if(store->keys) {
      sk_EVP_PKEY_free(store->keys);
    }
    free(store);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  store->magic = MOCK_MAGIC_STORE;
  store->refcount = 1;
  return (HCERTSTORE)store;
}

BOOL WINAPI CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags)
{
  mock_cert_store_t *store = (mock_cert_store_t *)hCertStore;
  int i;
  int n;
  (void)dwFlags;

  if(!store || store->magic != MOCK_MAGIC_STORE) {
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }

  store->refcount--;
  if(store->refcount > 0)
    return TRUE;

  if(store->certs) {
    n = sk_X509_num(store->certs);
    for(i = 0; i < n; i++)
      X509_free(sk_X509_value(store->certs, i));
    sk_X509_free(store->certs);
    store->certs = NULL;
  }

  if(store->keys) {
    n = sk_EVP_PKEY_num(store->keys);
    for(i = 0; i < n; i++) {
      EVP_PKEY *pk = sk_EVP_PKEY_value(store->keys, i);
      if(pk)
        EVP_PKEY_free(pk);
    }
    sk_EVP_PKEY_free(store->keys);
    store->keys = NULL;
  }

  store->magic = 0;
  free(store);
  return TRUE;
}

BOOL WINAPI CertAddCertificateContextToStore(HCERTSTORE hCertStore,
                                             PCCERT_CONTEXT pCertContext,
                                             DWORD dwAddDisposition,
                                             PCCERT_CONTEXT *ppStoreContext)
{
  mock_cert_store_t *store = (mock_cert_store_t *)hCertStore;
  mock_cert_context_t *mc;
  X509 *x509copy;
  (void)dwAddDisposition;

  if(!store || store->magic != MOCK_MAGIC_STORE) {
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  if(!pCertContext) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  mc = (mock_cert_context_t *)UNCONST(pCertContext);

  x509copy = mc->x509;
  if(x509copy) {
    X509_up_ref(x509copy);
    if(!sk_X509_push(store->certs, x509copy)) {
      X509_free(x509copy);
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      return FALSE;
    }
    sk_EVP_PKEY_push(store->keys, NULL);
  }

  if(ppStoreContext)
    *ppStoreContext = CertDuplicateCertificateContext(pCertContext);

  return TRUE;
}

PCCERT_CONTEXT WINAPI
CertEnumCertificatesInStore(HCERTSTORE hCertStore,
                            PCCERT_CONTEXT pPrevCertContext)
{
  mock_cert_store_t *store = (mock_cert_store_t *)hCertStore;
  mock_cert_context_t *prev_mc = NULL;
  int idx = 0;
  int n;
  int i;
  X509 *x509;
  mock_cert_context_t *mc;

  if(!store || store->magic != MOCK_MAGIC_STORE) {
    SetLastError(ERROR_INVALID_HANDLE);
    return NULL;
  }

  n = sk_X509_num(store->certs);
  if(n <= 0)
    return NULL;

  if(pPrevCertContext) {
    prev_mc = (mock_cert_context_t *)UNCONST(pPrevCertContext);

    idx = -1;
    for(i = 0; i < n; i++) {
      if(sk_X509_value(store->certs, i) == prev_mc->x509) {
        idx = i + 1;
        break;
      }
    }

    CertFreeCertificateContext(pPrevCertContext);

    if(idx < 0 || idx >= n)
      return NULL;
  }

  x509 = sk_X509_value(store->certs, idx);
  if(!x509)
    return NULL;

  X509_up_ref(x509);
  mc = mock_cert_context_new(x509, NULL, hCertStore);
  if(!mc) {
    X509_free(x509);
    return NULL;
  }
  return (PCCERT_CONTEXT)&mc->public_context;
}

PCCERT_CONTEXT WINAPI
CertFindCertificateInStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType,
                           DWORD dwFindFlags, DWORD dwFindType,
                           const void *pvFindPara,
                           PCCERT_CONTEXT pPrevCertContext)
{
  mock_cert_store_t *store = (mock_cert_store_t *)hCertStore;
  int n;
  int i;
  int start = 0;
  mock_cert_context_t *prev_mc = NULL;
  (void)dwCertEncodingType;
  (void)dwFindFlags;

  if(!store || store->magic != MOCK_MAGIC_STORE) {
    SetLastError(ERROR_INVALID_HANDLE);
    return NULL;
  }

  n = sk_X509_num(store->certs);

  if(pPrevCertContext) {
    prev_mc = (mock_cert_context_t *)UNCONST(pPrevCertContext);
    start = -1;
    for(i = 0; i < n; i++) {
      if(sk_X509_value(store->certs, i) == prev_mc->x509) {
        start = i + 1;
        break;
      }
    }
    CertFreeCertificateContext(pPrevCertContext);
    if(start < 0 || start >= n)
      return NULL;
  }

  for(i = start; i < n; i++) {
    X509 *x509 = sk_X509_value(store->certs, i);
    EVP_PKEY *pkey = NULL;
    int match = 0;

    if(!x509)
      continue;

    switch(dwFindType) {
    case CERT_FIND_ANY:
      match = 1;
      break;

    case CERT_FIND_HASH:
    {
      const CRYPT_HASH_BLOB *blob = (const CRYPT_HASH_BLOB *)pvFindPara;
      unsigned char sha1[20];
      unsigned int sha1_len = 0;
      if(blob && blob->cbData == 20) {
        if(X509_digest(x509, EVP_sha1(), sha1, &sha1_len)) {
          if(sha1_len == 20 &&
             !memcmp(sha1, blob->pbData, 20))
            match = 1;
        }
      }
      break;
    }

    case CERT_FIND_HAS_PRIVATE_KEY:
    {
      int ki = i;
      int kn = sk_EVP_PKEY_num(store->keys);
      if(ki < kn) {
        EVP_PKEY *pk = sk_EVP_PKEY_value(store->keys, ki);
        if(pk) {
          pkey = pk;
          match = 1;
        }
      }
      break;
    }

    default:
      break;
    }

    if(match) {
      X509 *x509dup;
      mock_cert_context_t *mc;
      X509_up_ref(x509);
      x509dup = x509;
      mc = mock_cert_context_new(x509dup, pkey, hCertStore);
      if(!mc) {
        X509_free(x509dup);
        return NULL;
      }
      if(pkey)
        EVP_PKEY_up_ref(pkey);
      return (PCCERT_CONTEXT)&mc->public_context;
    }
  }

  return NULL;
}

BOOL WINAPI CryptQueryObject(DWORD dwObjectType, const void *pvObject,
                             DWORD dwExpectedContentTypeFlags,
                             DWORD dwExpectedFormatTypeFlags,
                             DWORD dwFlags, DWORD *pdwMsgAndCertEncodingType,
                             DWORD *pdwContentType, DWORD *pdwFormatType,
                             HCERTSTORE *phCertStore, void **phMsg,
                             const void **ppvContext)
{
  const CRYPT_DATA_BLOB *blob;
  BIO *bio;
  X509 *x509 = NULL;
  mock_cert_context_t *mc;
  (void)dwExpectedContentTypeFlags;
  (void)dwExpectedFormatTypeFlags;
  (void)dwFlags;
  (void)phCertStore;
  (void)phMsg;

  if(dwObjectType != CERT_QUERY_OBJECT_BLOB) {
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
  }
  if(!pvObject) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  blob = (const CRYPT_DATA_BLOB *)pvObject;
  bio = BIO_new_mem_buf(blob->pbData, (int)blob->cbData);
  if(!bio) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }

  x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if(!x509) {
    BIO_reset(bio);
    x509 = d2i_X509_bio(bio, NULL);
  }
  BIO_free(bio);

  if(!x509) {
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
  }

  mc = mock_cert_context_new(x509, NULL, NULL);
  if(!mc) {
    X509_free(x509);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }

  if(pdwMsgAndCertEncodingType)
    *pdwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
  if(pdwContentType)
    *pdwContentType = CERT_QUERY_CONTENT_FLAG_CERT;
  if(pdwFormatType)
    *pdwFormatType = 0;
  if(ppvContext)
    *ppvContext = (const void *)&mc->public_context;

  return TRUE;
}

HCERTSTORE WINAPI PFXImportCertStore(CRYPT_DATA_BLOB *pPFX,
                                     LPCWSTR szPassword, DWORD dwFlags)
{
  BIO *bio;
  PKCS12 *p12 = NULL;
  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  STACK_OF(X509) *ca_certs = NULL;
  char pw_buf[256];
  const char *password;
  mock_cert_store_t *store;
  mock_cert_context_t *mc;
  int i;
  int rc;
  (void)dwFlags;

  if(!pPFX || !pPFX->pbData || !pPFX->cbData) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
  }

  if(szPassword) {
    WideCharToMultiByte(0, 0, szPassword, -1, pw_buf, (int)sizeof(pw_buf),
                        NULL, NULL);
    password = pw_buf;
  }
  else {
    password = NULL;
  }

  bio = BIO_new_mem_buf(pPFX->pbData, (int)pPFX->cbData);
  if(!bio) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  p12 = d2i_PKCS12_bio(bio, NULL);
  BIO_free(bio);
  if(!p12) {
    SetLastError(ERROR_INVALID_DATA);
    return NULL;
  }

  rc = PKCS12_parse(p12, password, &pkey, &cert, &ca_certs);
  PKCS12_free(p12);
  if(!rc || !cert) {
    if(pkey) {
      EVP_PKEY_free(pkey);
    }
    if(cert) {
      X509_free(cert);
    }
    if(ca_certs) {
      sk_X509_pop_free(ca_certs, X509_free);
    }
    SetLastError(ERROR_INVALID_PASSWORD);
    return NULL;
  }

  store = calloc(1, sizeof(mock_cert_store_t));
  if(!store) {
    EVP_PKEY_free(pkey);
    X509_free(cert);
    if(ca_certs) {
      sk_X509_pop_free(ca_certs, X509_free);
    }
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  store->certs = sk_X509_new_null();
  store->keys = sk_EVP_PKEY_new_null();
  if(!store->certs || !store->keys) {
    if(store->certs) {
      sk_X509_free(store->certs);
    }
    if(store->keys) {
      sk_EVP_PKEY_free(store->keys);
    }
    free(store);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    if(ca_certs) {
      sk_X509_pop_free(ca_certs, X509_free);
    }
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  store->magic = MOCK_MAGIC_STORE;
  store->refcount = 1;

  sk_X509_push(store->certs, cert);
  sk_EVP_PKEY_push(store->keys, pkey);

  if(ca_certs) {
    int n = sk_X509_num(ca_certs);
    for(i = 0; i < n; i++) {
      X509 *ca = sk_X509_value(ca_certs, i);
      if(ca) {
        X509_up_ref(ca);
        sk_X509_push(store->certs, ca);
        sk_EVP_PKEY_push(store->keys, NULL);
      }
    }
    sk_X509_pop_free(ca_certs, X509_free);
  }

  X509_up_ref(cert);
  mc = mock_cert_context_new(cert, NULL, (HCERTSTORE)store);
  if(mc)
    CertFreeCertificateContext((PCCERT_CONTEXT)&mc->public_context);

  return (HCERTSTORE)store;
}

BOOL WINAPI CryptStringToBinaryA(LPCSTR pszString, DWORD cchString,
                                 DWORD dwFlags, BYTE *pbBinary,
                                 DWORD *pcbBinary, DWORD *pdwSkip,
                                 DWORD *pdwFlags)
{
  size_t slen;
  size_t i;
  size_t out_idx;
  size_t hex_len;
  (void)pdwSkip;
  (void)pdwFlags;

  if(!pszString || !pcbBinary) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  slen = cchString ? (size_t)cchString : strlen(pszString);

  if(dwFlags != CRYPT_STRING_HEX) {
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
  }

  hex_len = 0;
  for(i = 0; i < slen; i++) {
    char c = pszString[i];
    if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
       (c >= 'A' && c <= 'F'))
      hex_len++;
  }

  if(hex_len % 2) {
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
  }

  *pcbBinary = (DWORD)(hex_len / 2);

  if(!pbBinary)
    return TRUE;

  out_idx = 0;
  i = 0;
  while(i < slen && out_idx < hex_len / 2) {
    unsigned char hi;
    unsigned char lo;
    char c;

    while(i < slen) {
      c = pszString[i];
      if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F'))
        break;
      i++;
    }
    if(i >= slen) {
      break;
    }
    c = pszString[i++];
    hi = (unsigned char)((c >= '0' && c <= '9') ? c - '0' :
                         (c >= 'a' && c <= 'f') ? c - 'a' + 10 : c - 'A' + 10);

    while(i < slen) {
      c = pszString[i];
      if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F'))
        break;
      i++;
    }
    if(i >= slen) {
      break;
    }
    c = pszString[i++];
    lo = (unsigned char)((c >= '0' && c <= '9') ? c - '0' :
                         (c >= 'a' && c <= 'f') ? c - 'a' + 10 : c - 'A' + 10);

    pbBinary[out_idx++] = (BYTE)((hi << 4) | lo);
  }

  return TRUE;
}

BOOL WINAPI CryptStringToBinaryW(LPCWSTR pszString, DWORD cchString,
                                 DWORD dwFlags, BYTE *pbBinary,
                                 DWORD *pcbBinary, DWORD *pdwSkip,
                                 DWORD *pdwFlags)
{
  char narrow[1024];
  DWORD wlen;
  DWORD i;

  if(!pszString) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  wlen = cchString ? cchString : (DWORD)wcslen(pszString);
  if(wlen >= (DWORD)sizeof(narrow))
    wlen = (DWORD)sizeof(narrow) - 1;

  for(i = 0; i < wlen; i++)
    narrow[i] = (char)pszString[i];
  narrow[wlen] = '\0';

  return CryptStringToBinaryA(narrow, wlen, dwFlags, pbBinary, pcbBinary,
                              pdwSkip, pdwFlags);
}

BOOL WINAPI CertCreateCertificateChainEngine(CERT_CHAIN_ENGINE_CONFIG *pConfig,
                                             HCERTCHAINENGINE *phChainEngine)
{
  mock_chain_engine_t *eng;
  mock_cert_store_t *ca_store;
  X509_STORE *xs;
  int i;
  int n;

  if(!pConfig || !phChainEngine) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  eng = calloc(1, sizeof(mock_chain_engine_t));
  if(!eng) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }

  xs = X509_STORE_new();
  if(!xs) {
    free(eng);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }

  if(pConfig->hExclusiveRoot) {
    ca_store = (mock_cert_store_t *)pConfig->hExclusiveRoot;
    if(ca_store->magic == MOCK_MAGIC_STORE && ca_store->certs) {
      n = sk_X509_num(ca_store->certs);
      for(i = 0; i < n; i++) {
        X509 *ca = sk_X509_value(ca_store->certs, i);
        if(ca)
          X509_STORE_add_cert(xs, ca);
      }
    }
  }

  if(pConfig->hRestrictedRoot) {
    ca_store = (mock_cert_store_t *)pConfig->hRestrictedRoot;
    if(ca_store->magic == MOCK_MAGIC_STORE && ca_store->certs) {
      n = sk_X509_num(ca_store->certs);
      for(i = 0; i < n; i++) {
        X509 *ca = sk_X509_value(ca_store->certs, i);
        if(ca)
          X509_STORE_add_cert(xs, ca);
      }
    }
  }

  eng->magic = MOCK_MAGIC_ENGINE;
  eng->x509_store = xs;
  *phChainEngine = (HCERTCHAINENGINE)eng;
  return TRUE;
}

void WINAPI CertFreeCertificateChainEngine(HCERTCHAINENGINE hChainEngine)
{
  mock_chain_engine_t *eng = (mock_chain_engine_t *)hChainEngine;
  if(!eng || eng->magic != MOCK_MAGIC_ENGINE)
    return;
  eng->magic = 0;
  if(eng->x509_store) {
    X509_STORE_free(eng->x509_store);
    eng->x509_store = NULL;
  }
  free(eng);
}

BOOL WINAPI CertGetCertificateChain(HCERTCHAINENGINE hChainEngine,
                                    PCCERT_CONTEXT pCertContext,
                                    void *pTime, HCERTSTORE hAdditionalStore,
                                    PCERT_CHAIN_PARA pChainPara,
                                    DWORD dwFlags, void *pvReserved,
                                    PCCERT_CHAIN_CONTEXT *ppChainContext)
{
  mock_chain_engine_t *eng;
  mock_cert_context_t *leaf_mc;
  mock_cert_store_t *add_store;
  X509_STORE_CTX *vctx;
  STACK_OF(X509) *untrusted;
  mock_chain_context_t *chain_ctx;
  DWORD err_status;
  int verify_rc;
  int i;
  int n;
  int chain_len;
  STACK_OF(X509) *verified_chain;
  (void)pTime;
  (void)pChainPara;
  (void)dwFlags;
  (void)pvReserved;

  if(!pCertContext || !ppChainContext) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  eng = (mock_chain_engine_t *)hChainEngine;
  if(!eng || eng->magic != MOCK_MAGIC_ENGINE) {
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }

  leaf_mc = (mock_cert_context_t *)UNCONST(pCertContext);
  if(!leaf_mc->x509) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  untrusted = sk_X509_new_null();
  if(!untrusted) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }

  if(hAdditionalStore) {
    add_store = (mock_cert_store_t *)hAdditionalStore;
    if(add_store->magic == MOCK_MAGIC_STORE && add_store->certs) {
      n = sk_X509_num(add_store->certs);
      for(i = 0; i < n; i++) {
        X509 *ca = sk_X509_value(add_store->certs, i);
        if(ca && ca != leaf_mc->x509) {
          X509_up_ref(ca);
          sk_X509_push(untrusted, ca);
        }
      }
    }
  }

  if(pCertContext->hCertStore &&
     pCertContext->hCertStore != hAdditionalStore) {
    add_store = (mock_cert_store_t *)pCertContext->hCertStore;
    if(add_store->magic == MOCK_MAGIC_STORE && add_store->certs) {
      n = sk_X509_num(add_store->certs);
      for(i = 0; i < n; i++) {
        X509 *ca = sk_X509_value(add_store->certs, i);
        if(ca && ca != leaf_mc->x509) {
          X509_up_ref(ca);
          sk_X509_push(untrusted, ca);
        }
      }
    }
  }

  vctx = X509_STORE_CTX_new();
  if(!vctx) {
    sk_X509_pop_free(untrusted, X509_free);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }

  X509_STORE_CTX_init(vctx, eng->x509_store, leaf_mc->x509, untrusted);
  verify_rc = X509_verify_cert(vctx);

  err_status = CERT_TRUST_NO_ERROR;
  if(verify_rc <= 0) {
    int ossl_err = X509_STORE_CTX_get_error(vctx);
    switch(ossl_err) {
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CERT_NOT_YET_VALID:
      err_status = CERT_TRUST_IS_NOT_TIME_VALID;
      break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      err_status = CERT_TRUST_IS_UNTRUSTED_ROOT;
      break;
    case X509_V_ERR_CERT_REVOKED:
      err_status = CERT_TRUST_IS_REVOKED;
      break;
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
      err_status = CERT_TRUST_IS_PARTIAL_CHAIN;
      break;
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_CERT_UNTRUSTED:
      err_status = CERT_TRUST_IS_NOT_SIGNATURE_VALID;
      break;
    default:
      err_status = CERT_TRUST_IS_UNTRUSTED_ROOT;
      break;
    }
  }

  verified_chain = X509_STORE_CTX_get0_chain(vctx);
  chain_len = verified_chain ? sk_X509_num(verified_chain) : 1;
  if(chain_len < 1) {
    chain_len = 1;
  }

  chain_ctx = calloc(1, sizeof(mock_chain_context_t));
  if(!chain_ctx) {
    X509_STORE_CTX_free(vctx);
    sk_X509_pop_free(untrusted, X509_free);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }

  chain_ctx->elements = calloc((size_t)chain_len, sizeof(CERT_CHAIN_ELEMENT));
  chain_ctx->element_ptrs = calloc((size_t)chain_len,
                                   sizeof(PCERT_CHAIN_ELEMENT));
  if(!chain_ctx->elements || !chain_ctx->element_ptrs) {
    free(chain_ctx->elements);
    free(chain_ctx->element_ptrs);
    free(chain_ctx);
    X509_STORE_CTX_free(vctx);
    sk_X509_pop_free(untrusted, X509_free);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }

  chain_ctx->num_elements = (DWORD)chain_len;

  for(i = 0; i < chain_len; i++) {
    X509 *xi;
    mock_cert_context_t *mc;

    chain_ctx->elements[i].cbSize = sizeof(CERT_CHAIN_ELEMENT);
    chain_ctx->elements[i].TrustStatus.dwErrorStatus =
      (i == 0) ? err_status : CERT_TRUST_NO_ERROR;
    chain_ctx->elements[i].TrustStatus.dwInfoStatus = 0;

    if(verified_chain)
      xi = sk_X509_value(verified_chain, i);
    else
      xi = leaf_mc->x509;

    if(xi) {
      X509_up_ref(xi);
      mc = mock_cert_context_new(xi, NULL, NULL);
      if(mc)
        chain_ctx->elements[i].pCertContext =
          (PCCERT_CONTEXT)&mc->public_context;
      else
        X509_free(xi);
    }

    chain_ctx->element_ptrs[i] = &chain_ctx->elements[i];
  }

  chain_ctx->simple_chain.cbSize = sizeof(CERT_SIMPLE_CHAIN);
  chain_ctx->simple_chain.TrustStatus.dwErrorStatus = err_status;
  chain_ctx->simple_chain.TrustStatus.dwInfoStatus = 0;
  chain_ctx->simple_chain.cElement = (DWORD)chain_len;
  chain_ctx->simple_chain.rgpElement = chain_ctx->element_ptrs;

  chain_ctx->chain_ptr = &chain_ctx->simple_chain;

  chain_ctx->magic = MOCK_MAGIC_CHAIN;
  chain_ctx->public_ctx.cbSize = sizeof(CERT_CHAIN_CONTEXT);
  chain_ctx->public_ctx.TrustStatus.dwErrorStatus = err_status;
  chain_ctx->public_ctx.TrustStatus.dwInfoStatus = 0;
  chain_ctx->public_ctx.cChain = 1;
  chain_ctx->public_ctx.rgpChain = &chain_ctx->chain_ptr;

  *ppChainContext = (PCCERT_CHAIN_CONTEXT)&chain_ctx->public_ctx;

  X509_STORE_CTX_free(vctx);
  sk_X509_pop_free(untrusted, X509_free);
  return TRUE;
}

void WINAPI CertFreeCertificateChain(PCCERT_CHAIN_CONTEXT pChainContext)
{
  mock_chain_context_t *chain_ctx;
  DWORD i;

  if(!pChainContext)
    return;

  chain_ctx = (mock_chain_context_t *)UNCONST(pChainContext);
  if(chain_ctx->magic != MOCK_MAGIC_CHAIN)
    return;

  if(chain_ctx->elements) {
    for(i = 0; i < chain_ctx->num_elements; i++) {
      if(chain_ctx->elements[i].pCertContext)
        CertFreeCertificateContext(chain_ctx->elements[i].pCertContext);
    }
    free(chain_ctx->elements);
    chain_ctx->elements = NULL;
  }

  if(chain_ctx->element_ptrs) {
    free(chain_ctx->element_ptrs);
    chain_ctx->element_ptrs = NULL;
  }

  chain_ctx->magic = 0;
  free(chain_ctx);
}
