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
 * test_crypto_store.c - Phase 5 test suite.
 *
 * Tests:
 *  1. CertOpenStore / CertCloseStore (memory store)
 *  2. CryptQueryObject - parse PEM cert blob
 *  3. CertAddCertificateContextToStore
 *  4. CertEnumCertificatesInStore
 *  5. CertFindCertificateInStore - CERT_FIND_ANY
 *  6. CertGetNameStringA - CN extraction
 *  7. CertFindExtension - SAN extension
 *  8. CryptDecodeObjectEx - parse SAN into CERT_ALT_NAME_INFO
 *  9. PFXImportCertStore - PKCS#12 import
 * 10. CertFindCertificateInStore - CERT_FIND_HAS_PRIVATE_KEY
 * 11. CertCreateCertificateChainEngine + CertGetCertificateChain (trusted)
 * 12. CertGetCertificateChain (untrusted / self-signed)
 * 13. CryptAcquireContext + CryptCreateHash + CryptHashData
 * 14. CryptDestroyHash + CryptReleaseContext
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

#include "windows.h"
#include "wincrypt.h"

/* -------------------------------------------------------------------------
 * Test certificate generation helpers
 * ------------------------------------------------------------------------- */

static void generate_rsa_key(EVP_PKEY **out_pkey)
{
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY *pkey = NULL;
  assert(pctx != NULL);
  assert(EVP_PKEY_keygen_init(pctx) > 0);
  assert(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0);
  assert(EVP_PKEY_keygen(pctx, &pkey) > 0);
  EVP_PKEY_CTX_free(pctx);
  *out_pkey = pkey;
}

/*
 * Generate a self-signed cert with CN=cn_name, optionally with a SAN.
 * If san_dns != NULL, adds a subjectAltName dNSName extension.
 * If ca != NULL / ca_key != NULL, signs with that CA instead of self-signing.
 */
static X509 *make_cert(EVP_PKEY *pkey, const char *cn_name,
                        const char *san_dns,
                        X509 *ca, EVP_PKEY *ca_key,
                        long serial)
{
  X509 *cert = X509_new();
  X509_NAME *name;
  assert(cert != NULL);
  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 86400L * 3650);
  X509_set_pubkey(cert, pkey);

  name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (const unsigned char *)cn_name, -1, -1, 0);
  if(ca)
    X509_set_issuer_name(cert, X509_get_subject_name(ca));
  else
    X509_set_issuer_name(cert, name);

  /* Add SAN extension if requested */
  if(san_dns) {
    X509V3_CTX ctx;
    char san_val[256];
    X509_EXTENSION *ext;
    snprintf(san_val, sizeof(san_val), "DNS:%s", san_dns);
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca ? ca : cert, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san_val);
    if(ext) {
      X509_add_ext(cert, ext, -1);
      X509_EXTENSION_free(ext);
    }
  }

  /* Basic Constraints: CA:TRUE for CA certs */
  if(!ca) {
    X509V3_CTX ctx;
    X509_EXTENSION *ext;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:TRUE");
    if(ext) {
      X509_add_ext(cert, ext, -1);
      X509_EXTENSION_free(ext);
    }
  }

  X509_sign(cert, ca_key ? ca_key : pkey, EVP_sha256());
  return cert;
}

/* Export X509 to PEM in memory, returns a malloc'd buffer and sets *plen */
static unsigned char *cert_to_pem(X509 *cert, size_t *plen)
{
  BIO *bio = BIO_new(BIO_s_mem());
  BUF_MEM *bptr;
  unsigned char *out;
  assert(bio != NULL);
  PEM_write_bio_X509(bio, cert);
  BIO_get_mem_ptr(bio, &bptr);
  *plen = bptr->length;
  out = malloc(*plen);
  assert(out != NULL);
  memcpy(out, bptr->data, *plen);
  BIO_free(bio);
  return out;
}

/* Export cert+key to PKCS12 DER in memory */
static unsigned char *make_pkcs12(X509 *cert, EVP_PKEY *pkey,
                                  const char *password, size_t *plen)
{
  PKCS12 *p12;
  BIO *bio;
  BUF_MEM *bptr;
  unsigned char *out;
  char pw[64];

  snprintf(pw, sizeof(pw), "%s", password);
  p12 = PKCS12_create(pw, "client", pkey, cert,
                      NULL, 0, 0, 0, 0, 0);
  assert(p12 != NULL);

  bio = BIO_new(BIO_s_mem());
  assert(bio != NULL);
  i2d_PKCS12_bio(bio, p12);
  PKCS12_free(p12);

  BIO_get_mem_ptr(bio, &bptr);
  *plen = bptr->length;
  out = malloc(*plen);
  assert(out != NULL);
  memcpy(out, bptr->data, *plen);
  BIO_free(bio);
  return out;
}

/* -------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------- */

static void test_cert_open_close(void)
{
  HCERTSTORE store;
  BOOL ok;

  printf("1. CertOpenStore / CertCloseStore\n");

  store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  assert(store != NULL);

  ok = CertCloseStore(store, 0);
  assert(ok == TRUE);

  printf(" PASS: memory store created and closed.\n\n");
}

static void test_crypt_query_object(X509 *cert)
{
  unsigned char *pem_data;
  size_t pem_len;
  CRYPT_DATA_BLOB blob;
  DWORD enc_type = 0;
  DWORD content_type = 0;
  DWORD format_type = 0;
  const void *pv_ctx = NULL;
  PCCERT_CONTEXT ctx;
  BOOL ok;

  printf("2. CryptQueryObject - parse PEM cert blob\n");

  pem_data = cert_to_pem(cert, &pem_len);
  blob.pbData = pem_data;
  blob.cbData = (DWORD)pem_len;

  ok = CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                        CERT_QUERY_CONTENT_FLAG_CERT,
                        CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
                        0, &enc_type, &content_type, &format_type,
                        NULL, NULL, &pv_ctx);
  assert(ok == TRUE);
  assert(pv_ctx != NULL);

  ctx = (PCCERT_CONTEXT)pv_ctx;
  assert(ctx->pbCertEncoded != NULL);
  assert(ctx->cbCertEncoded > 0);
  assert(ctx->pCertInfo != NULL);

  CertFreeCertificateContext(ctx);
  free(pem_data);

  printf(" PASS: cert parsed from PEM blob.\n\n");
}

static void test_add_and_enum(X509 *cert)
{
  unsigned char *pem_data;
  size_t pem_len;
  CRYPT_DATA_BLOB blob;
  const void *pv_ctx = NULL;
  PCCERT_CONTEXT ctx;
  HCERTSTORE store;
  PCCERT_CONTEXT enum_ctx;
  BOOL ok;
  int count;

  printf("3. CertAddCertificateContextToStore\n");

  pem_data = cert_to_pem(cert, &pem_len);
  blob.pbData = pem_data;
  blob.cbData = (DWORD)pem_len;

  CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                   CERT_QUERY_CONTENT_FLAG_CERT,
                   CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
                   0, NULL, NULL, NULL, NULL, NULL, &pv_ctx);
  ctx = (PCCERT_CONTEXT)pv_ctx;
  assert(ctx != NULL);

  store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  assert(store != NULL);

  ok = CertAddCertificateContextToStore(store, ctx,
                                        CERT_STORE_ADD_ALWAYS, NULL);
  assert(ok == TRUE);

  CertFreeCertificateContext(ctx);
  free(pem_data);

  printf(" PASS: cert added to store.\n\n");

  printf("4. CertEnumCertificatesInStore\n");

  count = 0;
  enum_ctx = NULL;
  for(;;) {
    enum_ctx = CertEnumCertificatesInStore(store, enum_ctx);
    if(!enum_ctx)
      break;
    count++;
    assert(enum_ctx->pbCertEncoded != NULL);
  }
  assert(count == 1);

  printf(" PASS: enumerated %d cert(s) from store.\n\n", count);

  printf("5. CertFindCertificateInStore - CERT_FIND_ANY\n");

  ctx = CertFindCertificateInStore(store,
                                   X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                   0, CERT_FIND_ANY, NULL, NULL);
  assert(ctx != NULL);
  CertFreeCertificateContext(ctx);

  printf(" PASS: found cert with CERT_FIND_ANY.\n\n");

  CertCloseStore(store, 0);
}

static void test_get_name_string(X509 *cert)
{
  unsigned char *pem_data;
  size_t pem_len;
  CRYPT_DATA_BLOB blob;
  const void *pv_ctx = NULL;
  PCCERT_CONTEXT ctx;
  char name_buf[256];
  DWORD ret;

  printf("6. CertGetNameStringA\n");

  pem_data = cert_to_pem(cert, &pem_len);
  blob.pbData = pem_data;
  blob.cbData = (DWORD)pem_len;

  CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                   CERT_QUERY_CONTENT_FLAG_CERT,
                   CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
                   0, NULL, NULL, NULL, NULL, NULL, &pv_ctx);
  ctx = (PCCERT_CONTEXT)pv_ctx;
  assert(ctx != NULL);

  /* DNS type should return "localhost" via SAN or CN */
  ret = CertGetNameStringA(ctx, CERT_NAME_DNS_TYPE, 0, NULL,
                           name_buf, (DWORD)sizeof(name_buf));
  assert(ret > 1);
  assert(strlen(name_buf) > 0);

  printf(" PASS: CertGetNameStringA returned \"%s\".\n\n", name_buf);

  CertFreeCertificateContext(ctx);
  free(pem_data);
}

static void test_find_extension_and_decode(X509 *san_cert)
{
  unsigned char *pem_data;
  size_t pem_len;
  CRYPT_DATA_BLOB blob;
  const void *pv_ctx = NULL;
  PCCERT_CONTEXT ctx;
  PCERT_EXTENSION ext;
  CERT_ALT_NAME_INFO *san_info = NULL;
  DWORD san_sz = 0;
  BOOL ok;
  DWORD i;

  printf("7. CertFindExtension - SAN extension lookup\n");

  pem_data = cert_to_pem(san_cert, &pem_len);
  blob.pbData = pem_data;
  blob.cbData = (DWORD)pem_len;

  CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                   CERT_QUERY_CONTENT_FLAG_CERT,
                   CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
                   0, NULL, NULL, NULL, NULL, NULL, &pv_ctx);
  ctx = (PCCERT_CONTEXT)pv_ctx;
  assert(ctx != NULL);
  assert(ctx->pCertInfo != NULL);

  ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
                          ctx->pCertInfo->cExtension,
                          ctx->pCertInfo->rgExtension);
  assert(ext != NULL);

  printf(" PASS: found SAN extension (OID %s).\n\n", ext->pszObjId);

  printf("8. CryptDecodeObjectEx - decode SAN extension\n");

  ok = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                           szOID_SUBJECT_ALT_NAME2,
                           ext->Value.pbData, ext->Value.cbData,
                           CRYPT_DECODE_ALLOC_FLAG, NULL,
                           &san_info, &san_sz);
  assert(ok == TRUE);
  assert(san_info != NULL);
  assert(san_info->cAltEntry >= 1);

  printf(" PASS: decoded %lu SAN entry/entries:\n",
         (unsigned long)san_info->cAltEntry);
  for(i = 0; i < san_info->cAltEntry; i++) {
    if(san_info->rgAltEntry[i].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME) {
      WCHAR *wname = san_info->rgAltEntry[i].pwszDNSName;
      char narrow[128];
      int j;
      for(j = 0; wname && wname[j]; j++)
        narrow[j] = (char)wname[j];
      narrow[j] = '\0';
      printf("   DNS: %s\n", narrow);
    }
  }

  LocalFree((HLOCAL)san_info);
  CertFreeCertificateContext(ctx);
  free(pem_data);

  printf("\n");
}

static void test_pfx_import(X509 *cert, EVP_PKEY *pkey)
{
  unsigned char *p12_data;
  size_t p12_len;
  CRYPT_DATA_BLOB pfx;
  HCERTSTORE store;
  PCCERT_CONTEXT found_ctx;
  WCHAR wpass[64];
  const char *password = "testpass";
  int i;

  printf("9. PFXImportCertStore\n");

  p12_data = make_pkcs12(cert, pkey, password, &p12_len);

  pfx.pbData = p12_data;
  pfx.cbData = (DWORD)p12_len;

  /* Convert password to wide */
  for(i = 0; password[i]; i++)
    wpass[i] = (WCHAR)(unsigned char)password[i];
  wpass[i] = 0;

  store = PFXImportCertStore(&pfx, wpass, PKCS12_NO_PERSIST_KEY);
  assert(store != NULL);

  free(p12_data);

  printf(" PASS: PKCS#12 imported successfully.\n\n");

  printf("10. CertFindCertificateInStore - CERT_FIND_HAS_PRIVATE_KEY\n");

  found_ctx = CertFindCertificateInStore(store,
                                         X509_ASN_ENCODING |
                                         PKCS_7_ASN_ENCODING,
                                         0, CERT_FIND_HAS_PRIVATE_KEY,
                                         NULL, NULL);
  assert(found_ctx != NULL);

  CertFreeCertificateContext(found_ctx);
  CertCloseStore(store, 0);

  printf(" PASS: found cert with private key in PKCS#12 store.\n\n");
}

static void test_chain_engine_trusted(X509 *leaf_cert, EVP_PKEY *leaf_key,
                                      X509 *ca_cert)
{
  HCERTSTORE ca_store;
  CERT_CHAIN_ENGINE_CONFIG engine_cfg;
  HCERTCHAINENGINE engine = NULL;
  HCERTSTORE leaf_store;
  PCCERT_CONTEXT leaf_ctx;
  CERT_CHAIN_PARA chain_para;
  PCCERT_CHAIN_CONTEXT chain_ctx = NULL;
  unsigned char *pem;
  size_t pem_len;
  CRYPT_DATA_BLOB blob;
  const void *pv_ctx;
  BOOL ok;
  (void)leaf_key;

  printf("11. CertCreateCertificateChainEngine + CertGetCertificateChain"
         " (trusted)\n");

  /* Build CA trust store */
  ca_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  assert(ca_store != NULL);

  pem = cert_to_pem(ca_cert, &pem_len);
  blob.pbData = pem;
  blob.cbData = (DWORD)pem_len;
  pv_ctx = NULL;
  CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                   CERT_QUERY_CONTENT_FLAG_CERT,
                   CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
                   0, NULL, NULL, NULL, NULL, NULL, &pv_ctx);
  assert(pv_ctx != NULL);
  CertAddCertificateContextToStore(ca_store, (PCCERT_CONTEXT)pv_ctx,
                                   CERT_STORE_ADD_ALWAYS, NULL);
  CertFreeCertificateContext((PCCERT_CONTEXT)pv_ctx);
  free(pem);

  /* Create chain engine with that CA */
  memset(&engine_cfg, 0, sizeof(engine_cfg));
  engine_cfg.cbSize = sizeof(engine_cfg);
  engine_cfg.hExclusiveRoot = ca_store;

  ok = CertCreateCertificateChainEngine(&engine_cfg, &engine);
  assert(ok == TRUE);
  assert(engine != NULL);

  /* Get leaf cert context */
  leaf_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  assert(leaf_store != NULL);

  pem = cert_to_pem(leaf_cert, &pem_len);
  blob.pbData = pem;
  blob.cbData = (DWORD)pem_len;
  pv_ctx = NULL;
  CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                   CERT_QUERY_CONTENT_FLAG_CERT,
                   CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
                   0, NULL, NULL, NULL, NULL, NULL, &pv_ctx);
  assert(pv_ctx != NULL);
  leaf_ctx = (PCCERT_CONTEXT)pv_ctx;
  free(pem);

  /* Get certificate chain */
  memset(&chain_para, 0, sizeof(chain_para));
  chain_para.cbSize = sizeof(chain_para);

  ok = CertGetCertificateChain(engine, leaf_ctx, NULL, leaf_store,
                               &chain_para, 0, NULL, &chain_ctx);
  assert(ok == TRUE);
  assert(chain_ctx != NULL);
  assert(chain_ctx->cChain == 1);
  assert(chain_ctx->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR);

  printf(" PASS: chain validated with CERT_TRUST_NO_ERROR.\n\n");

  CertFreeCertificateChain(chain_ctx);
  CertFreeCertificateContext(leaf_ctx);
  CertFreeCertificateChainEngine(engine);
  CertCloseStore(leaf_store, 0);
  CertCloseStore(ca_store, 0);
}

static void test_chain_engine_untrusted(X509 *self_signed_cert)
{
  HCERTSTORE empty_store;
  CERT_CHAIN_ENGINE_CONFIG engine_cfg;
  HCERTCHAINENGINE engine = NULL;
  HCERTSTORE leaf_store;
  PCCERT_CONTEXT leaf_ctx;
  CERT_CHAIN_PARA chain_para;
  PCCERT_CHAIN_CONTEXT chain_ctx = NULL;
  unsigned char *pem;
  size_t pem_len;
  CRYPT_DATA_BLOB blob;
  const void *pv_ctx;
  BOOL ok;

  printf("12. CertGetCertificateChain (untrusted / self-signed)\n");

  /* Create engine with empty trust store (no trusted CAs) */
  empty_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  assert(empty_store != NULL);

  memset(&engine_cfg, 0, sizeof(engine_cfg));
  engine_cfg.cbSize = sizeof(engine_cfg);
  engine_cfg.hExclusiveRoot = empty_store;

  ok = CertCreateCertificateChainEngine(&engine_cfg, &engine);
  assert(ok == TRUE);

  leaf_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  assert(leaf_store != NULL);

  pem = cert_to_pem(self_signed_cert, &pem_len);
  blob.pbData = pem;
  blob.cbData = (DWORD)pem_len;
  pv_ctx = NULL;
  CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                   CERT_QUERY_CONTENT_FLAG_CERT,
                   CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
                   0, NULL, NULL, NULL, NULL, NULL, &pv_ctx);
  assert(pv_ctx != NULL);
  leaf_ctx = (PCCERT_CONTEXT)pv_ctx;
  free(pem);

  memset(&chain_para, 0, sizeof(chain_para));
  chain_para.cbSize = sizeof(chain_para);

  ok = CertGetCertificateChain(engine, leaf_ctx, NULL, leaf_store,
                               &chain_para, 0, NULL, &chain_ctx);
  assert(ok == TRUE);
  assert(chain_ctx != NULL);
  /* Must report an error since the cert is not trusted */
  assert(chain_ctx->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR);

  printf(" PASS: untrusted cert reports dwErrorStatus=0x%08lX"
         " (expected non-zero).\n\n",
         (unsigned long)chain_ctx->TrustStatus.dwErrorStatus);

  CertFreeCertificateChain(chain_ctx);
  CertFreeCertificateContext(leaf_ctx);
  CertFreeCertificateChainEngine(engine);
  CertCloseStore(leaf_store, 0);
  CertCloseStore(empty_store, 0);
}

static void test_crypt_hash(void)
{
  HCRYPTPROV prov = 0;
  HCRYPTHASH hash = 0;
  BOOL ok;
  const char *msg = "hello";
  BYTE digest[32];
  DWORD digest_len = sizeof(digest);
  DWORD hash_size = 0;
  DWORD sz = sizeof(DWORD);

  /* Expected SHA-256 of "hello" */
  static const BYTE expected[32] = {
    0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
    0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
    0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
    0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
  };

  printf("13. CryptAcquireContext + CryptCreateHash + CryptHashData"
         " + CryptGetHashParam (SHA-256)\n");

  ok = CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_AES,
                            CRYPT_VERIFYCONTEXT);
  assert(ok == TRUE);
  assert(prov != 0);

  ok = CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash);
  assert(ok == TRUE);
  assert(hash != 0);

  ok = CryptHashData(hash, (const BYTE *)msg, (DWORD)strlen(msg), 0);
  assert(ok == TRUE);

  /* Query hash size */
  ok = CryptGetHashParam(hash, HP_HASHSIZE, (BYTE *)&hash_size, &sz, 0);
  assert(ok == TRUE);
  assert(hash_size == 32);

  /* Get hash value */
  ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_len, 0);
  assert(ok == TRUE);
  assert(digest_len == 32);
  assert(memcmp(digest, expected, 32) == 0);

  printf(" PASS: SHA-256(\"hello\") matches expected value.\n\n");

  printf("14. CryptDestroyHash + CryptReleaseContext\n");

  ok = CryptDestroyHash(hash);
  assert(ok == TRUE);

  ok = CryptReleaseContext(prov, 0);
  assert(ok == TRUE);

  printf(" PASS: hash and provider cleaned up.\n\n");
}

static void test_crypt_string_to_binary(void)
{
  const char *hex_str = "deadbeef";
  BYTE out[4];
  DWORD out_len = sizeof(out);
  BOOL ok;
  static const BYTE expected[4] = { 0xde, 0xad, 0xbe, 0xef };

  printf("15. CryptStringToBinaryA (hex decode)\n");

  ok = CryptStringToBinaryA(hex_str, 0, CRYPT_STRING_HEX,
                            out, &out_len, NULL, NULL);
  assert(ok == TRUE);
  assert(out_len == 4);
  assert(memcmp(out, expected, 4) == 0);

  printf(" PASS: hex decoded correctly.\n\n");
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int main(void)
{
  EVP_PKEY *ca_key = NULL;
  EVP_PKEY *leaf_key = NULL;
  EVP_PKEY *client_key = NULL;
  X509 *ca_cert = NULL;
  X509 *leaf_cert = NULL;
  X509 *self_cert = NULL;

  printf("Schannel Mockup - CryptoAPI Stores, Certificates & Chains\n\n");

  /* Generate key material once */
  generate_rsa_key(&ca_key);
  generate_rsa_key(&leaf_key);
  generate_rsa_key(&client_key);

  /* CA cert (self-signed, CA:TRUE) */
  ca_cert = make_cert(ca_key, "Test CA", NULL, NULL, NULL, 1);

  /* Leaf cert signed by CA, with SAN */
  leaf_cert = make_cert(leaf_key, "localhost", "localhost",
                        ca_cert, ca_key, 2);

  /* Extra self-signed cert (untrusted) */
  self_cert = make_cert(leaf_key, "selfsigned.example", "selfsigned.example",
                        NULL, NULL, 3);

  /* Run tests */
  test_cert_open_close();
  test_crypt_query_object(leaf_cert);
  test_add_and_enum(leaf_cert);
  test_get_name_string(leaf_cert);
  test_find_extension_and_decode(leaf_cert);
  test_pfx_import(leaf_cert, leaf_key);
  test_chain_engine_trusted(leaf_cert, leaf_key, ca_cert);
  test_chain_engine_untrusted(self_cert);
  test_crypt_hash();
  test_crypt_string_to_binary();

  /* Cleanup */
  X509_free(ca_cert);
  X509_free(leaf_cert);
  X509_free(self_cert);
  EVP_PKEY_free(ca_key);
  EVP_PKEY_free(leaf_key);
  EVP_PKEY_free(client_key);

  printf("All CryptoAPI Store & Chain tests PASSED successfully!\n");
  return 0;
}
