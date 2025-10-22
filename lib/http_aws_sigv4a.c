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

#include "curl_setup.h"

#ifndef CURL_DISABLE_AWS

#ifdef USE_OPENSSL
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

/* Detect SSL library variants */
#if defined(OPENSSL_IS_AWSLC) || \
    (defined(OPENSSL_VERSION_NUMBER) && defined(AWSLC_API_VERSION))
#define OPENSSL_IS_AWSLC
#endif

#if defined(OPENSSL_IS_BORINGSSL) || \
    (defined(OPENSSL_VERSION_NUMBER) && defined(BORINGSSL_API_VERSION))
#define OPENSSL_IS_BORINGSSL
#endif

/* Check if OpenSSL version is sufficient */
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L

#define HAVE_SIGV4A_SUPPORT 1

/* Determine OpenSSL API version to use */
#if !defined(OPENSSL_IS_AWSLC) && !defined(OPENSSL_IS_BORINGSSL) && \
    OPENSSL_VERSION_NUMBER >= 0x30000000L
#define USE_OPENSSL_3X
#else
#define USE_OPENSSL_1X
#endif

#endif

#endif

#include "http_aws_sigv4.h"
#include "http_aws_sigv4a.h"

#ifdef HAVE_SIGV4A_SUPPORT

#include "curlx/dynbuf.h"
#include "curl_sha256.h"
#include "curl_hmac.h"
#include "curl_memory.h"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#ifdef USE_OPENSSL_3X
#include <openssl/evp.h>
#include <openssl/core_names.h>
#endif

/* SigV4A constants */
#define SIGV4A_ALGORITHM "AWS4-ECDSA-P256-SHA256"
#define SECRET_PREFIX "AWS4A"
#define MAX_COUNTER_VALUE 254
#define SIGV4A_PRIVATE_KEY_LENGTH 32
#define SIGV4A_SIGNATURE_LENGTH 72

/* P-256 curve order minus 2 (N-2) */
static const unsigned char n_minus_2[SIGV4A_PRIVATE_KEY_LENGTH] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
  0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x4F,
};

/* Compare two 32-byte big-endian values in constant time */
static int compare_be_bytes(const unsigned char *a, const unsigned char *b)
{
  volatile unsigned char gt = 0;
  volatile unsigned char eq = 1;
  int i;

  for(i = 0; i < SIGV4A_PRIVATE_KEY_LENGTH; i++) {
    volatile int a_digit = (int)a[i];
    volatile int b_digit = (int)b[i];

    gt |= (unsigned char)(((b_digit - a_digit) >> 31) & eq);
    eq &= (unsigned char)((((a_digit ^ b_digit) - 1) >> 31) & 0x01);
  }

  return gt + gt + eq - 1;
}

/* Add one to 32-byte big-endian value in constant time */
static void add_one_be_bytes(unsigned char *value)
{
  volatile unsigned int carry = 1;
  int i;

  for(i = SIGV4A_PRIVATE_KEY_LENGTH - 1; i >= 0; i--) {
    volatile unsigned int digit = value[i];
    digit += carry;
    carry = (digit >> 8) & 0x01;
    value[i] = (unsigned char)(digit & 0xFF);
  }
}

/* Build fixed input string for SigV4A key derivation */
static CURLcode build_fixed_input(struct dynbuf *fixed_input,
                                  const char *access_key,
                                  unsigned char counter)
{
  const unsigned char one_be[4] = {0x00, 0x00, 0x00, 0x01};
  const unsigned char len_be[4] = {0x00, 0x00, 0x01, 0x00};

  curlx_dyn_reset(fixed_input);

  /* 0x00000001 */
  if(curlx_dyn_addn(fixed_input, one_be, 4))
    return CURLE_OUT_OF_MEMORY;

  /* "AWS4-ECDSA-P256-SHA256" */
  if(curlx_dyn_add(fixed_input, SIGV4A_ALGORITHM))
    return CURLE_OUT_OF_MEMORY;

  /* 0x00 */
  if(curlx_dyn_addn(fixed_input, "\x00", 1))
    return CURLE_OUT_OF_MEMORY;

  /* AccessKeyId */
  if(curlx_dyn_add(fixed_input, access_key))
    return CURLE_OUT_OF_MEMORY;

  /* Counter */
  if(curlx_dyn_addn(fixed_input, &counter, 1))
    return CURLE_OUT_OF_MEMORY;

  /* 0x00000100 (256 bits) */
  if(curlx_dyn_addn(fixed_input, len_be, 4))
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

/* Derive ECC private key from HMAC output */
static int derive_ecc_private_key(unsigned char *private_key,
                                  const unsigned char *k0)
{
  /* Check if k0 > N-2 */
  if(compare_be_bytes(k0, n_minus_2) > 0)
    return 0; /* Try next counter */

  /* private_key = k0 + 1 */
  memcpy(private_key, k0, SIGV4A_PRIVATE_KEY_LENGTH);
  add_one_be_bytes(private_key);

  return 1; /* Success */
}

/*
 * Derive SigV4A signing key from AWS credentials
 * Returns CURLE_OK on success, error code on failure
 */
CURLcode Curl_aws_sigv4a_derive_key(const char *access_key,
                                     const char *secret_key,
                                     unsigned char *private_key)
{
  struct dynbuf secret_buf;
  struct dynbuf fixed_input;
  unsigned char hmac_output[CURL_SHA256_DIGEST_LENGTH];
  unsigned char counter;
  CURLcode result = CURLE_OK;

  curlx_dyn_init(&secret_buf, 1024);
  curlx_dyn_init(&fixed_input, 1024);

  /* Build secret: "AWS4A" + secret_key */
  if(curlx_dyn_add(&secret_buf, SECRET_PREFIX) ||
     curlx_dyn_add(&secret_buf, secret_key)) {
    result = CURLE_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Try counters 1 through MAX_COUNTER_VALUE */
  for(counter = 1; counter <= MAX_COUNTER_VALUE; counter++) {
    /* Build fixed input string */
    result = build_fixed_input(&fixed_input, access_key, counter);
    if(result)
      goto cleanup;

    /* Compute HMAC-SHA256 */
    HMAC_SHA256(curlx_dyn_ptr(&secret_buf), curlx_dyn_len(&secret_buf),
                curlx_dyn_ptr(&fixed_input), curlx_dyn_len(&fixed_input),
                hmac_output);

    /* Try to derive valid ECC private key */
    if(derive_ecc_private_key(private_key, hmac_output)) {
      result = CURLE_OK;
      goto cleanup;
    }
  }

  /* Failed to derive valid key after MAX_COUNTER_VALUE attempts */
  result = CURLE_FAILED_INIT;

cleanup:
  curlx_dyn_free(&secret_buf);
  curlx_dyn_free(&fixed_input);

  /* Clear sensitive data */
  memset(hmac_output, 0, sizeof(hmac_output));

  return result;
}

/*
 * Sign string using SigV4A ECDSA algorithm
 * Returns CURLE_OK on success, error code on failure
 */
CURLcode Curl_aws_sigv4a_sign(const unsigned char *private_key,
                               const char *string_to_sign,
                               size_t string_len,
                               unsigned char *signature,
                               size_t *signature_len)
{
#ifdef HAVE_SIGV4A_SUPPORT
#ifdef USE_OPENSSL_3X
  /* OpenSSL 3.0+ EVP_PKEY approach */
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  unsigned char hash[CURL_SHA256_DIGEST_LENGTH];
  size_t sig_len = 0;
  CURLcode result = CURLE_OK;
  OSSL_PARAM params[3];

  /* Build parameter array for key creation */
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                               "prime256v1", 0);
  params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, 
                                      (unsigned char *)private_key, 
                                      SIGV4A_PRIVATE_KEY_LENGTH);
  params[2] = OSSL_PARAM_construct_end();

  /* Create key context and generate key */
  pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if(!pctx ||
     EVP_PKEY_fromdata_init(pctx) <= 0 ||
     EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
    result = CURLE_SSL_ENGINE_SETFAILED;
    goto cleanup;
  }

  /* Hash the string to sign */
  if(Curl_sha256it(hash, (const unsigned char *)string_to_sign, string_len)) {
    result = CURLE_SSL_ENGINE_SETFAILED;
    goto cleanup;
  }

  /* Create signing context and sign */
  ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if(!ctx || EVP_PKEY_sign_init(ctx) <= 0 ||
     EVP_PKEY_sign(ctx, NULL, &sig_len, hash,
                   CURL_SHA256_DIGEST_LENGTH) <= 0 ||
     sig_len > SIGV4A_SIGNATURE_LENGTH) {
    result = CURLE_SSL_ENGINE_SETFAILED;
    goto cleanup;
  }

  memset(signature, 0, SIGV4A_SIGNATURE_LENGTH);
  if(EVP_PKEY_sign(ctx, signature, &sig_len, hash,
                   CURL_SHA256_DIGEST_LENGTH) <= 0) {
    result = CURLE_SSL_ENGINE_SETFAILED;
    goto cleanup;
  }
  *signature_len = sig_len;

cleanup:
  if(ctx)
    EVP_PKEY_CTX_free(ctx);
  if(pctx)
    EVP_PKEY_CTX_free(pctx);
  if(pkey)
    EVP_PKEY_free(pkey);
  return result;

#else
  /* Legacy OpenSSL 1.1.x EC_KEY approach */
  EC_KEY *ec_key = NULL;
  ECDSA_SIG *ecdsa_sig = NULL;
  BIGNUM *priv_bn = NULL;
  unsigned char hash[CURL_SHA256_DIGEST_LENGTH];
  unsigned char *der_ptr;
  int der_len;
  CURLcode result = CURLE_OK;

  /* Create EC_KEY for P-256 curve */
  ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if(!ec_key)
    return CURLE_OUT_OF_MEMORY;

  /* Set private key */
  priv_bn = BN_bin2bn(private_key, SIGV4A_PRIVATE_KEY_LENGTH, NULL);
  if(!priv_bn || !EC_KEY_set_private_key(ec_key, priv_bn)) {
    result = CURLE_SSL_ENGINE_SETFAILED;
    goto cleanup;
  }

  /* Hash the string to sign */
  if(Curl_sha256it(hash, (const unsigned char *)string_to_sign, string_len)) {
    result = CURLE_SSL_ENGINE_SETFAILED;
    goto cleanup;
  }

  /* Sign the hash */
  ecdsa_sig = ECDSA_do_sign(hash, CURL_SHA256_DIGEST_LENGTH, ec_key);
  if(!ecdsa_sig) {
    result = CURLE_SSL_ENGINE_SETFAILED;
    goto cleanup;
  }

  /* Convert to DER format */
  der_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
  if(der_len <= 0 || der_len > SIGV4A_SIGNATURE_LENGTH) {
    result = CURLE_SSL_ENGINE_SETFAILED;
    goto cleanup;
  }

  memset(signature, 0, SIGV4A_SIGNATURE_LENGTH);
  der_ptr = signature;
  i2d_ECDSA_SIG(ecdsa_sig, &der_ptr);
  *signature_len = (size_t)der_len;

cleanup:
  if(priv_bn)
    BN_free(priv_bn);
  if(ecdsa_sig)
    ECDSA_SIG_free(ecdsa_sig);
  if(ec_key)
    EC_KEY_free(ec_key);

  return result;
#endif
#else
  (void)private_key;
  (void)string_to_sign;
  (void)string_len;
  (void)signature;
  (void)signature_len;
  return CURLE_NOT_BUILT_IN;
#endif
}

#else /* !HAVE_SIGV4A_SUPPORT */

/*
 * Stub functions for when SigV4A support is not available
 */
CURLcode Curl_aws_sigv4a_derive_key(const char *access_key,
                                     const char *secret_key,
                                     unsigned char *private_key)
{
  (void)access_key;
  (void)secret_key;
  (void)private_key;
  return CURLE_NOT_BUILT_IN;
}

CURLcode Curl_aws_sigv4a_sign(const unsigned char *private_key,
                               const char *string_to_sign,
                               size_t string_len,
                               unsigned char *signature,
                               size_t *signature_len)
{
  (void)private_key;
  (void)string_to_sign;
  (void)string_len;
  (void)signature;
  (void)signature_len;
  return CURLE_NOT_BUILT_IN;
}

#endif /* HAVE_SIGV4A_SUPPORT */

#endif /* !CURL_DISABLE_AWS */
