#ifndef HEADER_CURL_VQUIC_NGTCP2_CRYPTO_H
#define HEADER_CURL_VQUIC_NGTCP2_CRYPTO_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifdef USE_NGTCP2
struct Context {
#if defined(OPENSSL_IS_BORINGSSL)
  const EVP_AEAD *aead;
#else  /* !OPENSSL_IS_BORINGSSL */
  const EVP_CIPHER *aead;
#endif /* !OPENSSL_IS_BORINGSSL */
  const EVP_CIPHER *hp;
  const EVP_MD *prf;
  uint8_t tx_secret[64];
  uint8_t rx_secret[64];
  size_t secretlen;
};

void Curl_qc_prf_sha256(struct Context *ctx);
void Curl_qc_aead_aes_128_gcm(struct Context *ctx);
size_t Curl_qc_aead_nonce_length(const struct Context *ctx);
int Curl_qc_negotiated_prf(struct Context *ctx, SSL *ssl);
int Curl_qc_negotiated_aead(struct Context *ctx, SSL *ssl);
size_t Curl_qc_aead_max_overhead(const struct Context *ctx);
ssize_t Curl_qc_encrypt(uint8_t *dest, size_t destlen,
                        const uint8_t *plaintext, size_t plaintextlen,
                        const struct Context *ctx,
                        const uint8_t *key, size_t keylen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *ad, size_t adlen);
ssize_t Curl_qc_decrypt(uint8_t *dest, size_t destlen,
                        const uint8_t *ciphertext, size_t ciphertextlen,
                        const struct Context *ctx,
                        const uint8_t *key, size_t keylen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *ad, size_t adlen);
ssize_t Curl_qc_encrypt_pn(uint8_t *dest, size_t destlen,
                           const uint8_t *plaintext, size_t plaintextlen,
                           const struct Context *ctx,
                           const uint8_t *key, size_t keylen,
                           const uint8_t *nonce, size_t noncelen);
int Curl_qc_derive_initial_secret(uint8_t *dest, size_t destlen,
                                  const ngtcp2_cid *secret,
                                  const uint8_t *salt,
                                  size_t saltlen);
int Curl_qc_derive_client_initial_secret(uint8_t *dest,
                                         size_t destlen,
                                         const uint8_t *secret,
                                         size_t secretlen);
ssize_t Curl_qc_derive_packet_protection_key(uint8_t *dest, size_t destlen,
                                             const uint8_t *secret,
                                             size_t secretlen,
                                             const struct Context *ctx);
ssize_t Curl_qc_derive_packet_protection_iv(uint8_t *dest, size_t destlen,
                                            const uint8_t *secret,
                                            size_t secretlen,
                                            const struct Context *ctx);
int Curl_qc_derive_server_initial_secret(uint8_t *dest, size_t destlen,
                                         const uint8_t *secret,
                                         size_t secretlen);
ssize_t
Curl_qc_derive_header_protection_key(uint8_t *dest, size_t destlen,
                                     const uint8_t *secret, size_t secretlen,
                                     const struct Context *ctx);

ssize_t Curl_qc_hp_mask(uint8_t *dest, size_t destlen,
                        const struct Context *ctx,
                        const uint8_t *key, size_t keylen,
                        const uint8_t *sample, size_t samplelen);
#endif /* USE_NGTCP2 */
#endif /* HEADER_CURL_VQUIC_NGTCP2_CRYPTO_H */
