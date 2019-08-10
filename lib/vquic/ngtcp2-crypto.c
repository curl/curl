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
#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "ngtcp2-crypto.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static int hkdf_expand_label(uint8_t *dest, size_t destlen,
                             const uint8_t *secret, size_t secretlen,
                             const uint8_t *label, size_t labellen,
                             const struct Context *ctx);

void Curl_qc_prf_sha256(struct Context *ctx)
{
  ctx->prf = EVP_sha256();
}

void Curl_qc_aead_aes_128_gcm(struct Context *ctx)
{
  ctx->aead = EVP_aes_128_gcm();
  ctx->hp = EVP_aes_128_ctr();
}

size_t Curl_qc_aead_nonce_length(const struct Context *ctx)
{
  return EVP_CIPHER_iv_length(ctx->aead);
}


int Curl_qc_negotiated_prf(struct Context *ctx, SSL *ssl)
{
  switch(SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: /* TLS_AES_128_GCM_SHA256 */
  case 0x03001303u: /* TLS_CHACHA20_POLY1305_SHA256 */
  case 0x03001304u: /* TLS_AES_128_CCM_SHA256 */
    ctx->prf = EVP_sha256();
    return 0;
  case 0x03001302u: /* TLS_AES_256_GCM_SHA384 */
    ctx->prf = EVP_sha384();
    return 0;
  default:
    return -1;
  }
}

int Curl_qc_negotiated_aead(struct Context *ctx, SSL *ssl)
{
  switch(SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
  case 0x03001301u: /* TLS_AES_128_GCM_SHA256 */
    ctx->aead = EVP_aes_128_gcm();
    ctx->hp = EVP_aes_128_ctr();
    return 0;
  case 0x03001302u: /* TLS_AES_256_GCM_SHA384 */
    ctx->aead = EVP_aes_256_gcm();
    ctx->hp = EVP_aes_256_ctr();
    return 0;
  case 0x03001303u: /* TLS_CHACHA20_POLY1305_SHA256 */
    ctx->aead = EVP_chacha20_poly1305();
    ctx->hp = EVP_chacha20();
    return 0;
  case 0x03001304u: /* TLS_AES_128_CCM_SHA256 */
    ctx->aead = EVP_aes_128_ccm();
    ctx->hp = EVP_aes_128_ctr();
    return 0;
  default:
    return -1;
  }
}

ssize_t Curl_qc_encrypt_pn(uint8_t *dest, size_t destlen,
                           const uint8_t *plaintext, size_t plaintextlen,
                           const struct Context *ctx,
                           const uint8_t *key, size_t keylen,
                           const uint8_t *nonce, size_t noncelen)
{
  EVP_CIPHER_CTX *actx = EVP_CIPHER_CTX_new();
  size_t outlen = 0;
  int len;
  (void)destlen;
  (void)keylen;
  (void)noncelen;

  if(!actx)
    return -1;

  if(EVP_EncryptInit_ex(actx, ctx->hp, NULL, key, nonce) != 1)
    goto error;

  if(EVP_EncryptUpdate(actx, dest, &len, plaintext, (int)plaintextlen) != 1)
    goto error;

  assert(len > 0);

  outlen = len;

  if(EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1)
    goto error;

  assert(len == 0);
  /* outlen += len; */

  EVP_CIPHER_CTX_free(actx);
  return outlen;

  error:
  EVP_CIPHER_CTX_free(actx);
  return -1;
}

static int hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
                       size_t secretlen, const uint8_t *info, size_t infolen,
                       const struct Context *ctx)
{
  void *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if(!pctx)
    return -1;

  if(EVP_PKEY_derive_init(pctx) != 1)
    goto err;

  if(EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1)
    goto err;

  if(EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->prf) != 1)
    goto err;

  if(EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1)
    goto err;

  if(EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)secretlen) != 1)
    goto err;

  if(EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)infolen) != 1)
    goto err;

  if(EVP_PKEY_derive(pctx, dest, &destlen) != 1)
    goto err;

  return 0;
  err:
  EVP_PKEY_CTX_free(pctx);
  return -1;
}

static int hkdf_extract(uint8_t *dest, size_t destlen,
                        const uint8_t *secret, size_t secretlen,
                        const uint8_t *salt, size_t saltlen,
                        const struct Context *ctx)
{
  void *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if(!pctx)
    return -1;

  if(EVP_PKEY_derive_init(pctx) != 1)
    goto err;

  if(EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) {
    goto err;
  }

  if(EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->prf) != 1) {
    goto err;
  }

  if(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)saltlen) != 1) {
    goto err;
  }

  if(EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)secretlen) != 1) {
    goto err;
  }

  if(EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
    goto err;
  }

  EVP_PKEY_CTX_free(pctx);
  return 0;
  err:
  EVP_PKEY_CTX_free(pctx);
  return -1;
}

static size_t aead_key_length(const struct Context *ctx)
{
  return EVP_CIPHER_key_length(ctx->aead);
}

static size_t aead_tag_length(const struct Context *ctx)
{
  if(ctx->aead == EVP_aes_128_gcm() || ctx->aead == EVP_aes_256_gcm()) {
    return EVP_GCM_TLS_TAG_LEN;
  }
  if(ctx->aead == EVP_chacha20_poly1305()) {
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  }
  if(ctx->aead == EVP_aes_128_ccm())
    return EVP_CCM_TLS_TAG_LEN;
  assert(0);
}

size_t Curl_qc_aead_max_overhead(const struct Context *ctx)
{
  return aead_tag_length(ctx);
}

ssize_t Curl_qc_encrypt(uint8_t *dest, size_t destlen,
                        const uint8_t *plaintext, size_t plaintextlen,
                        const struct Context *ctx,
                        const uint8_t *key, size_t keylen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *ad, size_t adlen)
{
  size_t taglen = aead_tag_length(ctx);
  EVP_CIPHER_CTX *actx;
  size_t outlen = 0;
  int len;
  (void)keylen;

  if(destlen < plaintextlen + taglen) {
    return -1;
  }

  actx = EVP_CIPHER_CTX_new();
  if(!actx)
    return -1;

  if(EVP_EncryptInit_ex(actx, ctx->aead, NULL, NULL, NULL) != 1)
    goto error;

  if(EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN,
                         (int)noncelen, NULL) != 1)
    goto error;

  if(ctx->aead == EVP_aes_128_ccm() &&
     EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, (int)taglen, NULL) != 1)
    goto error;

  if(EVP_EncryptInit_ex(actx, NULL, NULL, key, nonce) != 1)
    goto error;

  if(ctx->aead == EVP_aes_128_ccm() &&
     EVP_EncryptUpdate(actx, NULL, &len, NULL, (int)plaintextlen) != 1)
    goto error;

  if(EVP_EncryptUpdate(actx, NULL, &len, ad, (int)adlen) != 1)
    goto error;

  if(EVP_EncryptUpdate(actx, dest, &len, plaintext, (int)plaintextlen) != 1)
    goto error;

  outlen = len;
  if(EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1)
    goto error;

  outlen += len;
  assert(outlen + taglen <= destlen);

  if(EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG,
                         (int)taglen, dest + outlen) != 1)
    goto error;

  outlen += taglen;

  EVP_CIPHER_CTX_free(actx);
  return outlen;

  error:
  EVP_CIPHER_CTX_free(actx);
  return -1;
}

ssize_t Curl_qc_decrypt(uint8_t *dest, size_t destlen,
                        const uint8_t *ciphertext, size_t ciphertextlen,
                        const struct Context *ctx,
                        const uint8_t *key, size_t keylen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *ad, size_t adlen)
{
  size_t taglen = aead_tag_length(ctx);
  const uint8_t *tag;
  EVP_CIPHER_CTX *actx;
  size_t outlen;
  int len;
  (void)keylen;

  if(taglen > ciphertextlen || destlen + taglen < ciphertextlen) {
    return -1;
  }

  ciphertextlen -= taglen;
  tag = ciphertext + ciphertextlen;

  actx = EVP_CIPHER_CTX_new();
  if(!actx)
    return -1;

  if(EVP_DecryptInit_ex(actx, ctx->aead, NULL, NULL, NULL) != 1)
    goto error;

  if(EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, (int)noncelen, NULL) !=
     1)
    goto error;

  if(ctx->aead == EVP_aes_128_ccm() &&
     EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
                         (uint8_t *)tag) != 1)
    goto error;

  if(EVP_DecryptInit_ex(actx, NULL, NULL, key, nonce) != 1)
    goto error;

  if(ctx->aead == EVP_aes_128_ccm() &&
     EVP_DecryptUpdate(actx, NULL, &len, NULL, (int)ciphertextlen) != 1)
    goto error;

  if(EVP_DecryptUpdate(actx, NULL, &len, ad, (int)adlen) != 1)
    goto error;

  if(EVP_DecryptUpdate(actx, dest, &len, ciphertext, (int)ciphertextlen) != 1)
    goto error;

  outlen = len;

  if(ctx->aead == EVP_aes_128_ccm())
    return outlen;

  if(EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG,
                         (int)taglen, (char *)tag) != 1)
    goto error;

  if(EVP_DecryptFinal_ex(actx, dest + outlen, &len) != 1)
    goto error;

  outlen += len;

  EVP_CIPHER_CTX_free(actx);
  return outlen;
  error:
  EVP_CIPHER_CTX_free(actx);
  return -1;
}

int Curl_qc_derive_initial_secret(uint8_t *dest, size_t destlen,
                                  const ngtcp2_cid *secret,
                                  const uint8_t *salt,
                                  size_t saltlen)
{
  struct Context ctx;
  Curl_qc_prf_sha256(&ctx);
  return hkdf_extract(dest, destlen, secret->data, secret->datalen, salt,
                      saltlen, &ctx);
}

int Curl_qc_derive_client_initial_secret(uint8_t *dest,
                                         size_t destlen,
                                         const uint8_t *secret,
                                         size_t secretlen)
{
  static uint8_t LABEL[] = "client in";
  struct Context ctx;
  Curl_qc_prf_sha256(&ctx);
  return hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
                           sizeof(LABEL) - 1, &ctx);
}

ssize_t Curl_qc_derive_packet_protection_key(uint8_t *dest, size_t destlen,
                                             const uint8_t *secret,
                                             size_t secretlen,
                                             const struct Context *ctx)
{
  int rv;
  static uint8_t LABEL[] = "quic key";
  size_t keylen = aead_key_length(ctx);
  if(keylen > destlen) {
    return -1;
  }

  rv = hkdf_expand_label(dest, keylen, secret, secretlen, LABEL,
                         sizeof(LABEL) - 1, ctx);
  if(rv) {
    return -1;
  }

  return keylen;
}

ssize_t Curl_qc_derive_packet_protection_iv(uint8_t *dest, size_t destlen,
                                            const uint8_t *secret,
                                            size_t secretlen,
                                            const struct Context *ctx)
{
  int rv;
  static uint8_t LABEL[] = "quic iv";

  size_t ivlen = CURLMAX(8, Curl_qc_aead_nonce_length(ctx));
  if(ivlen > destlen) {
    return -1;
  }

  rv = hkdf_expand_label(dest, ivlen, secret, secretlen, LABEL,
                         sizeof(LABEL) - 1, ctx);
  if(rv) {
    return -1;
  }

  return ivlen;
}

int Curl_qc_derive_server_initial_secret(uint8_t *dest, size_t destlen,
                                         const uint8_t *secret,
                                         size_t secretlen)
{
  static uint8_t LABEL[] = "server in";
  struct Context ctx;
  Curl_qc_prf_sha256(&ctx);
  return hkdf_expand_label(dest, destlen, secret, secretlen, LABEL,
                           sizeof(LABEL) - 1, &ctx);
}

static int
hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
                  size_t secretlen, const uint8_t *label, size_t labellen,
                  const struct Context *ctx)
{
  uint8_t info[256];
  static const uint8_t LABEL[] = "tls13 ";

  uint8_t *p = &info[0];
  *p++ = (destlen / 256)&0xff;
  *p++ = destlen % 256;
  *p++ = (sizeof(LABEL) - 1 + labellen) & 0xff;
  memcpy(p, LABEL, sizeof(LABEL) - 1);
  p += sizeof(LABEL) - 1;
  memcpy(p, label, labellen);
  p += labellen;
  *p++ = 0;

  return hkdf_expand(dest, destlen, secret, secretlen, &info[0],
                     p - &info[0], ctx);
}

ssize_t
Curl_qc_derive_header_protection_key(uint8_t *dest, size_t destlen,
                                     const uint8_t *secret, size_t secretlen,
                                     const struct Context *ctx)
{
  int rv;
  static uint8_t LABEL[] = "quic hp";

  size_t keylen = aead_key_length(ctx);
  if(keylen > destlen)
    return -1;

  rv = hkdf_expand_label(dest, keylen, secret, secretlen, LABEL,
                         sizeof(LABEL) - 1, ctx);

  if(rv)
    return -1;

  return keylen;
}

ssize_t Curl_qc_hp_mask(uint8_t *dest, size_t destlen,
                        const struct Context *ctx,
                        const uint8_t *key, size_t keylen,
                        const uint8_t *sample, size_t samplelen)
{
  static uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";
  EVP_CIPHER_CTX *actx;
  size_t outlen = 0;
  int len;
  (void)destlen; /* TODO: make use of these! */
  (void)keylen;
  (void)samplelen;

  actx = EVP_CIPHER_CTX_new();
  if(!actx)
    return -1;

  if(EVP_EncryptInit_ex(actx, ctx->hp, NULL, key, sample) != 1)
    goto error;
  if(EVP_EncryptUpdate(actx, dest, &len, PLAINTEXT,
                       (int)(sizeof(PLAINTEXT) - 1)) != 1)
    goto error;

  DEBUGASSERT(len == 5);

  outlen = len;

  if(EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1)
    goto error;

  DEBUGASSERT(len == 0);

  return outlen;
  error:
  EVP_CIPHER_CTX_free(actx);
  return -1;
}


#endif
