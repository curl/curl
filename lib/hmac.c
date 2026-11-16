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
 * RFC2104 Keyed-Hashing for Message Authentication
 *
 ***************************************************************************/
#include "curl_setup.h"

#if !defined(CURL_DISABLE_AWS) || !defined(CURL_DISABLE_HTTPSIG) || \
  !defined(CURL_DISABLE_DIGEST_AUTH) ||                             \
  defined(USE_LIBSSH2) || defined(USE_SSL)

#include "curl_hmac.h"

/*
 * Generic HMAC algorithm.
 *
 *   This module computes HMAC digests based on any hash function. Parameters
 * and computing procedures are setup dynamically at HMAC computation context
 * initialization.
 */

static const uint8_t hmac_ipad = 0x36;
static const uint8_t hmac_opad = 0x5C;

/* Some hash contexts need 16-byte alignment, e.g. wolfSSL on 64-bit CPUs */
#define HMAC_CTXT_OFFSET ((sizeof(struct HMAC_context) + 15) & ~(size_t)15)

struct HMAC_context *Curl_HMAC_init(const struct HMAC_params *hashparams,
                                    const void *key, size_t key_len)
{
  size_t i;
  struct HMAC_context *ctxt;
  const uint8_t *bkey;
  uint8_t *hkey;
  uint8_t b;
  CURLcode hok;
  bool hashctxt1_initialized;
  bool hashctxt2_initialized;

  /* Create HMAC context. */
  i = HMAC_CTXT_OFFSET + (2 * hashparams->ctxtsize) + hashparams->digest_len;
  ctxt = curlx_malloc(i);
  if(!ctxt)
    return ctxt;

  hashctxt1_initialized = FALSE;
  hashctxt2_initialized = FALSE;

  ctxt->hash = hashparams;
  ctxt->hashctxt1 = (void *)((char *)ctxt + HMAC_CTXT_OFFSET);
  ctxt->hashctxt2 = (void *)((char *)ctxt->hashctxt1 + hashparams->ctxtsize);

  /* If the key is too long, replace it by its hash digest. */
  if(key_len > hashparams->key_len_max) {
    if(hashparams->hinit(ctxt->hashctxt1))
      goto fail;
    hok = hashparams->hupdate(ctxt->hashctxt1, key, key_len);
    hkey = (uint8_t *)ctxt->hashctxt2 + hashparams->ctxtsize;
    hok |= hashparams->hfinal(hkey, ctxt->hashctxt1);
    if(hok)
      goto fail;
    key = hkey;
    key_len = hashparams->digest_len;
  }

  /* Prime the two hash contexts with the modified key. */
  if(hashparams->hinit(ctxt->hashctxt1))
    goto fail;
  hashctxt1_initialized = TRUE;
  if(hashparams->hinit(ctxt->hashctxt2))
    goto fail;
  hashctxt2_initialized = TRUE;

  bkey = key;
  for(i = 0; i < key_len; i++) {
    b = (uint8_t)(*bkey ^ hmac_ipad);
    if(hashparams->hupdate(ctxt->hashctxt1, &b, 1))
      goto fail;
    b = (uint8_t)(*bkey++ ^ hmac_opad);
    if(hashparams->hupdate(ctxt->hashctxt2, &b, 1))
      goto fail;
  }

  for(; i < hashparams->key_len_max; i++) {
    if(hashparams->hupdate(ctxt->hashctxt1, &hmac_ipad, 1))
      goto fail;
    if(hashparams->hupdate(ctxt->hashctxt2, &hmac_opad, 1))
      goto fail;
  }

  /* Done, return pointer to HMAC context. */
  return ctxt;

fail:
  if(hashctxt1_initialized)
    hashparams->hfinal((uint8_t *)ctxt->hashctxt2 + hashparams->ctxtsize,
                       ctxt->hashctxt1);
  if(hashctxt2_initialized)
    hashparams->hfinal((uint8_t *)ctxt->hashctxt2 + hashparams->ctxtsize,
                       ctxt->hashctxt2);
  curlx_free(ctxt);
  return NULL;
}

CURLcode Curl_HMAC_update(struct HMAC_context *ctxt,
                          const void *input, size_t input_len)
{
  /* Update first hash calculation. */
  return ctxt->hash->hupdate(ctxt->hashctxt1, input, input_len);
}

CURLcode Curl_HMAC_final(struct HMAC_context *ctxt, uint8_t *mac)
{
  const struct HMAC_params *hashparams = ctxt->hash;
  CURLcode hok;

  /* Do not get output if called with a NULL parameter: only release
     storage. */
  if(!mac)
    mac = (uint8_t *)ctxt->hashctxt2 + ctxt->hash->ctxtsize;

  hok = hashparams->hfinal(mac, ctxt->hashctxt1);
  if(!hok)
    hok |= hashparams->hupdate(ctxt->hashctxt2, mac, hashparams->digest_len);
  hok |= hashparams->hfinal(mac, ctxt->hashctxt2);

  curlx_free(ctxt);
  return hok ? CURLE_BAD_FUNCTION_ARGUMENT : hok;
}

/*
 * This is used to generate a HMAC hash, for the specified input data, given
 * the specified hash function and key.
 *
 * Parameters:
 *
 * hashparams [in]  - The hash function (Curl_HMAC_SHA256).
 * key        [in]  - The key to use.
 * key_len    [in]  - The length of the key.
 * input      [in]  - The data to encrypt.
 * input_len  [in]  - The length of the data.
 * mac        [out] - The output buffer.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_hmacit(const struct HMAC_params *hashparams,
                     const void *key, const size_t key_len,
                     const void *input, size_t input_len,
                     uint8_t *mac)
{
  struct HMAC_context *ctxt;
  CURLcode result;

  if(!hashparams->hinit)
    return CURLE_NOT_BUILT_IN;

  ctxt = Curl_HMAC_init(hashparams, key, key_len);
  if(!ctxt)
    return CURLE_OUT_OF_MEMORY;

  /* Update the digest with the given challenge */
  result = Curl_HMAC_update(ctxt, input, input_len);
  if(result) {
    (void)Curl_HMAC_final(ctxt, mac);
    return result;
  }

  return Curl_HMAC_final(ctxt, mac);  /* Finalise the digest */
}

#endif /* AWS, httpsig or Digest and TLS */
