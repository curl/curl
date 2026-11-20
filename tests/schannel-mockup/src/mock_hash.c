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
 * mock_hash.c - Cryptographic provider and hash function mocks.
 *
 * Implements CryptAcquireContext, CryptReleaseContext, CryptCreateHash,
 * CryptHashData, CryptGetHashParam, and CryptDestroyHash using OpenSSL EVP.
 */

#include "mock_internal.h"

/* Magic numbers for hash and provider handles */
#define MOCK_MAGIC_HASH  0x4D484153 /* "MHAS" */
#define MOCK_MAGIC_PROV  0x4D505256 /* "MPRV" */

/* Internal hash context */
typedef struct mock_hash_ctx {
  uint32_t magic;
  EVP_MD_CTX *mdctx;
  ALG_ID alg_id;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len;
  int finalized;
} mock_hash_t;

/* Internal provider context */
typedef struct mock_prov_ctx {
  uint32_t magic;
} mock_prov_t;

BOOL WINAPI CryptAcquireContextA(HCRYPTPROV *phProv, LPCSTR szContainer,
                                 LPCSTR szProvider, DWORD dwProvType,
                                 DWORD dwFlags)
{
  mock_prov_t *prov;
  (void)szContainer;
  (void)szProvider;
  (void)dwProvType;
  (void)dwFlags;

  if(!phProv) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  prov = calloc(1, sizeof(mock_prov_t));
  if(!prov) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }
  prov->magic = MOCK_MAGIC_PROV;
  *phProv = (HCRYPTPROV)prov;
  return TRUE;
}

BOOL WINAPI CryptAcquireContextW(HCRYPTPROV *phProv, LPCWSTR szContainer,
                                 LPCWSTR szProvider, DWORD dwProvType,
                                 DWORD dwFlags)
{
  (void)szContainer;
  (void)szProvider;
  return CryptAcquireContextA(phProv, NULL, NULL, dwProvType, dwFlags);
}

BOOL WINAPI CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags)
{
  mock_prov_t *prov = (mock_prov_t *)hProv;
  (void)dwFlags;

  if(!prov || prov->magic != MOCK_MAGIC_PROV) {
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  prov->magic = 0;
  free(prov);
  return TRUE;
}

BOOL WINAPI CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTPROV hKey,
                            DWORD dwFlags, HCRYPTHASH *phHash)
{
  mock_hash_t *h;
  const EVP_MD *md;
  (void)hProv;
  (void)hKey;
  (void)dwFlags;

  if(!phHash) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  switch(Algid) {
  case CALG_SHA_256:
    md = EVP_sha256();
    break;
  case CALG_SHA1:
    md = EVP_sha1();
    break;
  case CALG_MD5:
    md = EVP_md5();
    break;
  default:
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
  }

  h = calloc(1, sizeof(mock_hash_t));
  if(!h) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }
  h->mdctx = EVP_MD_CTX_new();
  if(!h->mdctx) {
    free(h);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }
  if(!EVP_DigestInit_ex(h->mdctx, md, NULL)) {
    EVP_MD_CTX_free(h->mdctx);
    free(h);
    SetLastError(ERROR_INVALID_FUNCTION);
    return FALSE;
  }
  h->magic = MOCK_MAGIC_HASH;
  h->alg_id = Algid;
  h->finalized = 0;
  *phHash = (HCRYPTHASH)h;
  return TRUE;
}

BOOL WINAPI CryptHashData(HCRYPTHASH hHash, const BYTE *pbData,
                          DWORD dwDataLen, DWORD dwFlags)
{
  mock_hash_t *h = (mock_hash_t *)hHash;
  (void)dwFlags;

  if(!h || h->magic != MOCK_MAGIC_HASH) {
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  if(!pbData || !dwDataLen)
    return TRUE;
  if(h->finalized) {
    SetLastError(ERROR_INVALID_FUNCTION);
    return FALSE;
  }
  if(!EVP_DigestUpdate(h->mdctx, pbData, (size_t)dwDataLen)) {
    SetLastError(ERROR_INVALID_FUNCTION);
    return FALSE;
  }
  return TRUE;
}

BOOL WINAPI CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData,
                              DWORD *pdwDataLen, DWORD dwFlags)
{
  mock_hash_t *h = (mock_hash_t *)hHash;
  DWORD mdsize;
  int size;
  (void)dwFlags;

  if(!h || h->magic != MOCK_MAGIC_HASH) {
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  if(!pdwDataLen) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  switch(dwParam) {
  case HP_HASHSIZE:
    size = EVP_MD_CTX_size(h->mdctx);
    if(size < 0) {
      SetLastError(ERROR_INVALID_FUNCTION);
      return FALSE;
    }
    mdsize = (DWORD)size;
    if(pbData) {
      if(*pdwDataLen < sizeof(DWORD)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
      }
      memcpy(pbData, &mdsize, sizeof(DWORD));
    }
    *pdwDataLen = sizeof(DWORD);
    return TRUE;

  case HP_HASHVAL:
    if(!h->finalized) {
      /* finalize into internal buffer */
      unsigned char tmp[EVP_MAX_MD_SIZE];
      unsigned int tmplen = 0;
      if(!EVP_DigestFinal_ex(h->mdctx, tmp, &tmplen)) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
      }
      memcpy(h->digest, tmp, tmplen);
      h->digest_len = tmplen;
      h->finalized = 1;
    }
    if(pbData) {
      if(*pdwDataLen < h->digest_len) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
      }
      memcpy(pbData, h->digest, h->digest_len);
    }
    *pdwDataLen = h->digest_len;
    return TRUE;

  default:
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
  }
}

BOOL WINAPI CryptDestroyHash(HCRYPTHASH hHash)
{
  mock_hash_t *h = (mock_hash_t *)hHash;

  if(!h || h->magic != MOCK_MAGIC_HASH) {
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  h->magic = 0;
  if(h->mdctx) {
    EVP_MD_CTX_free(h->mdctx);
    h->mdctx = NULL;
  }
  free(h);
  return TRUE;
}
