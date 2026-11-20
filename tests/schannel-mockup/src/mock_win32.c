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

/* Thread-local Win32 error code */
static __thread DWORD g_last_error = ERROR_SUCCESS;

DWORD WINAPI GetLastError(void)
{
  return g_last_error;
}

void WINAPI SetLastError(DWORD dwErrCode)
{
  g_last_error = dwErrCode;
}

HLOCAL WINAPI LocalAlloc(unsigned int uFlags, size_t uBytes)
{
  void *ptr;
  if(uFlags & LMEM_ZEROINIT)
    ptr = calloc(1, uBytes ? uBytes : 1);
  else
    ptr = malloc(uBytes ? uBytes : 1);

  if(!ptr)
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
  return (HLOCAL)ptr;
}

HLOCAL WINAPI LocalFree(HLOCAL hMem)
{
  if(hMem)
    free(hMem);
  return NULL;
}

int WINAPI MultiByteToWideChar(unsigned int CodePage, DWORD dwFlags,
                               LPCSTR lpMultiByteStr, int cbMultiByte,
                               LPWSTR lpWideCharStr, int cchWideChar)
{
  size_t len;
  size_t i;
  (void)CodePage;
  (void)dwFlags;
  if(!lpMultiByteStr) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
  }

  len = (cbMultiByte < 0) ? (strlen(lpMultiByteStr) + 1) : (size_t)cbMultiByte;

  if(!cchWideChar)
    return (int)len;

  if(cchWideChar < (int)len) {
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return 0;
  }

  for(i = 0; i < len; i++)
    lpWideCharStr[i] = (WCHAR)(unsigned char)lpMultiByteStr[i];

  return (int)len;
}

int WINAPI WideCharToMultiByte(unsigned int CodePage, DWORD dwFlags,
                               LPCWSTR lpWideCharStr, int cchWideChar,
                               LPSTR lpMultiByteStr, int cbMultiByte,
                               LPCSTR lpDefaultChar, BOOL *lpUsedDefaultChar)
{
  size_t len;
  size_t i;
  (void)CodePage;
  (void)dwFlags;
  (void)lpDefaultChar;
  (void)lpUsedDefaultChar;

  if(!lpWideCharStr) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
  }

  len = (cchWideChar < 0) ? (wcslen(lpWideCharStr) + 1) : (size_t)cchWideChar;

  if(cbMultiByte == 0) {
    return (int)len;
  }

  if(cbMultiByte < (int)len) {
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return 0;
  }

  for(i = 0; i < len; i++) {
    lpMultiByteStr[i] = (char)lpWideCharStr[i];
  }

  return (int)len;
}

HMODULE WINAPI GetModuleHandleA(LPCSTR lpModuleName)
{
  (void)lpModuleName;
  return (HMODULE)1;
}

HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName)
{
  (void)lpModuleName;
  return (HMODULE)1;
}

FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
  (void)hModule;
  (void)lpProcName;
  /* Return NULL for wine_get_version so curl uses standard version checks */
  return NULL;
}

BOOL WINAPI CertFreeCertificateContext(PCCERT_CONTEXT pCertContext)
{
  mock_cert_context_t *mc;
  if(!pCertContext)
    return TRUE;

  mc = (mock_cert_context_t *)UNCONST(pCertContext);
  mc->refcount--;
  if(mc->refcount <= 0) {
    if(mc->x509) {
      X509_free(mc->x509);
      mc->x509 = NULL;
    }
    if(mc->pkey) {
      EVP_PKEY_free(mc->pkey);
      mc->pkey = NULL;
    }
    if(mc->der_encoded) {
      OPENSSL_free(mc->der_encoded);
      mc->der_encoded = NULL;
    }
    mock_cert_context_free_extensions(&mc->cert_info);
    free(mc);
  }
  return TRUE;
}

PCCERT_CONTEXT WINAPI
CertDuplicateCertificateContext(PCCERT_CONTEXT pCertContext)
{
  mock_cert_context_t *mc;
  if(!pCertContext)
    return NULL;
  mc = (mock_cert_context_t *)UNCONST(pCertContext);
  mc->refcount++;
  return pCertContext;
}

LONG WINAPI InterlockedIncrement(LONG volatile *Addend)
{
  return ++(*Addend);
}

LONG WINAPI InterlockedDecrement(LONG volatile *Addend)
{
  return --(*Addend);
}
