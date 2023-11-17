#ifndef HEADER_CURL_SYSTEM_WIN32_H
#define HEADER_CURL_SYSTEM_WIN32_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Steve Holme, <steve_holme@hotmail.com>.
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

#ifdef _WIN32

extern LARGE_INTEGER Curl_freq;
extern bool Curl_isVistaOrGreater;
extern bool Curl_isWindows8OrGreater;

CURLcode Curl_win32_init(long flags);
void Curl_win32_cleanup(long init_flags);

/* We use our own typedef here since some headers might lack this */
typedef unsigned int(WINAPI *IF_NAMETOINDEX_FN)(const char *);

/* This is used instead of if_nametoindex if available on Windows */
extern IF_NAMETOINDEX_FN Curl_if_nametoindex;

/* Identical copy of addrinfoexW/ADDRINFOEXW */
typedef struct addrinfoexW_
{
  int                  ai_flags;
  int                  ai_family;
  int                  ai_socktype;
  int                  ai_protocol;
  size_t               ai_addrlen;
  PWSTR                ai_canonname;
  struct sockaddr     *ai_addr;
  void                *ai_blob;
  size_t               ai_bloblen;
  LPGUID               ai_provider;
  struct addrinfoexW_ *ai_next;
} ADDRINFOEXW_;

typedef void(CALLBACK *LOOKUP_COMPLETION)(DWORD, DWORD, LPWSAOVERLAPPED);
extern void(WSAAPI *Curl_FreeAddrInfoExW)(ADDRINFOEXW_*);
extern int(WSAAPI *Curl_GetAddrInfoExCancel)(LPHANDLE);
extern int(WSAAPI *Curl_GetAddrInfoExW)(PCWSTR, PCWSTR, DWORD, LPGUID,
  const ADDRINFOEXW_*, ADDRINFOEXW_**, struct timeval*, LPOVERLAPPED,
  LOOKUP_COMPLETION, LPHANDLE);

/* This is used to dynamically load DLLs */
HMODULE Curl_load_library(LPCTSTR filename);
#else  /* _WIN32 */
#define Curl_win32_init(x) CURLE_OK
#endif /* !_WIN32 */

#endif /* HEADER_CURL_SYSTEM_WIN32_H */
