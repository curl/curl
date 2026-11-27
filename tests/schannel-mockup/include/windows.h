#ifndef MOCK_WINDOWS_H
#define MOCK_WINDOWS_H
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
 * Mock Windows header for Schannel mockup on non-Windows platforms.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Calling conventions - no-ops on non-Windows */
#ifndef WINAPI
#define WINAPI
#endif
#ifndef APIENTRY
#define APIENTRY
#endif
#ifndef CALLBACK
#define CALLBACK
#endif

/* Base Win32 integer and boolean types. Stick to the types used on Windows,
   which makes the long ones 64 bit on non-Windows while they are 32 bit on
   Windows. Keeping the type makes printf() and things easier. */
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef long LONG;
typedef uint16_t USHORT;
typedef int BOOL;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* Pointer types */
typedef void *PVOID;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef char TCHAR;
typedef TCHAR *LPTSTR;
typedef const TCHAR *LPCTSTR;
typedef uintptr_t ULONG_PTR;
typedef intptr_t LONG_PTR;
typedef DWORD *LPDWORD;

/* Handle types */
typedef void *HANDLE;
typedef HANDLE HMODULE;
typedef HANDLE HLOCAL;
typedef HANDLE HCRYPTPROV;
typedef HANDLE HCRYPTHASH;

/* Character / string macros */
#ifndef _TEXT
#define _TEXT(x) x
#endif
#ifndef TEXT
#define TEXT(x) x
#endif

#ifndef _tcslen
#define _tcslen strlen
#endif
#ifndef _tcschr
#define _tcschr strchr
#endif
#ifndef _tcsncmp
#define _tcsncmp strncmp
#endif
#ifndef _tcsncpy_s
#define _tcsncpy_s(dst, dstsize, src, count) \
  (strncpy((dst), (src), (count)), ((dst)[(count)] = '\0'), 0)
#endif

/* Status and result types */
typedef int32_t HRESULT;
typedef int32_t NTSTATUS;

#define S_OK ((HRESULT)0L)
#define S_FALSE ((HRESULT)1L)
#define FAILED(hr) (((HRESULT)(hr)) < 0)
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)

/* Common Win32 error codes. These have 'L' suffixes on windows */
#define ERROR_SUCCESS                   0
#define ERROR_INVALID_FUNCTION          1
#define ERROR_FILE_NOT_FOUND            2
#define ERROR_PATH_NOT_FOUND            3
#define ERROR_ACCESS_DENIED             5
#define ERROR_INVALID_HANDLE            6
#define ERROR_NOT_ENOUGH_MEMORY         8
#define ERROR_INVALID_DATA              13
#define ERROR_NOT_SUPPORTED             50
#define ERROR_INVALID_PASSWORD          86
#define ERROR_INVALID_PARAMETER         87
#define ERROR_INSUFFICIENT_BUFFER       122
#define ERROR_MORE_DATA                 234

/* Code page and conversion flags */
#define CP_UTF8                         65001
#define MB_ERR_INVALID_CHARS            0x00000008

/* Local memory allocation flags */
#define LMEM_FIXED                      0x0000
#define LMEM_ZEROINIT                   0x0040

/* Error handling */
DWORD WINAPI GetLastError(void);
void WINAPI SetLastError(DWORD dwErrCode);

/* Memory management */
HLOCAL WINAPI LocalAlloc(unsigned int uFlags, size_t uBytes);
HLOCAL WINAPI LocalFree(HLOCAL hMem);

/* String conversions */
int WINAPI MultiByteToWideChar(unsigned int CodePage, DWORD dwFlags,
                              LPCSTR lpMultiByteStr, int cbMultiByte,
                              LPWSTR lpWideCharStr, int cchWideChar);

int WINAPI WideCharToMultiByte(unsigned int CodePage, DWORD dwFlags,
                              LPCWSTR lpWideCharStr, int cchWideChar,
                              LPSTR lpMultiByteStr, int cbMultiByte,
                              LPCSTR lpDefaultChar, BOOL *lpUsedDefaultChar);

/* Module management */
HMODULE WINAPI GetModuleHandleA(LPCSTR lpModuleName);
HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName);
#define GetModuleHandle GetModuleHandleA

typedef void (*FARPROC)(void);
FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

/*
 * Curl compatibility bridges when building without real _WIN32
 */
#ifndef curlx_tcsdup
#define curlx_tcsdup curlx_strdup
#endif

#ifndef curlx_convert_UTF8_to_tchar
#define curlx_convert_UTF8_to_tchar(ptr) curlx_strdup(ptr)
#endif

#ifndef curlx_convert_tchar_to_UTF8
#define curlx_convert_tchar_to_UTF8(ptr) curlx_strdup(ptr)
#endif

#ifndef _WIN32
typedef union {
  char                *tchar_ptr;
  const char          *const_tchar_ptr;
  unsigned char       *tbyte_ptr;
  const unsigned char *const_tbyte_ptr;
} xcharp_u;
#endif

/* Version condition enum matching curlx/version_win32.h */
#ifndef VERSION_LESS_THAN
typedef enum {
  VERSION_LESS_THAN,
  VERSION_LESS_THAN_EQUAL,
  VERSION_EQUAL,
  VERSION_GREATER_THAN_EQUAL,
  VERSION_GREATER_THAN
} VersionCondition;
#endif

#ifndef PLATFORM_DONT_CARE
typedef enum {
  PLATFORM_DONT_CARE,
  PLATFORM_WINDOWS,
  PLATFORM_WINNT
} PlatformIdentifier;
#endif

bool curlx_verify_windows_version(unsigned int majorVersion,
                                  unsigned int minorVersion,
                                  unsigned int buildVersion,
                                  PlatformIdentifier platform,
                                  VersionCondition condition);

#define WINAPI_ERROR_LEN 100
const char *curlx_winapi_strerror(DWORD err, char *buf, size_t buflen);
const char *curlx_get_winapi_error(DWORD err, char *buf, size_t buflen);

LONG InterlockedIncrement(LONG volatile *Addend);
LONG InterlockedDecrement(LONG volatile *Addend);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_WINDOWS_H */
