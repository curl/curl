/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "setup.h"

#ifdef USE_WINDOWS_SSPI

#include <curl/curl.h>

#include "curl_sspi.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"


/* We use our own typedef here since some headers might lack these */
typedef PSecurityFunctionTableA (APIENTRY *INITSECURITYINTERFACE_FN_A)(VOID);

/* Handle of security.dll or secur32.dll, depending on Windows version */
HMODULE s_hSecDll = NULL;

/* Pointer to SSPI dispatch table */
PSecurityFunctionTableA s_pSecFn = NULL;


/*
 * Curl_sspi_global_init()
 *
 * This is used to load the Security Service Provider Interface (SSPI)
 * dynamic link library portably across all Windows versions, without
 * the need to directly link libcurl, nor the application using it, at
 * build time.
 *
 * Once this function has been executed, Windows SSPI functions can be
 * called through the Security Service Provider Interface dispatch table.
 */

CURLcode
Curl_sspi_global_init(void)
{
  OSVERSIONINFO osver;
  INITSECURITYINTERFACE_FN_A pInitSecurityInterface;

  /* If security interface is not yet initialized try to do this */
  if(s_hSecDll == NULL) {

    /* Find out Windows version */
    memset(&osver, 0, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);
    if(! GetVersionEx(&osver))
      return CURLE_FAILED_INIT;

    /* Security Service Provider Interface (SSPI) functions are located in
     * security.dll on WinNT 4.0 and in secur32.dll on Win9x. Win2K and XP
     * have both these DLLs (security.dll forwards calls to secur32.dll) */

    /* Load SSPI dll into the address space of the calling process */
    if(osver.dwPlatformId == VER_PLATFORM_WIN32_NT
      && osver.dwMajorVersion == 4)
      s_hSecDll = LoadLibrary("security.dll");
    else
      s_hSecDll = LoadLibrary("secur32.dll");
    if(! s_hSecDll)
      return CURLE_FAILED_INIT;

    /* Get address of the InitSecurityInterfaceA function from the SSPI dll */
    pInitSecurityInterface = (INITSECURITYINTERFACE_FN_A)
      GetProcAddress(s_hSecDll, "InitSecurityInterfaceA");
    if(! pInitSecurityInterface)
      return CURLE_FAILED_INIT;

    /* Get pointer to Security Service Provider Interface dispatch table */
    s_pSecFn = pInitSecurityInterface();
    if(! s_pSecFn)
      return CURLE_FAILED_INIT;

  }
  return CURLE_OK;
}


/*
 * Curl_sspi_global_cleanup()
 *
 * This deinitializes the Security Service Provider Interface from libcurl.
 */

void
Curl_sspi_global_cleanup(void)
{
  if(s_hSecDll) {
    FreeLibrary(s_hSecDll);
    s_hSecDll = NULL;
    s_pSecFn = NULL;
  }
}


/*
 * Curl_sspi_version()
 *
 * This function returns the SSPI library version information.
 */
CURLcode Curl_sspi_version(int *major, int *minor, int *build, int *special)
{
  CURLcode result = CURLE_OK;
  VS_FIXEDFILEINFO *version_info = NULL;
  LPTSTR path = NULL;
  LPVOID data = NULL;
  DWORD size, handle;

  if(!s_hSecDll)
    return CURLE_FAILED_INIT;

  path = (char *) malloc(MAX_PATH);
  if(!path)
    return CURLE_OUT_OF_MEMORY;

  if(GetModuleFileName(s_hSecDll, path, MAX_PATH)) {
    size = GetFileVersionInfoSize(path, &handle);
    if(size) {
      data = malloc(size);
      if(data) {
        if(GetFileVersionInfo(path, handle, size, data)) {
          if(!VerQueryValue(data, "\\", &version_info, &handle))
            result = CURLE_OUT_OF_MEMORY;
        }
        else
          result = CURLE_OUT_OF_MEMORY;
      }
      else
        result = CURLE_OUT_OF_MEMORY;
    }
    else
      result = CURLE_OUT_OF_MEMORY;
  }
  else
    result = CURLE_OUT_OF_MEMORY;

  /* Set the out parameters */
  if(!result) {
    if(major)
      *major = (version_info->dwProductVersionMS >> 16) & 0xffff;
  
    if(minor)
      *minor = (version_info->dwProductVersionMS >> 0) & 0xffff;

    if(build)
      *build = (version_info->dwProductVersionLS >> 16) & 0xffff;

    if(special)
      *special = (version_info->dwProductVersionLS >> 0) & 0xffff;
  }

  Curl_safefree(data);
  Curl_safefree(path);

  return result;
}


/*
 * Curl_sspi_status(SECURIY_STATUS status)
 *
 * This function returns a string representing an SSPI status.
 * It will in any case return a usable string pointer which needs to be freed.
 */
char*
Curl_sspi_status(SECURITY_STATUS status)
{
  const char* status_const;

  switch(status) {
    case SEC_I_COMPLETE_AND_CONTINUE:
      status_const = "SEC_I_COMPLETE_AND_CONTINUE";
      break;
    case SEC_I_COMPLETE_NEEDED:
      status_const = "SEC_I_COMPLETE_NEEDED";
      break;
    case SEC_I_CONTINUE_NEEDED:
      status_const = "SEC_I_CONTINUE_NEEDED";
      break;
    case SEC_I_CONTEXT_EXPIRED:
      status_const = "SEC_I_CONTEXT_EXPIRED";
      break;
    case SEC_I_INCOMPLETE_CREDENTIALS:
      status_const = "SEC_I_INCOMPLETE_CREDENTIALS";
      break;
    case SEC_I_RENEGOTIATE:
      status_const = "SEC_I_RENEGOTIATE";
      break;
    case SEC_E_BUFFER_TOO_SMALL:
      status_const = "SEC_E_BUFFER_TOO_SMALL";
      break;
    case SEC_E_CONTEXT_EXPIRED:
      status_const = "SEC_E_CONTEXT_EXPIRED";
      break;
    case SEC_E_CRYPTO_SYSTEM_INVALID:
      status_const = "SEC_E_CRYPTO_SYSTEM_INVALID";
      break;
    case SEC_E_INCOMPLETE_MESSAGE:
      status_const = "SEC_E_INCOMPLETE_MESSAGE";
      break;
    case SEC_E_INSUFFICIENT_MEMORY:
      status_const = "SEC_E_INSUFFICIENT_MEMORY";
      break;
    case SEC_E_INTERNAL_ERROR:
      status_const = "SEC_E_INTERNAL_ERROR";
      break;
    case SEC_E_INVALID_HANDLE:
      status_const = "SEC_E_INVALID_HANDLE";
      break;
    case SEC_E_INVALID_TOKEN:
      status_const = "SEC_E_INVALID_TOKEN";
      break;
    case SEC_E_LOGON_DENIED:
      status_const = "SEC_E_LOGON_DENIED";
      break;
    case SEC_E_MESSAGE_ALTERED:
      status_const = "SEC_E_MESSAGE_ALTERED";
      break;
    case SEC_E_NO_AUTHENTICATING_AUTHORITY:
      status_const = "SEC_E_NO_AUTHENTICATING_AUTHORITY";
      break;
    case SEC_E_NO_CREDENTIALS:
      status_const = "SEC_E_NO_CREDENTIALS";
      break;
    case SEC_E_NOT_OWNER:
      status_const = "SEC_E_NOT_OWNER";
      break;
    case SEC_E_OK:
      status_const = "SEC_E_OK";
      break;
    case SEC_E_OUT_OF_SEQUENCE:
      status_const = "SEC_E_OUT_OF_SEQUENCE";
      break;
    case SEC_E_QOP_NOT_SUPPORTED:
      status_const = "SEC_E_QOP_NOT_SUPPORTED";
      break;
    case SEC_E_SECPKG_NOT_FOUND:
      status_const = "SEC_E_SECPKG_NOT_FOUND";
      break;
    case SEC_E_TARGET_UNKNOWN:
      status_const = "SEC_E_TARGET_UNKNOWN";
      break;
    case SEC_E_UNKNOWN_CREDENTIALS:
      status_const = "SEC_E_UNKNOWN_CREDENTIALS";
      break;
    case SEC_E_UNSUPPORTED_FUNCTION:
      status_const = "SEC_E_UNSUPPORTED_FUNCTION";
      break;
    case SEC_E_WRONG_PRINCIPAL:
      status_const = "SEC_E_WRONG_PRINCIPAL";
      break;
    default:
      status_const = "Unknown error";
  }

  return curl_maprintf("%s (0x%04X%04X)", status_const,
                       (status>>16)&0xffff, status&0xffff);
}


/*
 * Curl_sspi_status_msg(SECURITY_STATUS status)
 *
 * This function returns a message representing an SSPI status.
 * It will in any case return a usable string pointer which needs to be freed.
 */

char*
Curl_sspi_status_msg(SECURITY_STATUS status)
{
  LPSTR format_msg = NULL;
  char *status_msg = NULL, *status_const = NULL;
  int status_len = 0;

  status_len = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                             FORMAT_MESSAGE_FROM_SYSTEM |
                             FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, status, 0, (LPTSTR)&format_msg, 0, NULL);

  if(status_len > 0 && format_msg) {
    status_msg = strdup(format_msg);
    LocalFree(format_msg);

    /* remove trailing CR+LF */
    if(status_len > 0) {
      if(status_msg[status_len-1] == '\n') {
        status_msg[status_len-1] = '\0';
        if(status_len > 1) {
          if(status_msg[status_len-2] == '\r') {
            status_msg[status_len-2] = '\0';
          }
        }
      }
    }
  }

  status_const = Curl_sspi_status(status);
  if(status_msg) {
    status_msg = curl_maprintf("%s [%s]", status_msg, status_const);
    free(status_const);
  }
  else {
    status_msg = status_const;
  }

  return status_msg;
}

#endif /* USE_WINDOWS_SSPI */
