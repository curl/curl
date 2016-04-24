/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef USE_WINDOWS_SSPI

#include <curl/curl.h>
#include "curl_sspi.h"
#include "curl_multibyte.h"
#include "warnless.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/* We use our own typedef here since some headers might lack these */
typedef PSecurityFunctionTable (APIENTRY *INITSECURITYINTERFACE_FN)(VOID);

/* See definition of SECURITY_ENTRYPOINT in sspi.h */
#ifdef UNICODE
#  ifdef _WIN32_WCE
#    define SECURITYENTRYPOINT L"InitSecurityInterfaceW"
#  else
#    define SECURITYENTRYPOINT "InitSecurityInterfaceW"
#  endif
#else
#  define SECURITYENTRYPOINT "InitSecurityInterfaceA"
#endif

/* Handle of security.dll or secur32.dll, depending on Windows version */
HMODULE s_hSecDll = NULL;

/* Pointer to SSPI dispatch table */
PSecurityFunctionTable s_pSecFn = NULL;

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
CURLcode Curl_sspi_global_init(void)
{
  bool securityDll = FALSE;
  INITSECURITYINTERFACE_FN pInitSecurityInterface;

  /* If security interface is not yet initialized try to do this */
  if(!s_hSecDll) {
    /* Security Service Provider Interface (SSPI) functions are located in
     * security.dll on WinNT 4.0 and in secur32.dll on Win9x. Win2K and XP
     * have both these DLLs (security.dll forwards calls to secur32.dll) */
    DWORD majorVersion = 4;
    DWORD platformId = VER_PLATFORM_WIN32_NT;

#if !defined(_WIN32_WINNT) || !defined(_WIN32_WINNT_WIN2K) || \
    (_WIN32_WINNT < _WIN32_WINNT_WIN2K)
    OSVERSIONINFO osver;

    memset(&osver, 0, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);

    /* Find out Windows version */
    if(!GetVersionEx(&osver))
      return CURLE_FAILED_INIT;

    /* Verify the major version number == 4 and platform id == WIN_NT */
    if(osver.dwMajorVersion == majorVersion &&
       osver.dwPlatformId == platformId)
      securityDll = TRUE;
#else
    ULONGLONG cm;
    OSVERSIONINFOEX osver;

    memset(&osver, 0, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);
    osver.dwMajorVersion = majorVersion;
    osver.dwPlatformId = platformId;

    cm = VerSetConditionMask(0, VER_MAJORVERSION, VER_EQUAL);
    cm = VerSetConditionMask(cm, VER_MINORVERSION, VER_GREATER_EQUAL);
    cm = VerSetConditionMask(cm, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
    cm = VerSetConditionMask(cm, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL);
    cm = VerSetConditionMask(cm, VER_PLATFORMID, VER_EQUAL);

    /* Verify the major version number == 4 and platform id == WIN_NT */
    if(VerifyVersionInfo(&osver, (VER_MAJORVERSION | VER_MINORVERSION |
                                  VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR |
                                  VER_PLATFORMID),
                         cm))
      securityDll = TRUE;
#endif

    /* Load SSPI dll into the address space of the calling process */
    if(securityDll)
      s_hSecDll = LoadLibrary(TEXT("security.dll"));
    else
      s_hSecDll = LoadLibrary(TEXT("secur32.dll"));
    if(!s_hSecDll)
      return CURLE_FAILED_INIT;

    /* Get address of the InitSecurityInterfaceA function from the SSPI dll */
    pInitSecurityInterface = (INITSECURITYINTERFACE_FN)
      GetProcAddress(s_hSecDll, SECURITYENTRYPOINT);
    if(!pInitSecurityInterface)
      return CURLE_FAILED_INIT;

    /* Get pointer to Security Service Provider Interface dispatch table */
    s_pSecFn = pInitSecurityInterface();
    if(!s_pSecFn)
      return CURLE_FAILED_INIT;
  }

  return CURLE_OK;
}

/*
 * Curl_sspi_global_cleanup()
 *
 * This deinitializes the Security Service Provider Interface from libcurl.
 */

void Curl_sspi_global_cleanup(void)
{
  if(s_hSecDll) {
    FreeLibrary(s_hSecDll);
    s_hSecDll = NULL;
    s_pSecFn = NULL;
  }
}

/*
 * Curl_create_sspi_identity()
 *
 * This is used to populate a SSPI identity structure based on the supplied
 * username and password.
 *
 * Parameters:
 *
 * userp    [in]     - The user name in the format User or Domain\User.
 * passdwp  [in]     - The user's password.
 * identity [in/out] - The identity structure.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_create_sspi_identity(const char *userp, const char *passwdp,
                                   SEC_WINNT_AUTH_IDENTITY *identity)
{
  xcharp_u useranddomain;
  xcharp_u user, dup_user;
  xcharp_u domain, dup_domain;
  xcharp_u passwd, dup_passwd;
  size_t domlen = 0;

  domain.const_tchar_ptr = TEXT("");

  /* Initialize the identity */
  memset(identity, 0, sizeof(*identity));

  useranddomain.tchar_ptr = Curl_convert_UTF8_to_tchar((char *)userp);
  if(!useranddomain.tchar_ptr)
    return CURLE_OUT_OF_MEMORY;

  user.const_tchar_ptr = _tcschr(useranddomain.const_tchar_ptr, TEXT('\\'));
  if(!user.const_tchar_ptr)
    user.const_tchar_ptr = _tcschr(useranddomain.const_tchar_ptr, TEXT('/'));

  if(user.tchar_ptr) {
    domain.tchar_ptr = useranddomain.tchar_ptr;
    domlen = user.tchar_ptr - useranddomain.tchar_ptr;
    user.tchar_ptr++;
  }
  else {
    user.tchar_ptr = useranddomain.tchar_ptr;
    domain.const_tchar_ptr = TEXT("");
    domlen = 0;
  }

  /* Setup the identity's user and length */
  dup_user.tchar_ptr = _tcsdup(user.tchar_ptr);
  if(!dup_user.tchar_ptr) {
    Curl_unicodefree(useranddomain.tchar_ptr);
    return CURLE_OUT_OF_MEMORY;
  }
  identity->User = dup_user.tbyte_ptr;
  identity->UserLength = curlx_uztoul(_tcslen(dup_user.tchar_ptr));
  dup_user.tchar_ptr = NULL;

  /* Setup the identity's domain and length */
  dup_domain.tchar_ptr = malloc(sizeof(TCHAR) * (domlen + 1));
  if(!dup_domain.tchar_ptr) {
    Curl_unicodefree(useranddomain.tchar_ptr);
    return CURLE_OUT_OF_MEMORY;
  }
  _tcsncpy(dup_domain.tchar_ptr, domain.tchar_ptr, domlen);
  *(dup_domain.tchar_ptr + domlen) = TEXT('\0');
  identity->Domain = dup_domain.tbyte_ptr;
  identity->DomainLength = curlx_uztoul(domlen);
  dup_domain.tchar_ptr = NULL;

  Curl_unicodefree(useranddomain.tchar_ptr);

  /* Setup the identity's password and length */
  passwd.tchar_ptr = Curl_convert_UTF8_to_tchar((char *)passwdp);
  if(!passwd.tchar_ptr)
    return CURLE_OUT_OF_MEMORY;
  dup_passwd.tchar_ptr = _tcsdup(passwd.tchar_ptr);
  if(!dup_passwd.tchar_ptr) {
    Curl_unicodefree(passwd.tchar_ptr);
    return CURLE_OUT_OF_MEMORY;
  }
  identity->Password = dup_passwd.tbyte_ptr;
  identity->PasswordLength = curlx_uztoul(_tcslen(dup_passwd.tchar_ptr));
  dup_passwd.tchar_ptr = NULL;

  Curl_unicodefree(passwd.tchar_ptr);

  /* Setup the identity's flags */
  identity->Flags = SECFLAG_WINNT_AUTH_IDENTITY;

  return CURLE_OK;
}

void Curl_sspi_free_identity(SEC_WINNT_AUTH_IDENTITY *identity)
{
  if(identity) {
    Curl_safefree(identity->User);
    Curl_safefree(identity->Password);
    Curl_safefree(identity->Domain);
  }
}

#endif /* USE_WINDOWS_SSPI */
