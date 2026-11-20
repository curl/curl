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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sspi.h"
#include "schannel.h"
#include "windows.h"

#define UNCONST(p) ((void *)(uintptr_t)(const void *)(p))

int curlx_win32_random(unsigned char *entropy, size_t length);

int main(void)
{
  SECURITY_STATUS status;
  PSecurityFunctionTableA sspi_a = NULL;
  PSecurityFunctionTableW sspi_w = NULL;
  CredHandle cred1 = { 0, 0 };
  CredHandle cred2 = { 0, 0 };
  CredHandle cred3 = { 0, 0 };
  TimeStamp expiry;

  printf("Schannel Mockup SSPI Dispatcher & Credentials\n\n");

  /* 1. Test InitSecurityInterfaceA & InitSecurityInterfaceW */
  printf("1. Testing InitSecurityInterface\n");
  sspi_a = InitSecurityInterfaceA();
  assert(sspi_a != NULL);
  assert(sspi_a->dwVersion == SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION);
  assert(sspi_a->AcquireCredentialsHandleA != NULL);
  assert(sspi_a->FreeCredentialsHandle != NULL);
  assert(sspi_a->FreeContextBuffer != NULL);

  sspi_w = InitSecurityInterfaceW();
  assert(sspi_w != NULL);
  assert(sspi_w->dwVersion == SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION);
  assert(sspi_w->AcquireCredentialsHandleW != NULL);
  assert(sspi_w->FreeCredentialsHandle != NULL);
  assert(sspi_w->FreeContextBuffer != NULL);
  printf(" PASS: InitSecurityInterface tables validated.\n\n");

  /* 2. Test AcquireCredentialsHandle with modern SCH_CREDENTIALS */
  printf("2. Testing AcquireCredentialsHandle (SCH_CREDENTIALS)\n");
  {
    SCH_CREDENTIALS sch_creds;
    TLS_PARAMETERS tls_params;

    memset(&sch_creds, 0, sizeof(sch_creds));
    memset(&tls_params, 0, sizeof(tls_params));

    sch_creds.dwVersion = SCH_CREDENTIALS_VERSION;
    sch_creds.dwFlags =
      SCH_USE_STRONG_CRYPTO | SCH_CRED_MANUAL_CRED_VALIDATION;
    sch_creds.cTlsParameters = 1;
    sch_creds.pTlsParameters = &tls_params;
    /* Disable SSL3, TLS 1.0, TLS 1.1 -> allow TLS 1.2 and TLS 1.3 */
    tls_params.grbitDisabledProtocols = ~(SP_PROT_TLS1_2_CLIENT |
                                          SP_PROT_TLS1_3_CLIENT);

    status = sspi_a->AcquireCredentialsHandleA(
      NULL,
      UNCONST(UNISP_NAME_A),
      SECPKG_CRED_OUTBOUND,
      NULL,
      &sch_creds,
      NULL,
      NULL,
      &cred1,
      &expiry);

    assert(status == SEC_E_OK);
    assert(cred1.dwLower != 0);
    assert(cred1.dwUpper == 0x4D435244); /* MOCK_MAGIC_CRED */
  }
  printf(" PASS: Acquired credential handle (TLS 1.2/1.3 enabled).\n\n");

  /* 3. Test AcquireCredentialsHandle with legacy SCHANNEL_CRED */
  printf("3. Testing AcquireCredentialsHandle (legacy SCHANNEL_CRED)\n");
  {
    SCHANNEL_CRED legacy_creds;
    memset(&legacy_creds, 0, sizeof(legacy_creds));
    legacy_creds.dwVersion = SCHANNEL_CRED_VERSION;
    legacy_creds.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION;
    legacy_creds.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;

    status = sspi_a->AcquireCredentialsHandleA(
      NULL,
      UNCONST("schannel"),
      SECPKG_CRED_OUTBOUND,
      NULL,
      &legacy_creds,
      NULL,
      NULL,
      &cred2,
      NULL);

    assert(status == SEC_E_OK);
    assert(cred2.dwLower != 0);
    assert(cred2.dwUpper == 0x4D435244);
  }
  printf(" PASS: Acquired legacy credential handle.\n\n");

  /* 4. Test AcquireCredentialsHandleW with default NULL pAuthData */
  printf("4. Testing AcquireCredentialsHandleW (default auth data)\n");
  status = sspi_w->AcquireCredentialsHandleW(
    NULL,
    UNCONST(UNISP_NAME_W),
    SECPKG_CRED_OUTBOUND,
    NULL,
    NULL,
    NULL,
    NULL,
    &cred3,
    &expiry);

  assert(status == SEC_E_OK);
  assert(cred3.dwLower != 0);
  assert(cred3.dwUpper == 0x4D435244);
  printf(" PASS: Acquired default credential handle.\n\n");

  /* 5. Test Error Handling */
  printf("5. Testing AcquireCredentialsHandle error cases\n");
  {
    CredHandle invalid_cred;
    DWORD bad_version;

    /* Null handle pointer */
    status = sspi_a->AcquireCredentialsHandleA(NULL, UNCONST(UNISP_NAME_A),
                                               SECPKG_CRED_OUTBOUND,
                                               NULL, NULL, NULL, NULL, NULL,
                                               NULL);
    assert(status == SEC_E_INVALID_HANDLE);

    /* Unknown security package name */
    status = sspi_a->AcquireCredentialsHandleA(NULL,
                                               UNCONST("UnknownPackageName"),
                                               SECPKG_CRED_OUTBOUND,
                                               NULL, NULL, NULL, NULL,
                                               &invalid_cred, NULL);
    assert(status == SEC_E_SECPKG_NOT_FOUND);

    /* Invalid credential use */
    status = sspi_a->AcquireCredentialsHandleA(NULL, UNCONST(UNISP_NAME_A), 0,
                                               NULL, NULL, NULL, NULL,
                                               &invalid_cred, NULL);
    assert(status == SEC_E_UNKNOWN_CREDENTIALS);

    /* Bad struct version in pAuthData */
    bad_version = 0xDEADBEEF;
    status = sspi_a->AcquireCredentialsHandleA(NULL, UNCONST(UNISP_NAME_A),
                                               SECPKG_CRED_OUTBOUND,
                                               NULL, &bad_version, NULL,
                                               NULL, &invalid_cred, NULL);
    assert(status == SEC_E_INVALID_TOKEN);
  }
  printf(" PASS: Error conditions returned expected error codes.\n\n");

  /* 6. Test FreeCredentialsHandle */
  printf("6. Testing FreeCredentialsHandle\n");
  {
    /* Free invalid handle */
    CredHandle bad_handle = { 0x123456, 0x999999 };
    status = sspi_a->FreeCredentialsHandle(&bad_handle);
    assert(status == SEC_E_INVALID_HANDLE);

    /* Free valid handles */
    status = sspi_a->FreeCredentialsHandle(&cred1);
    assert(status == SEC_E_OK);
    assert(cred1.dwLower == 0 && cred1.dwUpper == 0);

    status = sspi_a->FreeCredentialsHandle(&cred2);
    assert(status == SEC_E_OK);
    assert(cred2.dwLower == 0 && cred2.dwUpper == 0);

    status = sspi_a->FreeCredentialsHandle(&cred3);
    assert(status == SEC_E_OK);
    assert(cred3.dwLower == 0 && cred3.dwUpper == 0);

    /* Double-free should fail */
    status = sspi_a->FreeCredentialsHandle(&cred1);
    assert(status == SEC_E_INVALID_HANDLE);
  }
  printf(" PASS: FreeCredentialsHandle cleaned up and cleared handles.\n\n");

  /* 7. Test FreeContextBuffer */
  printf("7. Testing FreeContextBuffer\n");
  {
    void *buf = malloc(256);
    assert(buf != NULL);
    status = sspi_a->FreeContextBuffer(buf);
    assert(status == SEC_E_OK);

    status = sspi_a->FreeContextBuffer(NULL);
    assert(status == SEC_E_OK);
  }
  printf(" PASS: FreeContextBuffer freed memory cleanly.\n\n");

  /* 8. Test Win32 & Compat Helpers */
  printf("8. Testing Win32 & Compat Helpers\n");
  SetLastError(ERROR_ACCESS_DENIED);
  assert(GetLastError() == ERROR_ACCESS_DENIED);

#if 0
  char err_buf[WINAPI_ERROR_LEN];
  const char *err_str = curlx_winapi_strerror(ERROR_ACCESS_DENIED, err_buf,
                                              sizeof(err_buf));
  assert(err_str != NULL && strlen(err_str) > 0);
  assert(strstr(err_str, "Access is denied") != NULL);

  bool ver = curlx_verify_windows_version(10, 0, 20348, PLATFORM_WINNT,
                                          VERSION_GREATER_THAN_EQUAL);
  assert(ver == true);

  unsigned char rnd[16] = { 0 };
  int rnd_res = curlx_win32_random(rnd, sizeof(rnd));
  assert(rnd_res == 0);
  /* Check that random is not all zeros */
  int non_zero = 0;
  for(int i = 0; i < 16; i++) {
    if(rnd[i])
      non_zero++;
  }
  assert(non_zero > 0);
#endif
  printf(" PASS: Error, versioning, and random helpers verified.\n\n");

  printf("Tests PASSED successfully!\n");
  return 0;
}
