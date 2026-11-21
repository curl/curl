#ifndef MOCK_SCHANNEL_H
#define MOCK_SCHANNEL_H
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

#include "windows.h"
#include "wincrypt.h"
#include "subauth.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Unified Security Protocol Provider Name
 */
#define UNISP_NAME_A "Microsoft Unified Security Protocol Provider"
#define UNISP_NAME_W L"Microsoft Unified Security Protocol Provider"

#ifdef UNICODE
#define UNISP_NAME UNISP_NAME_W
#else
#define UNISP_NAME UNISP_NAME_A
#endif

#define SCHANNEL_NAME_A  "Schannel-mockup"
#define SCHANNEL_NAME_W  L"Schannel-mockup"

#ifdef UNICODE
#define SCHANNEL_NAME    SCHANNEL_NAME_W
#else
#define SCHANNEL_NAME    SCHANNEL_NAME_A
#endif

/*
 * Control Tokens
 */
#define SCHANNEL_SHUTDOWN    0x00000001
#define SCHANNEL_RENEGOTIATE 0x00000002

/*
 * Protocol Flags
 */
#define SP_PROT_PCT1_SERVER  0x00000001
#define SP_PROT_PCT1_CLIENT  0x00000002
#define SP_PROT_PCT1         (SP_PROT_PCT1_SERVER | SP_PROT_PCT1_CLIENT)

#define SP_PROT_SSL2_SERVER  0x00000004
#define SP_PROT_SSL2_CLIENT  0x00000008
#define SP_PROT_SSL2         (SP_PROT_SSL2_SERVER | SP_PROT_SSL2_CLIENT)

#define SP_PROT_SSL3_SERVER  0x00000010
#define SP_PROT_SSL3_CLIENT  0x00000020
#define SP_PROT_SSL3         (SP_PROT_SSL3_SERVER | SP_PROT_SSL3_CLIENT)

#define SP_PROT_TLS1_0_SERVER 0x00000040
#define SP_PROT_TLS1_0_CLIENT 0x00000080
#define SP_PROT_TLS1_0        (SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_0_CLIENT)

#define SP_PROT_TLS1_1_SERVER  0x00000100
#define SP_PROT_TLS1_1_CLIENT  0x00000200
#define SP_PROT_TLS1_1         (SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_1_CLIENT)

#define SP_PROT_TLS1_2_SERVER  0x00000400
#define SP_PROT_TLS1_2_CLIENT  0x00000800
#define SP_PROT_TLS1_2         (SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_2_CLIENT)

#define SP_PROT_TLS1_3_SERVER  0x00001000
#define SP_PROT_TLS1_3_CLIENT  0x00002000
#define SP_PROT_TLS1_3         (SP_PROT_TLS1_3_SERVER | SP_PROT_TLS1_3_CLIENT)

#define SP_PROT_TLS1_CLIENT (SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT | \
                             SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT)
#define SP_PROT_TLS1_SERVER (SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER | \
                             SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER)
#define SP_PROT_TLS1        (SP_PROT_TLS1_CLIENT | SP_PROT_TLS1_SERVER)

/*
 * Credential Flags
 */
#define SCH_CRED_NO_SYSTEM_MAPPER                    0x00000002
#define SCH_CRED_NO_SERVERNAME_CHECK                 0x00000004
#define SCH_CRED_MANUAL_CRED_VALIDATION              0x00000008
#define SCH_CRED_NO_DEFAULT_CREDS                    0x00000010
#define SCH_CRED_AUTO_CRED_VALIDATION                0x00000020
#define SCH_CRED_USE_DEFAULT_CREDS                   0x00000040
#define SCH_CRED_REVOCATION_CHECK_CHAIN              0x00000200
#define SCH_CRED_REVOCATION_CHECK_CACHE_ONLY         0x00000400
#define SCH_CRED_REVOCATION_CHECK_CHAIN_CACHE_ONLY   0x00000800
#define SCH_CRED_IGNORE_NO_REVOCATION_CHECK          0x00000800
#define SCH_CRED_IGNORE_REVOCATION_OFFLINE           0x00001000
#define SCH_USE_STRONG_CRYPTO                        0x00400000

/*
 * Legacy SCHANNEL_CRED structure
 */
#define SCHANNEL_CRED_VERSION                   0x00000004

struct _HMAPPER;

typedef struct _SCHANNEL_CRED {
  DWORD dwVersion;
  DWORD cCreds;
  PCCERT_CONTEXT *paCred;
  HCERTSTORE hRootStore;
  DWORD cMappers;
  struct _HMAPPER **aphMappers;
  DWORD cSupportedAlgs;
  ALG_ID *palgSupportedAlgs;
  DWORD grbitEnabledProtocols;
  DWORD dwMinimumCipherStrength;
  DWORD dwMaximumCipherStrength;
  DWORD dwSessionLifespan;
  DWORD dwFlags;
  DWORD dwCredFormat;
} SCHANNEL_CRED, *PSCHANNEL_CRED;

/*
 * Modern SCH_CREDENTIALS structure (TLS 1.3 support)
 */
#ifndef SCH_CREDENTIALS_VERSION
#define SCH_CREDENTIALS_VERSION                 0x00000005

typedef enum _eTlsAlgorithmUsage {
  TlsParametersCngAlgUsageKeyExchange,
  TlsParametersCngAlgUsageSignature,
  TlsParametersCngAlgUsageCipher,
  TlsParametersCngAlgUsageDigest,
  TlsParametersCngAlgUsageCertSig
} eTlsAlgorithmUsage;

typedef struct _CRYPTO_SETTINGS {
  eTlsAlgorithmUsage eAlgorithmUsage;
  UNICODE_STRING strCngAlgId;
  DWORD cChainingModes;
  PUNICODE_STRING rgstrChainingModes;
  DWORD dwMinBitLength;
  DWORD dwMaxBitLength;
} CRYPTO_SETTINGS, *PCRYPTO_SETTINGS;

typedef struct _TLS_PARAMETERS {
  DWORD cAlpnIds;
  PUNICODE_STRING rgstrAlpnIds;
  DWORD grbitDisabledProtocols;
  DWORD cDisabledCrypto;
  PCRYPTO_SETTINGS pDisabledCrypto;
  DWORD dwFlags;
} TLS_PARAMETERS, *PTLS_PARAMETERS;

typedef struct _SCH_CREDENTIALS {
  DWORD dwVersion;
  DWORD dwCredFormat;
  DWORD cCreds;
  PCCERT_CONTEXT *paCred;
  HCERTSTORE hRootStore;
  DWORD cMappers;
  struct _HMAPPER **aphMappers;
  DWORD dwSessionLifespan;
  DWORD dwFlags;
  DWORD cTlsParameters;
  PTLS_PARAMETERS pTlsParameters;
} SCH_CREDENTIALS, *PSCH_CREDENTIALS;

#endif /* !SCH_CREDENTIALS_VERSION */

/* Compatibility prototype for non-Win32 builds */
#ifdef CURLINC_CURL_H
CURLcode curlx_win32_random(unsigned char *entropy, size_t length);
#endif

#ifdef __cplusplus
}
#endif

#endif /* MOCK_SCHANNEL_H */
