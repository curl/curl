#ifndef MOCK_WINCRYPT_H
#define MOCK_WINCRYPT_H
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

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Algorithm IDs
 */
typedef unsigned int ALG_ID;

#define ALG_CLASS_ANY                   (0)
#define ALG_CLASS_SIGNATURE             (1 << 13)
#define ALG_CLASS_MSG_ENCRYPT           (2 << 13)
#define ALG_CLASS_DATA_ENCRYPT          (3 << 13)
#define ALG_CLASS_HASH                  (4 << 13)
#define ALG_CLASS_KEY_EXCHANGE          (5 << 13)

#define ALG_TYPE_ANY                    (0)
#define ALG_TYPE_DSS                    (1 << 9)
#define ALG_TYPE_RSA                    (2 << 9)
#define ALG_TYPE_BLOCK                  (3 << 9)
#define ALG_TYPE_STREAM                 (4 << 9)
#define ALG_TYPE_DH                     (5 << 9)
#define ALG_TYPE_SECURECHANNEL          (6 << 9)

#define CALG_MD2                   (ALG_CLASS_HASH | ALG_TYPE_ANY | 1)
#define CALG_MD4                   (ALG_CLASS_HASH | ALG_TYPE_ANY | 2)
#define CALG_MD5                   (ALG_CLASS_HASH | ALG_TYPE_ANY | 3)
#define CALG_SHA                   (ALG_CLASS_HASH | ALG_TYPE_ANY | 4)
#define CALG_SHA1                  (ALG_CLASS_HASH | ALG_TYPE_ANY | 4)
#define CALG_MAC                   (ALG_CLASS_HASH | ALG_TYPE_ANY | 5)
#define CALG_RSA_SIGN              (ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | 0)
#define CALG_DSS_SIGN              (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | 0)
#define CALG_NO_SIGN               (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | 0)
#define CALG_RSA_KEYX              (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | 0)
#define CALG_DES                  (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 1)
#define CALG_3DES_112             (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 2)
#define CALG_3DES                 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 3)
#define CALG_DESX                 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 4)
#define CALG_RC2                  (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 2)
#define CALG_RC4                 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | 1)
#define CALG_SEAL                (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | 2)
#define CALG_DH_SF                 (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | 1)
#define CALG_DH_EPHEM              (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | 2)
#define CALG_AGREEDKEY_ANY         (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | 3)
#define CALG_HUGHES_MD5            (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 3)
#define CALG_SKIPJACK            (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 10)
#define CALG_TEK                 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 11)
#define CALG_CYLINK_MEK          (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 12)
#define CALG_SSL3_SHAMD5           (ALG_CLASS_HASH | ALG_TYPE_ANY | 8)
#define CALG_SSL3_MASTER           (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 1)
#define CALG_SCHANNEL_MASTER_HASH  (ALG_CLASS_HASH | ALG_TYPE_ANY | 2)
#define CALG_SCHANNEL_MAC_KEY      (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 3)
#define CALG_SCHANNEL_ENC_KEY      (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 4)
#define CALG_PCT1_MASTER           (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 5)
#define CALG_SSL2_MASTER           (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 6)
#define CALG_TLS1_MASTER           (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 7)
#define CALG_RC5                 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 13)
#define CALG_HMAC                  (ALG_CLASS_HASH | ALG_TYPE_ANY | 9)
#define CALG_TLS1PRF               (ALG_CLASS_HASH | ALG_TYPE_ANY | 10)
#define CALG_HASH_REPLACE_OWF      (ALG_CLASS_HASH | ALG_TYPE_ANY | 11)
#define CALG_AES_128             (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 14)
#define CALG_AES_192             (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 15)
#define CALG_AES_256             (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 16)
#define CALG_AES                 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 17)
#define CALG_SHA_256               (ALG_CLASS_HASH | ALG_TYPE_ANY | 12)
#define CALG_SHA_384               (ALG_CLASS_HASH | ALG_TYPE_ANY | 13)
#define CALG_SHA_512               (ALG_CLASS_HASH | ALG_TYPE_ANY | 14)
#define CALG_ECDH                  (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | 5)
#define CALG_ECDH_EPHEM            (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | 6)
#define CALG_ECMQV                 (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 1)
#define CALG_ECDSA                 (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | 3)

/* Provider Types */
#define PROV_RSA_FULL                   1
#define PROV_RSA_AES                    24

/* CryptAcquireContext flags */
#define CRYPT_VERIFYCONTEXT             0xF0000000
#define CRYPT_NEWKEYSET                 0x00000008
#define CRYPT_DELETEKEYSET              0x00000010
#define CRYPT_MACHINE_KEYSET            0x00000020
#define CRYPT_SILENT                    0x00000040

/* Hash parameters */
#define HP_ALGID                        0x0001
#define HP_HASHVAL                      0x0002
#define HP_HASHSIZE                     0x0004

/* Random generation */
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)

NTSTATUS WINAPI BCryptGenRandom(void *hAlgorithm, BYTE *pbBuffer,
                                ULONG cbBuffer, ULONG dwFlags);

/*
 * Cryptographic Hashing Functions
 */
BOOL WINAPI CryptAcquireContextA(HCRYPTPROV *phProv, LPCSTR szContainer,
                                LPCSTR szProvider, DWORD dwProvType,
                                DWORD dwFlags);
BOOL WINAPI CryptAcquireContextW(HCRYPTPROV *phProv, LPCWSTR szContainer,
                                LPCWSTR szProvider, DWORD dwProvType,
                                DWORD dwFlags);
BOOL WINAPI CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
BOOL WINAPI CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTPROV hKey,
                            DWORD dwFlags, HCRYPTHASH *phHash);
BOOL WINAPI CryptDestroyHash(HCRYPTHASH hHash);
BOOL WINAPI CryptHashData(HCRYPTHASH hHash, const BYTE *pbData,
                          DWORD dwDataLen, DWORD dwFlags);
BOOL WINAPI CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData,
                              DWORD *pdwDataLen, DWORD dwFlags);

#ifdef UNICODE
#define CryptAcquireContext CryptAcquireContextW
#else
#define CryptAcquireContext CryptAcquireContextA
#endif

/*
 * Certificate Encodings & Blobs
 */
#define X509_ASN_ENCODING               0x00000001
#define PKCS_7_ASN_ENCODING             0x00010000

typedef struct _CRYPTOAPI_BLOB {
  DWORD cbData;
  BYTE *pbData;
} DATA_BLOB, *PDATA_BLOB,
  CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB,
  CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB,
  CERT_BLOB, *PCERT_BLOB,
  CERT_NAME_BLOB, *PCERT_NAME_BLOB;

/*
 * Certificate Structures
 */
typedef struct _CERT_EXTENSION {
  LPSTR pszObjId;
  BOOL fCritical;
  CRYPT_DATA_BLOB Value;
} CERT_EXTENSION, *PCERT_EXTENSION;

typedef struct _CERT_INFO {
  DWORD dwVersion;
  CRYPT_DATA_BLOB SerialNumber;
  void *SignatureAlgorithm;
  CERT_NAME_BLOB Issuer;
  void *NotBefore;
  void *NotAfter;
  CERT_NAME_BLOB Subject;
  void *SubjectPublicKeyInfo;
  CRYPT_DATA_BLOB IssuerUniqueId;
  CRYPT_DATA_BLOB SubjectUniqueId;
  DWORD cExtension;
  PCERT_EXTENSION rgExtension;
} CERT_INFO, *PCERT_INFO;

typedef void *HCERTSTORE;

typedef struct _CERT_CONTEXT {
  DWORD dwCertEncodingType;
  BYTE *pbCertEncoded;
  DWORD cbCertEncoded;
  PCERT_INFO pCertInfo;
  HCERTSTORE hCertStore;
} CERT_CONTEXT, *PCERT_CONTEXT;
typedef const CERT_CONTEXT *PCCERT_CONTEXT;

/*
 * Certificate Store Providers & Flags
 */
#define CERT_STORE_PROV_MEMORY          ((LPCSTR)(size_t)2)
#define CERT_STORE_PROV_SYSTEM_A        ((LPCSTR)(size_t)9)
#define CERT_STORE_PROV_SYSTEM_W        ((LPCSTR)(size_t)10)

#define CERT_STORE_CREATE_NEW_FLAG      0x00002000
#define CERT_STORE_OPEN_EXISTING_FLAG   0x00004000
#define CERT_STORE_ADD_ALWAYS           4

#define CERT_FIND_ANY                   0
#define CERT_FIND_HASH                  0x10000
#define CERT_FIND_HAS_PRIVATE_KEY       0x150000

#define CERT_SYSTEM_STORE_CURRENT_USER               0x00010000
#define CERT_SYSTEM_STORE_LOCAL_MACHINE              0x00020000
#define CERT_SYSTEM_STORE_CURRENT_SERVICE            0x00040000
#define CERT_SYSTEM_STORE_SERVICES                   0x00050000
#define CERT_SYSTEM_STORE_USERS                      0x00060000
#define CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY  0x00070000
#define CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY 0x00080000
#define CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE   0x00090000

#define PKCS12_NO_PERSIST_KEY           0x00008000

#define CERT_QUERY_OBJECT_BLOB          0x00000002
#define CERT_QUERY_CONTENT_FLAG_CERT    (1 << 1)
#define CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED (1 << 1)

#define CRYPT_STRING_HEX                0x00000004

/*
 * Store & Certificate Functions
 */
HCERTSTORE WINAPI CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType,
                                HCRYPTPROV hCryptProv, DWORD dwFlags,
                                const void *pvPara);
BOOL WINAPI CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
BOOL WINAPI CertAddCertificateContextToStore(HCERTSTORE hCertStore,
                                             PCCERT_CONTEXT pCertContext,
                                             DWORD dwAddDisposition,
                                             PCCERT_CONTEXT *ppStoreContext);
PCCERT_CONTEXT WINAPI
CertEnumCertificatesInStore(HCERTSTORE hCertStore,
                            PCCERT_CONTEXT pPrevCertContext);
PCCERT_CONTEXT WINAPI
CertFindCertificateInStore(HCERTSTORE hCertStore,
                           DWORD dwCertEncodingType,
                           DWORD dwFindFlags,
                           DWORD dwFindType,
                           const void *pvFindPara,
                           PCCERT_CONTEXT pPrevCertContext);
BOOL WINAPI CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
PCCERT_CONTEXT WINAPI
CertDuplicateCertificateContext(PCCERT_CONTEXT pCertContext);

HCERTSTORE WINAPI PFXImportCertStore(CRYPT_DATA_BLOB *pPFX,
                                    LPCWSTR szPassword, DWORD dwFlags);

BOOL WINAPI CryptStringToBinaryA(LPCSTR pszString, DWORD cchString,
                                DWORD dwFlags, BYTE *pbBinary,
                                DWORD *pcbBinary, DWORD *pdwSkip,
                                DWORD *pdwFlags);
BOOL WINAPI CryptStringToBinaryW(LPCWSTR pszString, DWORD cchString,
                                DWORD dwFlags, BYTE *pbBinary,
                                DWORD *pcbBinary, DWORD *pdwSkip,
                                DWORD *pdwFlags);

BOOL WINAPI CryptQueryObject(DWORD dwObjectType, const void *pvObject,
                             DWORD dwExpectedContentTypeFlags,
                             DWORD dwExpectedFormatTypeFlags,
                             DWORD dwFlags, DWORD *pdwMsgAndCertEncodingType,
                             DWORD *pdwContentType, DWORD *pdwFormatType,
                             HCERTSTORE *phCertStore, void **phMsg,
                             const void **ppvContext);

PCERT_EXTENSION WINAPI CertFindExtension(LPCSTR pszObjId, DWORD cExtensions,
                                         CERT_EXTENSION *rgExtensions);

/*
 * Name String / Hostname Verification
 */
#define CERT_NAME_EMAIL_TYPE            1
#define CERT_NAME_RDN_TYPE              2
#define CERT_NAME_ATTR_TYPE             3
#define CERT_NAME_SIMPLE_DISPLAY_TYPE   4
#define CERT_NAME_FRIENDLY_DISPLAY_TYPE 5
#define CERT_NAME_DNS_TYPE              6
#define CERT_NAME_URL_TYPE              7
#define CERT_NAME_UPN_TYPE              8

#define CERT_NAME_DISABLE_IE4_UTF8_FLAG 0x00080000
#define CERT_NAME_SEARCH_ALL_NAMES_FLAG 0x00000002

DWORD WINAPI CertGetNameStringA(PCCERT_CONTEXT pCertContext, DWORD dwType,
                               DWORD dwFlags, void *pvTypePara,
                               LPSTR pszNameString, DWORD cchNameString);
DWORD WINAPI CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType,
                               DWORD dwFlags, void *pvTypePara,
                               LPWSTR pszNameString, DWORD cchNameString);

#ifdef UNICODE
#define CertGetNameString CertGetNameStringW
#define CryptStringToBinary CryptStringToBinaryW
#else
#define CertGetNameString CertGetNameStringA
#define CryptStringToBinary CryptStringToBinaryA
#endif

/* Standard OIDs */
#define szOID_SUBJECT_ALT_NAME          "2.5.29.7"
#define szOID_SUBJECT_ALT_NAME2         "2.5.29.17"
#define szOID_PKIX_KP_SERVER_AUTH       "1.3.6.1.5.5.7.3.1"

/*
 * Alternate Names
 */
#define CERT_ALT_NAME_OTHER_NAME        1
#define CERT_ALT_NAME_RFC822_NAME       2
#define CERT_ALT_NAME_DNS_NAME          3
#define CERT_ALT_NAME_X400_ADDRESS      4
#define CERT_ALT_NAME_DIRECTORY_NAME    5
#define CERT_ALT_NAME_EDI_PARTY_NAME    6
#define CERT_ALT_NAME_URL               7
#define CERT_ALT_NAME_IP_ADDRESS        8
#define CERT_ALT_NAME_REGISTERED_ID     9

typedef struct _CERT_ALT_NAME_ENTRY {
  DWORD dwAltNameChoice;
  __extension__ union {
    void *pOtherName;
    LPWSTR pwszRfc822Name;
    LPWSTR pwszDNSName;
    void *DirectoryName;
    LPWSTR pwszURL;
    CRYPT_DATA_BLOB IPAddress;
    LPSTR pszRegisteredID;
  };
} CERT_ALT_NAME_ENTRY, *PCERT_ALT_NAME_ENTRY;

typedef struct _CERT_ALT_NAME_INFO {
  DWORD cAltEntry;
  PCERT_ALT_NAME_ENTRY rgAltEntry;
} CERT_ALT_NAME_INFO, *PCERT_ALT_NAME_INFO;

#define CRYPT_DECODE_ALLOC_FLAG         0x8000
#define CRYPT_DECODE_NOCOPY_FLAG        0x1

typedef void *(WINAPI *PFN_CRYPT_ALLOC)(size_t cbSize);
typedef void (WINAPI *PFN_CRYPT_FREE)(void *pv);

typedef struct _CRYPT_DECODE_PARA {
  DWORD cbSize;
  PFN_CRYPT_ALLOC pfnAlloc;
  PFN_CRYPT_FREE pfnFree;
} CRYPT_DECODE_PARA, *PCRYPT_DECODE_PARA;

BOOL WINAPI CryptDecodeObjectEx(DWORD dwCertEncodingType,
                                LPCSTR lpszStructType,
                                const BYTE *pbEncoded, DWORD cbEncoded,
                                DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara,
                                void *pvStructInfo, DWORD *pcbStructInfo);

/*
 * Certificate Chain Engine & Validation
 */
#define CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG 0x00000001
#define CERT_CHAIN_REVOCATION_CHECK_CHAIN   0x20000000
#define USAGE_MATCH_TYPE_AND                0

#define CERT_TRUST_NO_ERROR                 0x00000000
#define CERT_TRUST_IS_NOT_TIME_VALID        0x00000001
#define CERT_TRUST_IS_NOT_TIME_NESTED       0x00000002
#define CERT_TRUST_IS_REVOKED               0x00000004
#define CERT_TRUST_IS_NOT_SIGNATURE_VALID   0x00000008
#define CERT_TRUST_IS_NOT_VALID_FOR_USAGE   0x00000010
#define CERT_TRUST_IS_UNTRUSTED_ROOT        0x00000020
#define CERT_TRUST_REVOCATION_STATUS_UNKNOWN 0x00000040
#define CERT_TRUST_IS_CYCLIC                0x00000080
#define CERT_TRUST_IS_PARTIAL_CHAIN         0x00010000
#define CERT_TRUST_IS_OFFLINE_REVOCATION    0x01000000

typedef void *HCERTCHAINENGINE;

typedef struct _CERT_CHAIN_ENGINE_CONFIG {
  DWORD cbSize;
  HCERTSTORE hRestrictedRoot;
  HCERTSTORE hRestrictedTrust;
  HCERTSTORE hRestrictedOther;
  DWORD cAdditionalStore;
  HCERTSTORE *rghAdditionalStore;
  DWORD dwFlags;
  DWORD dwUrlRetrievalTimeout;
  DWORD MaximumCachedCertificates;
  DWORD CycleDetectionModulus;
  HCERTSTORE hExclusiveRoot;
  HCERTSTORE hExclusiveTrustedPeople;
  DWORD dwExclusiveFlags;
} CERT_CHAIN_ENGINE_CONFIG, *PCERT_CHAIN_ENGINE_CONFIG;

typedef struct _CERT_USAGE_MATCH {
  DWORD dwType;
  struct {
    DWORD cUsageIdentifier;
    LPSTR *rgpszUsageIdentifier;
  } Usage;
} CERT_USAGE_MATCH, *PCERT_USAGE_MATCH;

typedef struct _CERT_CHAIN_PARA {
  DWORD cbSize;
  CERT_USAGE_MATCH RequestedUsage;
  CERT_USAGE_MATCH RequestedIssuancePolicy;
  DWORD dwUrlRetrievalTimeout;
  BOOL fCheckRevocationFreshnessTime;
  DWORD dwRevocationFreshnessTime;
  void *pftCacheResync;
  void *pStrongSignPara;
  DWORD dwStrongSignFlags;
} CERT_CHAIN_PARA, *PCERT_CHAIN_PARA;

typedef struct _CERT_TRUST_STATUS {
  DWORD dwErrorStatus;
  DWORD dwInfoStatus;
} CERT_TRUST_STATUS, *PCERT_TRUST_STATUS;

typedef struct _CERT_CHAIN_ELEMENT {
  DWORD cbSize;
  PCCERT_CONTEXT pCertContext;
  CERT_TRUST_STATUS TrustStatus;
  void *pRevocationInfo;
  void *pIssuanceUsage;
  void *pKeyUsages;
} CERT_CHAIN_ELEMENT, *PCERT_CHAIN_ELEMENT;

typedef struct _CERT_SIMPLE_CHAIN {
  DWORD cbSize;
  CERT_TRUST_STATUS TrustStatus;
  DWORD cElement;
  PCERT_CHAIN_ELEMENT *rgpElement;
  void *pTrustListInfo;
  BOOL fHasRevocationFreshnessTime;
  DWORD dwRevocationFreshnessTime;
} CERT_SIMPLE_CHAIN, *PCERT_SIMPLE_CHAIN;

typedef struct _CERT_CHAIN_CONTEXT {
  DWORD cbSize;
  CERT_TRUST_STATUS TrustStatus;
  DWORD cChain;
  PCERT_SIMPLE_CHAIN *rgpChain;
  DWORD cLowerQualityChainContext;
  void **rgpLowerQualityChainContext;
  BOOL fHasRevocationFreshnessTime;
  DWORD dwRevocationFreshnessTime;
} CERT_CHAIN_CONTEXT, *PCERT_CHAIN_CONTEXT;
typedef const CERT_CHAIN_CONTEXT *PCCERT_CHAIN_CONTEXT;

BOOL WINAPI CertCreateCertificateChainEngine(CERT_CHAIN_ENGINE_CONFIG *pConfig,
                                            HCERTCHAINENGINE *phChainEngine);
void WINAPI CertFreeCertificateChainEngine(HCERTCHAINENGINE hChainEngine);

BOOL WINAPI CertGetCertificateChain(HCERTCHAINENGINE hChainEngine,
                                    PCCERT_CONTEXT pCertContext,
                                    void *pTime,
                                    HCERTSTORE hAdditionalStore,
                                    PCERT_CHAIN_PARA pChainPara,
                                    DWORD dwFlags,
                                    void *pvReserved,
                                    PCCERT_CHAIN_CONTEXT *ppChainContext);
void WINAPI CertFreeCertificateChain(PCCERT_CHAIN_CONTEXT pChainContext);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_WINCRYPT_H */
