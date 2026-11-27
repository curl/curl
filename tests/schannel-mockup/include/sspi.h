#ifndef MOCK_SSPI_H
#define MOCK_SSPI_H
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
#include "subauth.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t SECURITY_STATUS;

typedef struct _SecHandle {
  uintptr_t dwLower;
  uintptr_t dwUpper;
} SecHandle, CredHandle, CtxtHandle;

typedef SecHandle *PSecHandle;
typedef CredHandle *PCredHandle;
typedef CtxtHandle *PCtxtHandle;

typedef struct _SECURITY_INTEGER {
  unsigned long LowPart;
  long HighPart;
} SECURITY_INTEGER, TimeStamp;

/*
 * SecBuffer & SecBufferDesc
 */
typedef struct _SecBuffer {
  unsigned long cbBuffer;
  unsigned long BufferType;
  void *pvBuffer;
} SecBuffer, *PSecBuffer;

typedef struct _SecBufferDesc {
  unsigned long ulVersion;
  unsigned long cBuffers;
  SecBuffer *pBuffers;
} SecBufferDesc, *PSecBufferDesc;

#define SECURITY_NATIVE_DREP 16

#define SECBUFFER_VERSION                       0
#define SECBUFFER_EMPTY                         0
#define SECBUFFER_DATA                          1
#define SECBUFFER_TOKEN                         2
#define SECBUFFER_PKG_PARAMS                    3
#define SECBUFFER_MISSING                       4
#define SECBUFFER_EXTRA                         5
#define SECBUFFER_STREAM_TRAILER                6
#define SECBUFFER_STREAM_HEADER                 7
#define SECBUFFER_NEGOTIATION_INFO              8
#define SECBUFFER_PADDING                       9
#define SECBUFFER_STREAM                        10
#define SECBUFFER_CHANNEL_BINDINGS              14
#define SECBUFFER_TARGET                        16
#define SECBUFFER_ALERT                         17
#define SECBUFFER_APPLICATION_PROTOCOLS         18

#define SECBUFFER_ATTRMASK                      0xF0000000
#define SECBUFFER_READONLY                      0x80000000

/*
 * Credential Usage
 */
#define SECPKG_CRED_INBOUND                     1
#define SECPKG_CRED_OUTBOUND                    2
#define SECPKG_CRED_BOTH                        3

#define SECPKG_CRED_ATTR_NAMES                  1
/*
 * Context Request Flags (ISC_REQ_*)
 */
#define ISC_REQ_DELEGATE                        0x00000001
#define ISC_REQ_MUTUAL_AUTH                     0x00000002
#define ISC_REQ_REPLAY_DETECT                   0x00000004
#define ISC_REQ_SEQUENCE_DETECT                 0x00000008
#define ISC_REQ_CONFIDENTIALITY                 0x00000010
#define ISC_REQ_USE_SESSION_KEY                 0x00000020
#define ISC_REQ_PROMPT_FOR_CREDS                0x00000040
#define ISC_REQ_USE_SUPPLIED_CREDS              0x00000080
#define ISC_REQ_ALLOCATE_MEMORY                 0x00000100
#define ISC_REQ_USE_DCE_STYLE                   0x00000200
#define ISC_REQ_DATAGRAM                        0x00000400
#define ISC_REQ_CONNECTION                      0x00000800
#define ISC_REQ_CALL_LEVEL                      0x00002000
#define ISC_REQ_FRAGMENT_TO_FIT                 0x00004000
#define ISC_REQ_EXTENDED_ERROR                  0x00008000
#define ISC_REQ_STREAM                          0x00010000
#define ISC_REQ_INTEGRITY                       0x00020000
#define ISC_REQ_MANUAL_CRED_VALIDATION          0x00080000
#define ISC_REQ_HTTP_STYLE                      0x01000000
#define ISC_REQ_USE_HTTP_STYLE                  0x01000000

/*
 * Context Return Flags (ISC_RET_*)
 */
#define ISC_RET_DELEGATE                        0x00000001
#define ISC_RET_MUTUAL_AUTH                     0x00000002
#define ISC_RET_REPLAY_DETECT                   0x00000004
#define ISC_RET_SEQUENCE_DETECT                 0x00000008
#define ISC_RET_CONFIDENTIALITY                 0x00000010
#define ISC_RET_USE_SESSION_KEY                 0x00000020
#define ISC_RET_USED_COLLECTED_CREDS            0x00000040
#define ISC_RET_USED_SUPPLIED_CREDS             0x00000080
#define ISC_RET_ALLOCATED_MEMORY                0x00000100
#define ISC_RET_USED_DCE_STYLE                  0x00000200
#define ISC_RET_DATAGRAM                        0x00000400
#define ISC_RET_CONNECTION                      0x00000800
#define ISC_RET_INTERMEDIATE_RETURN             0x00001000
#define ISC_RET_CALL_LEVEL                      0x00002000
#define ISC_RET_EXTENDED_ERROR                  0x00008000
#define ISC_RET_STREAM                          0x00010000
#define ISC_RET_INTEGRITY                       0x00020000

/*
 * QueryContextAttributes Attributes
 */
#define SECPKG_ATTR_SIZES                       0
#define SECPKG_ATTR_NAMES                       1
#define SECPKG_ATTR_LIFESPAN                    2
#define SECPKG_ATTR_DCE_INFO                    3
#define SECPKG_ATTR_STREAM_SIZES                4
#define SECPKG_ATTR_KEY_INFO                    5
#define SECPKG_ATTR_AUTHORITY                   6
#define SECPKG_ATTR_PROTO_INFO                  7
#define SECPKG_ATTR_PASSWORD_EXPIRY             8
#define SECPKG_ATTR_SESSION_KEY                 9
#define SECPKG_ATTR_PACKAGE_INFO                10
#define SECPKG_ATTR_USER_FLAGS                  11
#define SECPKG_ATTR_NEGOTIATION_INFO            12
#define SECPKG_ATTR_NATIVE_NAMES                13
#define SECPKG_ATTR_FLAGS                       14
#define SECPKG_ATTR_USE_VALIDATED               15
#define SECPKG_ATTR_CREDENTIAL_NAME             16
#define SECPKG_ATTR_TARGET_INFORMATION          17
#define SECPKG_ATTR_ACCESS_TOKEN                18
#define SECPKG_ATTR_TARGET                      19
#define SECPKG_ATTR_AUTHENTICATION_ID           20
#define SECPKG_ATTR_LOGOFF_TIME                 21
#define SECPKG_ATTR_NEGO_KEYS                   22
#define SECPKG_ATTR_PROT_NEG_ATTR               23
#define SECPKG_ATTR_ENDPOINT_BINDINGS           26
#define SECPKG_ATTR_APPLICATION_PROTOCOL        35
#define SECPKG_ATTR_REMOTE_CERT_CONTEXT         0x53
#define SECPKG_ATTR_LOCAL_CERT_CONTEXT          0x54
#define SECPKG_ATTR_ROOT_STORE                  0x55
#define SECPKG_ATTR_SUPPORTED_ALGS              0x56
#define SECPKG_ATTR_CIPHER_STRENGTHS            0x57
#define SECPKG_ATTR_SUPPORTED_PROTOCOLS         0x58
#define SECPKG_ATTR_ISSUER_LIST_EX              0x59
#define SECPKG_ATTR_CONNECTION_INFO             0x5a
#define SECPKG_ATTR_EAP_KEY_BLOCK               0x5b
#define SECPKG_ATTR_MAPPED_CRED_ATTR            0x5c
#define SECPKG_ATTR_APP_DATA                    0x5d
#define SECPKG_ATTR_REMOTE_CERTIFICATES         0x5F

/*
 * Context Attribute Structures
 */
typedef struct _SecPkgContext_StreamSizes {
  unsigned long cbHeader;
  unsigned long cbTrailer;
  unsigned long cbMaximumMessage;
  unsigned long cBuffers;
  unsigned long cbBlockSize;
} SecPkgContext_StreamSizes, *PSecPkgContext_StreamSizes;

typedef enum _SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS {
  SecApplicationProtocolNegotiationStatus_None = 0,
  SecApplicationProtocolNegotiationStatus_Success,
  SecApplicationProtocolNegotiationStatus_SelectedClientOnly
} SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS;

typedef enum _SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT {
  SecApplicationProtocolNegotiationExt_None = 0,
  SecApplicationProtocolNegotiationExt_NPN,
  SecApplicationProtocolNegotiationExt_ALPN
} SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT;

typedef struct _SecPkgContext_ApplicationProtocol {
  SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS ProtoNegoStatus;
  SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT ProtoNegoExt;
  unsigned char ProtocolIdSize;
  unsigned char ProtocolId[256];
} SecPkgContext_ApplicationProtocol, *PSecPkgContext_ApplicationProtocol;

typedef struct _SEC_CHANNEL_BINDINGS {
  unsigned long dwInitiatorAddrType;
  unsigned long cbInitiatorLength;
  unsigned long dwInitiatorOffset;
  unsigned long dwAcceptorAddrType;
  unsigned long cbAcceptorLength;
  unsigned long dwAcceptorOffset;
  unsigned long cbApplicationDataLength;
  unsigned long dwApplicationDataOffset;
} SEC_CHANNEL_BINDINGS, *PSEC_CHANNEL_BINDINGS;

typedef struct _SecPkgContext_Bindings {
  unsigned long BindingsLength;
  SEC_CHANNEL_BINDINGS *Bindings;
} SecPkgContext_Bindings, *PSecPkgContext_Bindings;

typedef struct _SecPkgContext_Sizes {
  unsigned long cbMaxToken;
  unsigned long cbMaxSignature;
  unsigned long cbBlockSize;
  unsigned long cbSecurityTrailer;
} SecPkgContext_Sizes, *PSecPkgContext_Sizes;

/*
 * Identity Structures
 */
#define SEC_WINNT_AUTH_IDENTITY_ANSI            0x1
#define SEC_WINNT_AUTH_IDENTITY_UNICODE         0x2
#define SEC_WINNT_AUTH_IDENTITY_VERSION         0x200

typedef struct _SEC_WINNT_AUTH_IDENTITY_EXW {
  unsigned long Version;
  unsigned long Length;
  unsigned short *User;
  unsigned long UserLength;
  unsigned short *Domain;
  unsigned long DomainLength;
  unsigned short *Password;
  unsigned long PasswordLength;
  unsigned long Flags;
  unsigned short *PackageList;
  unsigned long PackageListLength;
} SEC_WINNT_AUTH_IDENTITY_EXW, *PSEC_WINNT_AUTH_IDENTITY_EXW;

typedef struct _SEC_WINNT_AUTH_IDENTITY_EXA {
  unsigned long Version;
  unsigned long Length;
  unsigned char *User;
  unsigned long UserLength;
  unsigned char *Domain;
  unsigned long DomainLength;
  unsigned char *Password;
  unsigned long PasswordLength;
  unsigned long Flags;
  unsigned char *PackageList;
  unsigned long PackageListLength;
} SEC_WINNT_AUTH_IDENTITY_EXA, *PSEC_WINNT_AUTH_IDENTITY_EXA;

typedef char SEC_CHAR;
typedef WCHAR SEC_WCHAR;

#ifdef UNICODE
typedef struct _SecPkgInfoW {
  ULONG  fCapabilities;
  USHORT wVersion;
  USHORT wRPCID;
  ULONG  cbMaxToken;
  LPWSTR Name;
  LPWSTR Comment;
} SecPkgInfoW, *PSecPkgInfoW, *PSecPkgInfo;

typedef struct _SecPkgCredentials_NamesW {
  SEC_WCHAR *sUserName;
} SecPkgCredentials_NamesW, *PSecPkgCredentials_NamesW;

SECURITY_STATUS QuerySecurityPackageInfoW(
  SEC_WCHAR *pszPackageName,
  PSecPkgInfoW *ppPackageInfo);

#else
typedef struct _SecPkgInfoA {
  ULONG  fCapabilities;
  USHORT wVersion;
  USHORT wRPCID;
  ULONG  cbMaxToken;
  LPSTR Name;
  LPSTR Comment;
} SecPkgInfoW, *PSecPkgInfoW, *PSecPkgInfo;

typedef struct _SecPkgCredentials_NamesA {
  SEC_CHAR *sUserName;
} SecPkgCredentials_NamesA, *PSecPkgCredentials_NamesA;

SECURITY_STATUS QuerySecurityPackageInfoA(
  SEC_CHAR *pszPackageName,
  PSecPkgInfoW *ppPackageInfo);
#endif

#ifdef UNICODE
typedef SEC_WINNT_AUTH_IDENTITY_EXW SEC_WINNT_AUTH_IDENTITY_EX;
#else
typedef SEC_WINNT_AUTH_IDENTITY_EXA SEC_WINNT_AUTH_IDENTITY_EX;
#endif

/*
 * SSPI Status / Error Codes
 */
#define SEC_E_OK                              ((SECURITY_STATUS)0x00000000L)
#define SEC_I_CONTINUE_NEEDED                 ((SECURITY_STATUS)0x00090312L)
#define SEC_I_COMPLETE_NEEDED                 ((SECURITY_STATUS)0x00090313L)
#define SEC_I_COMPLETE_AND_CONTINUE           ((SECURITY_STATUS)0x00090314L)
#define SEC_I_LOCAL_LOGON                     ((SECURITY_STATUS)0x00090315L)
#define SEC_I_CONTEXT_EXPIRED                 ((SECURITY_STATUS)0x00090317L)
#define SEC_I_INCOMPLETE_CREDENTIALS          ((SECURITY_STATUS)0x00090320L)
#define SEC_I_RENEGOTIATE                     ((SECURITY_STATUS)0x00090321L)
#define SEC_I_NO_LSA_CONTEXT                  ((SECURITY_STATUS)0x00090323L)
#define SEC_I_SIGNATURE_NEEDED                ((SECURITY_STATUS)0x0009035CL)

#define SEC_E_INSUFFICIENT_MEMORY             ((SECURITY_STATUS)0x80090300L)
#define SEC_E_INVALID_HANDLE                  ((SECURITY_STATUS)0x80090301L)
#define SEC_E_UNSUPPORTED_FUNCTION            ((SECURITY_STATUS)0x80090302L)
#define SEC_E_TARGET_UNKNOWN                  ((SECURITY_STATUS)0x80090303L)
#define SEC_E_INTERNAL_ERROR                  ((SECURITY_STATUS)0x80090304L)
#define SEC_E_SECPKG_NOT_FOUND                ((SECURITY_STATUS)0x80090305L)
#define SEC_E_NOT_OWNER                       ((SECURITY_STATUS)0x80090306L)
#define SEC_E_CANNOT_INSTALL                  ((SECURITY_STATUS)0x80090307L)
#define SEC_E_INVALID_TOKEN                   ((SECURITY_STATUS)0x80090308L)
#define SEC_E_CANNOT_PACK                     ((SECURITY_STATUS)0x80090309L)
#define SEC_E_QOP_NOT_SUPPORTED               ((SECURITY_STATUS)0x8009030AL)
#define SEC_E_NO_IMPERSONATION                ((SECURITY_STATUS)0x8009030BL)
#define SEC_E_LOGON_DENIED                    ((SECURITY_STATUS)0x8009030CL)
#define SEC_E_UNKNOWN_CREDENTIALS             ((SECURITY_STATUS)0x8009030DL)
#define SEC_E_NO_CREDENTIALS                  ((SECURITY_STATUS)0x8009030EL)
#define SEC_E_MESSAGE_ALTERED                 ((SECURITY_STATUS)0x8009030FL)
#define SEC_E_OUT_OF_SEQUENCE                 ((SECURITY_STATUS)0x80090310L)
#define SEC_E_NO_AUTHENTICATING_AUTHORITY     ((SECURITY_STATUS)0x80090311L)
#define SEC_E_BAD_PKGID                       ((SECURITY_STATUS)0x80090316L)
#define SEC_E_CONTEXT_EXPIRED                 ((SECURITY_STATUS)0x80090317L)
#define SEC_E_INCOMPLETE_MESSAGE              ((SECURITY_STATUS)0x80090318L)
#define SEC_E_INCOMPLETE_CREDENTIALS          ((SECURITY_STATUS)0x80090320L)
#define SEC_E_BUFFER_TOO_SMALL                ((SECURITY_STATUS)0x80090321L)
#define SEC_E_WRONG_PRINCIPAL                 ((SECURITY_STATUS)0x80090322L)
#define SEC_E_TIME_SKEW                       ((SECURITY_STATUS)0x80090324L)
#define SEC_E_ILLEGAL_MESSAGE                 ((SECURITY_STATUS)0x80090326L)
#define SEC_E_UNTRUSTED_ROOT                  ((SECURITY_STATUS)0x80090327L)
#define SEC_E_CERT_EXPIRED                    ((SECURITY_STATUS)0x80090328L)
#define SEC_E_ENCRYPT_FAILURE                 ((SECURITY_STATUS)0x80090329L)
#define SEC_E_DECRYPT_FAILURE                 ((SECURITY_STATUS)0x80090330L)
#define SEC_E_ALGORITHM_MISMATCH              ((SECURITY_STATUS)0x80090331L)
#define SEC_E_SECURITY_QOS_FAILED             ((SECURITY_STATUS)0x80090332L)
#define SEC_E_UNFINISHED_CONTEXT_DELETED      ((SECURITY_STATUS)0x80090333L)
#define SEC_E_NO_TGT_REPLY                    ((SECURITY_STATUS)0x80090334L)
#define SEC_E_NO_IP_ADDRESSES                 ((SECURITY_STATUS)0x80090335L)
#define SEC_E_WRONG_CREDENTIAL_HANDLE         ((SECURITY_STATUS)0x80090336L)
#define SEC_E_CRYPTO_SYSTEM_INVALID           ((SECURITY_STATUS)0x80090337L)
#define SEC_E_MAX_REFERRALS_EXCEEDED          ((SECURITY_STATUS)0x80090338L)
#define SEC_E_MUST_BE_KDC                     ((SECURITY_STATUS)0x80090339L)
#define SEC_E_STRONG_CRYPTO_NOT_SUPPORTED     ((SECURITY_STATUS)0x8009033AL)
#define SEC_E_TOO_MANY_PRINCIPALS             ((SECURITY_STATUS)0x8009033BL)
#define SEC_E_NO_PA_DATA                      ((SECURITY_STATUS)0x8009033CL)
#define SEC_E_PKINIT_NAME_MISMATCH            ((SECURITY_STATUS)0x8009033DL)
#define SEC_E_SMARTCARD_LOGON_REQUIRED        ((SECURITY_STATUS)0x8009033EL)
#define SEC_E_SHUTDOWN_IN_PROGRESS            ((SECURITY_STATUS)0x8009033FL)
#define SEC_E_KDC_INVALID_REQUEST             ((SECURITY_STATUS)0x80090340L)
#define SEC_E_KDC_UNABLE_TO_REFER             ((SECURITY_STATUS)0x80090341L)
#define SEC_E_KDC_UNKNOWN_KEY_TYPE            ((SECURITY_STATUS)0x80090342L)
#define SEC_E_CERT_UNKNOWN                    ((SECURITY_STATUS)0x80090343L)
#define SEC_E_BAD_BINDINGS                    ((SECURITY_STATUS)0x80090344L)
#define SEC_E_CERT_WRONG_USAGE                ((SECURITY_STATUS)0x80090345L)
#define SEC_E_UNSUPPORTED_PREAUTH             ((SECURITY_STATUS)0x80090346L)
#define SEC_E_NO_KERB_KEY                     ((SECURITY_STATUS)0x80090347L)
#define SEC_E_ISSUING_CA_UNTRUSTED            ((SECURITY_STATUS)0x80090348L)
#define SEC_E_KDC_CERT_EXPIRED                ((SECURITY_STATUS)0x80090349L)
#define SEC_E_KDC_CERT_REVOKED                ((SECURITY_STATUS)0x8009034AL)
#define SEC_E_CROSSREALM_DELEGATION_FAILURE   ((SECURITY_STATUS)0x8009034BL)
#define SEC_E_PKINIT_CLIENT_FAILURE           ((SECURITY_STATUS)0x8009034CL)
#define SEC_E_SMARTCARD_CERT_REVOKED          ((SECURITY_STATUS)0x8009034DL)
#define SEC_E_SMARTCARD_CERT_EXPIRED          ((SECURITY_STATUS)0x8009034EL)
#define SEC_E_KDC_UNKNOWN_ETYPE               ((SECURITY_STATUS)0x8009034FL)
#define SEC_E_DOWNGRADE_DETECTED              ((SECURITY_STATUS)0x80090350L)
#define SEC_E_REVOCATION_OFFLINE_C            ((SECURITY_STATUS)0x80090353L)
#define SEC_E_DELEGATION_REQUIRED             ((SECURITY_STATUS)0x80090355L)
#define SEC_E_REVOCATION_OFFLINE_KDC          ((SECURITY_STATUS)0x80090356L)
#define SEC_E_ISSUING_CA_UNTRUSTED_KDC        ((SECURITY_STATUS)0x80090357L)
#define SEC_E_MULTIPLE_ACCOUNTS               ((SECURITY_STATUS)0x80090358L)
#define SEC_E_NO_S4U_PROT_SUPPORT             ((SECURITY_STATUS)0x8009035BL)
#define SEC_E_INVALID_PARAMETER               ((SECURITY_STATUS)0x8009035DL)
#define SEC_E_DELEGATION_POLICY               ((SECURITY_STATUS)0x8009035EL)
#define SEC_E_POLICY_NLTM_ONLY                ((SECURITY_STATUS)0x8009035FL)
#define SEC_E_APPLICATION_PROTOCOL_MISMATCH   ((SECURITY_STATUS)0x80090367L)

/*
 * Crypto Error Codes that may be returned by SSPI
 */
#define CRYPT_E_REVOKED                       ((SECURITY_STATUS)0x80092010L)
#define CRYPT_E_NO_REVOCATION_DLL             ((SECURITY_STATUS)0x80092011L)
#define CRYPT_E_NO_REVOCATION_CHECK           ((SECURITY_STATUS)0x80092012L)
#define CRYPT_E_REVOCATION_OFFLINE            ((SECURITY_STATUS)0x80092013L)
#define CRYPT_E_NOT_IN_REVOCATION_DATABASE    ((SECURITY_STATUS)0x80092014L)

#define UNCONST(p) ((void *)(uintptr_t)(const void *)(p))

/*
 * SSPI Function Signatures and Table
 */
typedef SECURITY_STATUS (WINAPI *ACQUIRE_CREDENTIALS_HANDLE_FN_A)(
  LPSTR pszPrincipal,
  LPSTR pszPackage,
  unsigned long fCredentialUse,
  void *pvLogonId,
  void *pAuthData,
  void *pGetKeyFn,
  void *pvGetKeyArgument,
  PCredHandle phCredential,
  TimeStamp *ptsExpiry);

typedef SECURITY_STATUS (WINAPI *ACQUIRE_CREDENTIALS_HANDLE_FN_W)(
  LPWSTR pszPrincipal,
  LPWSTR pszPackage,
  unsigned long fCredentialUse,
  void *pvLogonId,
  void *pAuthData,
  void *pGetKeyFn,
  void *pvGetKeyArgument,
  PCredHandle phCredential,
  TimeStamp *ptsExpiry);

typedef SECURITY_STATUS (WINAPI *FREE_CREDENTIALS_HANDLE_FN)(
  PCredHandle phCredential);

typedef SECURITY_STATUS (WINAPI *INITIALIZE_SECURITY_CONTEXT_FN_A)(
  PCredHandle phCredential,
  PCtxtHandle phContext,
  LPSTR pszTargetName,
  unsigned long fContextReq,
  unsigned long Reserved1,
  unsigned long TargetDataRep,
  PSecBufferDesc pInput,
  unsigned long Reserved2,
  PCtxtHandle phNewContext,
  PSecBufferDesc pOutput,
  unsigned long *pfContextAttr,
  TimeStamp *ptsExpiry);

typedef SECURITY_STATUS (WINAPI *INITIALIZE_SECURITY_CONTEXT_FN_W)(
  PCredHandle phCredential,
  PCtxtHandle phContext,
  LPWSTR pszTargetName,
  unsigned long fContextReq,
  unsigned long Reserved1,
  unsigned long TargetDataRep,
  PSecBufferDesc pInput,
  unsigned long Reserved2,
  PCtxtHandle phNewContext,
  PSecBufferDesc pOutput,
  unsigned long *pfContextAttr,
  TimeStamp *ptsExpiry);

typedef SECURITY_STATUS (WINAPI *DELETE_SECURITY_CONTEXT_FN)(
  PCtxtHandle phContext);

typedef SECURITY_STATUS (WINAPI *QUERY_CONTEXT_ATTRIBUTES_FN_A)(
  PCtxtHandle phContext,
  unsigned long ulAttribute,
  void *pBuffer);

typedef SECURITY_STATUS (WINAPI *QUERY_CONTEXT_ATTRIBUTES_FN_W)(
  PCtxtHandle phContext,
  unsigned long ulAttribute,
  void *pBuffer);

typedef SECURITY_STATUS (WINAPI *QUERY_CREDENTIALS_ATTRIBUTES_FN_A)(
  PCredHandle   phCredential,
  unsigned long ulAttribute,
  void          *pBuffer);

typedef SECURITY_STATUS (WINAPI *QUERY_SECURIYY_PACKAGE_INFO_FN_A)(
  SEC_CHAR *pszPackageName,
  PSecPkgInfoW *ppPackageInfo);

typedef SECURITY_STATUS (WINAPI *FREE_CONTEXT_BUFFER_FN)(
  void *pvContextBuffer);

typedef SECURITY_STATUS (WINAPI *ENCRYPT_MESSAGE_FN)(
  PCtxtHandle phContext,
  unsigned long fQOP,
  PSecBufferDesc pMessage,
  unsigned long MessageSeqNo);

typedef SECURITY_STATUS (WINAPI *DECRYPT_MESSAGE_FN)(
  PCtxtHandle phContext,
  PSecBufferDesc pMessage,
  unsigned long MessageSeqNo,
  unsigned long *pfQOP);

typedef SECURITY_STATUS (WINAPI *APPLY_CONTROL_TOKEN_FN)(
  PCtxtHandle phContext,
  PSecBufferDesc pInput);

typedef SECURITY_STATUS (WINAPI *COMPLETE_AUTH_TOKEN_FN)(
  PCtxtHandle phContext,
  PSecBufferDesc pToken);

typedef SECURITY_STATUS (WINAPI *MAKE_SIGNATURE_FN)(
  PCtxtHandle    phContext,
  unsigned long  fQOP,
  PSecBufferDesc pMessage,
  unsigned long  MessageSeqNo);

typedef struct _SECURITY_FUNCTION_TABLE_A {
  unsigned long dwVersion;
  void *EnumerateSecurityPackagesA;
  QUERY_CREDENTIALS_ATTRIBUTES_FN_A QueryCredentialsAttributesA;
  ACQUIRE_CREDENTIALS_HANDLE_FN_A AcquireCredentialsHandleA;
  FREE_CREDENTIALS_HANDLE_FN FreeCredentialsHandle;
  void *Reserved2;
  INITIALIZE_SECURITY_CONTEXT_FN_A InitializeSecurityContextA;
  void *AcceptSecurityContext;
  COMPLETE_AUTH_TOKEN_FN CompleteAuthToken;
  DELETE_SECURITY_CONTEXT_FN DeleteSecurityContext;
  APPLY_CONTROL_TOKEN_FN ApplyControlToken;
  QUERY_CONTEXT_ATTRIBUTES_FN_A QueryContextAttributesA;
  void *FreeContextBuffer_dummy;
  MAKE_SIGNATURE_FN MakeSignature;
  void *VerifySignature;
  FREE_CONTEXT_BUFFER_FN FreeContextBuffer;
  QUERY_SECURIYY_PACKAGE_INFO_FN_A QuerySecurityPackageInfoA;
  void *Reserved3;
  void *Reserved4;
  void *ExportSecurityContext;
  void *ImportSecurityContextA;
  void *AddCredentialsA;
  void *Reserved8;
  void *QuerySecurityContextToken;
  ENCRYPT_MESSAGE_FN EncryptMessage;
  DECRYPT_MESSAGE_FN DecryptMessage;
  void *SetContextAttributesA;
} SecurityFunctionTableA, *PSecurityFunctionTableA;

typedef struct _SECURITY_FUNCTION_TABLE_W {
  unsigned long dwVersion;
  void *EnumerateSecurityPackagesW;
  void *QueryCredentialsAttributesW;
  ACQUIRE_CREDENTIALS_HANDLE_FN_W AcquireCredentialsHandleW;
  FREE_CREDENTIALS_HANDLE_FN FreeCredentialsHandle;
  void *Reserved2;
  INITIALIZE_SECURITY_CONTEXT_FN_W InitializeSecurityContextW;
  void *AcceptSecurityContext;
  void *CompleteAuthToken;
  DELETE_SECURITY_CONTEXT_FN DeleteSecurityContext;
  APPLY_CONTROL_TOKEN_FN ApplyControlToken;
  QUERY_CONTEXT_ATTRIBUTES_FN_W QueryContextAttributesW;
  void *FreeContextBuffer_dummy;
  void *MakeSignature;
  void *VerifySignature;
  FREE_CONTEXT_BUFFER_FN FreeContextBuffer;
  void *QuerySecurityPackageInfoW;
  void *Reserved3;
  void *Reserved4;
  void *ExportSecurityContext;
  void *ImportSecurityContextW;
  void *AddCredentialsW;
  void *Reserved8;
  void *QuerySecurityContextToken;
  ENCRYPT_MESSAGE_FN EncryptMessage;
  DECRYPT_MESSAGE_FN DecryptMessage;
  void *SetContextAttributesW;
} SecurityFunctionTableW, *PSecurityFunctionTableW;

SECURITY_STATUS QueryCredentialsAttributesW(
  PCredHandle   phCredential,
  unsigned long ulAttribute,
  void          *pBuffer);

SECURITY_STATUS QueryCredentialsAttributesA(
  PCredHandle   phCredential,
  unsigned long ulAttribute,
  void          *pBuffer);

#define SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION 1

#ifdef UNICODE
typedef SecurityFunctionTableW SecurityFunctionTable;
typedef PSecurityFunctionTableW PSecurityFunctionTable;
#define AcquireCredentialsHandle AcquireCredentialsHandleW
#define InitializeSecurityContext InitializeSecurityContextW
#define QueryContextAttributes QueryContextAttributesW
#define InitSecurityInterface InitSecurityInterfaceW
#define QuerySecurityPackageInfo QuerySecurityPackageInfoW
#define SecPkgCredentials_Names SecPkgCredentials_NamesW
#define QueryCredentialsAttributes QueryCredentialsAttributesW
#else
typedef SecurityFunctionTableA SecurityFunctionTable;
typedef PSecurityFunctionTableA PSecurityFunctionTable;
#define AcquireCredentialsHandle AcquireCredentialsHandleA
#define InitializeSecurityContext InitializeSecurityContextA
#define QueryContextAttributes QueryContextAttributesA
#define InitSecurityInterface InitSecurityInterfaceA
#define QuerySecurityPackageInfo QuerySecurityPackageInfoA
#define SecPkgCredentials_Names SecPkgCredentials_NamesA
#define QueryCredentialsAttributes QueryCredentialsAttributesA
#endif

PSecurityFunctionTableA WINAPI InitSecurityInterfaceA(void);
PSecurityFunctionTableW WINAPI InitSecurityInterfaceW(void);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_SSPI_H */
