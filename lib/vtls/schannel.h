#ifndef HEADER_CURL_SCHANNEL_H
#define HEADER_CURL_SCHANNEL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Marc Hoersken, <info@marc-hoersken.de>, et al.
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
#include "curl_setup.h"

#ifdef USE_SCHANNEL

#define SCHANNEL_USE_BLACKLISTS 1

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4201)
#endif
#include <subauth.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif
/* Wincrypt must be included before anything that could include OpenSSL. */
#if defined(USE_WIN32_CRYPTO)
#include <wincrypt.h>
/* Undefine wincrypt conflicting symbols for BoringSSL. */
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif

#include <schnlsp.h>
#include <schannel.h>
#include "curl_sspi.h"

#include "cfilters.h"
#include "urldata.h"

/* <wincrypt.h> has been included via the above <schnlsp.h>.
 * Or in case of ldap.c, it was included via <winldap.h>.
 * And since <wincrypt.h> has this:
 *   #define X509_NAME  ((LPCSTR) 7)
 *
 * And in BoringSSL's <openssl/base.h> there is:
 *  typedef struct X509_name_st X509_NAME;
 *  etc.
 *
 * this will cause all kinds of C-preprocessing paste errors in
 * BoringSSL's <openssl/x509.h>: So just undefine those defines here
 * (and only here).
 */
#if defined(HAVE_BORINGSSL) || defined(OPENSSL_IS_BORINGSSL)
# undef X509_NAME
# undef X509_CERT_PAIR
# undef X509_EXTENSIONS
#endif

extern const struct Curl_ssl Curl_ssl_schannel;

CURLcode Curl_verify_certificate(struct Curl_cfilter *cf,
                                 struct Curl_easy *data);

/* structs to expose only in schannel.c and schannel_verify.c */
#ifdef EXPOSE_SCHANNEL_INTERNAL_STRUCTS

#ifdef __MINGW32__
#ifdef __MINGW64_VERSION_MAJOR
#define HAS_MANUAL_VERIFY_API
#endif
#else
#ifdef CERT_CHAIN_REVOCATION_CHECK_CHAIN
#define HAS_MANUAL_VERIFY_API
#endif
#endif

#if defined(CryptStringToBinary) && defined(CRYPT_STRING_HEX)   \
  && !defined(DISABLE_SCHANNEL_CLIENT_CERT)
#define HAS_CLIENT_CERT_PATH
#endif

#ifndef SCH_CREDENTIALS_VERSION

#define SCH_CREDENTIALS_VERSION  0x00000005

typedef enum _eTlsAlgorithmUsage
{
    TlsParametersCngAlgUsageKeyExchange,
    TlsParametersCngAlgUsageSignature,
    TlsParametersCngAlgUsageCipher,
    TlsParametersCngAlgUsageDigest,
    TlsParametersCngAlgUsageCertSig
} eTlsAlgorithmUsage;

typedef struct _CRYPTO_SETTINGS
{
    eTlsAlgorithmUsage  eAlgorithmUsage;
    UNICODE_STRING      strCngAlgId;
    DWORD               cChainingModes;
    PUNICODE_STRING     rgstrChainingModes;
    DWORD               dwMinBitLength;
    DWORD               dwMaxBitLength;
} CRYPTO_SETTINGS, * PCRYPTO_SETTINGS;

typedef struct _TLS_PARAMETERS
{
    DWORD               cAlpnIds;
    PUNICODE_STRING     rgstrAlpnIds;
    DWORD               grbitDisabledProtocols;
    DWORD               cDisabledCrypto;
    PCRYPTO_SETTINGS    pDisabledCrypto;
    DWORD               dwFlags;
} TLS_PARAMETERS, * PTLS_PARAMETERS;

typedef struct _SCH_CREDENTIALS
{
    DWORD               dwVersion;
    DWORD               dwCredFormat;
    DWORD               cCreds;
    PCCERT_CONTEXT* paCred;
    HCERTSTORE          hRootStore;

    DWORD               cMappers;
    struct _HMAPPER **aphMappers;

    DWORD               dwSessionLifespan;
    DWORD               dwFlags;
    DWORD               cTlsParameters;
    PTLS_PARAMETERS     pTlsParameters;
} SCH_CREDENTIALS, * PSCH_CREDENTIALS;

#define SCH_CRED_MAX_SUPPORTED_PARAMETERS 16
#define SCH_CRED_MAX_SUPPORTED_ALPN_IDS 16
#define SCH_CRED_MAX_SUPPORTED_CRYPTO_SETTINGS 16
#define SCH_CRED_MAX_SUPPORTED_CHAINING_MODES 16

#endif

struct Curl_schannel_cred {
  CredHandle cred_handle;
  TimeStamp time_stamp;
  TCHAR *sni_hostname;
#ifdef HAS_CLIENT_CERT_PATH
  HCERTSTORE client_cert_store;
#endif
  int refcount;
};

struct Curl_schannel_ctxt {
  CtxtHandle ctxt_handle;
  TimeStamp time_stamp;
};

struct ssl_backend_data {
  struct Curl_schannel_cred *cred;
  struct Curl_schannel_ctxt *ctxt;
  SecPkgContext_StreamSizes stream_sizes;
  size_t encdata_length, decdata_length;
  size_t encdata_offset, decdata_offset;
  unsigned char *encdata_buffer, *decdata_buffer;
  /* encdata_is_incomplete: if encdata contains only a partial record that
     can't be decrypted without another recv() (that is, status is
     SEC_E_INCOMPLETE_MESSAGE) then set this true. after an recv() adds
     more bytes into encdata then set this back to false. */
  bool encdata_is_incomplete;
  unsigned long req_flags, ret_flags;
  CURLcode recv_unrecoverable_err; /* schannel_recv had an unrecoverable err */
  bool recv_sspi_close_notify; /* true if connection closed by close_notify */
  bool recv_connection_closed; /* true if connection closed, regardless how */
  bool recv_renegotiating;     /* true if recv is doing renegotiation */
  bool use_alpn; /* true if ALPN is used for this connection */
#ifdef HAS_MANUAL_VERIFY_API
  bool use_manual_cred_validation; /* true if manual cred validation is used */
#endif
};
#endif /* EXPOSE_SCHANNEL_INTERNAL_STRUCTS */

#endif /* USE_SCHANNEL */
#endif /* HEADER_CURL_SCHANNEL_H */
