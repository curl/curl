/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Marc Hoersken, <info@marc-hoersken.de>
 * Copyright (C) Mark Salisbury, <mark.salisbury@hp.com>
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
 * Source file for all Schannel-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 */

#include "curl_setup.h"

#ifdef USE_SCHANNEL

#ifndef USE_WINDOWS_SSPI
#  error "cannot compile SCHANNEL support without SSPI."
#endif

#include "schannel.h"
#include "schannel_int.h"
#include "vtls.h"
#include "vtls_int.h"
#include "vtls_scache.h"
#include "strcase.h"
#include "sendf.h"
#include "connect.h" /* for the connect timeout */
#include "strerror.h"
#include "select.h" /* for the socket readiness */
#include "inet_pton.h" /* for IP addr SNI check */
#include "curl_multibyte.h"
#include "warnless.h"
#include "x509asn1.h"
#include "curl_printf.h"
#include "multiif.h"
#include "system_win32.h"
#include "version_win32.h"
#include "rand.h"
#include "strparse.h"

/* The last #include file should be: */
#include "curl_memory.h"
#include "memdebug.h"

/* Some verbose debug messages are wrapped by SCH_DEV() instead of DEBUGF()
 * and only shown if CURL_SCHANNEL_DEV_DEBUG was defined at build time. These
 * messages are extra verbose and intended for curl developers debugging
 * Schannel recv decryption.
 */
#ifdef CURL_SCHANNEL_DEV_DEBUG
#define SCH_DEV(x) x
#else
#define SCH_DEV(x) do { } while(0)
#endif

#ifndef BCRYPT_CHAIN_MODE_CCM
#define BCRYPT_CHAIN_MODE_CCM L"ChainingModeCCM"
#endif

#ifndef BCRYPT_CHAIN_MODE_GCM
#define BCRYPT_CHAIN_MODE_GCM L"ChainingModeGCM"
#endif

#ifndef BCRYPT_AES_ALGORITHM
#define BCRYPT_AES_ALGORITHM L"AES"
#endif

#ifndef BCRYPT_SHA256_ALGORITHM
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#endif

#ifndef BCRYPT_SHA384_ALGORITHM
#define BCRYPT_SHA384_ALGORITHM L"SHA384"
#endif

#ifdef HAS_CLIENT_CERT_PATH
#ifdef UNICODE
#define CURL_CERT_STORE_PROV_SYSTEM CERT_STORE_PROV_SYSTEM_W
#else
#define CURL_CERT_STORE_PROV_SYSTEM CERT_STORE_PROV_SYSTEM_A
#endif
#endif

#ifndef SP_PROT_TLS1_0_CLIENT
#define SP_PROT_TLS1_0_CLIENT           SP_PROT_TLS1_CLIENT
#endif

#ifndef SP_PROT_TLS1_1_CLIENT
#define SP_PROT_TLS1_1_CLIENT           0x00000200
#endif

#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT           0x00000800
#endif

#ifndef SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3_CLIENT           0x00002000
#endif

#ifndef SCH_USE_STRONG_CRYPTO
#define SCH_USE_STRONG_CRYPTO           0x00400000
#endif

#ifndef SECBUFFER_ALERT
#define SECBUFFER_ALERT                 17
#endif

/* Both schannel buffer sizes must be > 0 */
#define CURL_SCHANNEL_BUFFER_INIT_SIZE   4096
#define CURL_SCHANNEL_BUFFER_FREE_SIZE   1024

#define CERT_THUMBPRINT_STR_LEN 40
#define CERT_THUMBPRINT_DATA_LEN 20

/* Uncomment to force verbose output
 * #define infof(x, y, ...) printf(y, __VA_ARGS__)
 * #define failf(x, y, ...) printf(y, __VA_ARGS__)
 */

#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif

/* Work around typo in CeGCC (as of 0.59.1) w32api headers */
#if defined(__MINGW32CE__) && \
  !defined(ALG_CLASS_DHASH) && defined(ALG_CLASS_HASH)
#define ALG_CLASS_DHASH ALG_CLASS_HASH
#endif

#ifndef PKCS12_NO_PERSIST_KEY
#define PKCS12_NO_PERSIST_KEY 0x00008000
#endif

/* ALPN requires version 8.1 of the Windows SDK, which was
   shipped with Visual Studio 2013, aka _MSC_VER 1800:
     https://technet.microsoft.com/en-us/library/hh831771%28v=ws.11%29.aspx
   Or mingw-w64 9.0 or upper.
*/
#if (defined(__MINGW64_VERSION_MAJOR) && __MINGW64_VERSION_MAJOR >= 9) || \
  (defined(_MSC_VER) && (_MSC_VER >= 1800) && !defined(_USING_V110_SDK71_))
#define HAS_ALPN_SCHANNEL
static bool s_win_has_alpn;
#endif

static CURLcode schannel_pkp_pin_peer_pubkey(struct Curl_cfilter *cf,
                                             struct Curl_easy *data,
                                             const char *pinnedpubkey);

static void InitSecBuffer(SecBuffer *buffer, unsigned long BufType,
                          void *BufDataPtr, unsigned long BufByteSize)
{
  buffer->cbBuffer = BufByteSize;
  buffer->BufferType = BufType;
  buffer->pvBuffer = BufDataPtr;
}

static void InitSecBufferDesc(SecBufferDesc *desc, SecBuffer *BufArr,
                              unsigned long NumArrElem)
{
  desc->ulVersion = SECBUFFER_VERSION;
  desc->pBuffers = BufArr;
  desc->cBuffers = NumArrElem;
}

static CURLcode
schannel_set_ssl_version_min_max(DWORD *enabled_protocols,
                                 struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  long ssl_version = conn_config->version;
  long ssl_version_max = (long)conn_config->version_max;
  long i = ssl_version;

  switch(ssl_version_max) {
  case CURL_SSLVERSION_MAX_NONE:
  case CURL_SSLVERSION_MAX_DEFAULT:

    /* Windows Server 2022 and newer (including Windows 11) support TLS 1.3
       built-in. Previous builds of Windows 10 had broken TLS 1.3
       implementations that could be enabled via registry.
    */
    if(curlx_verify_windows_version(10, 0, 20348, PLATFORM_WINNT,
                                    VERSION_GREATER_THAN_EQUAL)) {
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_3;
    }
    else /* Windows 10 and older */
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;

    break;
  }

  for(; i <= (ssl_version_max >> 16); ++i) {
    switch(i) {
    case CURL_SSLVERSION_TLSv1_0:
      (*enabled_protocols) |= SP_PROT_TLS1_0_CLIENT;
      break;
    case CURL_SSLVERSION_TLSv1_1:
      (*enabled_protocols) |= SP_PROT_TLS1_1_CLIENT;
      break;
    case CURL_SSLVERSION_TLSv1_2:
      (*enabled_protocols) |= SP_PROT_TLS1_2_CLIENT;
      break;
    case CURL_SSLVERSION_TLSv1_3:

      /* Windows Server 2022 and newer */
      if(curlx_verify_windows_version(10, 0, 20348, PLATFORM_WINNT,
                                      VERSION_GREATER_THAN_EQUAL)) {
        (*enabled_protocols) |= SP_PROT_TLS1_3_CLIENT;
        break;
      }
      else { /* Windows 10 and older */
        failf(data, "schannel: TLS 1.3 not supported on Windows prior to 11");
        return CURLE_SSL_CONNECT_ERROR;
      }
    }
  }
  return CURLE_OK;
}

#define CIPHEROPTION(x) {#x, x}

struct algo {
  const char *name;
  int id;
};

static const struct algo algs[]= {
  CIPHEROPTION(CALG_MD2),
  CIPHEROPTION(CALG_MD4),
  CIPHEROPTION(CALG_MD5),
  CIPHEROPTION(CALG_SHA),
  CIPHEROPTION(CALG_SHA1),
  CIPHEROPTION(CALG_MAC),
  CIPHEROPTION(CALG_RSA_SIGN),
  CIPHEROPTION(CALG_DSS_SIGN),
/* ifdefs for the options that are defined conditionally in wincrypt.h */
#ifdef CALG_NO_SIGN
  CIPHEROPTION(CALG_NO_SIGN),
#endif
  CIPHEROPTION(CALG_RSA_KEYX),
  CIPHEROPTION(CALG_DES),
#ifdef CALG_3DES_112
  CIPHEROPTION(CALG_3DES_112),
#endif
  CIPHEROPTION(CALG_3DES),
  CIPHEROPTION(CALG_DESX),
  CIPHEROPTION(CALG_RC2),
  CIPHEROPTION(CALG_RC4),
  CIPHEROPTION(CALG_SEAL),
#ifdef CALG_DH_SF
  CIPHEROPTION(CALG_DH_SF),
#endif
  CIPHEROPTION(CALG_DH_EPHEM),
#ifdef CALG_AGREEDKEY_ANY
  CIPHEROPTION(CALG_AGREEDKEY_ANY),
#endif
#ifdef CALG_HUGHES_MD5
  CIPHEROPTION(CALG_HUGHES_MD5),
#endif
  CIPHEROPTION(CALG_SKIPJACK),
#ifdef CALG_TEK
  CIPHEROPTION(CALG_TEK),
#endif
  CIPHEROPTION(CALG_CYLINK_MEK),
  CIPHEROPTION(CALG_SSL3_SHAMD5),
#ifdef CALG_SSL3_MASTER
  CIPHEROPTION(CALG_SSL3_MASTER),
#endif
#ifdef CALG_SCHANNEL_MASTER_HASH
  CIPHEROPTION(CALG_SCHANNEL_MASTER_HASH),
#endif
#ifdef CALG_SCHANNEL_MAC_KEY
  CIPHEROPTION(CALG_SCHANNEL_MAC_KEY),
#endif
#ifdef CALG_SCHANNEL_ENC_KEY
  CIPHEROPTION(CALG_SCHANNEL_ENC_KEY),
#endif
#ifdef CALG_PCT1_MASTER
  CIPHEROPTION(CALG_PCT1_MASTER),
#endif
#ifdef CALG_SSL2_MASTER
  CIPHEROPTION(CALG_SSL2_MASTER),
#endif
#ifdef CALG_TLS1_MASTER
  CIPHEROPTION(CALG_TLS1_MASTER),
#endif
#ifdef CALG_RC5
  CIPHEROPTION(CALG_RC5),
#endif
#ifdef CALG_HMAC
  CIPHEROPTION(CALG_HMAC),
#endif
#ifdef CALG_TLS1PRF
  CIPHEROPTION(CALG_TLS1PRF),
#endif
#ifdef CALG_HASH_REPLACE_OWF
  CIPHEROPTION(CALG_HASH_REPLACE_OWF),
#endif
#ifdef CALG_AES_128
  CIPHEROPTION(CALG_AES_128),
#endif
#ifdef CALG_AES_192
  CIPHEROPTION(CALG_AES_192),
#endif
#ifdef CALG_AES_256
  CIPHEROPTION(CALG_AES_256),
#endif
#ifdef CALG_AES
  CIPHEROPTION(CALG_AES),
#endif
#ifdef CALG_SHA_256
  CIPHEROPTION(CALG_SHA_256),
#endif
#ifdef CALG_SHA_384
  CIPHEROPTION(CALG_SHA_384),
#endif
#ifdef CALG_SHA_512
  CIPHEROPTION(CALG_SHA_512),
#endif
#ifdef CALG_ECDH
  CIPHEROPTION(CALG_ECDH),
#endif
#ifdef CALG_ECMQV
  CIPHEROPTION(CALG_ECMQV),
#endif
#ifdef CALG_ECDSA
  CIPHEROPTION(CALG_ECDSA),
#endif
#ifdef CALG_ECDH_EPHEM
  CIPHEROPTION(CALG_ECDH_EPHEM),
#endif
  {NULL, 0},
};

static int
get_alg_id_by_name(const char *name)
{
  const char *nameEnd = strchr(name, ':');
  size_t n = nameEnd ? (size_t)(nameEnd - name) : strlen(name);
  int i;

  for(i = 0; algs[i].name; i++) {
    if((n == strlen(algs[i].name) && !strncmp(algs[i].name, name, n)))
      return algs[i].id;
  }
  return 0; /* not found */
}

#define NUM_CIPHERS 47 /* There are 47 options listed above */

static CURLcode
set_ssl_ciphers(SCHANNEL_CRED *schannel_cred, char *ciphers,
                ALG_ID *algIds)
{
  const char *startCur = ciphers;
  int algCount = 0;
  while(startCur && (0 != *startCur) && (algCount < NUM_CIPHERS)) {
    curl_off_t alg;
    if(Curl_str_number(&startCur, &alg, INT_MAX) || !alg)
      alg = get_alg_id_by_name(startCur);

    if(alg)
      algIds[algCount++] = (ALG_ID)alg;
    else if(!strncmp(startCur, "USE_STRONG_CRYPTO",
                     sizeof("USE_STRONG_CRYPTO") - 1) ||
            !strncmp(startCur, "SCH_USE_STRONG_CRYPTO",
                     sizeof("SCH_USE_STRONG_CRYPTO") - 1))
      schannel_cred->dwFlags |= SCH_USE_STRONG_CRYPTO;
    else
      return CURLE_SSL_CIPHER;
    startCur = strchr(startCur, ':');
    if(startCur)
      startCur++;
  }
  schannel_cred->palgSupportedAlgs = algIds;
  schannel_cred->cSupportedAlgs = (DWORD)algCount;
  return CURLE_OK;
}

#ifdef HAS_CLIENT_CERT_PATH

/* Function allocates memory for store_path only if CURLE_OK is returned */
static CURLcode
get_cert_location(TCHAR *path, DWORD *store_name, TCHAR **store_path,
                  TCHAR **thumbprint)
{
  TCHAR *sep;
  TCHAR *store_path_start;
  size_t store_name_len;

  sep = _tcschr(path, TEXT('\\'));
  if(!sep)
    return CURLE_SSL_CERTPROBLEM;

  store_name_len = sep - path;

  if(_tcsncmp(path, TEXT("CurrentUser"), store_name_len) == 0)
    *store_name = CERT_SYSTEM_STORE_CURRENT_USER;
  else if(_tcsncmp(path, TEXT("LocalMachine"), store_name_len) == 0)
    *store_name = CERT_SYSTEM_STORE_LOCAL_MACHINE;
  else if(_tcsncmp(path, TEXT("CurrentService"), store_name_len) == 0)
    *store_name = CERT_SYSTEM_STORE_CURRENT_SERVICE;
  else if(_tcsncmp(path, TEXT("Services"), store_name_len) == 0)
    *store_name = CERT_SYSTEM_STORE_SERVICES;
  else if(_tcsncmp(path, TEXT("Users"), store_name_len) == 0)
    *store_name = CERT_SYSTEM_STORE_USERS;
  else if(_tcsncmp(path, TEXT("CurrentUserGroupPolicy"),
                   store_name_len) == 0)
    *store_name = CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY;
  else if(_tcsncmp(path, TEXT("LocalMachineGroupPolicy"),
                   store_name_len) == 0)
    *store_name = CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY;
  else if(_tcsncmp(path, TEXT("LocalMachineEnterprise"),
                   store_name_len) == 0)
    *store_name = CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE;
  else
    return CURLE_SSL_CERTPROBLEM;

  store_path_start = sep + 1;

  sep = _tcschr(store_path_start, TEXT('\\'));
  if(!sep)
    return CURLE_SSL_CERTPROBLEM;

  *thumbprint = sep + 1;
  if(_tcslen(*thumbprint) != CERT_THUMBPRINT_STR_LEN)
    return CURLE_SSL_CERTPROBLEM;

  *sep = TEXT('\0');
  *store_path = _tcsdup(store_path_start);
  *sep = TEXT('\\');
  if(!*store_path)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}
#endif

static CURLcode
schannel_acquire_credential_handle(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);

#ifdef HAS_CLIENT_CERT_PATH
  PCCERT_CONTEXT client_certs[1] = { NULL };
  HCERTSTORE client_cert_store = NULL;
#endif
  SECURITY_STATUS sspi_status = SEC_E_OK;
  CURLcode result;

  /* setup Schannel API options */
  DWORD flags = 0;
  DWORD enabled_protocols = 0;

  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)(connssl->backend);

  DEBUGASSERT(backend);

  if(conn_config->verifypeer) {
#ifdef HAS_MANUAL_VERIFY_API
    if(backend->use_manual_cred_validation)
      flags = SCH_CRED_MANUAL_CRED_VALIDATION;
    else
#endif
      flags = SCH_CRED_AUTO_CRED_VALIDATION;

    if(ssl_config->no_revoke) {
      flags |= SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
        SCH_CRED_IGNORE_REVOCATION_OFFLINE;

      DEBUGF(infof(data, "schannel: disabled server certificate revocation "
                   "checks"));
    }
    else if(ssl_config->revoke_best_effort) {
      flags |= SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
        SCH_CRED_IGNORE_REVOCATION_OFFLINE | SCH_CRED_REVOCATION_CHECK_CHAIN;

      DEBUGF(infof(data, "schannel: ignore revocation offline errors"));
    }
    else {
      flags |= SCH_CRED_REVOCATION_CHECK_CHAIN;

      DEBUGF(infof(data,
                   "schannel: checking server certificate revocation"));
    }
  }
  else {
    flags = SCH_CRED_MANUAL_CRED_VALIDATION |
      SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
      SCH_CRED_IGNORE_REVOCATION_OFFLINE;
    DEBUGF(infof(data,
                 "schannel: disabled server cert revocation checks"));
  }

  if(!conn_config->verifyhost) {
    flags |= SCH_CRED_NO_SERVERNAME_CHECK;
    DEBUGF(infof(data, "schannel: verifyhost setting prevents Schannel from "
                 "comparing the supplied target name with the subject "
                 "names in server certificates."));
  }

  if(!ssl_config->auto_client_cert) {
    flags &= ~(DWORD)SCH_CRED_USE_DEFAULT_CREDS;
    flags |= SCH_CRED_NO_DEFAULT_CREDS;
    infof(data, "schannel: disabled automatic use of client certificate");
  }
  else
    infof(data, "schannel: enabled automatic use of client certificate");

  switch(conn_config->version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
  case CURL_SSLVERSION_TLSv1_2:
  case CURL_SSLVERSION_TLSv1_3:
  {
    result = schannel_set_ssl_version_min_max(&enabled_protocols, cf, data);
    if(result != CURLE_OK)
      return result;
    break;
  }
  case CURL_SSLVERSION_SSLv3:
  case CURL_SSLVERSION_SSLv2:
    failf(data, "SSL versions not supported");
    return CURLE_NOT_BUILT_IN;
  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef HAS_CLIENT_CERT_PATH
  /* client certificate */
  if(data->set.ssl.primary.clientcert || data->set.ssl.primary.cert_blob) {
    DWORD cert_store_name = 0;
    TCHAR *cert_store_path = NULL;
    TCHAR *cert_thumbprint_str = NULL;
    CRYPT_HASH_BLOB cert_thumbprint;
    BYTE cert_thumbprint_data[CERT_THUMBPRINT_DATA_LEN];
    HCERTSTORE cert_store = NULL;
    FILE *fInCert = NULL;
    void *certdata = NULL;
    size_t certsize = 0;
    bool blob = data->set.ssl.primary.cert_blob != NULL;
    TCHAR *cert_path = NULL;
    if(blob) {
      certdata = data->set.ssl.primary.cert_blob->data;
      certsize = data->set.ssl.primary.cert_blob->len;
    }
    else {
      cert_path = curlx_convert_UTF8_to_tchar(
        data->set.ssl.primary.clientcert);
      if(!cert_path)
        return CURLE_OUT_OF_MEMORY;

      result = get_cert_location(cert_path, &cert_store_name,
                                 &cert_store_path, &cert_thumbprint_str);

      if(result && (data->set.ssl.primary.clientcert[0]!='\0'))
        fInCert = FOPEN(data->set.ssl.primary.clientcert, "rb");

      if(result && !fInCert) {
        failf(data, "schannel: Failed to get certificate location"
              " or file for %s",
              data->set.ssl.primary.clientcert);
        curlx_unicodefree(cert_path);
        return result;
      }
    }

    if((fInCert || blob) && (data->set.ssl.cert_type) &&
       (!strcasecompare(data->set.ssl.cert_type, "P12"))) {
      failf(data, "schannel: certificate format compatibility error "
            " for %s",
            blob ? "(memory blob)" : data->set.ssl.primary.clientcert);
      curlx_unicodefree(cert_path);
      return CURLE_SSL_CERTPROBLEM;
    }

    if(fInCert || blob) {
      /* Reading a .P12 or .pfx file, like the example at bottom of
         https://social.msdn.microsoft.com/Forums/windowsdesktop/
         en-US/3e7bc95f-b21a-4bcd-bd2c-7f996718cae5
      */
      CRYPT_DATA_BLOB datablob;
      WCHAR* pszPassword;
      size_t pwd_len = 0;
      int str_w_len = 0;
      const char *cert_showfilename_error = blob ?
        "(memory blob)" : data->set.ssl.primary.clientcert;
      curlx_unicodefree(cert_path);
      if(fInCert) {
        long cert_tell = 0;
        bool continue_reading = fseek(fInCert, 0, SEEK_END) == 0;
        if(continue_reading)
          cert_tell = ftell(fInCert);
        if(cert_tell < 0)
          continue_reading = FALSE;
        else
          certsize = (size_t)cert_tell;
        if(continue_reading)
          continue_reading = fseek(fInCert, 0, SEEK_SET) == 0;
        if(continue_reading)
          certdata = MALLOC(certsize + 1);
        if((!certdata) ||
           ((int) fread(certdata, certsize, 1, fInCert) != 1))
          continue_reading = FALSE;
        FCLOSE(fInCert);
        if(!continue_reading) {
          failf(data, "schannel: Failed to read cert file %s",
                data->set.ssl.primary.clientcert);
          FREE(certdata);
          return CURLE_SSL_CERTPROBLEM;
        }
      }

      /* Convert key-pair data to the in-memory certificate store */
      datablob.pbData = (BYTE*)certdata;
      datablob.cbData = (DWORD)certsize;

      if(data->set.ssl.key_passwd)
        pwd_len = strlen(data->set.ssl.key_passwd);
      pszPassword = (WCHAR*)MALLOC(sizeof(WCHAR)*(pwd_len + 1));
      if(pszPassword) {
        if(pwd_len > 0)
          str_w_len = MultiByteToWideChar(CP_UTF8,
                                          MB_ERR_INVALID_CHARS,
                                          data->set.ssl.key_passwd,
                                          (int)pwd_len,
                                          pszPassword, (int)(pwd_len + 1));

        if((str_w_len >= 0) && (str_w_len <= (int)pwd_len))
          pszPassword[str_w_len] = 0;
        else
          pszPassword[0] = 0;

        if(Curl_isVistaOrGreater)
          cert_store = PFXImportCertStore(&datablob, pszPassword,
                                          PKCS12_NO_PERSIST_KEY);
        else
          cert_store = PFXImportCertStore(&datablob, pszPassword, 0);

        FREE(pszPassword);
      }
      if(!blob)
        FREE(certdata);
      if(!cert_store) {
        DWORD errorcode = GetLastError();
        if(errorcode == ERROR_INVALID_PASSWORD)
          failf(data, "schannel: Failed to import cert file %s, "
                "password is bad",
                cert_showfilename_error);
        else
          failf(data, "schannel: Failed to import cert file %s, "
                "last error is 0x%lx",
                cert_showfilename_error, errorcode);
        return CURLE_SSL_CERTPROBLEM;
      }

      client_certs[0] = CertFindCertificateInStore(
        cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_ANY, NULL, NULL);

      if(!client_certs[0]) {
        failf(data, "schannel: Failed to get certificate from file %s"
              ", last error is 0x%lx",
              cert_showfilename_error, GetLastError());
        CertCloseStore(cert_store, 0);
        return CURLE_SSL_CERTPROBLEM;
      }
    }
    else {
      cert_store =
        CertOpenStore(CURL_CERT_STORE_PROV_SYSTEM, 0,
                      (HCRYPTPROV)NULL,
                      CERT_STORE_OPEN_EXISTING_FLAG | cert_store_name,
                      cert_store_path);
      if(!cert_store) {
        char *path_utf8 =
          curlx_convert_tchar_to_UTF8(cert_store_path);
        failf(data, "schannel: Failed to open cert store %lx %s, "
              "last error is 0x%lx",
              cert_store_name,
              (path_utf8 ? path_utf8 : "(unknown)"),
              GetLastError());
        FREE(cert_store_path);
        curlx_unicodefree(path_utf8);
        curlx_unicodefree(cert_path);
        return CURLE_SSL_CERTPROBLEM;
      }
      FREE(cert_store_path);

      cert_thumbprint.pbData = cert_thumbprint_data;
      cert_thumbprint.cbData = CERT_THUMBPRINT_DATA_LEN;

      if(!CryptStringToBinary(cert_thumbprint_str,
                              CERT_THUMBPRINT_STR_LEN,
                              CRYPT_STRING_HEX,
                              cert_thumbprint_data,
                              &cert_thumbprint.cbData,
                              NULL, NULL)) {
        curlx_unicodefree(cert_path);
        CertCloseStore(cert_store, 0);
        return CURLE_SSL_CERTPROBLEM;
      }

      client_certs[0] = CertFindCertificateInStore(
        cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_HASH, &cert_thumbprint, NULL);

      curlx_unicodefree(cert_path);

      if(!client_certs[0]) {
        /* CRYPT_E_NOT_FOUND / E_INVALIDARG */
        CertCloseStore(cert_store, 0);
        return CURLE_SSL_CERTPROBLEM;
      }
    }
    client_cert_store = cert_store;
  }
#else
  if(data->set.ssl.primary.clientcert || data->set.ssl.primary.cert_blob) {
    failf(data, "schannel: client cert support not built in");
    return CURLE_NOT_BUILT_IN;
  }
#endif

  /* allocate memory for the reusable credential handle */
  backend->cred = (struct Curl_schannel_cred *)
    CALLOC(1, sizeof(struct Curl_schannel_cred));
  if(!backend->cred) {
    failf(data, "schannel: unable to allocate memory");

#ifdef HAS_CLIENT_CERT_PATH
    if(client_certs[0])
      CertFreeCertificateContext(client_certs[0]);
    if(client_cert_store)
      CertCloseStore(client_cert_store, 0);
#endif

    return CURLE_OUT_OF_MEMORY;
  }
  backend->cred->refcount = 1;

#ifdef HAS_CLIENT_CERT_PATH
  /* Since we did not persist the key, we need to extend the store's
   * lifetime until the end of the connection
   */
  backend->cred->client_cert_store = client_cert_store;
#endif

  /* We support TLS 1.3 starting in Windows 10 version 1809 (OS build 17763) as
     long as the user did not set a legacy algorithm list
     (CURLOPT_SSL_CIPHER_LIST). */
  if(!conn_config->cipher_list &&
     curlx_verify_windows_version(10, 0, 17763, PLATFORM_WINNT,
                                  VERSION_GREATER_THAN_EQUAL)) {

    SCH_CREDENTIALS credentials = { 0 };
    TLS_PARAMETERS tls_parameters = { 0 };
    CRYPTO_SETTINGS crypto_settings[1] = { { 0 } };

    tls_parameters.pDisabledCrypto = crypto_settings;

    /* The number of blocked suites */
    tls_parameters.cDisabledCrypto = (DWORD)0;
    credentials.pTlsParameters = &tls_parameters;
    credentials.cTlsParameters = 1;

    credentials.dwVersion = SCH_CREDENTIALS_VERSION;
    credentials.dwFlags = flags | SCH_USE_STRONG_CRYPTO;

    credentials.pTlsParameters->grbitDisabledProtocols =
      (DWORD)~enabled_protocols;

#ifdef HAS_CLIENT_CERT_PATH
    if(client_certs[0]) {
      credentials.cCreds = 1;
      credentials.paCred = client_certs;
    }
#endif

    sspi_status =
      Curl_pSecFn->AcquireCredentialsHandle(NULL,
                                            (TCHAR *)CURL_UNCONST(UNISP_NAME),
                                            SECPKG_CRED_OUTBOUND, NULL,
                                            &credentials, NULL, NULL,
                                            &backend->cred->cred_handle,
                                            &backend->cred->time_stamp);
  }
  else {
    /* Pre-Windows 10 1809 or the user set a legacy algorithm list.
       Schannel will not negotiate TLS 1.3 when SCHANNEL_CRED is used. */
    ALG_ID algIds[NUM_CIPHERS];
    char *ciphers = conn_config->cipher_list;
    SCHANNEL_CRED schannel_cred = { 0 };
    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    schannel_cred.dwFlags = flags;
    schannel_cred.grbitEnabledProtocols = enabled_protocols;

    if(ciphers) {
      if((enabled_protocols & SP_PROT_TLS1_3_CLIENT)) {
        infof(data, "schannel: WARNING: This version of Schannel "
              "negotiates a less-secure TLS version than TLS 1.3 because the "
              "user set an algorithm cipher list.");
      }
      result = set_ssl_ciphers(&schannel_cred, ciphers, algIds);
      if(CURLE_OK != result) {
        failf(data, "schannel: Failed setting algorithm cipher list");
        return result;
      }
    }
    else {
      schannel_cred.dwFlags = flags | SCH_USE_STRONG_CRYPTO;
    }

#ifdef HAS_CLIENT_CERT_PATH
    if(client_certs[0]) {
      schannel_cred.cCreds = 1;
      schannel_cred.paCred = client_certs;
    }
#endif

    sspi_status =
      Curl_pSecFn->AcquireCredentialsHandle(NULL,
                                            (TCHAR *)CURL_UNCONST(UNISP_NAME),
                                            SECPKG_CRED_OUTBOUND, NULL,
                                            &schannel_cred, NULL, NULL,
                                            &backend->cred->cred_handle,
                                            &backend->cred->time_stamp);
  }

#ifdef HAS_CLIENT_CERT_PATH
  if(client_certs[0])
    CertFreeCertificateContext(client_certs[0]);
#endif

  if(sspi_status != SEC_E_OK) {
    char buffer[STRERROR_LEN];
    failf(data, "schannel: AcquireCredentialsHandle failed: %s",
          Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
    Curl_safefree(backend->cred);
    switch(sspi_status) {
    case SEC_E_INSUFFICIENT_MEMORY:
      return CURLE_OUT_OF_MEMORY;
    case SEC_E_NO_CREDENTIALS:
    case SEC_E_SECPKG_NOT_FOUND:
    case SEC_E_NOT_OWNER:
    case SEC_E_UNKNOWN_CREDENTIALS:
    case SEC_E_INTERNAL_ERROR:
    default:
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  return CURLE_OK;
}

static CURLcode
schannel_connect_step1(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  ssize_t written = -1;
  struct ssl_connect_data *connssl = cf->ctx;
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;
#ifndef UNDER_CE
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
#endif
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  SecBuffer outbuf;
  SecBufferDesc outbuf_desc;
  SecBuffer inbuf;
  SecBufferDesc inbuf_desc;
#ifdef HAS_ALPN_SCHANNEL
  unsigned char alpn_buffer[128];
#endif
  SECURITY_STATUS sspi_status = SEC_E_OK;
  CURLcode result;

  DEBUGASSERT(backend);
  DEBUGF(infof(data,
               "schannel: SSL/TLS connection with %s port %d (step 1/3)",
               connssl->peer.hostname, connssl->peer.port));

  if(curlx_verify_windows_version(5, 1, 0, PLATFORM_WINNT,
                                  VERSION_LESS_THAN_EQUAL)) {
    /* Schannel in Windows XP (OS version 5.1) uses legacy handshakes and
       algorithms that may not be supported by all servers. */
    infof(data, "schannel: Windows version is old and may not be able to "
          "connect to some servers due to lack of SNI, algorithms, etc.");
  }

#ifdef HAS_ALPN_SCHANNEL
  backend->use_alpn = connssl->alpn && s_win_has_alpn;
#else
  backend->use_alpn = FALSE;
#endif

#ifdef UNDER_CE
#ifdef HAS_MANUAL_VERIFY_API
  /* certificate validation on Windows CE does not seem to work right; we will
   * do it following a more manual process. */
  backend->use_manual_cred_validation = TRUE;
#else
#error "compiler too old to support Windows CE requisite manual cert verify"
#endif
#else
#ifdef HAS_MANUAL_VERIFY_API
  if(conn_config->CAfile || conn_config->ca_info_blob) {
    if(curlx_verify_windows_version(6, 1, 0, PLATFORM_WINNT,
                                    VERSION_GREATER_THAN_EQUAL)) {
      backend->use_manual_cred_validation = TRUE;
    }
    else {
      failf(data, "schannel: this version of Windows is too old to support "
            "certificate verification via CA bundle file.");
      return CURLE_SSL_CACERT_BADFILE;
    }
  }
  else
    backend->use_manual_cred_validation = FALSE;
#else
  if(conn_config->CAfile || conn_config->ca_info_blob) {
    failf(data, "schannel: CA cert support not built in");
    return CURLE_NOT_BUILT_IN;
  }
#endif
#endif

  backend->cred = NULL;

  /* check for an existing reusable credential handle */
  if(ssl_config->primary.cache_session) {
    struct Curl_schannel_cred *old_cred;
    Curl_ssl_scache_lock(data);
    old_cred = Curl_ssl_scache_get_obj(cf, data, connssl->peer.scache_key);
    if(old_cred) {
      backend->cred = old_cred;
      DEBUGF(infof(data, "schannel: reusing existing credential handle"));

      /* increment the reference counter of the credential/session handle */
      backend->cred->refcount++;
      DEBUGF(infof(data,
                   "schannel: incremented credential handle refcount = %d",
                   backend->cred->refcount));
    }
    Curl_ssl_scache_unlock(data);
  }

  if(!backend->cred) {
    char *snihost;
    result = schannel_acquire_credential_handle(cf, data);
    if(result || !backend->cred)
      return result;
    /* schannel_acquire_credential_handle() sets backend->cred accordingly or
       it returns error otherwise. */

    /* A hostname associated with the credential is needed by
       InitializeSecurityContext for SNI and other reasons. */
    snihost = connssl->peer.sni ? connssl->peer.sni : connssl->peer.hostname;
    backend->cred->sni_hostname = curlx_convert_UTF8_to_tchar(snihost);
    if(!backend->cred->sni_hostname)
      return CURLE_OUT_OF_MEMORY;
  }

  /* Warn if SNI is disabled due to use of an IP address */
  if(connssl->peer.type != CURL_SSL_PEER_DNS) {
    infof(data, "schannel: using IP address, SNI is not supported by OS.");
  }

#ifdef HAS_ALPN_SCHANNEL
  if(backend->use_alpn) {
    int cur = 0;
    int list_start_index = 0;
    unsigned int *extension_len = NULL;
    unsigned short* list_len = NULL;
    struct alpn_proto_buf proto;

    /* The first four bytes will be an unsigned int indicating number
       of bytes of data in the rest of the buffer. */
    extension_len = (unsigned int *)(void *)(&alpn_buffer[cur]);
    cur += (int)sizeof(unsigned int);

    /* The next four bytes are an indicator that this buffer will contain
       ALPN data, as opposed to NPN, for example. */
    *(unsigned int *)(void *)&alpn_buffer[cur] =
      SecApplicationProtocolNegotiationExt_ALPN;
    cur += (int)sizeof(unsigned int);

    /* The next two bytes will be an unsigned short indicating the number
       of bytes used to list the preferred protocols. */
    list_len = (unsigned short*)(void *)(&alpn_buffer[cur]);
    cur += (int)sizeof(unsigned short);

    list_start_index = cur;

    result = Curl_alpn_to_proto_buf(&proto, connssl->alpn);
    if(result) {
      failf(data, "Error setting ALPN");
      return CURLE_SSL_CONNECT_ERROR;
    }
    memcpy(&alpn_buffer[cur], proto.data, proto.len);
    cur += proto.len;

    *list_len = curlx_uitous(cur - list_start_index);
    *extension_len = (unsigned int)(*list_len +
      sizeof(unsigned int) + sizeof(unsigned short));

    InitSecBuffer(&inbuf, SECBUFFER_APPLICATION_PROTOCOLS, alpn_buffer, cur);
    InitSecBufferDesc(&inbuf_desc, &inbuf, 1);

    Curl_alpn_to_proto_str(&proto, connssl->alpn);
    infof(data, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
  }
  else {
    InitSecBuffer(&inbuf, SECBUFFER_EMPTY, NULL, 0);
    InitSecBufferDesc(&inbuf_desc, &inbuf, 1);
  }
#else /* HAS_ALPN_SCHANNEL */
  InitSecBuffer(&inbuf, SECBUFFER_EMPTY, NULL, 0);
  InitSecBufferDesc(&inbuf_desc, &inbuf, 1);
#endif

  /* setup output buffer */
  InitSecBuffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
  InitSecBufferDesc(&outbuf_desc, &outbuf, 1);

  /* security request flags */
  backend->req_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
    ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
    ISC_REQ_STREAM;

  if(!ssl_config->auto_client_cert) {
    backend->req_flags |= ISC_REQ_USE_SUPPLIED_CREDS;
  }

  /* allocate memory for the security context handle */
  backend->ctxt = (struct Curl_schannel_ctxt *)
    CALLOC(1, sizeof(struct Curl_schannel_ctxt));
  if(!backend->ctxt) {
    failf(data, "schannel: unable to allocate memory");
    return CURLE_OUT_OF_MEMORY;
  }

  /* Schannel InitializeSecurityContext:
     https://msdn.microsoft.com/en-us/library/windows/desktop/aa375924.aspx

     At the moment we do not pass inbuf unless we are using ALPN since we only
     use it for that, and WINE (for which we currently disable ALPN) is giving
     us problems with inbuf regardless. https://github.com/curl/curl/issues/983
  */
  sspi_status = Curl_pSecFn->InitializeSecurityContext(
    &backend->cred->cred_handle, NULL, backend->cred->sni_hostname,
    backend->req_flags, 0, 0,
    (backend->use_alpn ? &inbuf_desc : NULL),
    0, &backend->ctxt->ctxt_handle,
    &outbuf_desc, &backend->ret_flags, &backend->ctxt->time_stamp);

  if(sspi_status != SEC_I_CONTINUE_NEEDED) {
    char buffer[STRERROR_LEN];
    Curl_safefree(backend->ctxt);
    switch(sspi_status) {
    case SEC_E_INSUFFICIENT_MEMORY:
      failf(data, "schannel: initial InitializeSecurityContext failed: %s",
            Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
      return CURLE_OUT_OF_MEMORY;
    case SEC_E_WRONG_PRINCIPAL:
      failf(data, "schannel: SNI or certificate check failed: %s",
            Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
      return CURLE_PEER_FAILED_VERIFICATION;
      /*
        case SEC_E_INVALID_HANDLE:
        case SEC_E_INVALID_TOKEN:
        case SEC_E_LOGON_DENIED:
        case SEC_E_TARGET_UNKNOWN:
        case SEC_E_NO_AUTHENTICATING_AUTHORITY:
        case SEC_E_INTERNAL_ERROR:
        case SEC_E_NO_CREDENTIALS:
        case SEC_E_UNSUPPORTED_FUNCTION:
        case SEC_E_APPLICATION_PROTOCOL_MISMATCH:
      */
    default:
      failf(data, "schannel: initial InitializeSecurityContext failed: %s",
            Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  DEBUGF(infof(data, "schannel: sending initial handshake data: "
               "sending %lu bytes.", outbuf.cbBuffer));

  /* send initial handshake data which is now stored in output buffer */
  written = Curl_conn_cf_send(cf->next, data,
                              outbuf.pvBuffer, outbuf.cbBuffer, FALSE,
                              &result);
  Curl_pSecFn->FreeContextBuffer(outbuf.pvBuffer);
  if((result != CURLE_OK) || (outbuf.cbBuffer != (size_t) written)) {
    failf(data, "schannel: failed to send initial handshake data: "
          "sent %zd of %lu bytes", written, outbuf.cbBuffer);
    return CURLE_SSL_CONNECT_ERROR;
  }

  DEBUGF(infof(data, "schannel: sent initial handshake data: "
               "sent %zd bytes", written));

  backend->recv_unrecoverable_err = CURLE_OK;
  backend->recv_sspi_close_notify = FALSE;
  backend->recv_connection_closed = FALSE;
  backend->recv_renegotiating = FALSE;
  backend->encdata_is_incomplete = FALSE;

  /* continue to second handshake step */
  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode
schannel_connect_step2(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  int i;
  ssize_t nread = -1, written = -1;
  unsigned char *reallocated_buffer;
  SecBuffer outbuf[3];
  SecBufferDesc outbuf_desc;
  SecBuffer inbuf[2];
  SecBufferDesc inbuf_desc;
  SECURITY_STATUS sspi_status = SEC_E_OK;
  CURLcode result;
  bool doread;
  const char *pubkey_ptr;

  DEBUGASSERT(backend);

  doread = (connssl->io_need & CURL_SSL_IO_NEED_SEND) ? FALSE : TRUE;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  DEBUGF(infof(data,
               "schannel: SSL/TLS connection with %s port %d (step 2/3)",
               connssl->peer.hostname, connssl->peer.port));

  if(!backend->cred || !backend->ctxt)
    return CURLE_SSL_CONNECT_ERROR;

  /* buffer to store previously received and decrypted data */
  if(!backend->decdata_buffer) {
    backend->decdata_offset = 0;
    backend->decdata_length = CURL_SCHANNEL_BUFFER_INIT_SIZE;
    backend->decdata_buffer = MALLOC(backend->decdata_length);
    if(!backend->decdata_buffer) {
      failf(data, "schannel: unable to allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* buffer to store previously received and encrypted data */
  if(!backend->encdata_buffer) {
    backend->encdata_is_incomplete = FALSE;
    backend->encdata_offset = 0;
    backend->encdata_length = CURL_SCHANNEL_BUFFER_INIT_SIZE;
    backend->encdata_buffer = MALLOC(backend->encdata_length);
    if(!backend->encdata_buffer) {
      failf(data, "schannel: unable to allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* if we need a bigger buffer to read a full message, increase buffer now */
  if(backend->encdata_length - backend->encdata_offset <
     CURL_SCHANNEL_BUFFER_FREE_SIZE) {
    /* increase internal encrypted data buffer */
    size_t reallocated_length = backend->encdata_offset +
      CURL_SCHANNEL_BUFFER_FREE_SIZE;
    reallocated_buffer = REALLOC(backend->encdata_buffer,
                                 reallocated_length);

    if(!reallocated_buffer) {
      failf(data, "schannel: unable to re-allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }
    else {
      backend->encdata_buffer = reallocated_buffer;
      backend->encdata_length = reallocated_length;
    }
  }

  for(;;) {
    if(doread) {
      /* read encrypted handshake data from socket */
      nread = Curl_conn_cf_recv(cf->next, data,
                               (char *) (backend->encdata_buffer +
                                         backend->encdata_offset),
                               backend->encdata_length -
                               backend->encdata_offset,
                               &result);
      if(result == CURLE_AGAIN) {
        connssl->io_need = CURL_SSL_IO_NEED_RECV;
        DEBUGF(infof(data, "schannel: failed to receive handshake, "
                     "need more data"));
        return CURLE_OK;
      }
      else if((result != CURLE_OK) || (nread == 0)) {
        failf(data, "schannel: failed to receive handshake, "
              "SSL/TLS connection failed");
        return CURLE_SSL_CONNECT_ERROR;
      }

      /* increase encrypted data buffer offset */
      backend->encdata_offset += nread;
      backend->encdata_is_incomplete = FALSE;
      SCH_DEV(infof(data, "schannel: encrypted data got %zd", nread));
    }

    SCH_DEV(infof(data,
                  "schannel: encrypted data buffer: offset %zu length %zu",
                  backend->encdata_offset, backend->encdata_length));

    /* setup input buffers */
    InitSecBuffer(&inbuf[0], SECBUFFER_TOKEN, MALLOC(backend->encdata_offset),
                  curlx_uztoul(backend->encdata_offset));
    InitSecBuffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
    InitSecBufferDesc(&inbuf_desc, inbuf, 2);

    /* setup output buffers */
    InitSecBuffer(&outbuf[0], SECBUFFER_TOKEN, NULL, 0);
    InitSecBuffer(&outbuf[1], SECBUFFER_ALERT, NULL, 0);
    InitSecBuffer(&outbuf[2], SECBUFFER_EMPTY, NULL, 0);
    InitSecBufferDesc(&outbuf_desc, outbuf, 3);

    if(!inbuf[0].pvBuffer) {
      failf(data, "schannel: unable to allocate memory");
      return CURLE_OUT_OF_MEMORY;
    }

    /* copy received handshake data into input buffer */
    memcpy(inbuf[0].pvBuffer, backend->encdata_buffer,
           backend->encdata_offset);

    sspi_status = Curl_pSecFn->InitializeSecurityContext(
      &backend->cred->cred_handle, &backend->ctxt->ctxt_handle,
      backend->cred->sni_hostname, backend->req_flags,
      0, 0, &inbuf_desc, 0, NULL,
      &outbuf_desc, &backend->ret_flags, &backend->ctxt->time_stamp);

    /* free buffer for received handshake data */
    Curl_safefree(inbuf[0].pvBuffer);

    /* check if the handshake was incomplete */
    if(sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
      backend->encdata_is_incomplete = TRUE;
      connssl->io_need = CURL_SSL_IO_NEED_RECV;
      DEBUGF(infof(data,
                   "schannel: received incomplete message, need more data"));
      return CURLE_OK;
    }

    /* If the server has requested a client certificate, attempt to continue
       the handshake without one. This will allow connections to servers which
       request a client certificate but do not require it. */
    if(sspi_status == SEC_I_INCOMPLETE_CREDENTIALS &&
       !(backend->req_flags & ISC_REQ_USE_SUPPLIED_CREDS)) {
      backend->req_flags |= ISC_REQ_USE_SUPPLIED_CREDS;
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
      DEBUGF(infof(data,
                   "schannel: a client certificate has been requested"));
      return CURLE_OK;
    }

    /* check if the handshake needs to be continued */
    if(sspi_status == SEC_I_CONTINUE_NEEDED || sspi_status == SEC_E_OK) {
      for(i = 0; i < 3; i++) {
        /* search for handshake tokens that need to be send */
        if(outbuf[i].BufferType == SECBUFFER_TOKEN && outbuf[i].cbBuffer > 0) {
          DEBUGF(infof(data, "schannel: sending next handshake data: "
                       "sending %lu bytes.", outbuf[i].cbBuffer));

          /* send handshake token to server */
          written = Curl_conn_cf_send(cf->next, data,
                                      outbuf[i].pvBuffer, outbuf[i].cbBuffer,
                                      FALSE, &result);
          if((result != CURLE_OK) ||
             (outbuf[i].cbBuffer != (size_t) written)) {
            failf(data, "schannel: failed to send next handshake data: "
                  "sent %zd of %lu bytes", written, outbuf[i].cbBuffer);
            return CURLE_SSL_CONNECT_ERROR;
          }
        }

        /* free obsolete buffer */
        if(outbuf[i].pvBuffer) {
          Curl_pSecFn->FreeContextBuffer(outbuf[i].pvBuffer);
        }
      }
    }
    else {
      char buffer[STRERROR_LEN];
      switch(sspi_status) {
      case SEC_E_INSUFFICIENT_MEMORY:
        failf(data, "schannel: next InitializeSecurityContext failed: %s",
              Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
        return CURLE_OUT_OF_MEMORY;
      case SEC_E_WRONG_PRINCIPAL:
        failf(data, "schannel: SNI or certificate check failed: %s",
              Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
        return CURLE_PEER_FAILED_VERIFICATION;
      case SEC_E_UNTRUSTED_ROOT:
        failf(data, "schannel: %s",
              Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
        return CURLE_PEER_FAILED_VERIFICATION;
        /*
          case SEC_E_INVALID_HANDLE:
          case SEC_E_INVALID_TOKEN:
          case SEC_E_LOGON_DENIED:
          case SEC_E_TARGET_UNKNOWN:
          case SEC_E_NO_AUTHENTICATING_AUTHORITY:
          case SEC_E_INTERNAL_ERROR:
          case SEC_E_NO_CREDENTIALS:
          case SEC_E_UNSUPPORTED_FUNCTION:
          case SEC_E_APPLICATION_PROTOCOL_MISMATCH:
        */
      default:
        failf(data, "schannel: next InitializeSecurityContext failed: %s",
              Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
        return CURLE_SSL_CONNECT_ERROR;
      }
    }

    /* check if there was additional remaining encrypted data */
    if(inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer > 0) {
      SCH_DEV(infof(data, "schannel: encrypted data length: %lu",
                    inbuf[1].cbBuffer));
      /*
        There are two cases where we could be getting extra data here:
        1) If we are renegotiating a connection and the handshake is already
        complete (from the server perspective), it can encrypted app data
        (not handshake data) in an extra buffer at this point.
        2) (sspi_status == SEC_I_CONTINUE_NEEDED) We are negotiating a
        connection and this extra data is part of the handshake.
        We should process the data immediately; waiting for the socket to
        be ready may fail since the server is done sending handshake data.
      */
      /* check if the remaining data is less than the total amount
         and therefore begins after the already processed data */
      if(backend->encdata_offset > inbuf[1].cbBuffer) {
        memmove(backend->encdata_buffer,
                (backend->encdata_buffer + backend->encdata_offset) -
                inbuf[1].cbBuffer, inbuf[1].cbBuffer);
        backend->encdata_offset = inbuf[1].cbBuffer;
        if(sspi_status == SEC_I_CONTINUE_NEEDED) {
          doread = FALSE;
          continue;
        }
      }
    }
    else {
      backend->encdata_offset = 0;
    }
    break;
  }

  /* check if the handshake needs to be continued */
  if(sspi_status == SEC_I_CONTINUE_NEEDED) {
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    return CURLE_OK;
  }

  /* check if the handshake is complete */
  if(sspi_status == SEC_E_OK) {
    connssl->connecting_state = ssl_connect_3;
    DEBUGF(infof(data, "schannel: SSL/TLS handshake complete"));
  }

#ifndef CURL_DISABLE_PROXY
  pubkey_ptr = Curl_ssl_cf_is_proxy(cf) ?
    data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
    data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#else
  pubkey_ptr = data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#endif
  if(pubkey_ptr) {
    result = schannel_pkp_pin_peer_pubkey(cf, data, pubkey_ptr);
    if(result) {
      failf(data, "SSL: public key does not match pinned public key");
      return result;
    }
  }

#ifdef HAS_MANUAL_VERIFY_API
  if(conn_config->verifypeer && backend->use_manual_cred_validation) {
    /* Certificate verification also verifies the hostname if verifyhost */
    return Curl_verify_certificate(cf, data);
  }
#endif

  /* Verify the hostname manually when certificate verification is disabled,
     because in that case Schannel will not verify it. */
  if(!conn_config->verifypeer && conn_config->verifyhost)
    return Curl_verify_host(cf, data);

  return CURLE_OK;
}

static bool
valid_cert_encoding(const CERT_CONTEXT *cert_context)
{
  return (cert_context != NULL) &&
    ((cert_context->dwCertEncodingType & X509_ASN_ENCODING) != 0) &&
    (cert_context->pbCertEncoded != NULL) &&
    (cert_context->cbCertEncoded > 0);
}

typedef bool(*Read_crt_func)(const CERT_CONTEXT *ccert_context,
                             bool reverse_order, void *arg);

static void
traverse_cert_store(const CERT_CONTEXT *context, Read_crt_func func,
                    void *arg)
{
  const CERT_CONTEXT *current_context = NULL;
  bool should_continue = TRUE;
  bool first = TRUE;
  bool reverse_order = FALSE;
  while(should_continue &&
        (current_context = CertEnumCertificatesInStore(
          context->hCertStore,
          current_context)) != NULL) {
    /* Windows 11 22H2 OS Build 22621.674 or higher enumerates certificates in
       leaf-to-root order while all previous versions of Windows enumerate
       certificates in root-to-leaf order. Determine the order of enumeration
       by comparing SECPKG_ATTR_REMOTE_CERT_CONTEXT's pbCertContext with the
       first certificate's pbCertContext. */
    if(first && context->pbCertEncoded != current_context->pbCertEncoded)
      reverse_order = TRUE;
    should_continue = func(current_context, reverse_order, arg);
    first = FALSE;
  }

  if(current_context)
    CertFreeCertificateContext(current_context);
}

static bool
cert_counter_callback(const CERT_CONTEXT *ccert_context, bool reverse_order,
                      void *certs_count)
{
  (void)reverse_order; /* unused */
  if(valid_cert_encoding(ccert_context))
    (*(int *)certs_count)++;
  return TRUE;
}

struct Adder_args
{
  struct Curl_easy *data;
  CURLcode result;
  int idx;
  int certs_count;
};

static bool
add_cert_to_certinfo(const CERT_CONTEXT *ccert_context, bool reverse_order,
                     void *raw_arg)
{
  struct Adder_args *args = (struct Adder_args*)raw_arg;
  args->result = CURLE_OK;
  if(valid_cert_encoding(ccert_context)) {
    const char *beg = (const char *) ccert_context->pbCertEncoded;
    const char *end = beg + ccert_context->cbCertEncoded;
    int insert_index = reverse_order ? (args->certs_count - 1) - args->idx :
                       args->idx;
    args->result = Curl_extract_certinfo(args->data, insert_index,
                                         beg, end);
    args->idx++;
  }
  return args->result == CURLE_OK;
}

static void schannel_session_free(void *sessionid)
{
  /* this is expected to be called under sessionid lock */
  struct Curl_schannel_cred *cred = sessionid;

  if(cred) {
    cred->refcount--;
    if(cred->refcount == 0) {
      Curl_pSecFn->FreeCredentialsHandle(&cred->cred_handle);
      curlx_unicodefree(cred->sni_hostname);
#ifdef HAS_CLIENT_CERT_PATH
      if(cred->client_cert_store) {
        CertCloseStore(cred->client_cert_store, 0);
        cred->client_cert_store = NULL;
      }
#endif
      Curl_safefree(cred);
    }
  }
}

static CURLcode
schannel_connect_step3(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  CURLcode result = CURLE_OK;
  SECURITY_STATUS sspi_status = SEC_E_OK;
  CERT_CONTEXT *ccert_context = NULL;
#ifdef HAS_ALPN_SCHANNEL
  SecPkgContext_ApplicationProtocol alpn_result;
#endif

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);
  DEBUGASSERT(backend);

  DEBUGF(infof(data,
               "schannel: SSL/TLS connection with %s port %d (step 3/3)",
               connssl->peer.hostname, connssl->peer.port));

  if(!backend->cred)
    return CURLE_SSL_CONNECT_ERROR;

  /* check if the required context attributes are met */
  if(backend->ret_flags != backend->req_flags) {
    if(!(backend->ret_flags & ISC_RET_SEQUENCE_DETECT))
      failf(data, "schannel: failed to setup sequence detection");
    if(!(backend->ret_flags & ISC_RET_REPLAY_DETECT))
      failf(data, "schannel: failed to setup replay detection");
    if(!(backend->ret_flags & ISC_RET_CONFIDENTIALITY))
      failf(data, "schannel: failed to setup confidentiality");
    if(!(backend->ret_flags & ISC_RET_ALLOCATED_MEMORY))
      failf(data, "schannel: failed to setup memory allocation");
    if(!(backend->ret_flags & ISC_RET_STREAM))
      failf(data, "schannel: failed to setup stream orientation");
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef HAS_ALPN_SCHANNEL
  if(backend->use_alpn) {
    sspi_status =
      Curl_pSecFn->QueryContextAttributes(&backend->ctxt->ctxt_handle,
                                       SECPKG_ATTR_APPLICATION_PROTOCOL,
                                       &alpn_result);

    if(sspi_status != SEC_E_OK) {
      failf(data, "schannel: failed to retrieve ALPN result");
      return CURLE_SSL_CONNECT_ERROR;
    }

    if(alpn_result.ProtoNegoStatus ==
       SecApplicationProtocolNegotiationStatus_Success) {
      unsigned char prev_alpn = cf->conn->alpn;

      Curl_alpn_set_negotiated(cf, data, connssl, alpn_result.ProtocolId,
                               alpn_result.ProtocolIdSize);
      if(backend->recv_renegotiating) {
        if(prev_alpn != cf->conn->alpn &&
           prev_alpn != CURL_HTTP_VERSION_NONE) {
          /* Renegotiation selected a different protocol now, we cannot
           * deal with this */
          failf(data, "schannel: server selected an ALPN protocol too late");
          return CURLE_SSL_CONNECT_ERROR;
        }
      }
    }
    else {
      if(!backend->recv_renegotiating)
        Curl_alpn_set_negotiated(cf, data, connssl, NULL, 0);
    }
  }
#endif

  /* save the current session data for possible reuse */
  if(ssl_config->primary.cache_session) {
    Curl_ssl_scache_lock(data);
    /* Up ref count since call takes ownership */
    backend->cred->refcount++;
    result = Curl_ssl_scache_add_obj(cf, data, connssl->peer.scache_key,
                                     backend->cred, schannel_session_free);
    Curl_ssl_scache_unlock(data);
    if(result)
      return result;
  }

  if(data->set.ssl.certinfo) {
    int certs_count = 0;
    sspi_status =
      Curl_pSecFn->QueryContextAttributes(&backend->ctxt->ctxt_handle,
                                       SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                       &ccert_context);

    if((sspi_status != SEC_E_OK) || !ccert_context) {
      failf(data, "schannel: failed to retrieve remote cert context");
      return CURLE_PEER_FAILED_VERIFICATION;
    }

    traverse_cert_store(ccert_context, cert_counter_callback, &certs_count);

    result = Curl_ssl_init_certinfo(data, certs_count);
    if(!result) {
      struct Adder_args args;
      args.data = data;
      args.idx = 0;
      args.certs_count = certs_count;
      args.result = CURLE_OK;
      traverse_cert_store(ccert_context, add_cert_to_certinfo, &args);
      result = args.result;
    }
    CertFreeCertificateContext(ccert_context);
    if(result)
      return result;
  }

  connssl->connecting_state = ssl_connect_done;

  return CURLE_OK;
}

static CURLcode schannel_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  CURLcode result;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;

  if(ssl_connect_1 == connssl->connecting_state) {
    result = schannel_connect_step1(cf, data);
    if(result)
      return result;
  }

  if(ssl_connect_2 == connssl->connecting_state) {
    result = schannel_connect_step2(cf, data);
    if(result)
      return result;
  }

  if(ssl_connect_3 == connssl->connecting_state) {
    result = schannel_connect_step3(cf, data);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;

#ifdef SECPKG_ATTR_ENDPOINT_BINDINGS
    /* When SSPI is used in combination with Schannel
     * we need the Schannel context to create the Schannel
     * binding to pass the IIS extended protection checks.
     * Available on Windows 7 or later.
     */
    {
      struct schannel_ssl_backend_data *backend =
        (struct schannel_ssl_backend_data *)connssl->backend;
      DEBUGASSERT(backend);
      cf->conn->sslContext = &backend->ctxt->ctxt_handle;
    }
#endif

    *done = TRUE;
  }

  return CURLE_OK;
}

static ssize_t
schannel_send(struct Curl_cfilter *cf, struct Curl_easy *data,
              const void *buf, size_t len, CURLcode *err)
{
  ssize_t written = -1;
  size_t data_len = 0;
  unsigned char *ptr = NULL;
  struct ssl_connect_data *connssl = cf->ctx;
  SecBuffer outbuf[4];
  SecBufferDesc outbuf_desc;
  SECURITY_STATUS sspi_status = SEC_E_OK;
  CURLcode result;
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;

  DEBUGASSERT(backend);

  /* check if the maximum stream sizes were queried */
  if(backend->stream_sizes.cbMaximumMessage == 0) {
    sspi_status = Curl_pSecFn->QueryContextAttributes(
      &backend->ctxt->ctxt_handle,
      SECPKG_ATTR_STREAM_SIZES,
      &backend->stream_sizes);
    if(sspi_status != SEC_E_OK) {
      *err = CURLE_SEND_ERROR;
      return -1;
    }
  }

  /* check if the buffer is longer than the maximum message length */
  if(len > backend->stream_sizes.cbMaximumMessage) {
    len = backend->stream_sizes.cbMaximumMessage;
  }

  /* calculate the complete message length and allocate a buffer for it */
  data_len = backend->stream_sizes.cbHeader + len +
    backend->stream_sizes.cbTrailer;
  ptr = (unsigned char *) MALLOC(data_len);
  if(!ptr) {
    *err = CURLE_OUT_OF_MEMORY;
    return -1;
  }

  /* setup output buffers (header, data, trailer, empty) */
  InitSecBuffer(&outbuf[0], SECBUFFER_STREAM_HEADER,
                ptr, backend->stream_sizes.cbHeader);
  InitSecBuffer(&outbuf[1], SECBUFFER_DATA,
                ptr + backend->stream_sizes.cbHeader, curlx_uztoul(len));
  InitSecBuffer(&outbuf[2], SECBUFFER_STREAM_TRAILER,
                ptr + backend->stream_sizes.cbHeader + len,
                backend->stream_sizes.cbTrailer);
  InitSecBuffer(&outbuf[3], SECBUFFER_EMPTY, NULL, 0);
  InitSecBufferDesc(&outbuf_desc, outbuf, 4);

  /* copy data into output buffer */
  memcpy(outbuf[1].pvBuffer, buf, len);

  /* https://msdn.microsoft.com/en-us/library/windows/desktop/aa375390.aspx */
  sspi_status = Curl_pSecFn->EncryptMessage(&backend->ctxt->ctxt_handle, 0,
                                         &outbuf_desc, 0);

  /* check if the message was encrypted */
  if(sspi_status == SEC_E_OK) {
    written = 0;

    /* send the encrypted message including header, data and trailer */
    len = outbuf[0].cbBuffer + outbuf[1].cbBuffer + outbuf[2].cbBuffer;

    /*
      it is important to send the full message which includes the header,
      encrypted payload, and trailer. Until the client receives all the
      data a coherent message has not been delivered and the client
      cannot read any of it.

      If we wanted to buffer the unwritten encrypted bytes, we would
      tell the client that all data it has requested to be sent has been
      sent. The unwritten encrypted bytes would be the first bytes to
      send on the next invocation.
      Here's the catch with this - if we tell the client that all the
      bytes have been sent, will the client call this method again to
      send the buffered data?  Looking at who calls this function, it
      seems the answer is NO.
    */

    /* send entire message or fail */
    while(len > (size_t)written) {
      ssize_t this_write = 0;
      int what;
      timediff_t timeout_ms = Curl_timeleft(data, NULL, FALSE);
      if(timeout_ms < 0) {
        /* we already got the timeout */
        failf(data, "schannel: timed out sending data "
              "(bytes sent: %zd)", written);
        *err = CURLE_OPERATION_TIMEDOUT;
        written = -1;
        break;
      }
      else if(!timeout_ms)
        timeout_ms = TIMEDIFF_T_MAX;
      what = SOCKET_WRITABLE(Curl_conn_cf_get_socket(cf, data), timeout_ms);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        *err = CURLE_SEND_ERROR;
        written = -1;
        break;
      }
      else if(0 == what) {
        failf(data, "schannel: timed out sending data "
              "(bytes sent: %zd)", written);
        *err = CURLE_OPERATION_TIMEDOUT;
        written = -1;
        break;
      }
      /* socket is writable */

       this_write = Curl_conn_cf_send(cf->next, data,
                                      ptr + written, len - written,
                                      FALSE, &result);
      if(result == CURLE_AGAIN)
        continue;
      else if(result != CURLE_OK) {
        *err = result;
        written = -1;
        break;
      }

      written += this_write;
    }
  }
  else if(sspi_status == SEC_E_INSUFFICIENT_MEMORY) {
    *err = CURLE_OUT_OF_MEMORY;
  }
  else{
    *err = CURLE_SEND_ERROR;
  }

  Curl_safefree(ptr);

  if(len == (size_t)written)
    /* Encrypted message including header, data and trailer entirely sent.
       The return value is the number of unencrypted bytes that were sent. */
    written = outbuf[1].cbBuffer;

  return written;
}

static ssize_t
schannel_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
              char *buf, size_t len, CURLcode *err)
{
  size_t size = 0;
  ssize_t nread = -1;
  struct ssl_connect_data *connssl = cf->ctx;
  unsigned char *reallocated_buffer;
  size_t reallocated_length;
  bool done = FALSE;
  SecBuffer inbuf[4];
  SecBufferDesc inbuf_desc;
  SECURITY_STATUS sspi_status = SEC_E_OK;
  /* we want the length of the encrypted buffer to be at least large enough
     that it can hold all the bytes requested and some TLS record overhead. */
  size_t min_encdata_length = len + CURL_SCHANNEL_BUFFER_FREE_SIZE;
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;

  DEBUGASSERT(backend);

  /****************************************************************************
   * Do not return or set backend->recv_unrecoverable_err unless in the
   * cleanup. The pattern for return error is set *err, optional infof, goto
   * cleanup.
   *
   * Some verbose debug messages are wrapped by SCH_DEV() instead of DEBUGF()
   * and only shown if CURL_SCHANNEL_DEV_DEBUG was defined at build time. These
   * messages are extra verbose and intended for curl developers debugging
   * Schannel recv decryption.
   *
   * Our priority is to always return as much decrypted data to the caller as
   * possible, even if an error occurs. The state of the decrypted buffer must
   * always be valid. Transfer of decrypted data to the caller's buffer is
   * handled in the cleanup.
   */

  SCH_DEV(infof(data, "schannel: client wants to read %zu bytes", len));
  *err = CURLE_OK;

  if(len && len <= backend->decdata_offset) {
    SCH_DEV(infof(data,
                  "schannel: enough decrypted data is already available"));
    goto cleanup;
  }
  else if(backend->recv_unrecoverable_err) {
    *err = backend->recv_unrecoverable_err;
    infof(data, "schannel: an unrecoverable error occurred in a prior call");
    goto cleanup;
  }
  else if(backend->recv_sspi_close_notify) {
    /* once a server has indicated shutdown there is no more encrypted data */
    infof(data, "schannel: server indicated shutdown in a prior call");
    goto cleanup;
  }
  /* it is debatable what to return when !len. Regardless we cannot return
     immediately because there may be data to decrypt (in the case we want to
     decrypt all encrypted cached data) so handle !len later in cleanup.
  */
  else if(len && !backend->recv_connection_closed) {
    /* increase enc buffer in order to fit the requested amount of data */
    size = backend->encdata_length - backend->encdata_offset;
    if(size < CURL_SCHANNEL_BUFFER_FREE_SIZE ||
       backend->encdata_length < min_encdata_length) {
      reallocated_length = backend->encdata_offset +
        CURL_SCHANNEL_BUFFER_FREE_SIZE;
      if(reallocated_length < min_encdata_length) {
        reallocated_length = min_encdata_length;
      }
      reallocated_buffer = REALLOC(backend->encdata_buffer,
                                   reallocated_length);
      if(!reallocated_buffer) {
        *err = CURLE_OUT_OF_MEMORY;
        failf(data, "schannel: unable to re-allocate memory");
        goto cleanup;
      }

      backend->encdata_buffer = reallocated_buffer;
      backend->encdata_length = reallocated_length;
      size = backend->encdata_length - backend->encdata_offset;
      SCH_DEV(infof(data, "schannel: encdata_buffer resized %zu",
                    backend->encdata_length));
    }

    SCH_DEV(infof(data,
                  "schannel: encrypted data buffer: offset %zu length %zu",
                  backend->encdata_offset, backend->encdata_length));

    /* read encrypted data from socket */
    nread = Curl_conn_cf_recv(cf->next, data,
                              (char *)(backend->encdata_buffer +
                                    backend->encdata_offset),
                              size, err);
    if(*err) {
      if(*err == CURLE_AGAIN)
        SCH_DEV(infof(data, "schannel: recv returned CURLE_AGAIN"));
      else if(*err == CURLE_RECV_ERROR)
        infof(data, "schannel: recv returned CURLE_RECV_ERROR");
      else
        infof(data, "schannel: recv returned error %d", *err);
    }
    else if(nread == 0) {
      backend->recv_connection_closed = TRUE;
      DEBUGF(infof(data, "schannel: server closed the connection"));
    }
    else if(nread > 0) {
      backend->encdata_offset += (size_t)nread;
      backend->encdata_is_incomplete = FALSE;
      SCH_DEV(infof(data, "schannel: encrypted data got %zd", nread));
    }
  }

  SCH_DEV(infof(data, "schannel: encrypted data buffer: offset %zu length %zu",
                backend->encdata_offset, backend->encdata_length));

  /* decrypt loop */
  while(backend->encdata_offset > 0 && sspi_status == SEC_E_OK &&
        (!len || backend->decdata_offset < len ||
         backend->recv_connection_closed)) {
    /* prepare data buffer for DecryptMessage call */
    InitSecBuffer(&inbuf[0], SECBUFFER_DATA, backend->encdata_buffer,
                  curlx_uztoul(backend->encdata_offset));

    /* we need 3 more empty input buffers for possible output */
    InitSecBuffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
    InitSecBuffer(&inbuf[2], SECBUFFER_EMPTY, NULL, 0);
    InitSecBuffer(&inbuf[3], SECBUFFER_EMPTY, NULL, 0);
    InitSecBufferDesc(&inbuf_desc, inbuf, 4);

    /* https://msdn.microsoft.com/en-us/library/windows/desktop/aa375348.aspx
     */
    sspi_status = Curl_pSecFn->DecryptMessage(&backend->ctxt->ctxt_handle,
                                           &inbuf_desc, 0, NULL);

    /* check if everything went fine (server may want to renegotiate
       or shutdown the connection context) */
    if(sspi_status == SEC_E_OK || sspi_status == SEC_I_RENEGOTIATE ||
       sspi_status == SEC_I_CONTEXT_EXPIRED) {
      /* check for successfully decrypted data, even before actual
         renegotiation or shutdown of the connection context */
      if(inbuf[1].BufferType == SECBUFFER_DATA) {
        SCH_DEV(infof(data, "schannel: decrypted data length: %lu",
                      inbuf[1].cbBuffer));

        /* increase buffer in order to fit the received amount of data */
        size = inbuf[1].cbBuffer > CURL_SCHANNEL_BUFFER_FREE_SIZE ?
          inbuf[1].cbBuffer : CURL_SCHANNEL_BUFFER_FREE_SIZE;
        if(backend->decdata_length - backend->decdata_offset < size ||
           backend->decdata_length < len) {
          /* increase internal decrypted data buffer */
          reallocated_length = backend->decdata_offset + size;
          /* make sure that the requested amount of data fits */
          if(reallocated_length < len) {
            reallocated_length = len;
          }
          reallocated_buffer = REALLOC(backend->decdata_buffer,
                                       reallocated_length);
          if(!reallocated_buffer) {
            *err = CURLE_OUT_OF_MEMORY;
            failf(data, "schannel: unable to re-allocate memory");
            goto cleanup;
          }
          backend->decdata_buffer = reallocated_buffer;
          backend->decdata_length = reallocated_length;
        }

        /* copy decrypted data to internal buffer */
        size = inbuf[1].cbBuffer;
        if(size) {
          memcpy(backend->decdata_buffer + backend->decdata_offset,
                 inbuf[1].pvBuffer, size);
          backend->decdata_offset += size;
        }

        SCH_DEV(infof(data, "schannel: decrypted data added: %zu", size));
        SCH_DEV(infof(data,
                      "schannel: decrypted cached: offset %zu length %zu",
                      backend->decdata_offset, backend->decdata_length));
      }

      /* check for remaining encrypted data */
      if(inbuf[3].BufferType == SECBUFFER_EXTRA && inbuf[3].cbBuffer > 0) {
        SCH_DEV(infof(data, "schannel: encrypted data length: %lu",
                      inbuf[3].cbBuffer));

        /* check if the remaining data is less than the total amount
         * and therefore begins after the already processed data
         */
        if(backend->encdata_offset > inbuf[3].cbBuffer) {
          /* move remaining encrypted data forward to the beginning of
             buffer */
          memmove(backend->encdata_buffer,
                  (backend->encdata_buffer + backend->encdata_offset) -
                  inbuf[3].cbBuffer, inbuf[3].cbBuffer);
          backend->encdata_offset = inbuf[3].cbBuffer;
        }

        SCH_DEV(infof(data,
                      "schannel: encrypted cached: offset %zu length %zu",
                      backend->encdata_offset, backend->encdata_length));
      }
      else {
        /* reset encrypted buffer offset, because there is no data remaining */
        backend->encdata_offset = 0;
      }

      /* check if server wants to renegotiate the connection context */
      if(sspi_status == SEC_I_RENEGOTIATE) {
        infof(data, "schannel: remote party requests renegotiation");
        if(*err && *err != CURLE_AGAIN) {
          infof(data, "schannel: cannot renegotiate, an error is pending");
          goto cleanup;
        }

        /* begin renegotiation */
        infof(data, "schannel: renegotiating SSL/TLS connection");
        connssl->state = ssl_connection_negotiating;
        connssl->connecting_state = ssl_connect_2;
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        backend->recv_renegotiating = TRUE;
        *err = schannel_connect(cf, data, &done);
        backend->recv_renegotiating = FALSE;
        if(*err) {
          infof(data, "schannel: renegotiation failed");
          goto cleanup;
        }
        /* now retry receiving data */
        sspi_status = SEC_E_OK;
        infof(data, "schannel: SSL/TLS connection renegotiated");
        continue;
      }
      /* check if the server closed the connection */
      else if(sspi_status == SEC_I_CONTEXT_EXPIRED) {
        /* In Windows 2000 SEC_I_CONTEXT_EXPIRED (close_notify) is not
           returned so we have to work around that in cleanup. */
        backend->recv_sspi_close_notify = TRUE;
        if(!backend->recv_connection_closed)
          backend->recv_connection_closed = TRUE;
        /* We received the close notify just fine, any error we got
         * from the lower filters afterwards (e.g. the socket), is not
         * an error on the TLS data stream. That one ended here. */
        if(*err == CURLE_RECV_ERROR)
          *err = CURLE_OK;
        infof(data,
              "schannel: server close notification received (close_notify)");
        goto cleanup;
      }
    }
    else if(sspi_status == SEC_E_INCOMPLETE_MESSAGE) {
      backend->encdata_is_incomplete = TRUE;
      if(!*err)
        *err = CURLE_AGAIN;
      SCH_DEV(infof(data, "schannel: failed to decrypt data, need more data"));
      goto cleanup;
    }
    else {
#ifndef CURL_DISABLE_VERBOSE_STRINGS
      char buffer[STRERROR_LEN];
      failf(data, "schannel: failed to read data from server: %s",
            Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
#endif
      *err = CURLE_RECV_ERROR;
      goto cleanup;
    }
  }

  SCH_DEV(infof(data, "schannel: encrypted data buffer: offset %zu length %zu",
                backend->encdata_offset, backend->encdata_length));

  SCH_DEV(infof(data, "schannel: decrypted data buffer: offset %zu length %zu",
                backend->decdata_offset, backend->decdata_length));

cleanup:
  /* Warning- there is no guarantee the encdata state is valid at this point */
  SCH_DEV(infof(data, "schannel: schannel_recv cleanup"));

  /* Error if the connection has closed without a close_notify.

     The behavior here is a matter of debate. We do not want to be vulnerable
     to a truncation attack however there is some browser precedent for
     ignoring the close_notify for compatibility reasons.

     Additionally, Windows 2000 (v5.0) is a special case since it seems it
     does not return close_notify. In that case if the connection was closed we
     assume it was graceful (close_notify) since there does not seem to be a
     way to tell.
  */
  if(len && !backend->decdata_offset && backend->recv_connection_closed &&
     !backend->recv_sspi_close_notify) {
    bool isWin2k = curlx_verify_windows_version(5, 0, 0, PLATFORM_WINNT,
                                                VERSION_EQUAL);

    if(isWin2k && sspi_status == SEC_E_OK)
      backend->recv_sspi_close_notify = TRUE;
    else {
      *err = CURLE_RECV_ERROR;
      failf(data, "schannel: server closed abruptly (missing close_notify)");
    }
  }

  /* Any error other than CURLE_AGAIN is an unrecoverable error. */
  if(*err && *err != CURLE_AGAIN)
    backend->recv_unrecoverable_err = *err;

  size = len < backend->decdata_offset ? len : backend->decdata_offset;
  if(size) {
    memcpy(buf, backend->decdata_buffer, size);
    memmove(backend->decdata_buffer, backend->decdata_buffer + size,
            backend->decdata_offset - size);
    backend->decdata_offset -= size;
    SCH_DEV(infof(data, "schannel: decrypted data returned %zu", size));
    SCH_DEV(infof(data,
                  "schannel: decrypted data buffer: offset %zu length %zu",
                  backend->decdata_offset, backend->decdata_length));
    *err = CURLE_OK;
    return (ssize_t)size;
  }

  if(!*err && !backend->recv_connection_closed)
    *err = CURLE_AGAIN;

  /* it is debatable what to return when !len. We could return whatever error
     we got from decryption but instead we override here so the return is
     consistent.
  */
  if(!len)
    *err = CURLE_OK;

  return *err ? -1 : 0;
}

static bool schannel_data_pending(struct Curl_cfilter *cf,
                                  const struct Curl_easy *data)
{
  const struct ssl_connect_data *connssl = cf->ctx;
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;

  (void)data;
  DEBUGASSERT(backend);

  if(backend->ctxt) /* SSL/TLS is in use */
    return backend->decdata_offset > 0 ||
           (backend->encdata_offset > 0 && !backend->encdata_is_incomplete) ||
           backend->recv_connection_closed ||
           backend->recv_sspi_close_notify ||
           backend->recv_unrecoverable_err;
  else
    return FALSE;
}

/* shut down the SSL connection and clean up related memory.
   this function can be called multiple times on the same connection including
   if the SSL connection failed (eg connection made but failed handshake). */
static CURLcode schannel_shutdown(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool send_shutdown, bool *done)
{
  /* See https://msdn.microsoft.com/en-us/library/windows/desktop/aa380138.aspx
   * Shutting Down an Schannel Connection
   */
  struct ssl_connect_data *connssl = cf->ctx;
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;
  CURLcode result = CURLE_OK;

  if(cf->shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }

  DEBUGASSERT(data);
  DEBUGASSERT(backend);

  /* Not supported in schannel */
  (void)send_shutdown;

  *done = FALSE;
  if(backend->ctxt) {
    infof(data, "schannel: shutting down SSL/TLS connection with %s port %d",
          connssl->peer.hostname, connssl->peer.port);
  }

  if(!backend->ctxt || cf->shutdown) {
    *done = TRUE;
    goto out;
  }

  if(backend->cred && backend->ctxt && !backend->sent_shutdown) {
    SecBufferDesc BuffDesc;
    SecBuffer Buffer;
    SECURITY_STATUS sspi_status;
    SecBuffer outbuf;
    SecBufferDesc outbuf_desc;
    DWORD dwshut = SCHANNEL_SHUTDOWN;

    InitSecBuffer(&Buffer, SECBUFFER_TOKEN, &dwshut, sizeof(dwshut));
    InitSecBufferDesc(&BuffDesc, &Buffer, 1);

    sspi_status = Curl_pSecFn->ApplyControlToken(&backend->ctxt->ctxt_handle,
                                              &BuffDesc);

    if(sspi_status != SEC_E_OK) {
      char buffer[STRERROR_LEN];
      failf(data, "schannel: ApplyControlToken failure: %s",
            Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
      result = CURLE_SEND_ERROR;
      goto out;
    }

    /* setup output buffer */
    InitSecBuffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
    InitSecBufferDesc(&outbuf_desc, &outbuf, 1);

    sspi_status = Curl_pSecFn->InitializeSecurityContext(
      &backend->cred->cred_handle,
      &backend->ctxt->ctxt_handle,
      backend->cred->sni_hostname,
      backend->req_flags,
      0,
      0,
      NULL,
      0,
      &backend->ctxt->ctxt_handle,
      &outbuf_desc,
      &backend->ret_flags,
      &backend->ctxt->time_stamp);

    if((sspi_status == SEC_E_OK) || (sspi_status == SEC_I_CONTEXT_EXPIRED)) {
      /* send close message which is in output buffer */
      ssize_t written = Curl_conn_cf_send(cf->next, data,
                                          outbuf.pvBuffer, outbuf.cbBuffer,
                                          FALSE, &result);
      Curl_pSecFn->FreeContextBuffer(outbuf.pvBuffer);
      if(!result) {
        if(written < (ssize_t)outbuf.cbBuffer) {
          failf(data, "schannel: failed to send close msg: %s"
                " (bytes written: %zd)", curl_easy_strerror(result), written);
          result = CURLE_SEND_ERROR;
          goto out;
        }
        backend->sent_shutdown = TRUE;
        *done = TRUE;
      }
      else if(result == CURLE_AGAIN) {
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        result = CURLE_OK;
        goto out;
      }
      else {
        if(!backend->recv_connection_closed) {
          failf(data, "schannel: error sending close msg: %d", result);
          result = CURLE_SEND_ERROR;
          goto out;
        }
        /* Looks like server already closed the connection.
         * An error to send our close notify is not a failure. */
        *done = TRUE;
        result = CURLE_OK;
      }
    }
  }

  /* If the connection seems open and we have not seen the close notify
   * from the server yet, try to receive it. */
  if(backend->cred && backend->ctxt &&
     !backend->recv_sspi_close_notify && !backend->recv_connection_closed) {
    char buffer[1024];
    ssize_t nread;

    nread = schannel_recv(cf, data, buffer, sizeof(buffer), &result);
    if(nread > 0) {
      /* still data coming in? */
    }
    else if(nread == 0) {
      /* We got the close notify alert and are done. */
      backend->recv_connection_closed = TRUE;
      *done = TRUE;
    }
    else if(nread < 0 && result == CURLE_AGAIN) {
      connssl->io_need = CURL_SSL_IO_NEED_RECV;
    }
    else {
      CURL_TRC_CF(data, cf, "SSL shutdown, error %d", result);
      result = CURLE_RECV_ERROR;
    }
  }

out:
  cf->shutdown = (result || *done);
  return result;
}

static void schannel_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;

  DEBUGASSERT(data);
  DEBUGASSERT(backend);

  /* free SSPI Schannel API security context handle */
  if(backend->ctxt) {
    DEBUGF(infof(data, "schannel: clear security context handle"));
    Curl_pSecFn->DeleteSecurityContext(&backend->ctxt->ctxt_handle);
    Curl_safefree(backend->ctxt);
  }

  /* free SSPI Schannel API credential handle */
  if(backend->cred) {
    Curl_ssl_scache_lock(data);
    schannel_session_free(backend->cred);
    Curl_ssl_scache_unlock(data);
    backend->cred = NULL;
  }

  /* free internal buffer for received encrypted data */
  if(backend->encdata_buffer) {
    Curl_safefree(backend->encdata_buffer);
    backend->encdata_length = 0;
    backend->encdata_offset = 0;
    backend->encdata_is_incomplete = FALSE;
  }

  /* free internal buffer for received decrypted data */
  if(backend->decdata_buffer) {
    Curl_safefree(backend->decdata_buffer);
    backend->decdata_length = 0;
    backend->decdata_offset = 0;
  }
}

static int schannel_init(void)
{
#if defined(HAS_ALPN_SCHANNEL) && !defined(UNDER_CE)
  bool wine = FALSE;
  bool wine_has_alpn = FALSE;

#ifndef CURL_WINDOWS_UWP
  typedef const char *(APIENTRY *WINE_GET_VERSION_FN)(void);
  /* GetModuleHandle() not available for UWP.
     Assume no WINE because WINE has no UWP support. */
  WINE_GET_VERSION_FN p_wine_get_version =
    CURLX_FUNCTION_CAST(WINE_GET_VERSION_FN,
                        (GetProcAddress(GetModuleHandleA("ntdll"),
                                        "wine_get_version")));
  wine = !!p_wine_get_version;
  if(wine) {
    const char *wine_version = p_wine_get_version();  /* e.g. "6.0.2" */
    /* Assume ALPN support with WINE 6.0 or upper */
    wine_has_alpn = wine_version && atoi(wine_version) >= 6;
  }
#endif
  if(wine)
    s_win_has_alpn = wine_has_alpn;
  else {
    /* ALPN is supported on Windows 8.1 / Server 2012 R2 and above. */
    s_win_has_alpn = curlx_verify_windows_version(6, 3, 0, PLATFORM_WINNT,
                                                  VERSION_GREATER_THAN_EQUAL);
  }
#endif /* HAS_ALPN_SCHANNEL && !UNDER_CE */

  return Curl_sspi_global_init() == CURLE_OK ? 1 : 0;
}

static void schannel_cleanup(void)
{
  Curl_sspi_global_cleanup();
}

static size_t schannel_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "Schannel");
}

static CURLcode schannel_random(struct Curl_easy *data UNUSED_PARAM,
                                unsigned char *entropy, size_t length)
{
  (void)data;

  return Curl_win32_random(entropy, length);
}

static CURLcode schannel_pkp_pin_peer_pubkey(struct Curl_cfilter *cf,
                                             struct Curl_easy *data,
                                             const char *pinnedpubkey)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;
  CERT_CONTEXT *pCertContextServer = NULL;

  /* Result is returned to caller */
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  DEBUGASSERT(backend);

  /* if a path was not specified, do not pin */
  if(!pinnedpubkey)
    return CURLE_OK;

  do {
    SECURITY_STATUS sspi_status;
    const char *x509_der;
    DWORD x509_der_len;
    struct Curl_X509certificate x509_parsed;
    struct Curl_asn1Element *pubkey;

    sspi_status =
      Curl_pSecFn->QueryContextAttributes(&backend->ctxt->ctxt_handle,
                                       SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                       &pCertContextServer);

    if((sspi_status != SEC_E_OK) || !pCertContextServer) {
      char buffer[STRERROR_LEN];
      failf(data, "schannel: Failed to read remote certificate context: %s",
            Curl_sspi_strerror(sspi_status, buffer, sizeof(buffer)));
      break; /* failed */
    }


    if(!(((pCertContextServer->dwCertEncodingType & X509_ASN_ENCODING) != 0) &&
         (pCertContextServer->cbCertEncoded > 0)))
      break;

    x509_der = (const char *)pCertContextServer->pbCertEncoded;
    x509_der_len = pCertContextServer->cbCertEncoded;
    memset(&x509_parsed, 0, sizeof(x509_parsed));
    if(Curl_parseX509(&x509_parsed, x509_der, x509_der + x509_der_len))
      break;

    pubkey = &x509_parsed.subjectPublicKeyInfo;
    if(!pubkey->header || pubkey->end <= pubkey->header) {
      failf(data, "SSL: failed retrieving public key from server certificate");
      break;
    }

    result = Curl_pin_peer_pubkey(data,
                                  pinnedpubkey,
                                  (const unsigned char *)pubkey->header,
                                  (size_t)(pubkey->end - pubkey->header));
    if(result) {
      failf(data, "SSL: public key does not match pinned public key");
    }
  } while(0);

  if(pCertContextServer)
    CertFreeCertificateContext(pCertContextServer);

  return result;
}

static void schannel_checksum(const unsigned char *input,
                              size_t inputlen,
                              unsigned char *checksum,
                              size_t checksumlen,
                              DWORD provType,
                              const unsigned int algId)
{
#ifdef CURL_WINDOWS_UWP
  (void)input;
  (void)inputlen;
  (void)provType;
  (void)algId;
  memset(checksum, 0, checksumlen);
#else
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  DWORD cbHashSize = 0;
  DWORD dwHashSizeLen = (DWORD)sizeof(cbHashSize);
  DWORD dwChecksumLen = (DWORD)checksumlen;

  /* since this can fail in multiple ways, zero memory first so we never
   * return old data
   */
  memset(checksum, 0, checksumlen);

  if(!CryptAcquireContext(&hProv, NULL, NULL, provType,
                          CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return; /* failed */

  do {
    if(!CryptCreateHash(hProv, algId, 0, 0, &hHash))
      break; /* failed */

#ifdef __MINGW32CE__
    /* workaround for CeGCC, should be (const BYTE*) */
    if(!CryptHashData(hHash, (BYTE*)CURL_UNCONST(input), (DWORD)inputlen, 0))
#else
    if(!CryptHashData(hHash, input, (DWORD)inputlen, 0))
#endif
      break; /* failed */

    /* get hash size */
    if(!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&cbHashSize,
                          &dwHashSizeLen, 0))
      break; /* failed */

    /* check hash size */
    if(checksumlen < cbHashSize)
      break; /* failed */

    if(CryptGetHashParam(hHash, HP_HASHVAL, checksum, &dwChecksumLen, 0))
      break; /* failed */
  } while(0);

  if(hHash)
    CryptDestroyHash(hHash);

  if(hProv)
    CryptReleaseContext(hProv, 0);
#endif
}

static CURLcode schannel_sha256sum(const unsigned char *input,
                                   size_t inputlen,
                                   unsigned char *sha256sum,
                                   size_t sha256len)
{
  schannel_checksum(input, inputlen, sha256sum, sha256len,
                    PROV_RSA_AES, CALG_SHA_256);
  return CURLE_OK;
}

static void *schannel_get_internals(struct ssl_connect_data *connssl,
                                    CURLINFO info UNUSED_PARAM)
{
  struct schannel_ssl_backend_data *backend =
    (struct schannel_ssl_backend_data *)connssl->backend;
  (void)info;
  DEBUGASSERT(backend);
  return &backend->ctxt->ctxt_handle;
}

HCERTSTORE Curl_schannel_get_cached_cert_store(struct Curl_cfilter *cf,
                                               const struct Curl_easy *data)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_multi *multi = data->multi;
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  struct schannel_cert_share *share;
  const struct ssl_general_config *cfg = &data->set.general_ssl;
  timediff_t timeout_ms;
  timediff_t elapsed_ms;
  struct curltime now;
  unsigned char info_blob_digest[CURL_SHA256_DIGEST_LENGTH];

  DEBUGASSERT(multi);

  if(!multi) {
    return NULL;
  }

  share = Curl_hash_pick(&multi->proto_hash,
                         CURL_UNCONST(MPROTO_SCHANNEL_CERT_SHARE_KEY),
                         sizeof(MPROTO_SCHANNEL_CERT_SHARE_KEY)-1);
  if(!share || !share->cert_store) {
    return NULL;
  }

  /* zero ca_cache_timeout completely disables caching */
  if(!cfg->ca_cache_timeout) {
    return NULL;
  }

  /* check for cache timeout by using the cached_x509_store_expired timediff
     calculation pattern from openssl.c.
     negative timeout means retain forever. */
  timeout_ms = cfg->ca_cache_timeout * (timediff_t)1000;
  if(timeout_ms >= 0) {
    now = Curl_now();
    elapsed_ms = Curl_timediff(now, share->time);
    if(elapsed_ms >= timeout_ms) {
      return NULL;
    }
  }

  if(ca_info_blob) {
    if(share->CAinfo_blob_size != ca_info_blob->len) {
      return NULL;
    }
    schannel_sha256sum((const unsigned char *)ca_info_blob->data,
                       ca_info_blob->len,
                       info_blob_digest,
                       CURL_SHA256_DIGEST_LENGTH);
    if(memcmp(share->CAinfo_blob_digest, info_blob_digest,
              CURL_SHA256_DIGEST_LENGTH)) {
      return NULL;
    }
  }
  else {
    if(!conn_config->CAfile || !share->CAfile ||
       strcmp(share->CAfile, conn_config->CAfile)) {
      return NULL;
    }
  }

  return share->cert_store;
}

static void schannel_cert_share_free(void *key, size_t key_len, void *p)
{
  struct schannel_cert_share *share = p;
  DEBUGASSERT(key_len == (sizeof(MPROTO_SCHANNEL_CERT_SHARE_KEY)-1));
  DEBUGASSERT(!memcmp(MPROTO_SCHANNEL_CERT_SHARE_KEY, key, key_len));
  (void)key;
  (void)key_len;
  if(share->cert_store) {
    CertCloseStore(share->cert_store, 0);
  }
  FREE(share->CAfile);
  FREE(share);
}

bool Curl_schannel_set_cached_cert_store(struct Curl_cfilter *cf,
                                         const struct Curl_easy *data,
                                         HCERTSTORE cert_store)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_multi *multi = data->multi;
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  struct schannel_cert_share *share;
  size_t CAinfo_blob_size = 0;
  char *CAfile = NULL;

  DEBUGASSERT(multi);

  if(!multi) {
    return FALSE;
  }

  share = Curl_hash_pick(&multi->proto_hash,
                         CURL_UNCONST(MPROTO_SCHANNEL_CERT_SHARE_KEY),
                         sizeof(MPROTO_SCHANNEL_CERT_SHARE_KEY)-1);
  if(!share) {
    share = CALLOC(1, sizeof(*share));
    if(!share) {
      return FALSE;
    }
    if(!Curl_hash_add2(&multi->proto_hash,
                       CURL_UNCONST(MPROTO_SCHANNEL_CERT_SHARE_KEY),
                       sizeof(MPROTO_SCHANNEL_CERT_SHARE_KEY)-1,
                       share, schannel_cert_share_free)) {
      FREE(share);
      return FALSE;
    }
  }

  if(ca_info_blob) {
    schannel_sha256sum((const unsigned char *)ca_info_blob->data,
                       ca_info_blob->len,
                       share->CAinfo_blob_digest,
                       CURL_SHA256_DIGEST_LENGTH);
    CAinfo_blob_size = ca_info_blob->len;
  }
  else {
    if(conn_config->CAfile) {
      CAfile = STRDUP(conn_config->CAfile);
      if(!CAfile) {
        return FALSE;
      }
    }
  }

  /* free old cache data */
  if(share->cert_store) {
    CertCloseStore(share->cert_store, 0);
  }
  FREE(share->CAfile);

  share->time = Curl_now();
  share->cert_store = cert_store;
  share->CAinfo_blob_size = CAinfo_blob_size;
  share->CAfile = CAfile;
  return TRUE;
}

const struct Curl_ssl Curl_ssl_schannel = {
  { CURLSSLBACKEND_SCHANNEL, "schannel" }, /* info */

  SSLSUPP_CERTINFO |
#ifdef HAS_MANUAL_VERIFY_API
  SSLSUPP_CAINFO_BLOB |
#endif
#ifndef CURL_WINDOWS_UWP
  SSLSUPP_PINNEDPUBKEY |
#endif
  SSLSUPP_CA_CACHE |
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CIPHER_LIST,

  sizeof(struct schannel_ssl_backend_data),

  schannel_init,                     /* init */
  schannel_cleanup,                  /* cleanup */
  schannel_version,                  /* version */
  schannel_shutdown,                 /* shutdown */
  schannel_data_pending,             /* data_pending */
  schannel_random,                   /* random */
  NULL,                              /* cert_status_request */
  schannel_connect,                  /* connect */
  Curl_ssl_adjust_pollset,           /* adjust_pollset */
  schannel_get_internals,            /* get_internals */
  schannel_close,                    /* close_one */
  NULL,                              /* close_all */
  NULL,                              /* set_engine */
  NULL,                              /* set_engine_default */
  NULL,                              /* engines_list */
  NULL,                              /* false_start */
  schannel_sha256sum,                /* sha256sum */
  schannel_recv,                     /* recv decrypted data */
  schannel_send,                     /* send data to encrypt */
  NULL,                              /* get_channel_binding */
};

#endif /* USE_SCHANNEL */
