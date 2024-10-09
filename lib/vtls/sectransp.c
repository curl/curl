/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Nick Zitzmann, <nickzman@gmail.com>.
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
 * Source file for all iOS and macOS Secure Transport-specific code for the
 * TLS/SSL layer. No code but vtls.c should ever call or use these functions.
 */

#include "curl_setup.h"

#ifdef USE_SECTRANSP

#include "urldata.h" /* for the Curl_easy definition */
#include "curl_base64.h"
#include "strtok.h"
#include "multiif.h"
#include "strcase.h"
#include "x509asn1.h"
#include "strerror.h"
#include "cipher_suite.h"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
#endif /* __clang__ */

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
#endif

#include <limits.h>

#include <Security/Security.h>
/* For some reason, when building for iOS, the omnibus header above does
 * not include SecureTransport.h as of iOS SDK 5.1. */
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>

/* The Security framework has changed greatly between iOS and different macOS
   versions, and we will try to support as many of them as we can (back to
   Leopard and iOS 5) by using macros and weak-linking.

   In general, you want to build this using the most recent OS SDK, since some
   features require curl to be built against the latest SDK. TLS 1.1 and 1.2
   support, for instance, require the macOS 10.8 SDK or later. TLS 1.3
   requires the macOS 10.13 or iOS 11 SDK or later. */
#if (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE))

#if MAC_OS_X_VERSION_MAX_ALLOWED < 1050
#error "The Secure Transport backend requires Leopard or later."
#endif /* MAC_OS_X_VERSION_MAX_ALLOWED < 1050 */

#define CURL_BUILD_IOS 0
#define CURL_BUILD_IOS_7 0
#define CURL_BUILD_IOS_9 0
#define CURL_BUILD_IOS_11 0
#define CURL_BUILD_IOS_13 0
#define CURL_BUILD_MAC 1
/* This is the maximum API level we are allowed to use when building: */
#define CURL_BUILD_MAC_10_5 MAC_OS_X_VERSION_MAX_ALLOWED >= 1050
#define CURL_BUILD_MAC_10_6 MAC_OS_X_VERSION_MAX_ALLOWED >= 1060
#define CURL_BUILD_MAC_10_7 MAC_OS_X_VERSION_MAX_ALLOWED >= 1070
#define CURL_BUILD_MAC_10_8 MAC_OS_X_VERSION_MAX_ALLOWED >= 1080
#define CURL_BUILD_MAC_10_9 MAC_OS_X_VERSION_MAX_ALLOWED >= 1090
#define CURL_BUILD_MAC_10_11 MAC_OS_X_VERSION_MAX_ALLOWED >= 101100
#define CURL_BUILD_MAC_10_13 MAC_OS_X_VERSION_MAX_ALLOWED >= 101300
#define CURL_BUILD_MAC_10_15 MAC_OS_X_VERSION_MAX_ALLOWED >= 101500
/* These macros mean "the following code is present to allow runtime backward
   compatibility with at least this cat or earlier":
   (You set this at build-time using the compiler command line option
   "-mmacosx-version-min.") */
#define CURL_SUPPORT_MAC_10_5 MAC_OS_X_VERSION_MIN_REQUIRED <= 1050
#define CURL_SUPPORT_MAC_10_6 MAC_OS_X_VERSION_MIN_REQUIRED <= 1060
#define CURL_SUPPORT_MAC_10_7 MAC_OS_X_VERSION_MIN_REQUIRED <= 1070
#define CURL_SUPPORT_MAC_10_8 MAC_OS_X_VERSION_MIN_REQUIRED <= 1080
#define CURL_SUPPORT_MAC_10_9 MAC_OS_X_VERSION_MIN_REQUIRED <= 1090

#elif TARGET_OS_EMBEDDED || TARGET_OS_IPHONE
#define CURL_BUILD_IOS 1
#define CURL_BUILD_IOS_7 __IPHONE_OS_VERSION_MAX_ALLOWED >= 70000
#define CURL_BUILD_IOS_9 __IPHONE_OS_VERSION_MAX_ALLOWED >= 90000
#define CURL_BUILD_IOS_11 __IPHONE_OS_VERSION_MAX_ALLOWED >= 110000
#define CURL_BUILD_IOS_13 __IPHONE_OS_VERSION_MAX_ALLOWED >= 130000
#define CURL_BUILD_MAC 0
#define CURL_BUILD_MAC_10_5 0
#define CURL_BUILD_MAC_10_6 0
#define CURL_BUILD_MAC_10_7 0
#define CURL_BUILD_MAC_10_8 0
#define CURL_BUILD_MAC_10_9 0
#define CURL_BUILD_MAC_10_11 0
#define CURL_BUILD_MAC_10_13 0
#define CURL_BUILD_MAC_10_15 0
#define CURL_SUPPORT_MAC_10_5 0
#define CURL_SUPPORT_MAC_10_6 0
#define CURL_SUPPORT_MAC_10_7 0
#define CURL_SUPPORT_MAC_10_8 0
#define CURL_SUPPORT_MAC_10_9 0

#else
#error "The Secure Transport backend requires iOS or macOS."
#endif /* (TARGET_OS_MAC && !(TARGET_OS_EMBEDDED || TARGET_OS_IPHONE)) */

#if CURL_BUILD_MAC
#include <sys/sysctl.h>
#endif /* CURL_BUILD_MAC */

#include "sendf.h"
#include "inet_pton.h"
#include "connect.h"
#include "select.h"
#include "vtls.h"
#include "vtls_int.h"
#include "sectransp.h"
#include "curl_printf.h"
#include "strdup.h"

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"


/* From MacTypes.h (which we cannot include because it is not present in
   iOS: */
#define ioErr -36
#define paramErr -50

struct st_ssl_backend_data {
  SSLContextRef ssl_ctx;
  bool ssl_direction; /* true if writing, false if reading */
  size_t ssl_write_buffered_length;
  BIT(sent_shutdown);
};

/* Create the list of default ciphers to use by making an intersection of the
 * ciphers supported by Secure Transport and the list below, using the order
 * of the former.
 * This list is based on TLS recommendations by Mozilla, balancing between
 * security and wide compatibility: "Most ciphers that are not clearly broken
 * and dangerous to use are supported"
 */
static const uint16_t default_ciphers[] = {
  TLS_RSA_WITH_3DES_EDE_CBC_SHA,                    /* 0x000A */
  TLS_RSA_WITH_AES_128_CBC_SHA,                     /* 0x002F */
  TLS_RSA_WITH_AES_256_CBC_SHA,                     /* 0x0035 */

#if CURL_BUILD_MAC_10_6 || CURL_BUILD_IOS
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,             /* 0xC009 */
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,             /* 0xC00A */
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,               /* 0xC013 */
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,               /* 0xC014 */
#endif /* CURL_BUILD_MAC_10_6 || CURL_BUILD_IOS */

#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
  TLS_RSA_WITH_AES_128_CBC_SHA256,                  /* 0x003C */
  TLS_RSA_WITH_AES_256_CBC_SHA256,                  /* 0x003D */
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,              /* 0x0067 */
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,              /* 0x006B */
  TLS_RSA_WITH_AES_128_GCM_SHA256,                  /* 0x009C */
  TLS_RSA_WITH_AES_256_GCM_SHA384,                  /* 0x009D */
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,              /* 0x009E */
  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,              /* 0x009F */
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,          /* 0xC023 */
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,          /* 0xC024 */
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,            /* 0xC027 */
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,            /* 0xC028 */
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,          /* 0xC02B */
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,          /* 0xC02C */
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,            /* 0xC02F */
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,            /* 0xC030 */
#endif /* CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS */

#if CURL_BUILD_MAC_10_13 || CURL_BUILD_IOS_11
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,      /* 0xCCA8 */
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,    /* 0xCCA9 */

  /* TLSv1.3 is not supported by Secure Transport, but there is also other
   * code referencing TLSv1.3, like: kTLSProtocol13 ? */
  TLS_AES_128_GCM_SHA256,                           /* 0x1301 */
  TLS_AES_256_GCM_SHA384,                           /* 0x1302 */
  TLS_CHACHA20_POLY1305_SHA256,                     /* 0x1303 */
#endif /* CURL_BUILD_MAC_10_13 || CURL_BUILD_IOS_11 */
};

#define DEFAULT_CIPHERS_LEN sizeof(default_ciphers)/sizeof(default_ciphers[0])


/* pinned public key support tests */

/* version 1 supports macOS 10.12+ and iOS 10+ */
#if ((TARGET_OS_IPHONE && __IPHONE_OS_VERSION_MIN_REQUIRED >= 100000) || \
    (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED  >= 101200))
#define SECTRANSP_PINNEDPUBKEY_V1 1
#endif

/* version 2 supports macOS 10.7+ */
#if (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070)
#define SECTRANSP_PINNEDPUBKEY_V2 1
#endif

#if defined(SECTRANSP_PINNEDPUBKEY_V1) || defined(SECTRANSP_PINNEDPUBKEY_V2)
/* this backend supports CURLOPT_PINNEDPUBLICKEY */
#define SECTRANSP_PINNEDPUBKEY 1
#endif /* SECTRANSP_PINNEDPUBKEY */

#ifdef SECTRANSP_PINNEDPUBKEY
/* both new and old APIs return rsa keys missing the spki header (not DER) */
static const unsigned char rsa4096SpkiHeader[] = {
                                       0x30, 0x82, 0x02, 0x22, 0x30, 0x0d,
                                       0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                       0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                                       0x00, 0x03, 0x82, 0x02, 0x0f, 0x00};

static const unsigned char rsa2048SpkiHeader[] = {
                                       0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
                                       0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                       0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                                       0x00, 0x03, 0x82, 0x01, 0x0f, 0x00};
#ifdef SECTRANSP_PINNEDPUBKEY_V1
/* the *new* version does not return DER encoded ecdsa certs like the old... */
static const unsigned char ecDsaSecp256r1SpkiHeader[] = {
                                       0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
                                       0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                                       0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                                       0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                                       0x42, 0x00};

static const unsigned char ecDsaSecp384r1SpkiHeader[] = {
                                       0x30, 0x76, 0x30, 0x10, 0x06, 0x07,
                                       0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
                                       0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
                                       0x00, 0x22, 0x03, 0x62, 0x00};
#endif /* SECTRANSP_PINNEDPUBKEY_V1 */
#endif /* SECTRANSP_PINNEDPUBKEY */

static OSStatus sectransp_bio_cf_in_read(SSLConnectionRef connection,
                                         void *buf,
                                         size_t *dataLength)  /* IN/OUT */
{
  struct Curl_cfilter *cf = (struct Curl_cfilter *)connection;
  struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nread;
  CURLcode result;
  OSStatus rtn = noErr;

  DEBUGASSERT(data);
  nread = Curl_conn_cf_recv(cf->next, data, buf, *dataLength, &result);
  CURL_TRC_CF(data, cf, "bio_read(len=%zu) -> %zd, result=%d",
              *dataLength, nread, result);
  if(nread < 0) {
    switch(result) {
      case CURLE_OK:
      case CURLE_AGAIN:
        rtn = errSSLWouldBlock;
        backend->ssl_direction = FALSE;
        break;
      default:
        rtn = ioErr;
        break;
    }
    nread = 0;
  }
  else if(nread == 0) {
    rtn = errSSLClosedGraceful;
  }
  else if((size_t)nread < *dataLength) {
    rtn = errSSLWouldBlock;
  }
  *dataLength = nread;
  return rtn;
}

static OSStatus sectransp_bio_cf_out_write(SSLConnectionRef connection,
                                           const void *buf,
                                           size_t *dataLength)  /* IN/OUT */
{
  struct Curl_cfilter *cf = (struct Curl_cfilter *)connection;
  struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nwritten;
  CURLcode result;
  OSStatus rtn = noErr;

  DEBUGASSERT(data);
  nwritten = Curl_conn_cf_send(cf->next, data, buf, *dataLength, FALSE,
                               &result);
  CURL_TRC_CF(data, cf, "bio_send(len=%zu) -> %zd, result=%d",
              *dataLength, nwritten, result);
  if(nwritten <= 0) {
    if(result == CURLE_AGAIN) {
      rtn = errSSLWouldBlock;
      backend->ssl_direction = TRUE;
    }
    else {
      rtn = ioErr;
    }
    nwritten = 0;
  }
  else if((size_t)nwritten < *dataLength) {
    rtn = errSSLWouldBlock;
  }
  *dataLength = nwritten;
  return rtn;
}

#if CURL_BUILD_MAC
CF_INLINE void GetDarwinVersionNumber(int *major, int *minor)
{
  int mib[2];
  char *os_version;
  size_t os_version_len;
  char *os_version_major, *os_version_minor;
  char *tok_buf;

  /* Get the Darwin kernel version from the kernel using sysctl(): */
  mib[0] = CTL_KERN;
  mib[1] = KERN_OSRELEASE;
  if(sysctl(mib, 2, NULL, &os_version_len, NULL, 0) == -1)
    return;
  os_version = malloc(os_version_len*sizeof(char));
  if(!os_version)
    return;
  if(sysctl(mib, 2, os_version, &os_version_len, NULL, 0) == -1) {
    free(os_version);
    return;
  }

  /* Parse the version: */
  os_version_major = strtok_r(os_version, ".", &tok_buf);
  os_version_minor = strtok_r(NULL, ".", &tok_buf);
  *major = atoi(os_version_major);
  *minor = atoi(os_version_minor);
  free(os_version);
}
#endif /* CURL_BUILD_MAC */

/* Apple provides a myriad of ways of getting information about a certificate
   into a string. Some are not available under iOS or newer cats. Here's a
   unified function for getting a string describing the certificate that ought
   to work in all cats starting with Leopard. */
CF_INLINE CFStringRef getsubject(SecCertificateRef cert)
{
  CFStringRef server_cert_summary = CFSTR("(null)");

#if CURL_BUILD_IOS
  /* iOS: There is only one way to do this. */
  server_cert_summary = SecCertificateCopySubjectSummary(cert);
#else
#if CURL_BUILD_MAC_10_7
  /* Lion & later: Get the long description if we can. */
  if(&SecCertificateCopyLongDescription)
    server_cert_summary =
      SecCertificateCopyLongDescription(NULL, cert, NULL);
  else
#endif /* CURL_BUILD_MAC_10_7 */
#if CURL_BUILD_MAC_10_6
  /* Snow Leopard: Get the certificate summary. */
  if(&SecCertificateCopySubjectSummary)
    server_cert_summary = SecCertificateCopySubjectSummary(cert);
  else
#endif /* CURL_BUILD_MAC_10_6 */
  /* Leopard is as far back as we go... */
  (void)SecCertificateCopyCommonName(cert, &server_cert_summary);
#endif /* CURL_BUILD_IOS */
  return server_cert_summary;
}

static CURLcode CopyCertSubject(struct Curl_easy *data,
                                SecCertificateRef cert, char **certp)
{
  CFStringRef c = getsubject(cert);
  CURLcode result = CURLE_OK;
  const char *direct;
  char *cbuf = NULL;
  *certp = NULL;

  if(!c) {
    failf(data, "SSL: invalid CA certificate subject");
    return CURLE_PEER_FAILED_VERIFICATION;
  }

  /* If the subject is already available as UTF-8 encoded (ie 'direct') then
     use that, else convert it. */
  direct = CFStringGetCStringPtr(c, kCFStringEncodingUTF8);
  if(direct) {
    *certp = strdup(direct);
    if(!*certp) {
      failf(data, "SSL: out of memory");
      result = CURLE_OUT_OF_MEMORY;
    }
  }
  else {
    size_t cbuf_size = ((size_t)CFStringGetLength(c) * 4) + 1;
    cbuf = calloc(1, cbuf_size);
    if(cbuf) {
      if(!CFStringGetCString(c, cbuf, (CFIndex)cbuf_size,
                             kCFStringEncodingUTF8)) {
        failf(data, "SSL: invalid CA certificate subject");
        result = CURLE_PEER_FAILED_VERIFICATION;
      }
      else
        /* pass back the buffer */
        *certp = cbuf;
    }
    else {
      failf(data, "SSL: could not allocate %zu bytes of memory", cbuf_size);
      result = CURLE_OUT_OF_MEMORY;
    }
  }
  if(result)
    free(cbuf);
  CFRelease(c);
  return result;
}

#if CURL_SUPPORT_MAC_10_6
/* The SecKeychainSearch API was deprecated in Lion, and using it will raise
   deprecation warnings, so let's not compile this unless it is necessary: */
static OSStatus CopyIdentityWithLabelOldSchool(char *label,
                                               SecIdentityRef *out_c_a_k)
{
  OSStatus status = errSecItemNotFound;
  SecKeychainAttributeList attr_list;
  SecKeychainAttribute attr;
  SecKeychainSearchRef search = NULL;
  SecCertificateRef cert = NULL;

  /* Set up the attribute list: */
  attr_list.count = 1L;
  attr_list.attr = &attr;

  /* Set up our lone search criterion: */
  attr.tag = kSecLabelItemAttr;
  attr.data = label;
  attr.length = (UInt32)strlen(label);

  /* Start searching: */
  status = SecKeychainSearchCreateFromAttributes(NULL,
                                                 kSecCertificateItemClass,
                                                 &attr_list,
                                                 &search);
  if(status == noErr) {
    status = SecKeychainSearchCopyNext(search,
                                       (SecKeychainItemRef *)&cert);
    if(status == noErr && cert) {
      /* If we found a certificate, does it have a private key? */
      status = SecIdentityCreateWithCertificate(NULL, cert, out_c_a_k);
      CFRelease(cert);
    }
  }

  if(search)
    CFRelease(search);
  return status;
}
#endif /* CURL_SUPPORT_MAC_10_6 */

static OSStatus CopyIdentityWithLabel(char *label,
                                      SecIdentityRef *out_cert_and_key)
{
  OSStatus status = errSecItemNotFound;

#if CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS
  CFArrayRef keys_list;
  CFIndex keys_list_count;
  CFIndex i;

  /* SecItemCopyMatching() was introduced in iOS and Snow Leopard.
     kSecClassIdentity was introduced in Lion. If both exist, let's use them
     to find the certificate. */
  if(&SecItemCopyMatching && kSecClassIdentity) {
    CFTypeRef keys[5];
    CFTypeRef values[5];
    CFDictionaryRef query_dict;
    CFStringRef label_cf = CFStringCreateWithCString(NULL, label,
      kCFStringEncodingUTF8);

    /* Set up our search criteria and expected results: */
    values[0] = kSecClassIdentity; /* we want a certificate and a key */
    keys[0] = kSecClass;
    values[1] = kCFBooleanTrue;    /* we want a reference */
    keys[1] = kSecReturnRef;
    values[2] = kSecMatchLimitAll; /* kSecMatchLimitOne would be better if the
                                    * label matching below worked correctly */
    keys[2] = kSecMatchLimit;
    /* identity searches need a SecPolicyRef in order to work */
    values[3] = SecPolicyCreateSSL(FALSE, NULL);
    keys[3] = kSecMatchPolicy;
    /* match the name of the certificate (does not work in macOS 10.12.1) */
    values[4] = label_cf;
    keys[4] = kSecAttrLabel;
    query_dict = CFDictionaryCreate(NULL, (const void **)keys,
                                    (const void **)values, 5L,
                                    &kCFCopyStringDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
    CFRelease(values[3]);

    /* Do we have a match? */
    status = SecItemCopyMatching(query_dict, (CFTypeRef *) &keys_list);

    /* Because kSecAttrLabel matching does not work with kSecClassIdentity,
     * we need to find the correct identity ourselves */
    if(status == noErr) {
      keys_list_count = CFArrayGetCount(keys_list);
      *out_cert_and_key = NULL;
      status = 1;
      for(i = 0; i < keys_list_count; i++) {
        OSStatus err = noErr;
        SecCertificateRef cert = NULL;
        SecIdentityRef identity =
          (SecIdentityRef) CFArrayGetValueAtIndex(keys_list, i);
        err = SecIdentityCopyCertificate(identity, &cert);
        if(err == noErr) {
          CFStringRef common_name = NULL;
          OSStatus copy_status = noErr;
#if CURL_BUILD_IOS
          common_name = SecCertificateCopySubjectSummary(cert);
#elif CURL_BUILD_MAC_10_7
          copy_status = SecCertificateCopyCommonName(cert, &common_name);
#endif
          if(copy_status == noErr &&
            CFStringCompare(common_name, label_cf, 0) == kCFCompareEqualTo) {
            CFRelease(cert);
            CFRelease(common_name);
            CFRetain(identity);
            *out_cert_and_key = identity;
            status = noErr;
            break;
          }
          if(common_name)
            CFRelease(common_name);
        }
        CFRelease(cert);
      }
    }

    if(keys_list)
      CFRelease(keys_list);
    CFRelease(query_dict);
    CFRelease(label_cf);
  }
  else {
#if CURL_SUPPORT_MAC_10_6
    /* On Leopard and Snow Leopard, fall back to SecKeychainSearch. */
    status = CopyIdentityWithLabelOldSchool(label, out_cert_and_key);
#endif /* CURL_SUPPORT_MAC_10_6 */
  }
#elif CURL_SUPPORT_MAC_10_6
  /* For developers building on older cats, we have no choice but to fall back
     to SecKeychainSearch. */
  status = CopyIdentityWithLabelOldSchool(label, out_cert_and_key);
#endif /* CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS */
  return status;
}

static OSStatus CopyIdentityFromPKCS12File(const char *cPath,
                                           const struct curl_blob *blob,
                                           const char *cPassword,
                                           SecIdentityRef *out_cert_and_key)
{
  OSStatus status = errSecItemNotFound;
  CFURLRef pkcs_url = NULL;
  CFStringRef password = cPassword ? CFStringCreateWithCString(NULL,
    cPassword, kCFStringEncodingUTF8) : NULL;
  CFDataRef pkcs_data = NULL;

  /* We can import P12 files on iOS or macOS 10.7 or later: */
  /* These constants are documented as having first appeared in 10.6 but they
     raise linker errors when used on that cat for some reason. */
#if CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS
  bool resource_imported;

  if(blob) {
    pkcs_data = CFDataCreate(kCFAllocatorDefault,
                             (const unsigned char *)blob->data,
                             (CFIndex)blob->len);
    status = (pkcs_data != NULL) ? errSecSuccess : errSecAllocate;
    resource_imported = (pkcs_data != NULL);
  }
  else {
    pkcs_url =
      CFURLCreateFromFileSystemRepresentation(NULL,
                                              (const UInt8 *)cPath,
                                              (CFIndex)strlen(cPath), FALSE);
    resource_imported =
      CFURLCreateDataAndPropertiesFromResource(NULL,
                                               pkcs_url, &pkcs_data,
                                               NULL, NULL, &status);
  }

  if(resource_imported) {
    CFArrayRef items = NULL;

  /* On iOS SecPKCS12Import will never add the client certificate to the
   * Keychain.
   *
   * It gives us back a SecIdentityRef that we can use directly. */
#if CURL_BUILD_IOS
    const void *cKeys[] = {kSecImportExportPassphrase};
    const void *cValues[] = {password};
    CFDictionaryRef options = CFDictionaryCreate(NULL, cKeys, cValues,
      password ? 1L : 0L, NULL, NULL);

    if(options) {
      status = SecPKCS12Import(pkcs_data, options, &items);
      CFRelease(options);
    }


  /* On macOS SecPKCS12Import will always add the client certificate to
   * the Keychain.
   *
   * As this does not match iOS, and apps may not want to see their client
   * certificate saved in the user's keychain, we use SecItemImport
   * with a NULL keychain to avoid importing it.
   *
   * This returns a SecCertificateRef from which we can construct a
   * SecIdentityRef.
   */
#elif CURL_BUILD_MAC_10_7
    SecItemImportExportKeyParameters keyParams;
    SecExternalFormat inputFormat = kSecFormatPKCS12;
    SecExternalItemType inputType = kSecItemTypeCertificate;

    memset(&keyParams, 0x00, sizeof(keyParams));
    keyParams.version    = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    keyParams.passphrase = password;

    status = SecItemImport(pkcs_data, NULL, &inputFormat, &inputType,
                           0, &keyParams, NULL, &items);
#endif


    /* Extract the SecIdentityRef */
    if(status == errSecSuccess && items && CFArrayGetCount(items)) {
      CFIndex i, count;
      count = CFArrayGetCount(items);

      for(i = 0; i < count; i++) {
        CFTypeRef item = (CFTypeRef) CFArrayGetValueAtIndex(items, i);
        CFTypeID  itemID = CFGetTypeID(item);

        if(itemID == CFDictionaryGetTypeID()) {
          CFTypeRef identity = (CFTypeRef) CFDictionaryGetValue(
                                                 (CFDictionaryRef) item,
                                                 kSecImportItemIdentity);
          CFRetain(identity);
          *out_cert_and_key = (SecIdentityRef) identity;
          break;
        }
#if CURL_BUILD_MAC_10_7
        else if(itemID == SecCertificateGetTypeID()) {
          status = SecIdentityCreateWithCertificate(NULL,
                                                 (SecCertificateRef) item,
                                                 out_cert_and_key);
          break;
        }
#endif
      }
    }

    if(items)
      CFRelease(items);
    CFRelease(pkcs_data);
  }
#endif /* CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS */
  if(password)
    CFRelease(password);
  if(pkcs_url)
    CFRelease(pkcs_url);
  return status;
}

/* This code was borrowed from nss.c, with some modifications:
 * Determine whether the nickname passed in is a filename that needs to
 * be loaded as a PEM or a nickname.
 *
 * returns 1 for a file
 * returns 0 for not a file
 */
CF_INLINE bool is_file(const char *filename)
{
  struct_stat st;

  if(!filename)
    return FALSE;

  if(stat(filename, &st) == 0)
    return S_ISREG(st.st_mode);
  return FALSE;
}

static CURLcode
sectransp_set_ssl_version_min_max(struct Curl_easy *data,
                                  struct st_ssl_backend_data *backend,
                                  struct ssl_primary_config *conn_config)
{
#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
  OSStatus err;
  SSLProtocol ver_min;
  SSLProtocol ver_max;

#if CURL_SUPPORT_MAC_10_7
  if(!&SSLSetProtocolVersionMax)
    goto legacy;
#endif

  switch(conn_config->version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
    case CURL_SSLVERSION_TLSv1_0:
      ver_min = kTLSProtocol1;
      break;
    case CURL_SSLVERSION_TLSv1_1:
      ver_min = kTLSProtocol11;
      break;
    case CURL_SSLVERSION_TLSv1_2:
      ver_min = kTLSProtocol12;
      break;
    case CURL_SSLVERSION_TLSv1_3:
    default:
      failf(data, "SSL: unsupported minimum TLS version value");
      return CURLE_SSL_CONNECT_ERROR;
  }

  switch(conn_config->version_max) {
    case CURL_SSLVERSION_MAX_DEFAULT:
    case CURL_SSLVERSION_MAX_NONE:
    case CURL_SSLVERSION_MAX_TLSv1_3:
    case CURL_SSLVERSION_MAX_TLSv1_2:
      ver_max = kTLSProtocol12;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_1:
      ver_max = kTLSProtocol11;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_0:
      ver_max = kTLSProtocol1;
      break;
    default:
      failf(data, "SSL: unsupported maximum TLS version value");
      return CURLE_SSL_CONNECT_ERROR;
  }

  err = SSLSetProtocolVersionMin(backend->ssl_ctx, ver_min);
  if(err != noErr) {
    failf(data, "SSL: failed to set minimum TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }
  err = SSLSetProtocolVersionMax(backend->ssl_ctx, ver_max);
  if(err != noErr) {
    failf(data, "SSL: failed to set maximum TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  return CURLE_OK;
#endif
#if CURL_SUPPORT_MAC_10_7
  goto legacy;
legacy:
  switch(conn_config->version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
    case CURL_SSLVERSION_TLSv1_0:
      break;
    default:
      failf(data, "SSL: unsupported minimum TLS version value");
      return CURLE_SSL_CONNECT_ERROR;
  }

  /* only TLS 1.0 is supported, disable SSL 3.0 and SSL 2.0 */
  SSLSetProtocolVersionEnabled(backend->ssl_ctx, kSSLProtocolAll, FALSE);
  SSLSetProtocolVersionEnabled(backend->ssl_ctx, kTLSProtocol1, TRUE);

  return CURLE_OK;
#endif
}

static int sectransp_cipher_suite_get_str(uint16_t id, char *buf,
                                          size_t buf_size, bool prefer_rfc)
{
  /* are these fortezza suites even supported ? */
  if(id == SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA)
    msnprintf(buf, buf_size, "%s", "SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA");
  else if(id == SSL_FORTEZZA_DMS_WITH_NULL_SHA)
    msnprintf(buf, buf_size, "%s", "SSL_FORTEZZA_DMS_WITH_NULL_SHA");
  /* can TLS_EMPTY_RENEGOTIATION_INFO_SCSV even be set ? */
  else if(id == TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    msnprintf(buf, buf_size, "%s", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
  /* do we still need to support these SSL2-only ciphers ? */
  else if(id == SSL_RSA_WITH_RC2_CBC_MD5)
    msnprintf(buf, buf_size, "%s", "SSL_RSA_WITH_RC2_CBC_MD5");
  else if(id == SSL_RSA_WITH_IDEA_CBC_MD5)
    msnprintf(buf, buf_size, "%s", "SSL_RSA_WITH_IDEA_CBC_MD5");
  else if(id == SSL_RSA_WITH_DES_CBC_MD5)
    msnprintf(buf, buf_size, "%s", "SSL_RSA_WITH_DES_CBC_MD5");
  else if(id == SSL_RSA_WITH_3DES_EDE_CBC_MD5)
    msnprintf(buf, buf_size, "%s", "SSL_RSA_WITH_3DES_EDE_CBC_MD5");
  else
    return Curl_cipher_suite_get_str(id, buf, buf_size, prefer_rfc);
  return 0;
}

static uint16_t sectransp_cipher_suite_walk_str(const char **str,
                                                const char **end)
{
  uint16_t id = Curl_cipher_suite_walk_str(str, end);
  size_t len = *end - *str;

  if(!id) {
    /* are these fortezza suites even supported ? */
    if(strncasecompare("SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA", *str, len))
      id = SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA;
    else if(strncasecompare("SSL_FORTEZZA_DMS_WITH_NULL_SHA", *str, len))
      id = SSL_FORTEZZA_DMS_WITH_NULL_SHA;
    /* can TLS_EMPTY_RENEGOTIATION_INFO_SCSV even be set ? */
    else if(strncasecompare("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", *str, len))
      id = TLS_EMPTY_RENEGOTIATION_INFO_SCSV;
    /* do we still need to support these SSL2-only ciphers ? */
    else if(strncasecompare("SSL_RSA_WITH_RC2_CBC_MD5", *str, len))
      id = SSL_RSA_WITH_RC2_CBC_MD5;
    else if(strncasecompare("SSL_RSA_WITH_IDEA_CBC_MD5", *str, len))
      id = SSL_RSA_WITH_IDEA_CBC_MD5;
    else if(strncasecompare("SSL_RSA_WITH_DES_CBC_MD5", *str, len))
      id = SSL_RSA_WITH_DES_CBC_MD5;
    else if(strncasecompare("SSL_RSA_WITH_3DES_EDE_CBC_MD5", *str, len))
      id = SSL_RSA_WITH_3DES_EDE_CBC_MD5;
  }
  return id;
}

/* allocated memory must be freed */
static SSLCipherSuite * sectransp_get_supported_ciphers(SSLContextRef ssl_ctx,
                                                        size_t *len)
{
  SSLCipherSuite *ciphers = NULL;
  OSStatus err = noErr;
  *len = 0;

  err = SSLGetNumberSupportedCiphers(ssl_ctx, len);
  if(err != noErr)
    goto failed;

  ciphers = malloc(*len * sizeof(SSLCipherSuite));
  if(!ciphers)
    goto failed;

  err = SSLGetSupportedCiphers(ssl_ctx, ciphers, len);
  if(err != noErr)
    goto failed;

#if CURL_BUILD_MAC
  {
    int maj = 0, min = 0;
    GetDarwinVersionNumber(&maj, &min);
    /* There is a known bug in early versions of Mountain Lion where ST's ECC
       ciphers (cipher suite 0xC001 through 0xC032) simply do not work.
       Work around the problem here by disabling those ciphers if we are
       running in an affected version of macOS. */
    if(maj == 12 && min <= 3) {
      size_t i = 0, j = 0;
      for(; i < *len; i++) {
        if(ciphers[i] >= 0xC001 && ciphers[i] <= 0xC032)
          continue;
        ciphers[j++] = ciphers[i];
      }
      *len = j;
    }
  }
#endif

  return ciphers;
failed:
  *len = 0;
  Curl_safefree(ciphers);
  return NULL;
}

static CURLcode sectransp_set_default_ciphers(struct Curl_easy *data,
                                              SSLContextRef ssl_ctx)
{
  CURLcode ret = CURLE_SSL_CIPHER;
  size_t count = 0, i, j;
  OSStatus err;
  size_t supported_len;
  SSLCipherSuite *ciphers = NULL;

  ciphers = sectransp_get_supported_ciphers(ssl_ctx, &supported_len);
  if(!ciphers) {
    failf(data, "SSL: Failed to get supported ciphers");
    goto failed;
  }

  /* Intersect the ciphers supported by Secure Transport with the default
   * ciphers, using the order of the former. */
  for(i = 0; i < supported_len; i++) {
    for(j = 0; j < DEFAULT_CIPHERS_LEN; j++) {
      if(default_ciphers[j] == ciphers[i]) {
        ciphers[count++] = ciphers[i];
        break;
      }
    }
  }

  if(count == 0) {
    failf(data, "SSL: no supported default ciphers");
    goto failed;
  }

  err = SSLSetEnabledCiphers(ssl_ctx, ciphers, count);
  if(err != noErr) {
    failf(data, "SSL: SSLSetEnabledCiphers() failed: OSStatus %d", err);
    goto failed;
  }

  ret = CURLE_OK;
failed:
  Curl_safefree(ciphers);
  return ret;
}

static CURLcode sectransp_set_selected_ciphers(struct Curl_easy *data,
                                               SSLContextRef ssl_ctx,
                                               const char *ciphers)
{
  CURLcode ret = CURLE_SSL_CIPHER;
  size_t count = 0, i;
  const char *ptr, *end;
  OSStatus err;
  size_t supported_len;
  SSLCipherSuite *supported = NULL;
  SSLCipherSuite *selected = NULL;

  supported = sectransp_get_supported_ciphers(ssl_ctx, &supported_len);
  if(!supported) {
    failf(data, "SSL: Failed to get supported ciphers");
    goto failed;
  }

  selected = malloc(supported_len * sizeof(SSLCipherSuite));
  if(!selected) {
    failf(data, "SSL: Failed to allocate memory");
    goto failed;
  }

  for(ptr = ciphers; ptr[0] != '\0' && count < supported_len; ptr = end) {
    uint16_t id = sectransp_cipher_suite_walk_str(&ptr, &end);

    /* Check if cipher is supported */
    if(id) {
      for(i = 0; i < supported_len && supported[i] != id; i++);
      if(i == supported_len)
        id = 0;
    }
    if(!id) {
      if(ptr[0] != '\0')
        infof(data, "SSL: unknown cipher in list: \"%.*s\"", (int) (end - ptr),
              ptr);
      continue;
    }

    /* No duplicates allowed (so selected cannot overflow) */
    for(i = 0; i < count && selected[i] != id; i++);
    if(i < count) {
      infof(data, "SSL: duplicate cipher in list: \"%.*s\"", (int) (end - ptr),
            ptr);
      continue;
    }

    selected[count++] = id;
  }

  if(count == 0) {
    failf(data, "SSL: no supported cipher in list");
    goto failed;
  }

  err = SSLSetEnabledCiphers(ssl_ctx, selected, count);
  if(err != noErr) {
    failf(data, "SSL: SSLSetEnabledCiphers() failed: OSStatus %d", err);
    goto failed;
  }

  ret = CURLE_OK;
failed:
  Curl_safefree(supported);
  Curl_safefree(selected);
  return ret;
}

static void sectransp_session_free(void *sessionid, size_t idsize)
{
  /* ST, as of iOS 5 and Mountain Lion, has no public method of deleting a
     cached session ID inside the Security framework. There is a private
     function that does this, but I do not want to have to explain to you why I
     got your application rejected from the App Store due to the use of a
     private API, so the best we can do is free up our own char array that we
     created way back in sectransp_connect_step1... */
  (void)idsize;
  Curl_safefree(sessionid);
}

static CURLcode sectransp_connect_step1(struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const struct curl_blob *ssl_cablob = conn_config->ca_info_blob;
  const char * const ssl_cafile =
    /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
    (ssl_cablob ? NULL : conn_config->CAfile);
  const bool verifypeer = conn_config->verifypeer;
  char * const ssl_cert = ssl_config->primary.clientcert;
  const struct curl_blob *ssl_cert_blob = ssl_config->primary.cert_blob;
  char *ciphers;
  OSStatus err = noErr;
  CURLcode result;
#if CURL_BUILD_MAC
  int darwinver_maj = 0, darwinver_min = 0;

  DEBUGASSERT(backend);

  CURL_TRC_CF(data, cf, "connect_step1");
  GetDarwinVersionNumber(&darwinver_maj, &darwinver_min);
#endif /* CURL_BUILD_MAC */

#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
  if(&SSLCreateContext) {  /* use the newer API if available */
    if(backend->ssl_ctx)
      CFRelease(backend->ssl_ctx);
    backend->ssl_ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if(!backend->ssl_ctx) {
      failf(data, "SSL: could not create a context");
      return CURLE_OUT_OF_MEMORY;
    }
  }
  else {
  /* The old ST API does not exist under iOS, so do not compile it: */
#if CURL_SUPPORT_MAC_10_8
    if(backend->ssl_ctx)
      (void)SSLDisposeContext(backend->ssl_ctx);
    err = SSLNewContext(FALSE, &(backend->ssl_ctx));
    if(err != noErr) {
      failf(data, "SSL: could not create a context: OSStatus %d", err);
      return CURLE_OUT_OF_MEMORY;
    }
#endif /* CURL_SUPPORT_MAC_10_8 */
  }
#else
  if(backend->ssl_ctx)
    (void)SSLDisposeContext(backend->ssl_ctx);
  err = SSLNewContext(FALSE, &(backend->ssl_ctx));
  if(err != noErr) {
    failf(data, "SSL: could not create a context: OSStatus %d", err);
    return CURLE_OUT_OF_MEMORY;
  }
#endif /* CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS */
  backend->ssl_write_buffered_length = 0UL; /* reset buffered write length */

  result = sectransp_set_ssl_version_min_max(data, backend, conn_config);
  if(result != CURLE_OK)
    return result;

#if (CURL_BUILD_MAC_10_13 || CURL_BUILD_IOS_11) && \
    defined(HAVE_BUILTIN_AVAILABLE)
  if(connssl->alpn) {
    if(__builtin_available(macOS 10.13.4, iOS 11, tvOS 11, *)) {
      struct alpn_proto_buf proto;
      size_t i;
      CFStringRef cstr;
      CFMutableArrayRef alpnArr = CFArrayCreateMutable(NULL, 0,
                                                       &kCFTypeArrayCallBacks);
      for(i = 0; i < connssl->alpn->count; ++i) {
        cstr = CFStringCreateWithCString(NULL, connssl->alpn->entries[i],
                                         kCFStringEncodingUTF8);
        if(!cstr)
          return CURLE_OUT_OF_MEMORY;
        CFArrayAppendValue(alpnArr, cstr);
        CFRelease(cstr);
      }
      err = SSLSetALPNProtocols(backend->ssl_ctx, alpnArr);
      if(err != noErr)
        infof(data, "WARNING: failed to set ALPN protocols; OSStatus %d",
              err);
      CFRelease(alpnArr);
      Curl_alpn_to_proto_str(&proto, connssl->alpn);
      infof(data, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
    }
  }
#endif

  if(ssl_config->key) {
    infof(data, "WARNING: SSL: CURLOPT_SSLKEY is ignored by Secure "
          "Transport. The private key must be in the Keychain.");
  }

  if(ssl_cert || ssl_cert_blob) {
    bool is_cert_data = ssl_cert_blob != NULL;
    bool is_cert_file = (!is_cert_data) && is_file(ssl_cert);
    SecIdentityRef cert_and_key = NULL;

    /* User wants to authenticate with a client cert. Look for it. Assume that
       the user wants to use an identity loaded from the Keychain. If not, try
       it as a file on disk */

    if(!is_cert_data)
      err = CopyIdentityWithLabel(ssl_cert, &cert_and_key);
    else
      err = !noErr;
    if((err != noErr) && (is_cert_file || is_cert_data)) {
      if(!ssl_config->cert_type)
        infof(data, "SSL: Certificate type not set, assuming "
              "PKCS#12 format.");
      else if(!strcasecompare(ssl_config->cert_type, "P12")) {
        failf(data, "SSL: The Security framework only supports "
              "loading identities that are in PKCS#12 format.");
        return CURLE_SSL_CERTPROBLEM;
      }

      err = CopyIdentityFromPKCS12File(ssl_cert, ssl_cert_blob,
                                       ssl_config->key_passwd,
                                       &cert_and_key);
    }

    if(err == noErr && cert_and_key) {
      SecCertificateRef cert = NULL;
      CFTypeRef certs_c[1];
      CFArrayRef certs;

      /* If we found one, print it out: */
      err = SecIdentityCopyCertificate(cert_and_key, &cert);
      if(err == noErr) {
        char *certp;
        result = CopyCertSubject(data, cert, &certp);
        if(!result) {
          infof(data, "Client certificate: %s", certp);
          free(certp);
        }

        CFRelease(cert);
        if(result == CURLE_PEER_FAILED_VERIFICATION)
          return CURLE_SSL_CERTPROBLEM;
        if(result)
          return result;
      }
      certs_c[0] = cert_and_key;
      certs = CFArrayCreate(NULL, (const void **)certs_c, 1L,
                            &kCFTypeArrayCallBacks);
      err = SSLSetCertificate(backend->ssl_ctx, certs);
      if(certs)
        CFRelease(certs);
      if(err != noErr) {
        failf(data, "SSL: SSLSetCertificate() failed: OSStatus %d", err);
        return CURLE_SSL_CERTPROBLEM;
      }
      CFRelease(cert_and_key);
    }
    else {
      const char *cert_showfilename_error =
        is_cert_data ? "(memory blob)" : ssl_cert;

      switch(err) {
      case errSecAuthFailed: case -25264: /* errSecPkcs12VerifyFailure */
        failf(data, "SSL: Incorrect password for the certificate \"%s\" "
                    "and its private key.", cert_showfilename_error);
        break;
      case -26275: /* errSecDecode */ case -25257: /* errSecUnknownFormat */
        failf(data, "SSL: Couldn't make sense of the data in the "
                    "certificate \"%s\" and its private key.",
                    cert_showfilename_error);
        break;
      case -25260: /* errSecPassphraseRequired */
        failf(data, "SSL The certificate \"%s\" requires a password.",
                    cert_showfilename_error);
        break;
      case errSecItemNotFound:
        failf(data, "SSL: cannot find the certificate \"%s\" and its private "
                    "key in the Keychain.", cert_showfilename_error);
        break;
      default:
        failf(data, "SSL: cannot load the certificate \"%s\" and its private "
                    "key: OSStatus %d", cert_showfilename_error, err);
        break;
      }
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* SSL always tries to verify the peer, this only says whether it should
   * fail to connect if the verification fails, or if it should continue
   * anyway. In the latter case the result of the verification is checked with
   * SSL_get_verify_result() below. */
#if CURL_BUILD_MAC_10_6 || CURL_BUILD_IOS
  /* Snow Leopard introduced the SSLSetSessionOption() function, but due to
     a library bug with the way the kSSLSessionOptionBreakOnServerAuth flag
     works, it does not work as expected under Snow Leopard, Lion or
     Mountain Lion.
     So we need to call SSLSetEnableCertVerify() on those older cats in order
     to disable certificate validation if the user turned that off.
     (Secure Transport always validates the certificate chain by default.)
  Note:
  Darwin 11.x.x is Lion (10.7)
  Darwin 12.x.x is Mountain Lion (10.8)
  Darwin 13.x.x is Mavericks (10.9)
  Darwin 14.x.x is Yosemite (10.10)
  Darwin 15.x.x is El Capitan (10.11)
  */
#if CURL_BUILD_MAC
  if(&SSLSetSessionOption && darwinver_maj >= 13) {
#else
  if(&SSLSetSessionOption) {
#endif /* CURL_BUILD_MAC */
    bool break_on_auth = !conn_config->verifypeer ||
      ssl_cafile || ssl_cablob;
    err = SSLSetSessionOption(backend->ssl_ctx,
                              kSSLSessionOptionBreakOnServerAuth,
                              break_on_auth);
    if(err != noErr) {
      failf(data, "SSL: SSLSetSessionOption() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
#if CURL_SUPPORT_MAC_10_8
    err = SSLSetEnableCertVerify(backend->ssl_ctx,
                                 conn_config->verifypeer ? true : FALSE);
    if(err != noErr) {
      failf(data, "SSL: SSLSetEnableCertVerify() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
#endif /* CURL_SUPPORT_MAC_10_8 */
  }
#else
  err = SSLSetEnableCertVerify(backend->ssl_ctx,
                               conn_config->verifypeer ? true : FALSE);
  if(err != noErr) {
    failf(data, "SSL: SSLSetEnableCertVerify() failed: OSStatus %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }
#endif /* CURL_BUILD_MAC_10_6 || CURL_BUILD_IOS */

  if((ssl_cafile || ssl_cablob) && verifypeer) {
    bool is_cert_data = ssl_cablob != NULL;
    bool is_cert_file = (!is_cert_data) && is_file(ssl_cafile);

    if(!(is_cert_file || is_cert_data)) {
      failf(data, "SSL: cannot load CA certificate file %s",
            ssl_cafile ? ssl_cafile : "(blob memory)");
      return CURLE_SSL_CACERT_BADFILE;
    }
  }

  /* Configure hostname check. SNI is used if available.
   * Both hostname check and SNI require SSLSetPeerDomainName().
   * Also: the verifyhost setting influences SNI usage */
  if(conn_config->verifyhost) {
    char *server = connssl->peer.sni ?
      connssl->peer.sni : connssl->peer.hostname;
    err = SSLSetPeerDomainName(backend->ssl_ctx, server, strlen(server));

    if(err != noErr) {
      failf(data, "SSL: SSLSetPeerDomainName() failed: OSStatus %d",
            err);
      return CURLE_SSL_CONNECT_ERROR;
    }

    if(connssl->peer.type != CURL_SSL_PEER_DNS) {
      infof(data, "WARNING: using IP address, SNI is being disabled by "
            "the OS.");
    }
  }
  else {
    infof(data, "WARNING: disabling hostname validation also disables SNI.");
  }

  ciphers = conn_config->cipher_list;
  if(ciphers) {
    result = sectransp_set_selected_ciphers(data, backend->ssl_ctx, ciphers);
  }
  else {
    result = sectransp_set_default_ciphers(data, backend->ssl_ctx);
  }
  if(result != CURLE_OK) {
    failf(data, "SSL: Unable to set ciphers for SSL/TLS handshake. "
          "Error code: %d", (int)result);
    return CURLE_SSL_CIPHER;
  }

#if CURL_BUILD_MAC_10_9 || CURL_BUILD_IOS_7
  /* We want to enable 1/n-1 when using a CBC cipher unless the user
     specifically does not want us doing that: */
  if(&SSLSetSessionOption) {
    SSLSetSessionOption(backend->ssl_ctx, kSSLSessionOptionSendOneByteRecord,
                        !ssl_config->enable_beast);
    SSLSetSessionOption(backend->ssl_ctx, kSSLSessionOptionFalseStart,
                      ssl_config->falsestart); /* false start support */
  }
#endif /* CURL_BUILD_MAC_10_9 || CURL_BUILD_IOS_7 */

  /* Check if there is a cached ID we can/should use here! */
  if(ssl_config->primary.cache_session) {
    char *ssl_sessionid;
    size_t ssl_sessionid_len;

    Curl_ssl_sessionid_lock(data);
    if(!Curl_ssl_getsessionid(cf, data, &connssl->peer,
                              (void **)&ssl_sessionid, &ssl_sessionid_len,
                              NULL)) {
      /* we got a session id, use it! */
      err = SSLSetPeerID(backend->ssl_ctx, ssl_sessionid, ssl_sessionid_len);
      Curl_ssl_sessionid_unlock(data);
      if(err != noErr) {
        failf(data, "SSL: SSLSetPeerID() failed: OSStatus %d", err);
        return CURLE_SSL_CONNECT_ERROR;
      }
      /* Informational message */
      infof(data, "SSL reusing session ID");
    }
    /* If there is not one, then let's make one up! This has to be done prior
       to starting the handshake. */
    else {
      ssl_sessionid =
        aprintf("%s:%d:%d:%s:%d",
                ssl_cafile ? ssl_cafile : "(blob memory)",
                verifypeer, conn_config->verifyhost, connssl->peer.hostname,
                connssl->peer.port);
      ssl_sessionid_len = strlen(ssl_sessionid);

      err = SSLSetPeerID(backend->ssl_ctx, ssl_sessionid, ssl_sessionid_len);
      if(err != noErr) {
        Curl_ssl_sessionid_unlock(data);
        failf(data, "SSL: SSLSetPeerID() failed: OSStatus %d", err);
        return CURLE_SSL_CONNECT_ERROR;
      }

      result = Curl_ssl_set_sessionid(cf, data, &connssl->peer, NULL,
                                      ssl_sessionid, ssl_sessionid_len,
                                      sectransp_session_free);
      Curl_ssl_sessionid_unlock(data);
      if(result)
        return result;
    }
  }

  err = SSLSetIOFuncs(backend->ssl_ctx,
                      sectransp_bio_cf_in_read,
                      sectransp_bio_cf_out_write);
  if(err != noErr) {
    failf(data, "SSL: SSLSetIOFuncs() failed: OSStatus %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  err = SSLSetConnection(backend->ssl_ctx, cf);
  if(err != noErr) {
    failf(data, "SSL: SSLSetConnection() failed: %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static long pem_to_der(const char *in, unsigned char **out, size_t *outlen)
{
  char *sep_start, *sep_end, *cert_start, *cert_end;
  size_t i, j, err;
  size_t len;
  char *b64;

  /* Jump through the separators at the beginning of the certificate. */
  sep_start = strstr(in, "-----");
  if(!sep_start)
    return 0;
  cert_start = strstr(sep_start + 1, "-----");
  if(!cert_start)
    return -1;

  cert_start += 5;

  /* Find separator after the end of the certificate. */
  cert_end = strstr(cert_start, "-----");
  if(!cert_end)
    return -1;

  sep_end = strstr(cert_end + 1, "-----");
  if(!sep_end)
    return -1;
  sep_end += 5;

  len = cert_end - cert_start;
  b64 = malloc(len + 1);
  if(!b64)
    return -1;

  /* Create base64 string without linefeeds. */
  for(i = 0, j = 0; i < len; i++) {
    if(cert_start[i] != '\r' && cert_start[i] != '\n')
      b64[j++] = cert_start[i];
  }
  b64[j] = '\0';

  err = Curl_base64_decode((const char *)b64, out, outlen);
  free(b64);
  if(err) {
    free(*out);
    return -1;
  }

  return sep_end - in;
}

#define MAX_CERTS_SIZE (50*1024*1024) /* arbitrary - to catch mistakes */

static int read_cert(const char *file, unsigned char **out, size_t *outlen)
{
  int fd;
  ssize_t n;
  unsigned char buf[512];
  struct dynbuf certs;

  Curl_dyn_init(&certs, MAX_CERTS_SIZE);

  fd = open(file, 0);
  if(fd < 0)
    return -1;

  for(;;) {
    n = read(fd, buf, sizeof(buf));
    if(!n)
      break;
    if(n < 0) {
      close(fd);
      Curl_dyn_free(&certs);
      return -1;
    }
    if(Curl_dyn_addn(&certs, buf, n)) {
      close(fd);
      return -1;
    }
  }
  close(fd);

  *out = Curl_dyn_uptr(&certs);
  *outlen = Curl_dyn_len(&certs);

  return 0;
}

static CURLcode append_cert_to_array(struct Curl_easy *data,
                                     const unsigned char *buf, size_t buflen,
                                     CFMutableArrayRef array)
{
    char *certp;
    CURLcode result;
    SecCertificateRef cacert;
    CFDataRef certdata;

    certdata = CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)buflen);
    if(!certdata) {
      failf(data, "SSL: failed to allocate array for CA certificate");
      return CURLE_OUT_OF_MEMORY;
    }

    cacert = SecCertificateCreateWithData(kCFAllocatorDefault, certdata);
    CFRelease(certdata);
    if(!cacert) {
      failf(data, "SSL: failed to create SecCertificate from CA certificate");
      return CURLE_SSL_CACERT_BADFILE;
    }

    /* Check if cacert is valid. */
    result = CopyCertSubject(data, cacert, &certp);
    switch(result) {
      case CURLE_OK:
        break;
      case CURLE_PEER_FAILED_VERIFICATION:
        return CURLE_SSL_CACERT_BADFILE;
      case CURLE_OUT_OF_MEMORY:
      default:
        return result;
    }
    free(certp);

    CFArrayAppendValue(array, cacert);
    CFRelease(cacert);

    return CURLE_OK;
}

static CURLcode verify_cert_buf(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const unsigned char *certbuf, size_t buflen,
                                SSLContextRef ctx)
{
  int n = 0;
  CURLcode rc;
  long res;
  unsigned char *der;
  size_t derlen, offset = 0;
  OSStatus ret;
  SecTrustResultType trust_eval;
  CFMutableArrayRef array = NULL;
  SecTrustRef trust = NULL;
  CURLcode result = CURLE_PEER_FAILED_VERIFICATION;
  (void)cf;
  /*
   * Certbuf now contains the contents of the certificate file, which can be
   * - a single DER certificate,
   * - a single PEM certificate or
   * - a bunch of PEM certificates (certificate bundle).
   *
   * Go through certbuf, and convert any PEM certificate in it into DER
   * format.
   */
  array = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  if(!array) {
    failf(data, "SSL: out of memory creating CA certificate array");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  while(offset < buflen) {
    n++;

    /*
     * Check if the certificate is in PEM format, and convert it to DER. If
     * this fails, we assume the certificate is in DER format.
     */
    res = pem_to_der((const char *)certbuf + offset, &der, &derlen);
    if(res < 0) {
      failf(data, "SSL: invalid CA certificate #%d (offset %zu) in bundle",
            n, offset);
      result = CURLE_SSL_CACERT_BADFILE;
      goto out;
    }
    offset += res;

    if(res == 0 && offset == 0) {
      /* This is not a PEM file, probably a certificate in DER format. */
      rc = append_cert_to_array(data, certbuf, buflen, array);
      if(rc != CURLE_OK) {
        CURL_TRC_CF(data, cf, "append_cert for CA failed");
        result = rc;
        goto out;
      }
      break;
    }
    else if(res == 0) {
      /* No more certificates in the bundle. */
      break;
    }

    rc = append_cert_to_array(data, der, derlen, array);
    free(der);
    if(rc != CURLE_OK) {
      CURL_TRC_CF(data, cf, "append_cert for CA failed");
      result = rc;
      goto out;
    }
  }

  ret = SSLCopyPeerTrust(ctx, &trust);
  if(!trust) {
    failf(data, "SSL: error getting certificate chain");
    goto out;
  }
  else if(ret != noErr) {
    failf(data, "SSLCopyPeerTrust() returned error %d", ret);
    goto out;
  }

  CURL_TRC_CF(data, cf, "setting %d trust anchors", n);
  ret = SecTrustSetAnchorCertificates(trust, array);
  if(ret != noErr) {
    failf(data, "SecTrustSetAnchorCertificates() returned error %d", ret);
    goto out;
  }
  ret = SecTrustSetAnchorCertificatesOnly(trust, TRUE);
  if(ret != noErr) {
    failf(data, "SecTrustSetAnchorCertificatesOnly() returned error %d", ret);
    goto out;
  }

  trust_eval = 0;
  ret = SecTrustEvaluate(trust, &trust_eval);
  if(ret != noErr) {
    failf(data, "SecTrustEvaluate() returned error %d", ret);
    goto out;
  }

  switch(trust_eval) {
    case kSecTrustResultUnspecified:
      /* what does this really mean? */
      CURL_TRC_CF(data, cf, "trust result: Unspecified");
      result = CURLE_OK;
      goto out;
    case kSecTrustResultProceed:
      CURL_TRC_CF(data, cf, "trust result: Proceed");
      result = CURLE_OK;
      goto out;

    case kSecTrustResultRecoverableTrustFailure:
      failf(data, "SSL: peer not verified:  RecoverableTrustFailure");
      goto out;
    case kSecTrustResultDeny:
      failf(data, "SSL: peer not verified:  Deny");
      goto out;
    default:
      failf(data, "SSL: perr not verified: result=%d", trust_eval);
      goto out;
  }

out:
  if(trust)
    CFRelease(trust);
  if(array)
    CFRelease(array);
  return result;
}

static CURLcode verify_cert(struct Curl_cfilter *cf,
                            struct Curl_easy *data, const char *cafile,
                            const struct curl_blob *ca_info_blob,
                            SSLContextRef ctx)
{
  CURLcode result;
  unsigned char *certbuf;
  size_t buflen;
  bool free_certbuf = FALSE;

  if(ca_info_blob) {
    CURL_TRC_CF(data, cf, "verify_peer, CA from config blob");
    certbuf = ca_info_blob->data;
    buflen = ca_info_blob->len;
  }
  else if(cafile) {
    CURL_TRC_CF(data, cf, "verify_peer, CA from file '%s'", cafile);
    if(read_cert(cafile, &certbuf, &buflen) < 0) {
      failf(data, "SSL: failed to read or invalid CA certificate");
      return CURLE_SSL_CACERT_BADFILE;
    }
    free_certbuf = TRUE;
  }
  else
    return CURLE_SSL_CACERT_BADFILE;

  result = verify_cert_buf(cf, data, certbuf, buflen, ctx);
  if(free_certbuf)
    free(certbuf);
  return result;
}


#ifdef SECTRANSP_PINNEDPUBKEY
static CURLcode pkp_pin_peer_pubkey(struct Curl_easy *data,
                                    SSLContextRef ctx,
                                    const char *pinnedpubkey)
{  /* Scratch */
  size_t pubkeylen, realpubkeylen, spkiHeaderLength = 24;
  unsigned char *pubkey = NULL, *realpubkey = NULL;
  const unsigned char *spkiHeader = NULL;
  CFDataRef publicKeyBits = NULL;

  /* Result is returned to caller */
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  /* if a path was not specified, do not pin */
  if(!pinnedpubkey)
    return CURLE_OK;


  if(!ctx)
    return result;

  do {
    SecTrustRef trust;
    OSStatus ret;
    SecKeyRef keyRef;

    ret = SSLCopyPeerTrust(ctx, &trust);
    if(ret != noErr || !trust)
      break;

    keyRef = SecTrustCopyPublicKey(trust);
    CFRelease(trust);
    if(!keyRef)
      break;

#ifdef SECTRANSP_PINNEDPUBKEY_V1

    publicKeyBits = SecKeyCopyExternalRepresentation(keyRef, NULL);
    CFRelease(keyRef);
    if(!publicKeyBits)
      break;

#elif SECTRANSP_PINNEDPUBKEY_V2

    {
      OSStatus success;
      success = SecItemExport(keyRef, kSecFormatOpenSSL, 0, NULL,
                              &publicKeyBits);
      CFRelease(keyRef);
      if(success != errSecSuccess || !publicKeyBits)
        break;
    }

#endif /* SECTRANSP_PINNEDPUBKEY_V2 */

    pubkeylen = (size_t)CFDataGetLength(publicKeyBits);
    pubkey = (unsigned char *)CFDataGetBytePtr(publicKeyBits);

    switch(pubkeylen) {
      case 526:
        /* 4096 bit RSA pubkeylen == 526 */
        spkiHeader = rsa4096SpkiHeader;
        break;
      case 270:
        /* 2048 bit RSA pubkeylen == 270 */
        spkiHeader = rsa2048SpkiHeader;
        break;
#ifdef SECTRANSP_PINNEDPUBKEY_V1
      case 65:
        /* ecDSA secp256r1 pubkeylen == 65 */
        spkiHeader = ecDsaSecp256r1SpkiHeader;
        spkiHeaderLength = 26;
        break;
      case 97:
        /* ecDSA secp384r1 pubkeylen == 97 */
        spkiHeader = ecDsaSecp384r1SpkiHeader;
        spkiHeaderLength = 23;
        break;
      default:
        infof(data, "SSL: unhandled public key length: %zu", pubkeylen);
#elif SECTRANSP_PINNEDPUBKEY_V2
      default:
        /* ecDSA secp256r1 pubkeylen == 91 header already included?
         * ecDSA secp384r1 header already included too
         * we assume rest of algorithms do same, so do nothing
         */
        result = Curl_pin_peer_pubkey(data, pinnedpubkey, pubkey,
                                    pubkeylen);
#endif /* SECTRANSP_PINNEDPUBKEY_V2 */
        continue; /* break from loop */
    }

    realpubkeylen = pubkeylen + spkiHeaderLength;
    realpubkey = malloc(realpubkeylen);
    if(!realpubkey)
      break;

    memcpy(realpubkey, spkiHeader, spkiHeaderLength);
    memcpy(realpubkey + spkiHeaderLength, pubkey, pubkeylen);

    result = Curl_pin_peer_pubkey(data, pinnedpubkey, realpubkey,
                                  realpubkeylen);

  } while(0);

  Curl_safefree(realpubkey);
  if(publicKeyBits)
    CFRelease(publicKeyBits);

  return result;
}
#endif /* SECTRANSP_PINNEDPUBKEY */

static CURLcode sectransp_connect_step2(struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  OSStatus err;
  SSLCipherSuite cipher;
  SSLProtocol protocol = 0;

  DEBUGASSERT(ssl_connect_2 == connssl->connecting_state);
  DEBUGASSERT(backend);
  CURL_TRC_CF(data, cf, "connect_step2");

  /* Here goes nothing: */
check_handshake:
  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  err = SSLHandshake(backend->ssl_ctx);

  if(err != noErr) {
    switch(err) {
      case errSSLWouldBlock:  /* they are not done with us yet */
        connssl->io_need = backend->ssl_direction ?
            CURL_SSL_IO_NEED_SEND : CURL_SSL_IO_NEED_RECV;
        return CURLE_OK;

      /* The below is errSSLServerAuthCompleted; it is not defined in
        Leopard's headers */
      case -9841:
        if((conn_config->CAfile || conn_config->ca_info_blob) &&
           conn_config->verifypeer) {
          CURLcode result = verify_cert(cf, data, conn_config->CAfile,
                                        conn_config->ca_info_blob,
                                        backend->ssl_ctx);
          if(result)
            return result;
        }
        /* the documentation says we need to call SSLHandshake() again */
        goto check_handshake;

      /* Problem with encrypt / decrypt */
      case errSSLPeerDecodeError:
        failf(data, "Decode failed");
        break;
      case errSSLDecryptionFail:
      case errSSLPeerDecryptionFail:
        failf(data, "Decryption failed");
        break;
      case errSSLPeerDecryptError:
        failf(data, "A decryption error occurred");
        break;
      case errSSLBadCipherSuite:
        failf(data, "A bad SSL cipher suite was encountered");
        break;
      case errSSLCrypto:
        failf(data, "An underlying cryptographic error was encountered");
        break;
#if CURL_BUILD_MAC_10_11 || CURL_BUILD_IOS_9
      case errSSLWeakPeerEphemeralDHKey:
        failf(data, "Indicates a weak ephemeral Diffie-Hellman key");
        break;
#endif

      /* Problem with the message record validation */
      case errSSLBadRecordMac:
      case errSSLPeerBadRecordMac:
        failf(data, "A record with a bad message authentication code (MAC) "
                    "was encountered");
        break;
      case errSSLRecordOverflow:
      case errSSLPeerRecordOverflow:
        failf(data, "A record overflow occurred");
        break;

      /* Problem with zlib decompression */
      case errSSLPeerDecompressFail:
        failf(data, "Decompression failed");
        break;

      /* Problem with access */
      case errSSLPeerAccessDenied:
        failf(data, "Access was denied");
        break;
      case errSSLPeerInsufficientSecurity:
        failf(data, "There is insufficient security for this operation");
        break;

      /* These are all certificate problems with the server: */
      case errSSLXCertChainInvalid:
        failf(data, "SSL certificate problem: Invalid certificate chain");
        return CURLE_PEER_FAILED_VERIFICATION;
      case errSSLUnknownRootCert:
        failf(data, "SSL certificate problem: Untrusted root certificate");
        return CURLE_PEER_FAILED_VERIFICATION;
      case errSSLNoRootCert:
        failf(data, "SSL certificate problem: No root certificate");
        return CURLE_PEER_FAILED_VERIFICATION;
      case errSSLCertNotYetValid:
        failf(data, "SSL certificate problem: The certificate chain had a "
                    "certificate that is not yet valid");
        return CURLE_PEER_FAILED_VERIFICATION;
      case errSSLCertExpired:
      case errSSLPeerCertExpired:
        failf(data, "SSL certificate problem: Certificate chain had an "
              "expired certificate");
        return CURLE_PEER_FAILED_VERIFICATION;
      case errSSLBadCert:
      case errSSLPeerBadCert:
        failf(data, "SSL certificate problem: Couldn't understand the server "
              "certificate format");
        return CURLE_PEER_FAILED_VERIFICATION;
      case errSSLPeerUnsupportedCert:
        failf(data, "SSL certificate problem: An unsupported certificate "
                    "format was encountered");
        return CURLE_PEER_FAILED_VERIFICATION;
      case errSSLPeerCertRevoked:
        failf(data, "SSL certificate problem: The certificate was revoked");
        return CURLE_PEER_FAILED_VERIFICATION;
      case errSSLPeerCertUnknown:
        failf(data, "SSL certificate problem: The certificate is unknown");
        return CURLE_PEER_FAILED_VERIFICATION;

      /* These are all certificate problems with the client: */
      case errSecAuthFailed:
        failf(data, "SSL authentication failed");
        break;
      case errSSLPeerHandshakeFail:
        failf(data, "SSL peer handshake failed, the server most likely "
              "requires a client certificate to connect");
        break;
      case errSSLPeerUnknownCA:
        failf(data, "SSL server rejected the client certificate due to "
              "the certificate being signed by an unknown certificate "
              "authority");
        break;

      /* This error is raised if the server's cert did not match the server's
         hostname: */
      case errSSLHostNameMismatch:
        failf(data, "SSL certificate peer verification failed, the "
              "certificate did not match \"%s\"\n", connssl->peer.dispname);
        return CURLE_PEER_FAILED_VERIFICATION;

      /* Problem with SSL / TLS negotiation */
      case errSSLNegotiation:
        failf(data, "Could not negotiate an SSL cipher suite with the server");
        break;
      case errSSLBadConfiguration:
        failf(data, "A configuration error occurred");
        break;
      case errSSLProtocol:
        failf(data, "SSL protocol error");
        break;
      case errSSLPeerProtocolVersion:
        failf(data, "A bad protocol version was encountered");
        break;
      case errSSLPeerNoRenegotiation:
        failf(data, "No renegotiation is allowed");
        break;

      /* Generic handshake errors: */
      case errSSLConnectionRefused:
        failf(data, "Server dropped the connection during the SSL handshake");
        break;
      case errSSLClosedAbort:
        failf(data, "Server aborted the SSL handshake");
        break;
      case errSSLClosedGraceful:
        failf(data, "The connection closed gracefully");
        break;
      case errSSLClosedNoNotify:
        failf(data, "The server closed the session with no notification");
        break;
      /* Sometimes paramErr happens with buggy ciphers: */
      case paramErr:
      case errSSLInternal:
      case errSSLPeerInternalError:
        failf(data, "Internal SSL engine error encountered during the "
              "SSL handshake");
        break;
      case errSSLFatalAlert:
        failf(data, "Fatal SSL engine error encountered during the SSL "
              "handshake");
        break;
      /* Unclassified error */
      case errSSLBufferOverflow:
        failf(data, "An insufficient buffer was provided");
        break;
      case errSSLIllegalParam:
        failf(data, "An illegal parameter was encountered");
        break;
      case errSSLModuleAttach:
        failf(data, "Module attach failure");
        break;
      case errSSLSessionNotFound:
        failf(data, "An attempt to restore an unknown session failed");
        break;
      case errSSLPeerExportRestriction:
        failf(data, "An export restriction occurred");
        break;
      case errSSLPeerUserCancelled:
        failf(data, "The user canceled the operation");
        break;
      case errSSLPeerUnexpectedMsg:
        failf(data, "Peer rejected unexpected message");
        break;
#if CURL_BUILD_MAC_10_11 || CURL_BUILD_IOS_9
      /* Treating non-fatal error as fatal like before */
      case errSSLClientHelloReceived:
        failf(data, "A non-fatal result for providing a server name "
                    "indication");
        break;
#endif

      /* Error codes defined in the enum but should never be returned.
         We list them here just in case. */
#if CURL_BUILD_MAC_10_6
      /* Only returned when kSSLSessionOptionBreakOnCertRequested is set */
      case errSSLClientCertRequested:
        failf(data, "Server requested a client certificate during the "
              "handshake");
        return CURLE_SSL_CLIENTCERT;
#endif
#if CURL_BUILD_MAC_10_9
      /* Alias for errSSLLast, end of error range */
      case errSSLUnexpectedRecord:
        failf(data, "Unexpected (skipped) record in DTLS");
        break;
#endif
      default:
        /* May also return codes listed in Security Framework Result Codes */
        failf(data, "Unknown SSL protocol error in connection to %s:%d",
              connssl->peer.hostname, err);
        break;
    }
    return CURLE_SSL_CONNECT_ERROR;
  }
  else {
    char cipher_str[64];
    /* we have been connected fine, we are not waiting for anything else. */
    connssl->connecting_state = ssl_connect_3;

#ifdef SECTRANSP_PINNEDPUBKEY
    if(data->set.str[STRING_SSL_PINNEDPUBLICKEY]) {
      CURLcode result =
        pkp_pin_peer_pubkey(data, backend->ssl_ctx,
                            data->set.str[STRING_SSL_PINNEDPUBLICKEY]);
      if(result) {
        failf(data, "SSL: public key does not match pinned public key");
        return result;
      }
    }
#endif /* SECTRANSP_PINNEDPUBKEY */

    /* Informational message */
    (void)SSLGetNegotiatedCipher(backend->ssl_ctx, &cipher);
    (void)SSLGetNegotiatedProtocolVersion(backend->ssl_ctx, &protocol);

    sectransp_cipher_suite_get_str((uint16_t) cipher, cipher_str,
                                   sizeof(cipher_str), TRUE);
    switch(protocol) {
      case kSSLProtocol2:
        infof(data, "SSL 2.0 connection using %s", cipher_str);
        break;
      case kSSLProtocol3:
        infof(data, "SSL 3.0 connection using %s", cipher_str);
        break;
      case kTLSProtocol1:
        infof(data, "TLS 1.0 connection using %s", cipher_str);
        break;
#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
      case kTLSProtocol11:
        infof(data, "TLS 1.1 connection using %s", cipher_str);
        break;
      case kTLSProtocol12:
        infof(data, "TLS 1.2 connection using %s", cipher_str);
        break;
#endif /* CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS */
#if CURL_BUILD_MAC_10_13 || CURL_BUILD_IOS_11
      case kTLSProtocol13:
        infof(data, "TLS 1.3 connection using %s", cipher_str);
        break;
#endif /* CURL_BUILD_MAC_10_13 || CURL_BUILD_IOS_11 */
      default:
        infof(data, "Unknown protocol connection");
        break;
    }

#if (CURL_BUILD_MAC_10_13 || CURL_BUILD_IOS_11) && \
    defined(HAVE_BUILTIN_AVAILABLE)
    if(connssl->alpn) {
      if(__builtin_available(macOS 10.13.4, iOS 11, tvOS 11, *)) {
        CFArrayRef alpnArr = NULL;
        CFStringRef chosenProtocol = NULL;
        err = SSLCopyALPNProtocols(backend->ssl_ctx, &alpnArr);

        if(err == noErr && alpnArr && CFArrayGetCount(alpnArr) >= 1)
          chosenProtocol = CFArrayGetValueAtIndex(alpnArr, 0);

#ifdef USE_HTTP2
        if(chosenProtocol &&
           !CFStringCompare(chosenProtocol, CFSTR(ALPN_H2), 0)) {
          cf->conn->alpn = CURL_HTTP_VERSION_2;
        }
        else
#endif
        if(chosenProtocol &&
           !CFStringCompare(chosenProtocol, CFSTR(ALPN_HTTP_1_1), 0)) {
          cf->conn->alpn = CURL_HTTP_VERSION_1_1;
        }
        else
          infof(data, VTLS_INFOF_NO_ALPN);

        /* chosenProtocol is a reference to the string within alpnArr
           and does not need to be freed separately */
        if(alpnArr)
          CFRelease(alpnArr);
      }
    }
#endif

    return CURLE_OK;
  }
}

static CURLcode
add_cert_to_certinfo(struct Curl_easy *data,
                     SecCertificateRef server_cert,
                     int idx)
{
  CURLcode result = CURLE_OK;
  const char *beg;
  const char *end;
  CFDataRef cert_data = SecCertificateCopyData(server_cert);

  if(!cert_data)
    return CURLE_PEER_FAILED_VERIFICATION;

  beg = (const char *)CFDataGetBytePtr(cert_data);
  end = beg + CFDataGetLength(cert_data);
  result = Curl_extract_certinfo(data, idx, beg, end);
  CFRelease(cert_data);
  return result;
}

static CURLcode
collect_server_cert_single(struct Curl_cfilter *cf, struct Curl_easy *data,
                           SecCertificateRef server_cert,
                           CFIndex idx)
{
  CURLcode result = CURLE_OK;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(data->set.verbose) {
    char *certp;
    result = CopyCertSubject(data, server_cert, &certp);
    if(!result) {
      infof(data, "Server certificate: %s", certp);
      free(certp);
    }
  }
#endif
  if(ssl_config->certinfo)
    result = add_cert_to_certinfo(data, server_cert, (int)idx);
  return result;
}

/* This should be called during step3 of the connection at the earliest */
static CURLcode collect_server_cert(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  const bool show_verbose_server_cert = data->set.verbose;
#else
  const bool show_verbose_server_cert = FALSE;
#endif
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  CURLcode result = ssl_config->certinfo ?
    CURLE_PEER_FAILED_VERIFICATION : CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  CFArrayRef server_certs = NULL;
  SecCertificateRef server_cert;
  OSStatus err;
  CFIndex i, count;
  SecTrustRef trust = NULL;

  DEBUGASSERT(backend);

  if(!show_verbose_server_cert && !ssl_config->certinfo)
    return CURLE_OK;

  if(!backend->ssl_ctx)
    return result;

#if CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS
#if CURL_BUILD_IOS
#pragma unused(server_certs)
  err = SSLCopyPeerTrust(backend->ssl_ctx, &trust);
  /* For some reason, SSLCopyPeerTrust() can return noErr and yet return
     a null trust, so be on guard for that: */
  if(err == noErr && trust) {
    count = SecTrustGetCertificateCount(trust);
    if(ssl_config->certinfo)
      result = Curl_ssl_init_certinfo(data, (int)count);
    for(i = 0L ; !result && (i < count) ; i++) {
      server_cert = SecTrustGetCertificateAtIndex(trust, i);
      result = collect_server_cert_single(cf, data, server_cert, i);
    }
    CFRelease(trust);
  }
#else
  /* SSLCopyPeerCertificates() is deprecated as of Mountain Lion.
     The function SecTrustGetCertificateAtIndex() is officially present
     in Lion, but it is unfortunately also present in Snow Leopard as
     private API and does not work as expected. So we have to look for
     a different symbol to make sure this code is only executed under
     Lion or later. */
  if(&SecTrustCopyPublicKey) {
#pragma unused(server_certs)
    err = SSLCopyPeerTrust(backend->ssl_ctx, &trust);
    /* For some reason, SSLCopyPeerTrust() can return noErr and yet return
       a null trust, so be on guard for that: */
    if(err == noErr && trust) {
      count = SecTrustGetCertificateCount(trust);
      if(ssl_config->certinfo)
        result = Curl_ssl_init_certinfo(data, (int)count);
      for(i = 0L ; !result && (i < count) ; i++) {
        server_cert = SecTrustGetCertificateAtIndex(trust, i);
        result = collect_server_cert_single(cf, data, server_cert, i);
      }
      CFRelease(trust);
    }
  }
  else {
#if CURL_SUPPORT_MAC_10_8
    err = SSLCopyPeerCertificates(backend->ssl_ctx, &server_certs);
    /* Just in case SSLCopyPeerCertificates() returns null too... */
    if(err == noErr && server_certs) {
      count = CFArrayGetCount(server_certs);
      if(ssl_config->certinfo)
        result = Curl_ssl_init_certinfo(data, (int)count);
      for(i = 0L ; !result && (i < count) ; i++) {
        server_cert = (SecCertificateRef)CFArrayGetValueAtIndex(server_certs,
                                                                i);
        result = collect_server_cert_single(cf, data, server_cert, i);
      }
      CFRelease(server_certs);
    }
#endif /* CURL_SUPPORT_MAC_10_8 */
  }
#endif /* CURL_BUILD_IOS */
#else
#pragma unused(trust)
  err = SSLCopyPeerCertificates(backend->ssl_ctx, &server_certs);
  if(err == noErr) {
    count = CFArrayGetCount(server_certs);
    if(ssl_config->certinfo)
      result = Curl_ssl_init_certinfo(data, (int)count);
    for(i = 0L ; !result && (i < count) ; i++) {
      server_cert = (SecCertificateRef)CFArrayGetValueAtIndex(server_certs, i);
      result = collect_server_cert_single(cf, data, server_cert, i);
    }
    CFRelease(server_certs);
  }
#endif /* CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS */
  return result;
}

static CURLcode sectransp_connect_step3(struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  CURLcode result;

  CURL_TRC_CF(data, cf, "connect_step3");
  /* There is no step 3!
   * Well, okay, let's collect server certificates, and if verbose mode is on,
   * let's print the details of the server certificates. */
  result = collect_server_cert(cf, data);
  if(result)
    return result;

  connssl->connecting_state = ssl_connect_done;
  return CURLE_OK;
}

static CURLcode
sectransp_connect_common(struct Curl_cfilter *cf, struct Curl_easy *data,
                         bool nonblocking,
                         bool *done)
{
  CURLcode result;
  struct ssl_connect_data *connssl = cf->ctx;
  curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    /* Find out how much more time we are allowed */
    const timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = sectransp_connect_step1(cf, data);
    if(result)
      return result;
  }

  while(ssl_connect_2 == connssl->connecting_state) {

    /* check allowed time left */
    const timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* if ssl is expecting something, check if it is available. */
    if(connssl->io_need) {

      curl_socket_t writefd = (connssl->io_need & CURL_SSL_IO_NEED_SEND) ?
        sockfd : CURL_SOCKET_BAD;
      curl_socket_t readfd = (connssl->io_need & CURL_SSL_IO_NEED_RECV) ?
        sockfd : CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd,
                               nonblocking ? 0 : timeout_ms);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          /* timeout */
          failf(data, "SSL connection timeout");
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      /* socket is readable or writable */
    }

    /* Run transaction, and return to the caller if it failed or if this
     * connection is done nonblocking and this loop would execute again. This
     * permits the owner of a multi handle to abort a connection attempt
     * before step2 has completed while ensuring that a client using select()
     * or epoll() will always have a valid fdset to wait on.
     */
    result = sectransp_connect_step2(cf, data);
    if(result || (nonblocking && (ssl_connect_2 == connssl->connecting_state)))
      return result;

  } /* repeat step2 until all transactions are done. */


  if(ssl_connect_3 == connssl->connecting_state) {
    result = sectransp_connect_step3(cf, data);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    CURL_TRC_CF(data, cf, "connected");
    connssl->state = ssl_connection_complete;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

static CURLcode sectransp_connect_nonblocking(struct Curl_cfilter *cf,
                                              struct Curl_easy *data,
                                              bool *done)
{
  return sectransp_connect_common(cf, data, TRUE, done);
}

static CURLcode sectransp_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  CURLcode result;
  bool done = FALSE;

  result = sectransp_connect_common(cf, data, FALSE, &done);

  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static ssize_t sectransp_recv(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              char *buf,
                              size_t buffersize,
                              CURLcode *curlcode);

static CURLcode sectransp_shutdown(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  CURLcode result = CURLE_OK;
  ssize_t nread;
  char buf[1024];
  size_t i;

  DEBUGASSERT(backend);
  if(!backend->ssl_ctx || cf->shutdown) {
    *done = TRUE;
    goto out;
  }

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  *done = FALSE;

  if(send_shutdown && !backend->sent_shutdown) {
    OSStatus err;

    CURL_TRC_CF(data, cf, "shutdown, send close notify");
    err = SSLClose(backend->ssl_ctx);
    switch(err) {
      case noErr:
        backend->sent_shutdown = TRUE;
        break;
      case errSSLWouldBlock:
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        result = CURLE_OK;
        goto out;
      default:
        CURL_TRC_CF(data, cf, "shutdown, error: %d", (int)err);
        result = CURLE_SEND_ERROR;
        goto out;
    }
  }

  for(i = 0; i < 10; ++i) {
    if(!backend->sent_shutdown) {
      nread = sectransp_recv(cf, data, buf, (int)sizeof(buf), &result);
    }
    else {
      /* We would like to read the close notify from the server using
       * Secure Transport, however SSLRead() no longer works after we
       * sent the notify from our side. So, we just read from the
       * underlying filter and hope it will end. */
      nread = Curl_conn_cf_recv(cf->next, data, buf, sizeof(buf), &result);
    }
    CURL_TRC_CF(data, cf, "shutdown read -> %zd, %d", nread, result);
    if(nread <= 0)
      break;
  }

  if(nread > 0) {
    /* still data coming in? */
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
  }
  else if(nread == 0) {
    /* We got the close notify alert and are done. */
    CURL_TRC_CF(data, cf, "shutdown done");
    *done = TRUE;
  }
  else if(result == CURLE_AGAIN) {
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    result = CURLE_OK;
  }
  else {
    DEBUGASSERT(result);
    CURL_TRC_CF(data, cf, "shutdown, error: %d", result);
  }

out:
  cf->shutdown = (result || *done);
  return result;
}

static void sectransp_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;

  (void) data;

  DEBUGASSERT(backend);

  if(backend->ssl_ctx) {
    CURL_TRC_CF(data, cf, "close");
#if CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS
    if(&SSLCreateContext)
      CFRelease(backend->ssl_ctx);
#if CURL_SUPPORT_MAC_10_8
    else
      (void)SSLDisposeContext(backend->ssl_ctx);
#endif  /* CURL_SUPPORT_MAC_10_8 */
#else
    (void)SSLDisposeContext(backend->ssl_ctx);
#endif /* CURL_BUILD_MAC_10_8 || CURL_BUILD_IOS */
    backend->ssl_ctx = NULL;
  }
}

static size_t sectransp_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "SecureTransport");
}

static bool sectransp_data_pending(struct Curl_cfilter *cf,
                                   const struct Curl_easy *data)
{
  const struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  OSStatus err;
  size_t buffer;

  (void)data;
  DEBUGASSERT(backend);

  if(backend->ssl_ctx) {  /* SSL is in use */
    CURL_TRC_CF((struct Curl_easy *)data, cf, "data_pending");
    err = SSLGetBufferedReadSize(backend->ssl_ctx, &buffer);
    if(err == noErr)
      return buffer > 0UL;
    return FALSE;
  }
  else
    return FALSE;
}

static CURLcode sectransp_random(struct Curl_easy *data UNUSED_PARAM,
                                 unsigned char *entropy, size_t length)
{
  /* arc4random_buf() is not available on cats older than Lion, so let's
     do this manually for the benefit of the older cats. */
  size_t i;
  u_int32_t random_number = 0;

  (void)data;

  for(i = 0 ; i < length ; i++) {
    if(i % sizeof(u_int32_t) == 0)
      random_number = arc4random();
    entropy[i] = random_number & 0xFF;
    random_number >>= 8;
  }
  i = random_number = 0;
  return CURLE_OK;
}

static CURLcode sectransp_sha256sum(const unsigned char *tmp, /* input */
                                    size_t tmplen,
                                    unsigned char *sha256sum, /* output */
                                    size_t sha256len)
{
  (void)sha256len;
  assert(sha256len >= CURL_SHA256_DIGEST_LENGTH);
  (void)CC_SHA256(tmp, (CC_LONG)tmplen, sha256sum);
  return CURLE_OK;
}

static bool sectransp_false_start(void)
{
#if CURL_BUILD_MAC_10_9 || CURL_BUILD_IOS_7
  if(&SSLSetSessionOption)
    return TRUE;
#endif
  return FALSE;
}

static ssize_t sectransp_send(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const void *mem,
                              size_t len,
                              CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  size_t processed = 0UL;
  OSStatus err;

  DEBUGASSERT(backend);

  /* The SSLWrite() function works a little differently than expected. The
     fourth argument (processed) is currently documented in Apple's
     documentation as: "On return, the length, in bytes, of the data actually
     written."

     Now, one could interpret that as "written to the socket," but actually,
     it returns the amount of data that was written to a buffer internal to
     the SSLContextRef instead. So it is possible for SSLWrite() to return
     errSSLWouldBlock and a number of bytes "written" because those bytes were
     encrypted and written to a buffer, not to the socket.

     So if this happens, then we need to keep calling SSLWrite() over and
     over again with no new data until it quits returning errSSLWouldBlock. */

  /* Do we have buffered data to write from the last time we were called? */
  if(backend->ssl_write_buffered_length) {
    /* Write the buffered data: */
    err = SSLWrite(backend->ssl_ctx, NULL, 0UL, &processed);
    switch(err) {
      case noErr:
        /* processed is always going to be 0 because we did not write to
           the buffer, so return how much was written to the socket */
        processed = backend->ssl_write_buffered_length;
        backend->ssl_write_buffered_length = 0UL;
        break;
      case errSSLWouldBlock: /* argh, try again */
        *curlcode = CURLE_AGAIN;
        return -1L;
      default:
        failf(data, "SSLWrite() returned error %d", err);
        *curlcode = CURLE_SEND_ERROR;
        return -1L;
    }
  }
  else {
    /* We have got new data to write: */
    err = SSLWrite(backend->ssl_ctx, mem, len, &processed);
    if(err != noErr) {
      switch(err) {
        case errSSLWouldBlock:
          /* Data was buffered but not sent, we have to tell the caller
             to try sending again, and remember how much was buffered */
          backend->ssl_write_buffered_length = len;
          *curlcode = CURLE_AGAIN;
          return -1L;
        default:
          failf(data, "SSLWrite() returned error %d", err);
          *curlcode = CURLE_SEND_ERROR;
          return -1L;
      }
    }
  }
  return (ssize_t)processed;
}

static ssize_t sectransp_recv(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              char *buf,
                              size_t buffersize,
                              CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  size_t processed = 0UL;
  OSStatus err;

  DEBUGASSERT(backend);

again:
  *curlcode = CURLE_OK;
  err = SSLRead(backend->ssl_ctx, buf, buffersize, &processed);

  if(err != noErr) {
    switch(err) {
      case errSSLWouldBlock:  /* return how much we read (if anything) */
        if(processed) {
          return (ssize_t)processed;
        }
        *curlcode = CURLE_AGAIN;
        return -1L;

      /* errSSLClosedGraceful - server gracefully shut down the SSL session
         errSSLClosedNoNotify - server hung up on us instead of sending a
           closure alert notice, read() is returning 0
         Either way, inform the caller that the server disconnected. */
      case errSSLClosedGraceful:
      case errSSLClosedNoNotify:
        *curlcode = CURLE_OK;
        return 0;

        /* The below is errSSLPeerAuthCompleted; it is not defined in
           Leopard's headers */
      case -9841:
        if((conn_config->CAfile || conn_config->ca_info_blob) &&
           conn_config->verifypeer) {
          CURLcode result = verify_cert(cf, data, conn_config->CAfile,
                                        conn_config->ca_info_blob,
                                        backend->ssl_ctx);
          if(result) {
            *curlcode = result;
            return -1;
          }
        }
        goto again;
      default:
        failf(data, "SSLRead() return error %d", err);
        *curlcode = CURLE_RECV_ERROR;
        return -1L;
    }
  }
  return (ssize_t)processed;
}

static void *sectransp_get_internals(struct ssl_connect_data *connssl,
                                     CURLINFO info UNUSED_PARAM)
{
  struct st_ssl_backend_data *backend =
    (struct st_ssl_backend_data *)connssl->backend;
  (void)info;
  DEBUGASSERT(backend);
  return backend->ssl_ctx;
}

const struct Curl_ssl Curl_ssl_sectransp = {
  { CURLSSLBACKEND_SECURETRANSPORT, "secure-transport" }, /* info */

  SSLSUPP_CAINFO_BLOB |
  SSLSUPP_CERTINFO |
#ifdef SECTRANSP_PINNEDPUBKEY
  SSLSUPP_PINNEDPUBKEY |
#endif /* SECTRANSP_PINNEDPUBKEY */
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CIPHER_LIST,

  sizeof(struct st_ssl_backend_data),

  Curl_none_init,                     /* init */
  Curl_none_cleanup,                  /* cleanup */
  sectransp_version,                  /* version */
  Curl_none_check_cxn,                /* check_cxn */
  sectransp_shutdown,                 /* shutdown */
  sectransp_data_pending,             /* data_pending */
  sectransp_random,                   /* random */
  Curl_none_cert_status_request,      /* cert_status_request */
  sectransp_connect,                  /* connect */
  sectransp_connect_nonblocking,      /* connect_nonblocking */
  Curl_ssl_adjust_pollset,            /* adjust_pollset */
  sectransp_get_internals,            /* get_internals */
  sectransp_close,                    /* close_one */
  Curl_none_close_all,                /* close_all */
  Curl_none_set_engine,               /* set_engine */
  Curl_none_set_engine_default,       /* set_engine_default */
  Curl_none_engines_list,             /* engines_list */
  sectransp_false_start,              /* false_start */
  sectransp_sha256sum,                /* sha256sum */
  NULL,                               /* associate_connection */
  NULL,                               /* disassociate_connection */
  sectransp_recv,                     /* recv decrypted data */
  sectransp_send,                     /* send data to encrypt */
  NULL,                               /* get_channel_binding */
};

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif /* USE_SECTRANSP */
