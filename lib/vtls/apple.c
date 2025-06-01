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
 * Source file for iOS and macOS code shared between Secure Transport and
 * Network.framework. No code but nwf.c or sectransp.c should ever
 * call or use these functions.
 */

#include "../curl_setup.h"

#if (defined(USE_SECTRANSP) || defined(USE_NWF))

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
#endif /* __clang__ */

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress"
#endif

#if defined(__GNUC__) && defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#include "apple.h"
#include "../sendf.h"
#include "vtls.h"
#include "vtls_int.h"
#include "x509asn1.h"
#include "../strcase.h"

#include "../curl_memory.h"
/* The last #include file should be: */
#include "../memdebug.h"

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
        const void *item = CFArrayGetValueAtIndex(keys_list, i);
        SecIdentityRef identity = (SecIdentityRef)CURL_UNCONST(item);
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
        const CFTypeRef item = CFArrayGetValueAtIndex(items, i);
        CFTypeID itemID = CFGetTypeID(item);

        if(itemID == CFDictionaryGetTypeID()) {
          const CFTypeRef identity = CFDictionaryGetValue(
                                           (CFDictionaryRef)item,
                                           kSecImportItemIdentity);
          CFRetain(identity);
          *out_cert_and_key = (SecIdentityRef)CURL_UNCONST(identity);
          break;
        }
#if CURL_BUILD_MAC_10_7
        else if(itemID == SecCertificateGetTypeID()) {
          status = SecIdentityCreateWithCertificate(NULL,
                                         (SecCertificateRef)CURL_UNCONST(item),
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
bool apple_is_file(const char *filename)
{
  struct_stat st;

  if(!filename)
    return FALSE;

  if(stat(filename, &st) == 0)
    return S_ISREG(st.st_mode);
  return FALSE;
}

OSStatus apple_copy_identity(struct Curl_easy *data,
                             struct ssl_config_data *ssl_config,
                             SecIdentityRef *identity)
{
  OSStatus err = noErr;

  char * const ssl_cert = ssl_config->primary.clientcert;
  const struct curl_blob *ssl_cert_blob = ssl_config->primary.cert_blob;

  if(ssl_config->key) {
    infof(data, "WARNING: SSL: CURLOPT_SSLKEY is ignored by Secure "
          "Transport. The private key must be in the Keychain.");
  }

  if(ssl_cert || ssl_cert_blob) {
    bool is_cert_data = ssl_cert_blob != NULL;
    bool is_cert_file = (!is_cert_data) && apple_is_file(ssl_cert);
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

    if(err != noErr) {
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
    }

    *identity = cert_and_key;
  }

  return err;
}

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

CURLcode apple_copy_cert_subject(struct Curl_easy *data,
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

static CURLcode
add_cert_to_certinfo(struct Curl_easy *data,
                     SecCertificateRef server_cert, int idx)
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

CURLcode apple_collect_cert_single(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   SecCertificateRef cert,
                                   CFIndex idx)
{
  CURLcode result = CURLE_OK;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(data->set.verbose) {
    char *certp;
    result = apple_copy_cert_subject(data, cert, &certp);
    if(!result) {
      infof(data, "Server certificate: %s", certp);
      free(certp);
    }
  }
#endif
  if(ssl_config->certinfo)
    result = add_cert_to_certinfo(data, cert, (int)idx);
  return result;
}

CURLcode apple_collect_cert_trust(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  SecTrustRef trust)
{
  CURLcode result = CURLE_OK;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  SecCertificateRef server_cert;
  CFIndex i, count;

  DEBUGASSERT(trust);

  count = SecTrustGetCertificateCount(trust);
  if(ssl_config->certinfo)
    result = Curl_ssl_init_certinfo(data, (int)count);
  for(i = 0L ; !result && (i < count) ; i++) {
    server_cert = SecTrustGetCertificateAtIndex(trust, i);
    result = apple_collect_cert_single(cf, data, server_cert, i);
  }

  return result;
}

#if defined(__GNUC__) && defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif /* defined(USE_SECTRANSP) || defined(USE_NWF) */
