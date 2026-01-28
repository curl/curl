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

/* This file is for implementing all "generic" SSL functions that all libcurl
   internals should use. It is then responsible for calling the proper
   "backend" function.

   SSL-functions in libcurl should call functions in this source file, and not
   to any specific SSL-layer.

   Curl_ssl_ - prefix for generic ones

   Note that this source code uses the functions of the configured SSL
   backend via the global Curl_ssl instance.

   "SSL/TLS Strong Encryption: An Introduction"
   https://httpd.apache.org/docs/2.0/ssl/ssl_intro.html
*/

#include "../curl_setup.h"

#include "../urldata.h"
#include "../cfilters.h"
#include "../curl_trc.h"
#include "vtls.h"
#include "apple.h"

#ifdef USE_APPLE_SECTRUST
#include <Security/Security.h>
#endif


#ifdef USE_APPLE_SECTRUST
#define SSL_SYSTEM_VERIFIER

#if (defined(MAC_OS_X_VERSION_MAX_ALLOWED) &&   \
     MAC_OS_X_VERSION_MAX_ALLOWED >= 101400) || \
  (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) &&  \
   __IPHONE_OS_VERSION_MAX_ALLOWED >= 120000)
#define SUPPORTS_SecTrustEvaluateWithError 1
#endif

#if defined(SUPPORTS_SecTrustEvaluateWithError) && \
  ((defined(MAC_OS_X_VERSION_MIN_REQUIRED) &&      \
    MAC_OS_X_VERSION_MIN_REQUIRED >= 101400) ||    \
   (defined(__IPHONE_OS_VERSION_MIN_REQUIRED) &&   \
    __IPHONE_OS_VERSION_MIN_REQUIRED >= 120000))
#define REQUIRES_SecTrustEvaluateWithError 1
#endif

#if defined(SUPPORTS_SecTrustEvaluateWithError) && \
  !defined(HAVE_BUILTIN_AVAILABLE) &&              \
  !defined(REQUIRES_SecTrustEvaluateWithError)
#undef SUPPORTS_SecTrustEvaluateWithError
#endif

#if (defined(MAC_OS_X_VERSION_MAX_ALLOWED) &&   \
     MAC_OS_X_VERSION_MAX_ALLOWED >= 100900) || \
  (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) &&  \
   __IPHONE_OS_VERSION_MAX_ALLOWED >= 70000)
#define SUPPORTS_SecOCSP 1
#endif

CURLcode Curl_vtls_apple_verify(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct ssl_peer *peer,
                                size_t num_certs,
                                Curl_vtls_get_cert_der *der_cb,
                                void *cb_user_data,
                                const unsigned char *ocsp_buf,
                                size_t ocsp_len)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  CURLcode result = CURLE_OK;
  SecTrustRef trust = NULL;
  SecPolicyRef policy = NULL;
  CFMutableArrayRef policies = NULL;
  CFMutableArrayRef cert_array = NULL;
  CFStringRef host_str = NULL;
  CFErrorRef error = NULL;
  OSStatus status = noErr;
  CFStringRef error_ref = NULL;
  char *err_desc = NULL;
  size_t i;

  if(conn_config->verifyhost) {
    host_str = CFStringCreateWithCString(NULL,
      peer->sni ? peer->sni : peer->hostname, kCFStringEncodingUTF8);
    if(!host_str) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  policies = CFArrayCreateMutable(NULL, 2, &kCFTypeArrayCallBacks);
  if(!policies) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  policy = SecPolicyCreateSSL(true, host_str);
  if(!policy) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  CFArrayAppendValue(policies, policy);
  CFRelease(policy);
  policy = NULL;

#if defined(HAVE_BUILTIN_AVAILABLE) && defined(SUPPORTS_SecOCSP)
  {
    struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
    if(!ssl_config->no_revoke) {
      if(__builtin_available(macOS 10.9, iOS 7, tvOS 9, watchOS 2, *)) {
        /* Even without this set, validation will seemingly-unavoidably fail
         * for certificates that trustd already knows to be revoked.
         * This policy further allows trustd to consult CRLs and OCSP data
         * to determine revocation status (which it may then cache). */
        CFOptionFlags revocation_flags = kSecRevocationUseAnyAvailableMethod;
#if 0
        /* `revoke_best_effort` is off by default in libcurl. When we
         * add `kSecRevocationRequirePositiveResponse` to the Apple
         * Trust policies, it interprets this as it NEEDs a confirmation
         * of a cert being NOT REVOKED. Which not in general available for
         * certificates on the Internet.
         * It seems that applications using this policy are expected to PIN
         * their certificate public keys or verification will fail.
         * This does not seem to be what we want here. */
        if(!ssl_config->revoke_best_effort) {
          revocation_flags |= kSecRevocationRequirePositiveResponse;
        }
#endif
        policy = SecPolicyCreateRevocation(revocation_flags);
        if(!policy) {
          result = CURLE_OUT_OF_MEMORY;
          goto out;
        }

        CFArrayAppendValue(policies, policy);
      }
    }
  }
#endif

  cert_array = CFArrayCreateMutable(NULL, num_certs, &kCFTypeArrayCallBacks);
  if(!cert_array) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  for(i = 0; i < num_certs; i++) {
    SecCertificateRef cert;
    CFDataRef certdata;
    unsigned char *der;
    size_t der_len;

    result = der_cb(cf, data, cb_user_data, i, &der, &der_len);
    if(result)
      goto out;

    certdata = CFDataCreate(NULL, der, (CFIndex)der_len);
    if(!certdata) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }

    cert = SecCertificateCreateWithData(NULL, certdata);
    CFRelease(certdata);
    if(!cert) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }

    CFArrayAppendValue(cert_array, cert);
    CFRelease(cert);
  }

  status = SecTrustCreateWithCertificates(cert_array, policies, &trust);
  if(status != noErr || !trust) {
    failf(data, "Apple SecTrust: failed to create validation trust");
    result = CURLE_PEER_FAILED_VERIFICATION;
    goto out;
  }

#if defined(HAVE_BUILTIN_AVAILABLE) && defined(SUPPORTS_SecOCSP)
  if(ocsp_len > 0) {
    if(__builtin_available(macOS 10.9, iOS 7, tvOS 9, watchOS 2, *)) {
      CFDataRef ocspdata = CFDataCreate(NULL, ocsp_buf, (CFIndex)ocsp_len);

      status = SecTrustSetOCSPResponse(trust, ocspdata);
      CFRelease(ocspdata);
      if(status != noErr) {
        failf(data, "Apple SecTrust: failed to set OCSP response: %i",
              (int)status);
        result = CURLE_PEER_FAILED_VERIFICATION;
        goto out;
      }
    }
  }
#else
  (void)ocsp_buf;
  (void)ocsp_len;
#endif

#ifdef SUPPORTS_SecTrustEvaluateWithError
#ifdef HAVE_BUILTIN_AVAILABLE
  if(__builtin_available(macOS 10.14, iOS 12, tvOS 12, watchOS 5, *)) {
#else
  if(1) {
#endif
    result = SecTrustEvaluateWithError(trust, &error) ?
             CURLE_OK : CURLE_PEER_FAILED_VERIFICATION;
    if(error) {
      VERBOSE(CFIndex code = CFErrorGetCode(error));
      error_ref = CFErrorCopyDescription(error);

      if(error_ref) {
        CFIndex size = CFStringGetMaximumSizeForEncoding(
          CFStringGetLength(error_ref), kCFStringEncodingUTF8);
        err_desc = curlx_malloc(size + 1);
        if(err_desc) {
          if(!CFStringGetCString(error_ref, err_desc, size,
                                 kCFStringEncodingUTF8)) {
            curlx_free(err_desc);
            err_desc = NULL;
          }
        }
      }
      infof(data, "Apple SecTrust failure %ld%s%s", code,
            err_desc ? ": " : "", err_desc ? err_desc : "");
    }
  }
  else
#endif /* SUPPORTS_SecTrustEvaluateWithError */
  {
#ifndef REQUIRES_SecTrustEvaluateWithError
    SecTrustResultType sec_result;
    status = SecTrustEvaluate(trust, &sec_result);

    if(status != noErr) {
      failf(data, "Apple SecTrust verification failed: error %i", (int)status);
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    else if((sec_result == kSecTrustResultUnspecified) ||
            (sec_result == kSecTrustResultProceed)) {
      /* "unspecified" means system-trusted with no explicit user setting */
      result = CURLE_OK;
    }
    else {
      /* Any other trust result is a verification failure in this context */
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
#endif /* REQUIRES_SecTrustEvaluateWithError */
  }

out:
  curlx_free(err_desc);
  if(error_ref)
    CFRelease(error_ref);
  if(error)
    CFRelease(error);
  if(host_str)
    CFRelease(host_str);
  if(policies)
    CFRelease(policies);
  if(policy)
    CFRelease(policy);
  if(cert_array)
    CFRelease(cert_array);
  if(trust)
    CFRelease(trust);
  return result;
}

#endif /* USE_APPLE_SECTRUST */
