#ifndef HEADER_CURL_SECTRUST_H
#define HEADER_CURL_SECTRUST_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Nick Zitzmann, <nickzman@gmail.com>.
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
#include "../curl_setup.h"
#include <curl/curl.h>

#if (defined(USE_SECTRANSP) || defined(USE_NETWORKFMWK))

#include <Security/Security.h>

#include "../cfilters.h"
#include "vtls.h"

/* pinned public key support tests */

/* version 1 supports macOS 10.12+ and iOS 10+ */
#if ((TARGET_OS_IPHONE && __IPHONE_OS_VERSION_MIN_REQUIRED >= 100000) || \
    (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED  >= 101200))
#define APPLE_PINNEDPUBKEY_V1 1
#endif

/* version 2 supports macOS 10.7+ */
#if (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070)
#define APPLE_PINNEDPUBKEY_V2 1
#endif

#if defined(APPLE_PINNEDPUBKEY_V1) || defined(APPLE_PINNEDPUBKEY_V2)
/* this backend supports CURLOPT_PINNEDPUBLICKEY */
#define APPLE_PINNEDPUBKEY 1
#endif /* APPLE_PINNEDPUBKEY */

bool apple_is_file(const char *filename);

OSStatus apple_copy_identity(struct Curl_easy *data,
                             struct ssl_config_data *ssl_config,
                             SecIdentityRef *identity);

CURLcode apple_copy_cert_subject(struct Curl_easy *data,
                                 SecCertificateRef cert, char **certp);

CURLcode apple_collect_cert_single(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   SecCertificateRef cert, CFIndex idx);

CURLcode apple_collect_cert_trust(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  SecTrustRef trust);

CURLcode apple_setup_trust(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           SecTrustRef trust);

#ifdef APPLE_PINNEDPUBKEY
CURLcode apple_pin_peer_pubkey(struct Curl_easy *data,
                               SecTrustRef trust,
                               const char *pinnedpubkey);
#endif

#endif

#endif /* HEADER_CURL_SECTRUST_H */
