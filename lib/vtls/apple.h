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

#endif

#endif /* HEADER_CURL_SECTRUST_H */
