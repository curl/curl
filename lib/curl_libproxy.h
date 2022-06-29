#ifndef HEADER_CURL_LIBPROXY_H
#define HEADER_CURL_LIBPROXY_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Jan-Michael Brummer, <jan-michael.brummer1@volkswagen.de>.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"
#include "urldata.h"

#ifndef CURL_DISABLE_LIBPROXY

#include <proxy.h>

void Curl_libproxy_cleanup(pxProxyFactory *proxy_factory);

char *Curl_libproxy_detect_proxy(struct Curl_easy *data, const char *url);

#endif /* CURL_DISABLE_LIBPROXY */

#endif /* HEADER_CURL_LIBPROXY_H */
