/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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
#include "ssl_hlp.h"
#include "curl/curl.h"

long retrieve_ssl_version_max(long ssl_version, long ssl_version_max_default)
{
  switch(ssl_version_max_default) {
    case CURL_SSLVERSION_MAX_NONE:
      switch(ssl_version) {
        case CURL_SSLVERSION_TLSv1_0:
          return CURL_SSLVERSION_MAX_TLSv1_0;
        case CURL_SSLVERSION_TLSv1_1:
          return CURL_SSLVERSION_MAX_TLSv1_1;
        case CURL_SSLVERSION_TLSv1_2:
          return CURL_SSLVERSION_MAX_TLSv1_2;
        case CURL_SSLVERSION_TLSv1_3:
          return CURL_SSLVERSION_MAX_TLSv1_3;
      }
  }
  return ssl_version_max_default;
}
