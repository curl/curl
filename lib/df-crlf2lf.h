#ifndef HEADER_CURL_DF_CRLF2LF_H
#define HEADER_CURL_DF_CRLF2LF_H
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
#include "curl_setup.h"
#include "dfilters.h"
#include "urldata.h"

#if defined(CURL_DO_LINEEND_CONV) && !defined(CURL_DISABLE_FTP)

extern const struct Curl_df_write_type df_crlf2lf;

#endif /* CURL_DO_LINEEND_CONV) && !CURL_DISABLE_FTP */

#endif /* HEADER_CURL_DF_CRLF2LF_H */
