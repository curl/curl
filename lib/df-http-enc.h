#ifndef HEADER_CURL_DF_HTTP_ENC_H
#define HEADER_CURL_DF_HTTP_ENC_H
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

#ifndef CURL_DISABLE_HTTP

/**
 * Add all decoders listed in `enclist` in HTTP header format to the
 * dfilter writer chain of `data`.
 * @param data     transfer to add dfilters to
 * @param enclist  list of encodings
 * @param phase    phase in the dfilter write chain where decoders apply
 */
CURLcode Curl_df_http_enc_add(struct Curl_easy *data,
                              const char *enclist,
                              curl_df_phase phase);

/**
 * Get the HTTP header value list of encodings we accept
 * to decode for the given phase.
 * @return allocated string listing all supported content encodings
 *         or NULL if none are supported for this phase
 */
char *Curl_df_http_enc_list_all(curl_df_phase phase);

#endif /* !CURL_DISABLE_HTTP */

#endif /* HEADER_CURL_DF_HTTP_ENC_H */
