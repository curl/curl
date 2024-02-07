#ifndef HEADER_CURL_CW_OUT_H
#define HEADER_CURL_CW_OUT_H
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

#include "sendf.h"

/**
 * The client writer type "cw-out" that does the actual writing to
 * the client callbacks. Intended to be the last installed in the
 * client writer stack of a transfer.
 */
extern struct Curl_cwtype Curl_cwt_out;

/**
 * For a paused transfer, there might be buffered data held back.
 * Attempt to flush this data to the client. This *may* trigger
 * another pause of the transfer.
 */
CURLcode Curl_cw_out_unpause(struct Curl_easy *data);

/**
 * Return TRUE iff 'cw-out' client write has paused data.
 */
bool Curl_cw_out_is_paused(struct Curl_easy *data);

#endif /* HEADER_CURL_CW_OUT_H */
