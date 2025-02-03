#ifndef HEADER_FETCH_CW_OUT_H
#define HEADER_FETCH_CW_OUT_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#include "sendf.h"

/**
 * The client writer type "cw-out" that does the actual writing to
 * the client callbacks. Intended to be the last installed in the
 * client writer stack of a transfer.
 */
extern struct Fetch_cwtype Fetch_cwt_out;

/**
 * Return TRUE iff 'cw-out' client write has paused data.
 */
bool Fetch_cw_out_is_paused(struct Fetch_easy *data);

/**
 * Flush any buffered date to the client, chunk collation still applies.
 */
FETCHcode Fetch_cw_out_unpause(struct Fetch_easy *data);

/**
 * Mark EndOfStream reached and flush ALL data to the client.
 */
FETCHcode Fetch_cw_out_done(struct Fetch_easy *data);

#endif /* HEADER_FETCH_CW_OUT_H */
