#ifndef HEADER_FETCH_CF_HAPROXY_H
#define HEADER_FETCH_CF_HAPROXY_H
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
#include "urldata.h"

#if !defined(FETCH_DISABLE_PROXY)

FETCHcode Fetch_cf_haproxy_insert_after(struct Fetch_cfilter *cf_at,
                                       struct Fetch_easy *data);

extern struct Fetch_cftype Fetch_cft_haproxy;

#endif /* !FETCH_DISABLE_PROXY */

#endif /* HEADER_FETCH_CF_HAPROXY_H */
