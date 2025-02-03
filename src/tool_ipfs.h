#ifndef HEADER_FETCH_TOOL_IPFS_H
#define HEADER_FETCH_TOOL_IPFS_H
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "tool_setup.h"

#ifndef FETCH_DISABLE_IPFS
#define MAX_GATEWAY_URL_LEN 10000

FETCHcode ipfs_url_rewrite(FETCHU *uh, const char *protocol, char **url,
                           struct OperationConfig *config);

#endif /* HEADER_FETCH_TOOL_IPFS_H */
#endif /* !FETCH_DISABLE_IPFS */
