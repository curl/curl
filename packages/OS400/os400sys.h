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
 *
 ***************************************************************************/

/* OS/400 additional definitions. */

#ifndef __OS400_SYS_
#define __OS400_SYS_


/* Per-thread item identifiers. */

typedef enum {
        LK_SSL_ERROR,
        LK_GSK_ERROR,
        LK_LDAP_ERROR,
        LK_CURL_VERSION,
        LK_VERSION_INFO,
        LK_VERSION_INFO_DATA,
        LK_EASY_STRERROR,
        LK_SHARE_STRERROR,
        LK_MULTI_STRERROR,
        LK_ZLIB_VERSION,
        LK_ZLIB_MSG,
        LK_LAST
}               localkey_t;


extern char *   (* Curl_thread_buffer)(localkey_t key, long size);


/* Maximum string expansion factor due to character code conversion. */

#define MAX_CONV_EXPANSION      4       /* Can deal with UTF-8. */

#endif
