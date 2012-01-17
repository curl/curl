#ifndef HEADER_LIBTEST_TESTTRACE_H
#define HEADER_LIBTEST_TESTTRACE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

struct libtest_trace_cfg {
  int tracetime;  /* 0 represents FALSE, anything else TRUE */
  int nohex;      /* 0 represents FALSE, anything else TRUE */
};

extern struct libtest_trace_cfg libtest_debug_config;

int libtest_debug_cb(CURL *handle, curl_infotype type,
                     unsigned char *data, size_t size,
                     void *userp);

#endif /* HEADER_LIBTEST_TESTTRACE_H */

