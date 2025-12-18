#ifndef HEADER_CURL_TOOL_PARAMHLP_H
#define HEADER_CURL_TOOL_PARAMHLP_H
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
#include "tool_setup.h"
#include "tool_libinfo.h"

struct getout *new_getout(struct OperationConfig *config);

ParameterError file2string(char **bufp, FILE *file);

#if SIZEOF_SIZE_T > 4
#define MAX_FILE2MEMORY (16LL*1024*1024*1024)
#else
#define MAX_FILE2MEMORY (INT_MAX)
#endif

ParameterError file2memory(char **bufp, size_t *size, FILE *file);
ParameterError file2memory_range(char **bufp, size_t *size, FILE *file,
                                 curl_off_t starto, curl_off_t endo);

ParameterError str2num(long *val, const char *str);
ParameterError str2unum(long *val, const char *str);
ParameterError oct2nummax(long *val, const char *str, long max);
ParameterError str2unummax(long *val, const char *str, long max);
ParameterError secs2ms(long *val, const char *str);
ParameterError proto2num(const char * const *val, char **obuf,
                         const char *str);
ParameterError check_protocol(const char *str);
ParameterError str2offset(curl_off_t *val, const char *str);
CURLcode get_args(struct OperationConfig *config, const size_t i);
ParameterError add2list(struct curl_slist **list, const char *ptr);
long ftpfilemethod(const char *str);
long ftpcccmethod(const char *str);
long delegation(const char *str);

ParameterError str2tls_max(unsigned char *val, const char *str);

#endif /* HEADER_CURL_TOOL_PARAMHLP_H */
