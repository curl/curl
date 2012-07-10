#ifndef HEADER_CURL_TOOL_PARAMHLP_H
#define HEADER_CURL_TOOL_PARAMHLP_H
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
#include "tool_setup.h"

struct getout *new_getout(struct Configurable *config);

ParameterError file2string(char **bufp, FILE *file);

ParameterError file2memory(char **bufp, size_t *size, FILE *file);

void cleanarg(char *str);

int str2num(long *val, const char *str);
int str2unum(long *val, const char *str); /* for unsigned input numbers */

long proto2num(struct Configurable *config, long *val, const char *str);

int str2offset(curl_off_t *val, const char *str);

ParameterError checkpasswd(const char *kind, char **userpwd);

ParameterError add2list(struct curl_slist **list, const char *ptr);

int ftpfilemethod(struct Configurable *config, const char *str);

int ftpcccmethod(struct Configurable *config, const char *str);

long delegation(struct Configurable *config, char *str);

#endif /* HEADER_CURL_TOOL_PARAMHLP_H */

