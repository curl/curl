#ifndef HEADER_CURL_TOOL_GETPARAM_H
#define HEADER_CURL_TOOL_GETPARAM_H
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

typedef enum {
  PARAM_OK = 0,
  PARAM_OPTION_AMBIGUOUS,
  PARAM_OPTION_UNKNOWN,
  PARAM_REQUIRES_PARAMETER,
  PARAM_BAD_USE,
  PARAM_HELP_REQUESTED,
  PARAM_GOT_EXTRA_PARAMETER,
  PARAM_BAD_NUMERIC,
  PARAM_NEGATIVE_NUMERIC,
  PARAM_LIBCURL_DOESNT_SUPPORT,
  PARAM_NO_MEM,
  PARAM_LAST
} ParameterError;

struct Configurable;

ParameterError getparameter(char *flag,
                            char *nextarg,
                            bool *usedarg,
                            struct Configurable *config);

#endif /* HEADER_CURL_TOOL_GETPARAM_H */

