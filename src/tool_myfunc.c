/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "setup.h"

#include <curl/curl.h>

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "version.h"
#include "tool_myfunc.h"

#include "memdebug.h" /* keep this as LAST include */

/*
 * my_useragent: returns allocated string with default user agent
 */

char *my_useragent(void)
{
  char useragent[256]; /* we don't want a larger default user agent */

  snprintf(useragent, sizeof(useragent),
           CURL_NAME "/" CURL_VERSION " (" OS ") " "%s", curl_version());

  return strdup(useragent);
}

