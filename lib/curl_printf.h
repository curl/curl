#ifndef HEADER_CURL_PRINTF_H
#define HEADER_CURL_PRINTF_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
 * This header should be included by ALL code in libcurl that uses any
 * *rintf() functions.
 */

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* We define away the sprintf functions unconditonally since we don't want
   internal code to be using them, intentionally or by mistake!*/
# undef sprintf
# undef vsprintf
# define sprintf sprintf_was_used
# define vsprintf vsprintf_was_used

#endif /* HEADER_CURL_PRINTF_H */
