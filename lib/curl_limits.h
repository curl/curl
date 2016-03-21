#ifndef HEADER_CURL_LIMITS_H
#define HEADER_CURL_LIMITS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2016, Karlson2k (Evgeny Grin).
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifndef USHORT_MAX
#define USHORT_MAX ((unsigned short)~((unsigned short)0)))
#endif /* USHORT_MAX */

#ifndef INT_MAX
#define INT_MAX ((int)((~((int)0))>>1))
#endif /* INT_MAX */

#ifndef UINT_MAX
#define UINT_MAX ((unsigned int)~((unsigned int)0)))
#endif /* UINT_MAX */


#endif /* HEADER_CURL_LIMITS_H */
