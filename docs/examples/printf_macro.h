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
/* Simple hack trying to get a valid printf format string for size_t.
 * If that fails for your platform you can define your own _FMT_SIZE_T,
 * f.e.: -D_FMT_SIZE_T="zd"
 */
#ifndef _PRINTF_MACRO_H
#define _PRINTF_MACRO_H

#ifndef _FMT_SIZE_T
#ifdef WIN32
#define _FMT_SIZE_T "Id"
#else
/*
"zd" is a GNU extension to POSIX; so we dont use it for size_t but hack around
#define _FMT_SIZE_T "zd"
*/
#ifdef __x86_64__
#define _FMT_SIZE_T "lu"
#else
#define _FMT_SIZE_T "u"
#endif /* __x86_64__ */
#endif /* WIN32 */
#endif /* !_FMT_SIZE_T */

#endif /* !_PRINTF_MACRO_H */
