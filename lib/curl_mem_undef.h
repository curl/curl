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

/* Unset redefined system symbols. */

#undef strdup
#undef malloc
#undef calloc
#undef realloc
#undef free
#undef send
#undef recv

#ifdef _WIN32
#undef _tcsdup
#endif

#undef socket
#ifdef HAVE_ACCEPT4
#undef accept4
#endif
#ifdef HAVE_SOCKETPAIR
#undef socketpair
#endif

#undef fopen
#ifdef CURL_FOPEN
#define fopen(fname, mode) CURL_FOPEN(fname, mode)
#endif
#undef fdopen
#undef fclose

#undef HEADER_CURL_MEMORY_H
#undef HEADER_CURL_MEMDEBUG_H
