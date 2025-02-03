#ifndef HEADER_FETCH_WARNLESS_H
#define HEADER_FETCH_WARNLESS_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifdef USE_WINSOCK
#include <fetch/fetch.h> /* for fetch_socket_t */
#endif

#define FETCHX_FUNCTION_CAST(target_type, func) \
  (target_type)(void (*)(void))(func)

unsigned short fetchx_ultous(unsigned long ulnum);

unsigned char fetchx_ultouc(unsigned long ulnum);

int fetchx_uztosi(size_t uznum);

unsigned long fetchx_uztoul(size_t uznum);

unsigned int fetchx_uztoui(size_t uznum);

int fetchx_sltosi(long slnum);

unsigned int fetchx_sltoui(long slnum);

unsigned short fetchx_sltous(long slnum);

ssize_t fetchx_uztosz(size_t uznum);

size_t fetchx_sotouz(fetch_off_t sonum);

int fetchx_sztosi(ssize_t sznum);

unsigned short fetchx_uitous(unsigned int uinum);

size_t fetchx_sitouz(int sinum);

#if defined(_WIN32)

ssize_t fetchx_read(int fd, void *buf, size_t count);

ssize_t fetchx_write(int fd, const void *buf, size_t count);

#endif /* _WIN32 */

#endif /* HEADER_FETCH_WARNLESS_H */

#ifndef HEADER_FETCH_WARNLESS_H_REDEFS
#define HEADER_FETCH_WARNLESS_H_REDEFS

#if defined(_WIN32)
#undef read
#define read(fd, buf, count) fetchx_read(fd, buf, count)
#undef write
#define write(fd, buf, count) fetchx_write(fd, buf, count)
#endif

#endif /* HEADER_FETCH_WARNLESS_H_REDEFS */
