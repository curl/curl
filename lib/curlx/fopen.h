#ifndef HEADER_CURLX_FOPEN_H
#define HEADER_CURLX_FOPEN_H
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

#include "../curl_setup.h"

#include "multibyte.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>  /* for open() and attributes */
#endif

int curlx_fseek(void *stream, curl_off_t offset, int whence);

#if defined(_WIN32) && !defined(UNDER_CE)
FILE *curlx_win32_fopen(const char *filename, const char *mode);
int curlx_win32_stat(const char *path, struct_stat *buffer);
int curlx_win32_open(const char *filename, int oflag, ...);
#define CURLX_FOPEN_LOW(fname, mode) curlx_win32_fopen(fname, mode)
#define curlx_stat(fname, stp)       curlx_win32_stat(fname, stp)
#define curlx_open                   curlx_win32_open
#else
#define CURLX_FOPEN_LOW              fopen
#define curlx_stat(fname, stp)       stat(fname, stp)
#define curlx_open                   open
#endif

#ifdef CURLDEBUG
#define curlx_fopen(file,mode)  curl_dbg_fopen(file,mode,__LINE__,__FILE__)
#define curlx_fdopen(file,mode) curl_dbg_fdopen(file,mode,__LINE__,__FILE__)
#define curlx_fclose(file)      curl_dbg_fclose(file,__LINE__,__FILE__)
#else
#define curlx_fopen             CURLX_FOPEN_LOW
#define curlx_fdopen            fdopen
#define curlx_fclose            fclose
#endif

#endif /* HEADER_CURLX_FOPEN_H */
