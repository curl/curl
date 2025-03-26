#ifndef HEADER_CURL_TOOL_BINMODE_H
#define HEADER_CURL_TOOL_BINMODE_H
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

#if (defined(HAVE_SETMODE) || defined(HAVE__SETMODE)) && defined(O_BINARY)
/* Requires io.h and/or fcntl.h when available */
#ifdef HAVE__SETMODE
#  define CURL_SET_BINMODE(stream)  (void)_setmode(fileno(stream), O_BINARY)
#else
#  define CURL_SET_BINMODE(stream)  (void)setmode(fileno(stream), O_BINARY)
#endif
#else
#  define CURL_SET_BINMODE(stream)  (void)stream; tool_nop_stmt
#endif

#endif /* HEADER_CURL_TOOL_BINMODE_H */
