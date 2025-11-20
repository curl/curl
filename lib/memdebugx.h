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
#define X_STRINGIFY(x) #x
#define X_TOSTRING(x) X_STRINGIFY(x)
#ifdef XMEM
#if XMEM == 1
/*#warning "XMEM defined DEFAULT"*/
#elif XMEM == 2
/*#warning "XMEM defined CURLALLOC"*/
#elif XMEM == 9
/*#warning "XMEM defined DEBUG"*/
#else
/*#warning "XMEM defined unknown " X_TOSTRING(XMEM)*/
#endif
#else
/*#warning "XMEM not defined"*/
#endif
#ifdef XMEMNEW
#if XMEMNEW == 1
/*#warning "XMEMNEW defined DEFAULT"*/
#elif XMEMNEW == 2
/*#warning "XMEMNEW defined CURLALLOC"*/
#elif XMEMNEW == 9
/*#warning "XMEMNEW defined DEBUG"*/
#else
/*#warning "XMEMNEW defined unknown " X_TOSTRING(XMEMNEW)*/
#endif
#else
/*#warning "XMEMNEW not defined"*/
#endif
#if (XMEM != XMEMNEW)
/*#error "ERROR: new macros do not match the old overrides"*/
#endif
