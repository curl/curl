#ifndef HEADER_FETCH_DYNBUF_H
#define HEADER_FETCH_DYNBUF_H
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

#include <fetch/fetch.h>

#ifndef BUILDING_LIBFETCH
/* this renames the functions so that the tool code can use the same code
   without getting symbol collisions */
#define Fetch_dyn_init(a, b) fetchx_dyn_init(a, b)
#define Fetch_dyn_add(a, b) fetchx_dyn_add(a, b)
#define Fetch_dyn_addn(a, b, c) fetchx_dyn_addn(a, b, c)
#define Fetch_dyn_addf fetchx_dyn_addf
#define Fetch_dyn_vaddf fetchx_dyn_vaddf
#define Fetch_dyn_free(a) fetchx_dyn_free(a)
#define Fetch_dyn_ptr(a) fetchx_dyn_ptr(a)
#define Fetch_dyn_uptr(a) fetchx_dyn_uptr(a)
#define Fetch_dyn_len(a) fetchx_dyn_len(a)
#define Fetch_dyn_reset(a) fetchx_dyn_reset(a)
#define Fetch_dyn_take(a, b) fetchx_dyn_take(a, b)
#define Fetch_dyn_tail(a, b) fetchx_dyn_tail(a, b)
#define Fetch_dyn_setlen(a, b) fetchx_dyn_setlen(a, b)
#define fetchx_dynbuf dynbuf /* for the struct name */
#endif

struct dynbuf
{
  char *bufr;    /* point to a null-terminated allocated buffer */
  size_t leng;   /* number of bytes *EXCLUDING* the null-terminator */
  size_t allc;   /* size of the current allocation */
  size_t toobig; /* size limit for the buffer */
#ifdef DEBUGBUILD
  int init; /* detect API usage mistakes */
#endif
};

void Fetch_dyn_init(struct dynbuf *s, size_t toobig);
void Fetch_dyn_free(struct dynbuf *s);
FETCHcode Fetch_dyn_addn(struct dynbuf *s, const void *mem, size_t len)
    WARN_UNUSED_RESULT;
FETCHcode Fetch_dyn_add(struct dynbuf *s, const char *str)
    WARN_UNUSED_RESULT;
FETCHcode Fetch_dyn_addf(struct dynbuf *s, const char *fmt, ...)
    WARN_UNUSED_RESULT FETCH_PRINTF(2, 3);
FETCHcode Fetch_dyn_vaddf(struct dynbuf *s, const char *fmt, va_list ap)
    WARN_UNUSED_RESULT FETCH_PRINTF(2, 0);
void Fetch_dyn_reset(struct dynbuf *s);
FETCHcode Fetch_dyn_tail(struct dynbuf *s, size_t trail);
FETCHcode Fetch_dyn_setlen(struct dynbuf *s, size_t set);
char *Fetch_dyn_ptr(const struct dynbuf *s);
unsigned char *Fetch_dyn_uptr(const struct dynbuf *s);
size_t Fetch_dyn_len(const struct dynbuf *s);

/* returns 0 on success, -1 on error */
/* The implementation of this function exists in mprintf.c */
int Fetch_dyn_vprintf(struct dynbuf *dyn, const char *format, va_list ap_save);

/* Take the buffer out of the dynbuf. Caller has ownership and
 * dynbuf resets to initial state. */
char *Fetch_dyn_take(struct dynbuf *s, size_t *plen);

/* Dynamic buffer max sizes */
#define DYN_DOH_RESPONSE 3000
#define DYN_DOH_CNAME 256
#define DYN_PAUSE_BUFFER (64 * 1024 * 1024)
#define DYN_HAXPROXY 2048
#define DYN_HTTP_REQUEST (1024 * 1024)
#define DYN_APRINTF 8000000
#define DYN_RTSP_REQ_HEADER (64 * 1024)
#define DYN_TRAILERS (64 * 1024)
#define DYN_PROXY_CONNECT_HEADERS 16384
#define DYN_QLOG_NAME 1024
#define DYN_H1_TRAILER 4096
#define DYN_PINGPPONG_CMD (64 * 1024)
#define DYN_IMAP_CMD (64 * 1024)
#define DYN_MQTT_RECV (64 * 1024)
#endif
