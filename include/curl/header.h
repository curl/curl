#ifndef FETCHINC_HEADER_H
#define FETCHINC_HEADER_H
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

#ifdef  __cplusplus
extern "C" {
#endif

struct fetch_header {
  char *name;    /* this might not use the same case */
  char *value;
  size_t amount; /* number of headers using this name  */
  size_t index;  /* ... of this instance, 0 or higher */
  unsigned int origin; /* see bits below */
  void *anchor; /* handle privately used by libfetch */
};

/* 'origin' bits */
#define FETCHH_HEADER    (1<<0) /* plain server header */
#define FETCHH_TRAILER   (1<<1) /* trailers */
#define FETCHH_CONNECT   (1<<2) /* CONNECT headers */
#define FETCHH_1XX       (1<<3) /* 1xx headers */
#define FETCHH_PSEUDO    (1<<4) /* pseudo headers */

typedef enum {
  FETCHHE_OK,
  FETCHHE_BADINDEX,      /* header exists but not with this index */
  FETCHHE_MISSING,       /* no such header exists */
  FETCHHE_NOHEADERS,     /* no headers at all exist (yet) */
  FETCHHE_NOREQUEST,     /* no request with this number was used */
  FETCHHE_OUT_OF_MEMORY, /* out of memory while processing */
  FETCHHE_BAD_ARGUMENT,  /* a function argument was not okay */
  FETCHHE_NOT_BUILT_IN   /* if API was disabled in the build */
} FETCHHcode;

FETCH_EXTERN FETCHHcode fetch_easy_header(FETCH *easy,
                                       const char *name,
                                       size_t index,
                                       unsigned int origin,
                                       int request,
                                       struct fetch_header **hout);

FETCH_EXTERN struct fetch_header *fetch_easy_nextheader(FETCH *easy,
                                                     unsigned int origin,
                                                     int request,
                                                     struct fetch_header *prev);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* FETCHINC_HEADER_H */
