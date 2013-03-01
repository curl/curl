#ifndef HEADER_CURL_HTTP_CHUNKS_H
#define HEADER_CURL_HTTP_CHUNKS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * The longest possible hexadecimal number we support in a chunked transfer.
 * Weird enough, RFC2616 doesn't set a maximum size! Since we use strtoul()
 * to convert it, we "only" support 2^32 bytes chunk data.
 */
#define MAXNUM_SIZE 16

typedef enum {
  CHUNK_FIRST, /* never use */

  /* In this we await and buffer all hexadecimal digits until we get one
     that isn't a hexadecimal digit. When done, we go POSTHEX */
  CHUNK_HEX,

  /* We have received the hexadecimal digit and we eat all characters until
     we get a CRLF pair. When we see a CR we go to the CR state. */
  CHUNK_POSTHEX,

  /* A single CR has been found and we should get a LF right away in this
     state or we go back to POSTHEX. When LF is received, we go to DATA.
     If the size given was zero, we set state to STOP and return. */
  CHUNK_CR,

  /* We eat the amount of data specified. When done, we move on to the
     POST_CR state. */
  CHUNK_DATA,

  /* POSTCR should get a CR and nothing else, then move to POSTLF */
  CHUNK_POSTCR,

  /* POSTLF should get a LF and nothing else, then move back to HEX as the
     CRLF combination marks the end of a chunk */
  CHUNK_POSTLF,

  /* Each Chunk body should end with a CRLF.  Read a CR and nothing else,
     then move to CHUNK_STOP */
  CHUNK_STOPCR,

  /* This is mainly used to really mark that we're out of the game.
     NOTE: that there's a 'dataleft' field in the struct that will tell how
     many bytes that were not passed to the client in the end of the last
     buffer! */
  CHUNK_STOP,

  /* At this point optional trailer headers can be found, unless the next line
     is CRLF */
  CHUNK_TRAILER,

  /* A trailer CR has been found - next state is CHUNK_TRAILER_POSTCR.
     Next char must be a LF */
  CHUNK_TRAILER_CR,

  /* A trailer LF must be found now, otherwise CHUNKE_BAD_CHUNK will be
     signalled If this is an empty trailer CHUNKE_STOP will be signalled.
     Otherwise the trailer will be broadcasted via Curl_client_write() and the
     next state will be CHUNK_TRAILER */
  CHUNK_TRAILER_POSTCR,

  CHUNK_LAST /* never use */

} ChunkyState;

typedef enum {
  CHUNKE_STOP = -1,
  CHUNKE_OK = 0,
  CHUNKE_TOO_LONG_HEX = 1,
  CHUNKE_ILLEGAL_HEX,
  CHUNKE_BAD_CHUNK,
  CHUNKE_WRITE_ERROR,
  CHUNKE_STATE_ERROR,
  CHUNKE_BAD_ENCODING,
  CHUNKE_OUT_OF_MEMORY,
  CHUNKE_LAST
} CHUNKcode;

struct Curl_chunker {
  char hexbuffer[ MAXNUM_SIZE + 1];
  int hexindex;
  ChunkyState state;
  size_t datasize;
  size_t dataleft; /* untouched data amount at the end of the last buffer */
};

#endif /* HEADER_CURL_HTTP_CHUNKS_H */

