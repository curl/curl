#ifndef HEADER_CURL_GEMINI_H
#define HEADER_CURL_GEMINI_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#if defined USE_SSL && !defined CURL_DISABLE_GEMINI
extern const struct Curl_handler Curl_handler_gemini;
#endif

/*
 * According to specification, response has following format:
 *
 *     <STATUS><SPACE><META><CR><LF>
 *
 * and <META> is UTF-8 string up to 1024 bytes long, so buffer of
 * size >= (2 + 1 + 1024 + 1 + 1) = 1029 is enough to read whole
 * response header into memory. It is more efficient than reading
 * byte-after-byte until \n is found.
 */
#define GEMINI_RESPONSE_BUFSIZE 1029

struct GEMINI {
  struct {
    char memory[GEMINI_RESPONSE_BUFSIZE];
    size_t amount; /* Count of bytes read */
    bool done;
    char *lf; /* Pointer to linefeed character in {data} */
  } block;
  struct {
    char *memory; /* Allocated string */
    size_t amount_total; /* How many bytes in {data} */
    size_t amount_sent; /* How many bytes of it we already sent */
  } request;
  bool redirect;
};

#endif /* HEADER_CURL_GEMINI_H */
