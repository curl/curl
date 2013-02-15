#ifndef HEADER_CURL_MULTIIF_H
#define HEADER_CURL_MULTIIF_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * Prototypes for library-wide functions provided by multi.c
 */
void Curl_expire(struct SessionHandle *data, long milli);

bool Curl_multi_pipeline_enabled(const struct Curl_multi* multi);
void Curl_multi_handlePipeBreak(struct SessionHandle *data);

/* the write bits start at bit 16 for the *getsock() bitmap */
#define GETSOCK_WRITEBITSTART 16

#define GETSOCK_BLANK 0 /* no bits set */

/* set the bit for the given sock number to make the bitmap for writable */
#define GETSOCK_WRITESOCK(x) (1 << (GETSOCK_WRITEBITSTART + (x)))

/* set the bit for the given sock number to make the bitmap for readable */
#define GETSOCK_READSOCK(x) (1 << (x))

#ifdef DEBUGBUILD
 /*
  * Curl_multi_dump is not a stable public function, this is only meant to
  * allow easier tracking of the internal handle's state and what sockets
  * they use. Only for research and development DEBUGBUILD enabled builds.
  */
void Curl_multi_dump(const struct Curl_multi *multi_handle);
#endif

/* Update the current connection of a One_Easy handle */
void Curl_multi_set_easy_connection(struct SessionHandle *handle,
                                    struct connectdata *conn);

void Curl_multi_process_pending_handles(struct Curl_multi *multi);

/* Return the value of the CURLMOPT_MAX_HOST_CONNECTIONS option */
size_t Curl_multi_max_host_connections(struct Curl_multi *multi);

/* Return the value of the CURLMOPT_MAX_PIPELINE_LENGTH option */
size_t Curl_multi_max_pipeline_length(struct Curl_multi *multi);

/* Return the value of the CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE option */
curl_off_t Curl_multi_content_length_penalty_size(struct Curl_multi *multi);

/* Return the value of the CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE option */
curl_off_t Curl_multi_chunk_length_penalty_size(struct Curl_multi *multi);

/* Return the value of the CURLMOPT_PIPELINING_SITE_BL option */
struct curl_llist *Curl_multi_pipelining_site_bl(struct Curl_multi *multi);

/* Return the value of the CURLMOPT_PIPELINING_SERVER_BL option */
struct curl_llist *Curl_multi_pipelining_server_bl(struct Curl_multi *multi);

/* Return the value of the CURLMOPT_MAX_TOTAL_CONNECTIONS option */
size_t Curl_multi_max_total_connections(struct Curl_multi *multi);

#endif /* HEADER_CURL_MULTIIF_H */
