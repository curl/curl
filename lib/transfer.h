#ifndef HEADER_CURL_TRANSFER_H
#define HEADER_CURL_TRANSFER_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#define Curl_headersep(x) ((((x)==':') || ((x)==';')))
char *Curl_checkheaders(const struct connectdata *conn,
                        const char *thisheader);

void Curl_init_CONNECT(struct Curl_easy *data);

CURLcode Curl_pretransfer(struct Curl_easy *data);
CURLcode Curl_posttransfer(struct Curl_easy *data);

typedef enum {
  FOLLOW_NONE,  /* not used within the function, just a placeholder to
                   allow initing to this */
  FOLLOW_FAKE,  /* only records stuff, not actually following */
  FOLLOW_RETRY, /* set if this is a request retry as opposed to a real
                          redirect following */
  FOLLOW_REDIR, /* a full true redirect */
  FOLLOW_LAST   /* never used */
} followtype;

CURLcode Curl_follow(struct Curl_easy *data, char *newurl,
                     followtype type);
CURLcode Curl_readwrite(struct connectdata *conn,
                        struct Curl_easy *data, bool *done,
                        bool *comeback);
int Curl_single_getsock(const struct connectdata *conn,
                        curl_socket_t *socks);
CURLcode Curl_readrewind(struct connectdata *conn);
CURLcode Curl_fillreadbuffer(struct connectdata *conn, size_t bytes,
                             size_t *nreadp);
CURLcode Curl_retry_request(struct connectdata *conn, char **url);
bool Curl_meets_timecondition(struct Curl_easy *data, time_t timeofdoc);
CURLcode Curl_get_upload_buffer(struct Curl_easy *data);

CURLcode Curl_done_sending(struct connectdata *conn,
                           struct SingleRequest *k);

/* This sets up a forthcoming transfer */
void
Curl_setup_transfer (struct Curl_easy *data,
                     int sockindex,     /* socket index to read from or -1 */
                     curl_off_t size,   /* -1 if unknown at this point */
                     bool getheader,    /* TRUE if header parsing is wanted */
                     int writesockindex /* socket index to write to. May be
                                           the same we read from. -1
                                           disables */
  );

#endif /* HEADER_CURL_TRANSFER_H */
