#ifndef HEADER_CURL_TRANSFER_H
#define HEADER_CURL_TRANSFER_H
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

#define Curl_headersep(x) ((((x)==':') || ((x)==';')))
char *Curl_checkheaders(const struct Curl_easy *data,
                        const char *thisheader,
                        const size_t thislen);

void Curl_init_CONNECT(struct Curl_easy *data);

CURLcode Curl_pretransfer(struct Curl_easy *data);
CURLcode Curl_posttransfer(struct Curl_easy *data);

typedef enum {
  FOLLOW_NONE,  /* not used within the function, just a placeholder to
                   allow initing to this */
  FOLLOW_FAKE,  /* only records stuff, not actually following */
  FOLLOW_RETRY, /* set if this is a request retry as opposed to a real
                   redirect following */
  FOLLOW_REDIR /* a full true redirect */
} followtype;

CURLcode Curl_follow(struct Curl_easy *data, char *newurl,
                     followtype type);
CURLcode Curl_readwrite(struct Curl_easy *data);
int Curl_single_getsock(struct Curl_easy *data,
                        struct connectdata *conn, curl_socket_t *socks);
CURLcode Curl_retry_request(struct Curl_easy *data, char **url);
bool Curl_meets_timecondition(struct Curl_easy *data, time_t timeofdoc);

/**
 * Write the transfer raw response bytes, as received from the connection.
 * Will handle all passed bytes or return an error. By default, this will
 * write the bytes as BODY to the client. Protocols may provide a
 * "write_resp" callback in their handler to add specific treatment. E.g.
 * HTTP parses response headers and passes them differently to the client.
 * @param data     the transfer
 * @param buf      the raw response bytes
 * @param blen     the amount of bytes in `buf`
 * @param is_eos   TRUE iff the connection indicates this to be the last
 *                 bytes of the response
 */
CURLcode Curl_xfer_write_resp(struct Curl_easy *data,
                              const char *buf, size_t blen,
                              bool is_eos);

/**
 * Write a single "header" line from a server response.
 * @param hd0      the 0-terminated, single header line
 * @param hdlen    the length of the header line
 * @param is_eos   TRUE iff this is the end of the response
 */
CURLcode Curl_xfer_write_resp_hd(struct Curl_easy *data,
                                 const char *hd0, size_t hdlen, bool is_eos);

/* This sets up a forthcoming transfer */
void Curl_xfer_setup(struct Curl_easy *data,
                     int sockindex,     /* socket index to read from or -1 */
                     curl_off_t size,   /* -1 if unknown at this point */
                     bool getheader,    /* TRUE if header parsing is wanted */
                     int writesockindex /* socket index to write to. May be
                                           the same we read from. -1
                                           disables */
  );

/**
 * Multi has set transfer to DONE. Last chance to trigger
 * missing response things like writing an EOS to the client.
 */
CURLcode Curl_xfer_write_done(struct Curl_easy *data, bool premature);

/**
 * Send data on the socket/connection filter designated
 * for transfer's outgoing data.
 * Will return CURLE_OK on blocking with (*pnwritten == 0).
 */
CURLcode Curl_xfer_send(struct Curl_easy *data,
                        const void *buf, size_t blen,
                        size_t *pnwritten);

/**
 * Receive data on the socket/connection filter designated
 * for transfer's incoming data.
 * Will return CURLE_AGAIN on blocking with (*pnrcvd == 0).
 */
CURLcode Curl_xfer_recv(struct Curl_easy *data,
                        char *buf, size_t blen,
                        ssize_t *pnrcvd);

CURLcode Curl_xfer_send_close(struct Curl_easy *data);

#endif /* HEADER_CURL_TRANSFER_H */
