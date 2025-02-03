#ifndef HEADER_FETCH_TRANSFER_H
#define HEADER_FETCH_TRANSFER_H
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

#define Fetch_headersep(x) ((((x) == ':') || ((x) == ';')))
char *Fetch_checkheaders(const struct Fetch_easy *data,
                        const char *thisheader,
                        const size_t thislen);

void Fetch_init_CONNECT(struct Fetch_easy *data);

FETCHcode Fetch_pretransfer(struct Fetch_easy *data);

FETCHcode Fetch_sendrecv(struct Fetch_easy *data, struct fetchtime *nowp);
int Fetch_single_getsock(struct Fetch_easy *data,
                        struct connectdata *conn, fetch_socket_t *socks);
FETCHcode Fetch_retry_request(struct Fetch_easy *data, char **url);
bool Fetch_meets_timecondition(struct Fetch_easy *data, time_t timeofdoc);

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
FETCHcode Fetch_xfer_write_resp(struct Fetch_easy *data,
                               const char *buf, size_t blen,
                               bool is_eos);

/**
 * Write a single "header" line from a server response.
 * @param hd0      the 0-terminated, single header line
 * @param hdlen    the length of the header line
 * @param is_eos   TRUE iff this is the end of the response
 */
FETCHcode Fetch_xfer_write_resp_hd(struct Fetch_easy *data,
                                  const char *hd0, size_t hdlen, bool is_eos);

#define FETCH_XFER_NOP (0)
#define FETCH_XFER_RECV (1 << (0))
#define FETCH_XFER_SEND (1 << (1))
#define FETCH_XFER_SENDRECV (FETCH_XFER_RECV | FETCH_XFER_SEND)

/**
 * The transfer is neither receiving nor sending now.
 */
void Fetch_xfer_setup_nop(struct Fetch_easy *data);

/**
 * The transfer will use socket 1 to send/recv. `recv_size` is
 * the amount to receive or -1 if unknown. `getheader` indicates
 * response header processing is expected.
 */
void Fetch_xfer_setup1(struct Fetch_easy *data,
                      int send_recv,
                      fetch_off_t recv_size,
                      bool getheader);

/**
 * The transfer will use socket 2 to send/recv. `recv_size` is
 * the amount to receive or -1 if unknown. With `shutdown` being
 * set, the transfer is only allowed to either send OR receive
 * and the socket 2 connection will be shutdown at the end of
 * the transfer. An unclean shutdown will fail the transfer
 * unless `shutdown_err_ignore` is TRUE.
 */
void Fetch_xfer_setup2(struct Fetch_easy *data,
                      int send_recv,
                      fetch_off_t recv_size,
                      bool shutdown, bool shutdown_err_ignore);

/**
 * Multi has set transfer to DONE. Last chance to trigger
 * missing response things like writing an EOS to the client.
 */
FETCHcode Fetch_xfer_write_done(struct Fetch_easy *data, bool premature);

/**
 * Return TRUE iff transfer has pending data to send. Checks involved
 * connection filters.
 */
bool Fetch_xfer_needs_flush(struct Fetch_easy *data);

/**
 * Flush any pending send data on the transfer connection.
 */
FETCHcode Fetch_xfer_flush(struct Fetch_easy *data);

/**
 * Send data on the socket/connection filter designated
 * for transfer's outgoing data.
 * Will return FETCHE_OK on blocking with (*pnwritten == 0).
 */
FETCHcode Fetch_xfer_send(struct Fetch_easy *data,
                         const void *buf, size_t blen, bool eos,
                         size_t *pnwritten);

/**
 * Receive data on the socket/connection filter designated
 * for transfer's incoming data.
 * Will return FETCHE_AGAIN on blocking with (*pnrcvd == 0).
 */
FETCHcode Fetch_xfer_recv(struct Fetch_easy *data,
                         char *buf, size_t blen,
                         ssize_t *pnrcvd);

FETCHcode Fetch_xfer_send_close(struct Fetch_easy *data);
FETCHcode Fetch_xfer_send_shutdown(struct Fetch_easy *data, bool *done);

/**
 * Return TRUE iff the transfer is not done, but further progress
 * is blocked. For example when it is only receiving and its writer
 * is PAUSED.
 */
bool Fetch_xfer_is_blocked(struct Fetch_easy *data);

#endif /* HEADER_FETCH_TRANSFER_H */
