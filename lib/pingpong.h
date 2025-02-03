#ifndef HEADER_FETCH_PINGPONG_H
#define HEADER_FETCH_PINGPONG_H
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

#include "fetch_setup.h"

#if !defined(FETCH_DISABLE_IMAP) || !defined(FETCH_DISABLE_FTP) || \
    !defined(FETCH_DISABLE_POP3) || !defined(FETCH_DISABLE_SMTP)
#define USE_PINGPONG
#endif

/* forward-declaration, this is defined in urldata.h */
struct connectdata;

typedef enum
{
  PPTRANSFER_BODY, /* yes do transfer a body */
  PPTRANSFER_INFO, /* do still go through to get info/headers */
  PPTRANSFER_NONE  /* do not get anything and do not get info */
} fetch_pp_transfer;

/*
 * 'pingpong' is the generic struct used for protocols doing server<->client
 * conversations in a back-and-forth style such as FTP, IMAP, POP3, SMTP etc.
 *
 * It holds response cache and non-blocking sending data.
 */
struct pingpong
{
  size_t nread_resp;         /* number of bytes currently read of a server response */
  bool pending_resp;         /* set TRUE when a server response is pending or in
                                progress, and is cleared once the last response is
                                read */
  char *sendthis;            /* pointer to a buffer that is to be sent to the server */
  size_t sendleft;           /* number of bytes left to send from the sendthis buffer */
  size_t sendsize;           /* total size of the sendthis buffer */
  struct fetchtime response; /* set to Fetch_now() when a command has been sent
                               off, used to time-out response reading */
  timediff_t response_time;  /* When no timeout is given, this is the amount of
                                milliseconds we await for a server response. */
  struct dynbuf sendbuf;
  struct dynbuf recvbuf;
  size_t overflow; /* number of bytes left after a final response line */
  size_t nfinal;   /* number of bytes in the final response line, which
                      after a match is first in the receice buffer */

  /* Function pointers the protocols MUST implement and provide for the
     pingpong layer to function */

  FETCHcode (*statemachine)(struct Fetch_easy *data, struct connectdata *conn);
  bool (*endofresp)(struct Fetch_easy *data, struct connectdata *conn,
                    char *ptr, size_t len, int *code);
};

#define PINGPONG_SETUP(pp, s, e)      \
  do                                  \
  {                                   \
    pp->response_time = RESP_TIMEOUT; \
    pp->statemachine = s;             \
    pp->endofresp = e;                \
  } while (0)

/*
 * Fetch_pp_statemach()
 *
 * called repeatedly until done. Set 'wait' to make it wait a while on the
 * socket if there is no traffic.
 */
FETCHcode Fetch_pp_statemach(struct Fetch_easy *data, struct pingpong *pp,
                            bool block, bool disconnecting);

/* initialize stuff to prepare for reading a fresh new response */
void Fetch_pp_init(struct pingpong *pp);

/* Returns timeout in ms. 0 or negative number means the timeout has already
   triggered */
timediff_t Fetch_pp_state_timeout(struct Fetch_easy *data,
                                 struct pingpong *pp, bool disconnecting);

/***********************************************************************
 *
 * Fetch_pp_sendf()
 *
 * Send the formatted string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * made to never block
 */
FETCHcode Fetch_pp_sendf(struct Fetch_easy *data,
                        struct pingpong *pp,
                        const char *fmt, ...) FETCH_PRINTF(3, 4);

/***********************************************************************
 *
 * Fetch_pp_vsendf()
 *
 * Send the formatted string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * made to never block
 */
FETCHcode Fetch_pp_vsendf(struct Fetch_easy *data,
                         struct pingpong *pp,
                         const char *fmt,
                         va_list args) FETCH_PRINTF(3, 0);

/*
 * Fetch_pp_readresp()
 *
 * Reads a piece of a server response.
 */
FETCHcode Fetch_pp_readresp(struct Fetch_easy *data,
                           int sockindex,
                           struct pingpong *pp,
                           int *code,     /* return the server code if done */
                           size_t *size); /* size of the response */

bool Fetch_pp_needs_flush(struct Fetch_easy *data,
                         struct pingpong *pp);

FETCHcode Fetch_pp_flushsend(struct Fetch_easy *data,
                            struct pingpong *pp);

/* call this when a pingpong connection is disconnected */
FETCHcode Fetch_pp_disconnect(struct pingpong *pp);

int Fetch_pp_getsock(struct Fetch_easy *data, struct pingpong *pp,
                    fetch_socket_t *socks);

/***********************************************************************
 *
 * Fetch_pp_moredata()
 *
 * Returns whether there are still more data in the cache and so a call
 * to Fetch_pp_readresp() will not block.
 */
bool Fetch_pp_moredata(struct pingpong *pp);

#endif /* HEADER_FETCH_PINGPONG_H */
