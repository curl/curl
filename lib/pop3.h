#ifndef HEADER_CURL_POP3_H
#define HEADER_CURL_POP3_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2009 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/****************************************************************************
 * POP3 unique setup
 ***************************************************************************/
typedef enum {
  POP3_STOP,        /* do nothing state, stops the state machine */
  POP3_SERVERGREET, /* waiting for the initial greeting immediately after
                       a connect */
  POP3_USER,
  POP3_PASS,
  POP3_STARTTLS,
  POP3_LIST,
  POP3_LIST_SINGLE,
  POP3_RETR,
  POP3_QUIT,
  POP3_LAST  /* never used */
} pop3state;

/* pop3_conn is used for struct connection-oriented data in the connectdata
   struct */
struct pop3_conn {
  struct pingpong pp;
  char *mailbox;     /* what to RETR */
  size_t eob;        /* number of bytes of the EOB (End Of Body) that has been
                        received thus far */
  size_t strip;      /* number of bytes from the start to ignore as non-body */
  pop3state state; /* always use pop3.c:state() to change state! */
};

extern const struct Curl_handler Curl_handler_pop3;
extern const struct Curl_handler Curl_handler_pop3s;

/*
 * This function scans the body after the end-of-body and writes everything
 * until the end is found.
 */
CURLcode Curl_pop3_write(struct connectdata *conn,
                         char *str,
                         size_t nread);

#endif /* HEADER_CURL_POP3_H */
