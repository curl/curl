#ifndef HEADER_CURL_POP3_H
#define HEADER_CURL_POP3_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2009 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
  POP3_STOP,         /* do nothing state, stops the state machine */
  POP3_SERVERGREET,  /* waiting for the initial greeting immediately after
                        a connect */
  POP3_STARTTLS,
  POP3_CAPA,
  POP3_AUTH_PLAIN,
  POP3_AUTH_LOGIN,
  POP3_AUTH_LOGIN_PASSWD,
  POP3_AUTH_CRAMMD5,
  POP3_AUTH_DIGESTMD5,
  POP3_AUTH_DIGESTMD5_RESP,
  POP3_AUTH_NTLM,
  POP3_AUTH_NTLM_TYPE2MSG,
  POP3_AUTH,
  POP3_USER,
  POP3_PASS,
  POP3_COMMAND,
  POP3_QUIT,
  POP3_LAST          /* never used */
} pop3state;

/* pop3_conn is used for struct connection-oriented data in the connectdata
   struct */
struct pop3_conn {
  struct pingpong pp;
  char *mailbox;          /* Message ID */
  char *custom;           /* Custom Request */
  size_t eob;             /* Number of bytes of the EOB (End Of Body) that
                             have been received so far */
  size_t strip;           /* Number of bytes from the start to ignore as
                             non-body */
  unsigned int authmechs; /* Accepted authentication methods */
  unsigned int authused;  /* Authentication method used for the connection */
  pop3state state;        /* Always use pop3.c:state() to change state! */
};

extern const struct Curl_handler Curl_handler_pop3;
extern const struct Curl_handler Curl_handler_pop3s;

/* This is the 5-bytes End-Of-Body marker for POP3 */
#define POP3_EOB "\x0d\x0a\x2e\x0d\x0a"
#define POP3_EOB_LEN 5

/* This function scans the body after the end-of-body and writes everything
 * until the end is found */
CURLcode Curl_pop3_write(struct connectdata *conn, char *str, size_t nread);

#endif /* HEADER_CURL_POP3_H */
