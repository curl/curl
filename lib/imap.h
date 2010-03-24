#ifndef __IMAP_H
#define __IMAP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "pingpong.h"

/****************************************************************************
 * IMAP unique setup
 ***************************************************************************/
typedef enum {
  IMAP_STOP,    /* do nothing state, stops the state machine */
  IMAP_SERVERGREET, /* waiting for the initial greeting immediately after
                       a connect */
  IMAP_LOGIN,
  IMAP_STARTTLS,
  IMAP_SELECT,
  IMAP_FETCH,
  IMAP_LOGOUT,
  IMAP_LAST  /* never used */
} imapstate;

/* imap_conn is used for struct connection-oriented data in the connectdata
   struct */
struct imap_conn {
  struct pingpong pp;
  char *mailbox;     /* what to FETCH */
  imapstate state; /* always use imap.c:state() to change state! */
  int cmdid;       /* id number/index */
  const char *idstr; /* pointer to a string for which to wait for as id */
};

extern const struct Curl_handler Curl_handler_imap;
extern const struct Curl_handler Curl_handler_imaps;

#endif /* __IMAP_H */
