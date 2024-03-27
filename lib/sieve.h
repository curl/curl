#ifndef HEADER_CURL_SIEVE_H
#define HEADER_CURL_SIEVE_H
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

#include "pingpong.h"
#include "dynbuf.h"
#include "bufref.h"

/****************************************************************************
 * SIEVE unique setup
 ***************************************************************************/

/* Machine states */
typedef enum {
  SIEVE_STOP,
  SIEVE_SERVERGREET,
  SIEVE_STARTTLS,
  SIEVE_UPGRADETLS,
  SIEVE_TLS,
  SIEVE_AUTHENTICATE,
  SIEVE_CAPABILITY,
  SIEVE_LISTSCRIPTS,
  SIEVE_PUTSCRIPT,
  SIEVE_GETSCRIPT,
  SIEVE_GETSCRIPT_FINAL,
  SIEVE_LOGOUT,
  SIEVE_LAST            /* never used */
} sievestate;

/* This SIEVE struct is used in the Curl_easy. All SIEVE data that is
   connection-oriented must be in sieve_conn to properly deal with the fact
   that perhaps the Curl_easy is changed between the times the connection is
   used. */
struct SIEVE {
  curl_pp_transfer transfer;
  char *owner;                  /* Script owner. */
  char *scriptname;             /* Script name. */
  char *custom;                 /* Custom request. */
  char *custom_params;          /* Custom request parameters. */
};

/* Connection flags. */
#define SIEVE_CONN_HAS_TLS      (1 << 0)        /* STARTTLS supported. */
#define SIEVE_CONN_BYE          (1 << 1)        /* BYE received. */
#define SIEVE_CONN_REDIRECTED   (1 << 2)        /* Redirection requested. */
#define SIEVE_CONN_INITED       (1 << 3)        /* Connection initialized. */

/* sieve_conn is used for struct connection-oriented data in the connectdata
   struct */
struct sieve_conn {
  struct pingpong pp;
  struct dynbuf respbuf;        /* Multi-line response buffer. */
  struct SASL sasl;             /* SASL-related parameters */
  struct bufref saslmsg;        /* SASL response message */
  CURLU *referral;              /* Redirection URL. */
  sievestate state;             /* Always use sieve_state() to change state! */
  sievestate donestate;         /* State to enter after DO phase. */
  size_t litlength;             /* Literal length to read */
  unsigned int maxredirs;       /* Redirection count allowed by the server. */
  unsigned int flags;           /* Connection flags. */
};

extern const struct Curl_handler Curl_handler_sieve;

#endif /* HEADER_CURL_SIEVE_H */
