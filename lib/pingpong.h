#ifndef __PINGPONG_H
#define __PINGPONG_H
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

#include <stdarg.h>

#include "setup.h"

#if !defined(CURL_DISABLE_IMAP) || !defined(CURL_DISABLE_FTP) || \
  !defined(CURL_DISABLE_POP3) || !defined(CURL_DISABLE_SMTP)
#define USE_PINGPONG
#endif

/* forward-declaration, this is defined in urldata.h */
struct connectdata;

/*
 * 'pingpong' is the generic struct used for protocols doing server<->client
 * conversations in a back-and-forth style such as FTP, IMAP, POP3, SMTP etc.
 *
 * It holds response cache and non-blocking sending data.
 */
struct pingpong {
  char *cache;     /* data cache between getresponse()-calls */
  size_t cache_size;  /* size of cache in bytes */
  size_t nread_resp;  /* number of bytes currently read of a server response */
  char *linestart_resp; /* line start pointer for the server response
                           reader function */
  bool pending_resp;  /* set TRUE when a server response is pending or in
                         progress, and is cleared once the last response is
                         read */
  char *sendthis; /* allocated pointer to a buffer that is to be sent to the
                     server */
  size_t sendleft; /* number of bytes left to send from the sendthis buffer */
  size_t sendsize; /* total size of the sendthis buffer */
  struct timeval response; /* set to Curl_tvnow() when a command has been sent
                              off, used to time-out response reading */
  long response_time; /* When no timeout is given, this is the amount of
                         milliseconds we await for a server response. */

  struct connectdata *conn; /* points to the connectdata struct that this
                               belongs to */

  /* Function pointers the protocols MUST implement and provide for the
     pingpong layer to function */

  CURLcode (*statemach_act)(struct connectdata *conn);

  int (*endofresp)(struct pingpong *pp, int *code);
};

/*
 * Curl_pp_multi_statemach()
 *
 * called repeatedly until done when the multi interface is used.
 */
CURLcode Curl_pp_multi_statemach(struct pingpong *pp);

/*
 * Curl_pp_easy_statemach()
 *
 * called repeatedly until done when the easy interface is used.
 */
CURLcode Curl_pp_easy_statemach(struct pingpong *pp);


/* initialize stuff to prepare for reading a fresh new response */
void Curl_pp_init(struct pingpong *pp);

/* Returns timeout in ms. 0 or negative number means the timeout has already
   triggered */
long Curl_pp_state_timeout(struct pingpong *pp);


/***********************************************************************
 *
 * Curl_pp_sendf()
 *
 * Send the formated string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * NOTE: we build the command in a fixed-length buffer, which sets length
 * restrictions on the command!
 *
 * made to never block
 */
CURLcode Curl_pp_sendf(struct pingpong *pp,
                       const char *fmt, ...);

/***********************************************************************
 *
 * Curl_pp_vsendf()
 *
 * Send the formated string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * NOTE: we build the command in a fixed-length buffer, which sets length
 * restrictions on the command!
 *
 * made to never block
 */
CURLcode Curl_pp_vsendf(struct pingpong *pp,
                        const char *fmt,
                        va_list args);

/*
 * Curl_pp_readresp()
 *
 * Reads a piece of a server response.
 */
CURLcode Curl_pp_readresp(curl_socket_t sockfd,
                          struct pingpong *pp,
                          int *code, /* return the server code if done */
                          size_t *size); /* size of the response */


CURLcode Curl_pp_flushsend(struct pingpong *pp);

/* call this when a pingpong connection is disconnected */
CURLcode Curl_pp_disconnect(struct pingpong *pp);

int Curl_pp_getsock(struct pingpong *pp, curl_socket_t *socks,
                    int numsocks);

#endif /* __PINGPONG_H */
