#ifndef __CONNECT_H
#define __CONNECT_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

int Curl_nonblock(int socket,    /* operate on this */
                  int nonblock   /* TRUE or FALSE */);

CURLcode Curl_is_connected(struct connectdata *conn,
                           int sockfd,
                           bool *connected);

CURLcode Curl_connecthost(struct connectdata *conn,
                          struct Curl_dns_entry *host, /* connect to this */
                          int port,       /* connect to this port number */
                          int *sockconn,  /* not set if error is returned */
                          Curl_ipconnect **addr, /* the one we used */
                          bool *connected /* truly connected? */
                          );
#endif
