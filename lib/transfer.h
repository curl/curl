#ifndef __TRANSFER_H
#define __TRANSFER_H
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
CURLcode Curl_perform(struct SessionHandle *data);
CURLcode Curl_pretransfer(struct SessionHandle *data);
CURLcode Curl_posttransfer(struct SessionHandle *data);
CURLcode Curl_follow(struct SessionHandle *data, char *newurl);
CURLcode Curl_readwrite(struct connectdata *conn, bool *done);
void Curl_single_fdset(struct connectdata *conn, 
                       fd_set *read_fd_set,
                       fd_set *write_fd_set,
                       fd_set *exc_fd_set,
                       int *max_fd);
CURLcode Curl_readwrite_init(struct connectdata *conn);

/* This sets up a forthcoming transfer */
CURLcode 
Curl_Transfer (struct connectdata *data,
               int sockfd,		/* socket to read from or -1 */
               int size,		/* -1 if unknown at this point */
               bool getheader,     	/* TRUE if header parsing is wanted */
               long *bytecountp,	/* return number of bytes read */
               int writesockfd,      /* socket to write to, it may very well be
                                        the same we read from. -1 disables */
               long *writebytecountp /* return number of bytes written */
);
#endif
