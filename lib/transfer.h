#ifndef __TRANSFER_H
#define __TRANSFER_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/
CURLcode Curl_perform(CURL *curl);

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

#ifdef _OLDCURL
/* "hackish" define to make sources compile without too much human editing.
   Don't use "Tranfer()" anymore! */
#define Transfer(a,b,c,d,e,f,g) Curl_Transfer(a,b,c,d,e,f,g)
#endif

#endif
