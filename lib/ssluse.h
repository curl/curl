#ifndef __SSLUSE_H
#define __SSLUSE_H
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
#include "urldata.h"
CURLcode Curl_SSLConnect(struct connectdata *conn);

void Curl_SSL_init(void);    /* Global SSL init */
void Curl_SSL_cleanup(void); /* Global SSL cleanup */

/* init the SSL session ID cache */
CURLcode Curl_SSL_InitSessions(struct SessionHandle *, long);
void Curl_SSL_Close(struct connectdata *conn); /* close a SSL connection */

/* tell the SSL stuff to close down all open information regarding 
   connections (and thus session ID caching etc) */
int Curl_SSL_Close_All(struct SessionHandle *data);
#endif
