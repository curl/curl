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

#include "setup.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "urldata.h"
#include <curl/curl.h>

#ifdef __BEOS__
#include <net/socket.h>
#endif

#ifdef WIN32
#if !defined( __GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#endif
#include <time.h> /* for the time_t typedef! */

#if defined(__GNUC__) && defined(TIME_WITH_SYS_TIME)
#include <sys/time.h>
#endif

#endif

#include "progress.h"
#include "sendf.h"

#include <curl/types.h>

/* --- download and upload a stream from/to a socket --- */

/* Parts of this function was brought to us by the friendly Mark Butler
   <butlerm@xmission.com>. */

CURLcode 
Curl_Transfer(CURLconnect *c_conn,
         /* READ stuff */
	  int sockfd,		/* socket to read from or -1 */
	  int size,		/* -1 if unknown at this point */
	  bool getheader,	/* TRUE if header parsing is wanted */
	  long *bytecountp,	/* return number of bytes read or NULL */
          
          /* WRITE stuff */
          int writesockfd,      /* socket to write to, it may very well be
                                   the same we read from. -1 disables */
          long *writebytecountp /* return number of bytes written or NULL */
          )
{
  struct connectdata *conn = (struct connectdata *)c_conn;
  if(!conn)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* now copy all input parameters */
  conn->sockfd = sockfd;
  conn->size = size;
  conn->getheader = getheader;
  conn->bytecountp = bytecountp;
  conn->writesockfd = writesockfd;
  conn->writebytecountp = writebytecountp;

  return CURLE_OK;

}
          
