/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "setup.h"

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
#include "speedcheck.h"
#include "sendf.h"

#include <curl/types.h>

/* --- download and upload a stream from/to a socket --- */

/* Parts of this function was brought to us by the friendly Mark Butler
   <butlerm@xmission.com>. */

CURLcode 
Transfer(CURLconnect *c_conn,
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
          
