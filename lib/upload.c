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

#include "setup.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef WIN32
#if !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#endif
#include <time.h> /* for the time_t typedef! */

#if defined(__GNUC__) && defined(TIME_WITH_SYS_TIME)
#include <sys/time.h>
#endif

#endif

#include <curl/curl.h>

#ifdef __BEOS__
#include <net/socket.h>
#endif

#include "urldata.h"
#include "speedcheck.h"
#include "sendf.h"
#include "progress.h"

/* --- upload a stream to a socket --- */

UrgError Upload(struct UrlData *data,
                int sockfd,
                long *bytecountp)
{
  fd_set writefd;
  fd_set keepfd;
  struct timeval interval;
  bool keepon=TRUE;
  char *buf = data->buffer;
  size_t nread;
  long bytecount=0;
  struct timeval start;
  struct timeval now;
  UrgError urg;
  char scratch[BUFSIZE * 2];
  int i, si;
      
  /* timeout every X second
     - makes a better progressmeter (i.e even when no data is sent, the
       meter can be updated and reflect reality)
     - allows removal of the alarm() crap
     - variable timeout is easier
     */
            
  myalarm(0); /* switch off the alarm-style timeout */

  start = tvnow();
  now = start;

  FD_ZERO(&writefd); /* clear it */
  FD_SET(sockfd, &writefd);
      
  keepfd = writefd;

  while(keepon) {
    size_t bytes_written = 0;

    writefd = keepfd; /* set this every lap in the loop */
    interval.tv_sec = 2;
    interval.tv_usec = 0;

    switch(select(sockfd+1, NULL, &writefd, NULL, &interval)) {
    case -1: /* error, stop writing */
      keepon=FALSE;
      continue;
    case 0: /* timeout */
      break;
    default: /* write! */
      if(data->crlf)
        buf = data->buffer; /* put it back on the buffer */

      nread = data->fread(buf, 1, BUFSIZE, data->in);
      bytecount += nread;

      if (nread==0) {
        /* done */
        keepon = FALSE; 
        break;
      }

      /* convert LF to CRLF if so asked */
      if (data->crlf) {
	for(i = 0, si = 0; i < (int)nread; i++, si++) {
          if (buf[i] == 0x0a) {
            scratch[si++] = 0x0d;
            scratch[si] = 0x0a;
          }
          else {
            scratch[si] = buf[i];
          }
	}
	nread = si;
        buf = scratch; /* point to the new buffer */
      }

      /* write to socket */
#ifndef USE_SSLEAY
      bytes_written = swrite(sockfd, buf, nread);
#else
      if (data->use_ssl) {
        bytes_written = SSL_write(data->ssl, buf, nread);
      } else {
        bytes_written = swrite(sockfd, buf, nread);
      }
#endif /* USE_SSLEAY */
      if(nread != bytes_written) {
        failf(data, "Failed uploading file");
        return URG_FTP_WRITE_ERROR;
      }
    }
    now = tvnow();
    ProgressShow(data, bytecount, start, now, FALSE);
    urg=speedcheck(data, now);
    if(urg)
      return urg;
    if(data->timeout && (tvdiff(now,start)>data->timeout)) {
      failf(data, "Upload timed out with %d bytes sent", bytecount);
      return URG_OPERATION_TIMEOUTED;
    }

  }
  ProgressShow(data, bytecount, start, now, TRUE);
  *bytecountp = bytecount;

  return URG_OK;
}
