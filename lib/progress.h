#ifndef __PROGRESS_H
#define __PROGRESS_H
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

#include "timeval.h"


typedef enum {
  TIMER_NONE,
  TIMER_NAMELOOKUP,
  TIMER_CONNECT,
  TIMER_PRETRANSFER,
  TIMER_STARTTRANSFER,
  TIMER_POSTRANSFER,
  TIMER_STARTSINGLE,
  TIMER_REDIRECT,
  TIMER_LAST /* must be last */
} timerid;
  
void Curl_pgrsDone(struct connectdata *);
void Curl_pgrsStartNow(struct SessionHandle *data);
void Curl_pgrsSetDownloadSize(struct SessionHandle *data, double size);
void Curl_pgrsSetUploadSize(struct SessionHandle *data, double size);
void Curl_pgrsSetDownloadCounter(struct SessionHandle *data, double size);
void Curl_pgrsSetUploadCounter(struct SessionHandle *data, double size);
int Curl_pgrsUpdate(struct connectdata *);
void Curl_pgrsResetTimes(struct SessionHandle *data);
void Curl_pgrsTime(struct SessionHandle *data, timerid timer);


/* Don't show progress for sizes smaller than: */
#define LEAST_SIZE_PROGRESS BUFSIZE

#define PROGRESS_DOWNLOAD (1<<0)
#define PROGRESS_UPLOAD   (1<<1)
#define PROGRESS_DOWN_AND_UP (PROGRESS_UPLOAD | PROGRESS_DOWNLOAD)

#define PGRS_SHOW_DL (1<<0)
#define PGRS_SHOW_UL (1<<1)
#define PGRS_DONE_DL (1<<2)
#define PGRS_DONE_UL (1<<3)
#define PGRS_HIDE    (1<<4)
#define PGRS_UL_SIZE_KNOWN (1<<5)
#define PGRS_DL_SIZE_KNOWN (1<<6)

#define PGRS_HEADERS_OUT (1<<7) /* set when the headers have been written */


#endif /* __PROGRESS_H */
