#ifndef __PROGRESS_H
#define __PROGRESS_H
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

#include "timeval.h"

#if 0
void ProgressInit(struct UrlData *data, int max);
void ProgressShow(struct UrlData *data,
                  int point, struct timeval start, struct timeval now, bool force);
void ProgressEnd(struct UrlData *data);
void ProgressMode(int mode);
#endif

void pgrsMode(struct UrlData *data, int mode);
void pgrsStartNow(struct UrlData *data);
void pgrsSetDownloadSize(struct UrlData *data, double size);
void pgrsSetUploadSize(struct UrlData *data, double size);
void pgrsSetDownloadCounter(struct UrlData *data, double size);
     void pgrsSetUploadCounter(struct UrlData *data, double size);
void pgrsUpdate(struct UrlData *data);


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


typedef enum {
  TIMER_NONE,
  TIMER_NAMELOOKUP,
  TIMER_CONNECT,
  TIMER_PRETRANSFER,
  TIMER_POSTRANSFER,
  TIMER_LAST /* must be last */
} timerid;
  

#endif /* __PROGRESS_H */
