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
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
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

#include <stdio.h>
#if defined(__MINGW32__)
#include <winsock.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "speedcheck.h"

void speedinit(struct UrlData *data)
{
  memset(&data->keeps_speed, 0, sizeof(struct timeval));
}

CURLcode speedcheck(struct UrlData *data,
                    struct timeval now)
{
  if((data->progress.current_speed >= 0) &&
     data->low_speed_time &&
     (tvlong(data->keeps_speed) != 0) &&
     (data->progress.current_speed < data->low_speed_limit)) {

    /* We are now below the "low speed limit". If we are below it
       for "low speed time" seconds we consider that enough reason
       to abort the download. */
    
    if( tvdiff(now, data->keeps_speed) > data->low_speed_time) {
      /* we have been this slow for long enough, now die */
      failf(data,
	    "Operation too slow. "
	    "Less than %d bytes/sec transfered the last %d seconds",
	    data->low_speed_limit,
	    data->low_speed_time);
      return CURLE_OPERATION_TIMEOUTED;
    }
  }
  else {
    /* we keep up the required speed all right */
    data->keeps_speed = now;
  }
  return CURLE_OK;
}

