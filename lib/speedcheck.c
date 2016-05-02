/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "multiif.h"
#include "speedcheck.h"

void Curl_speedinit(struct SessionHandle *data)
{
  memset(&data->state.keeps_speed, 0, sizeof(struct timeval));
}

CURLcode Curl_speedcheck(struct SessionHandle *data,
                         struct timeval now)
{
  if((data->progress.current_speed >= 0) &&
     data->set.low_speed_time &&
     (Curl_tvlong(data->state.keeps_speed) != 0) &&
     (data->progress.current_speed < data->set.low_speed_limit)) {
    long howlong = Curl_tvdiff(now, data->state.keeps_speed);
    long nextcheck = (data->set.low_speed_time * 1000) - howlong;

    /* We are now below the "low speed limit". If we are below it
       for "low speed time" seconds we consider that enough reason
       to abort the download. */
    if(nextcheck <= 0) {
      /* we have been this slow for long enough, now die */
      failf(data,
            "Operation too slow. "
            "Less than %ld bytes/sec transferred the last %ld seconds",
            data->set.low_speed_limit,
            data->set.low_speed_time);
      return CURLE_OPERATION_TIMEDOUT;
    }
    else {
      /* wait complete low_speed_time */
      Curl_expire_latest(data, nextcheck);
    }
  }
  else {
    /* we keep up the required speed all right */
    data->state.keeps_speed = now;

    if(data->set.low_speed_limit)
      /* if there is a low speed limit enabled, we set the expire timer to
         make this connection's speed get checked again no later than when
         this time is up */
      Curl_expire_latest(data, data->set.low_speed_time*1000);
  }
  return CURLE_OK;
}
