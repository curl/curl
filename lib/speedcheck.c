/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

void Curl_speedinit(struct Curl_easy *data)
{
  memset(&data->state.speedcheck_starttime, 0, sizeof(struct timeval));
  data->state.speedcheck_startbytes = 0;
}

/*
 * @unittest: 1606
 */
CURLcode Curl_speedcheck(struct Curl_easy *data,
                         struct timeval now)
{
  time_t howlong = Curl_tvdiff(now, data->state.speedcheck_starttime);
  if(data->set.low_speed_time > 0 && howlong > 0) {
    /* Note the starttime<now test, don't bother in the same second */

    curl_off_t so_far = data->progress.downloaded + data->progress.uploaded;

    if(data->state.speedcheck_starttime.tv_sec) {
      /* we have recorded a starttime */

      /* TODO: thresh is rounded down in this integer division,
       * is that a problem? */
      curl_off_t thresh = (data->set.low_speed_limit * howlong) / 1000L;

      if(thresh < (so_far - data->state.speedcheck_startbytes)) {
        /* reset if enough bytes have been transferred inside the time limit */
        data->state.speedcheck_starttime = now;
        data->state.speedcheck_startbytes = so_far;
      }
      else if(howlong >= data->set.low_speed_time * 1000) {
        /* too long */
        failf(data,
              "Operation too slow. "
              "Less than %ld bytes/sec transferred the last %ld seconds",
              data->set.low_speed_limit,
              data->set.low_speed_time);
        return CURLE_OPERATION_TIMEDOUT;
      }
      /* else, we'll check again next time */
    }
    else {
      /* we have not started the count yet, begin now */
      data->state.speedcheck_starttime = now;
      data->state.speedcheck_startbytes = so_far;
    }

    /* set the expire timer to checked again in a second */
    Curl_expire(data, 1000, EXPIRE_SPEEDCHECK);
  }

  return CURLE_OK;
}
