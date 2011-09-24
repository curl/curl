/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "setup.h"

#include <curl/curl.h>

#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_msgs.h"
#include "tool_cb_skt.h"

#include "memdebug.h" /* keep this as LAST include */

/*
** callback for CURLOPT_SOCKOPTFUNCTION
*/

int tool_sockopt_cb(void *userdata, curl_socket_t curlfd, curlsocktype purpose)
{
  struct Configurable *config = userdata;

  int onoff = 1; /* this callback is only used if we ask for keepalives on the
                    connection */

#if defined(TCP_KEEPIDLE) || defined(TCP_KEEPINTVL)
  int keepidle = (int)config->alivetime;
#endif

  switch(purpose) {
  case CURLSOCKTYPE_IPCXN:
    if(setsockopt(curlfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&onoff,
                  sizeof(onoff)) < 0) {
      /* don't abort operation, just issue a warning */
      SET_SOCKERRNO(0);
      warnf(config, "Could not set SO_KEEPALIVE!\n");
      return 0;
    }
    else {
      if(config->alivetime) {
#ifdef TCP_KEEPIDLE
        if(setsockopt(curlfd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&keepidle,
                      sizeof(keepidle)) < 0) {
          /* don't abort operation, just issue a warning */
          SET_SOCKERRNO(0);
          warnf(config, "Could not set TCP_KEEPIDLE!\n");
          return 0;
        }
#endif
#ifdef TCP_KEEPINTVL
        if(setsockopt(curlfd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepidle,
                      sizeof(keepidle)) < 0) {
          /* don't abort operation, just issue a warning */
          SET_SOCKERRNO(0);
          warnf(config, "Could not set TCP_KEEPINTVL!\n");
          return 0;
        }
#endif
#if !defined(TCP_KEEPIDLE) || !defined(TCP_KEEPINTVL)
        warnf(config, "Keep-alive functionality somewhat crippled due to "
              "missing support in your operating system!\n");
#endif
      }
    }
    break;
  default:
    break;
  }

  return 0;
}

