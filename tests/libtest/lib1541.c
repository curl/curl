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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define XSTR(x) #x
#define STRING(y) XSTR(y)

int test(char *URL)
{
  char detect[512];
  char syst[512];

  const char *types_h = "No";
  const char *socket_h = "No";
  const char *ws2tcpip_h = "No";
  const char *stypes_h = "No";
  const char *ssocket_h = "No";
  const char *sws2tcpip_h = "No";

  (void)(URL);

#ifdef CURL_PULL_SYS_TYPES_H
  types_h = "Yes";
#endif
#ifdef CURL_PULL_SYS_SOCKET_H
  socket_h = "Yes";
#endif
#ifdef CURL_PULL_WS2TCPIP_H
  ws2tcpip_h = "Yes";
#endif
  snprintf(detect, sizeof(detect),
#ifdef CHECK_CURL_OFF_T
           "CURL_TYPEOF_CURL_OFF_T:     %s\n"
#endif
           "CURL_FORMAT_CURL_OFF_T:     %s\n"
           "CURL_FORMAT_CURL_OFF_TU:    %s\n"
           "CURL_SUFFIX_CURL_OFF_T:     %s\n"
           "CURL_SUFFIX_CURL_OFF_TU:    %s\n"
           "CURL_SIZEOF_CURL_OFF_T:     %d\n"
           "CURL_SIZEOF_LONG:           %d\n"
           "CURL_TYPEOF_CURL_SOCKLEN_T: %s\n"
           "CURL_PULL_SYS_TYPES_H:      %s\n"
           "CURL_PULL_SYS_SOCKET_H:     %s\n"
           "CURL_PULL_WS2TCPIP_H:       %s\n"

#ifdef CHECK_CURL_OFF_T
           , STRING(CURL_TYPEOF_CURL_OFF_T)
#endif
           , CURL_FORMAT_CURL_OFF_T
           , CURL_FORMAT_CURL_OFF_TU
           , STRING(CURL_SUFFIX_CURL_OFF_T)
           , STRING(CURL_SUFFIX_CURL_OFF_TU)
           , CURL_SIZEOF_CURL_OFF_T
           , CURL_SIZEOF_LONG
           , STRING(CURL_TYPEOF_CURL_SOCKLEN_T)
           , types_h
           , socket_h
           , ws2tcpip_h);

#ifdef CURLSYS_PULL_SYS_TYPES_H
  stypes_h = "Yes";
#endif
#ifdef CURLSYS_PULL_SYS_SOCKET_H
  ssocket_h = "Yes";
#endif
#ifdef CURLSYS_PULL_WS2TCPIP_H
  sws2tcpip_h = "Yes";
#endif
  snprintf(syst, sizeof(syst),
#ifdef CHECK_CURL_OFF_T
           "CURL_TYPEOF_CURL_OFF_T:     %s\n"
#endif
           "CURL_FORMAT_CURL_OFF_T:     %s\n"
           "CURL_FORMAT_CURL_OFF_TU:    %s\n"
           "CURL_SUFFIX_CURL_OFF_T:     %s\n"
           "CURL_SUFFIX_CURL_OFF_TU:    %s\n"
           "CURL_SIZEOF_CURL_OFF_T:     %d\n"
           "CURL_SIZEOF_LONG:           %d\n"
           "CURL_TYPEOF_CURL_SOCKLEN_T: %s\n"
           "CURL_PULL_SYS_TYPES_H:      %s\n"
           "CURL_PULL_SYS_SOCKET_H:     %s\n"
           "CURL_PULL_WS2TCPIP_H:       %s\n"

#ifdef CHECK_CURL_OFF_T
           , STRING(CURLSYS_TYPEOF_CURL_OFF_T)
#endif
           , CURLSYS_FORMAT_CURL_OFF_T
           , CURLSYS_FORMAT_CURL_OFF_TU
           , STRING(CURLSYS_SUFFIX_CURL_OFF_T)
           , STRING(CURLSYS_SUFFIX_CURL_OFF_TU)
           , CURLSYS_SIZEOF_CURL_OFF_T
           , CURLSYS_SIZEOF_LONG
           , STRING(CURLSYS_TYPEOF_CURL_SOCKLEN_T)
           , stypes_h
           , ssocket_h
           , sws2tcpip_h);

  if(strcmp(detect, syst)) {
    printf("===> Type detection failed <====\n");
    printf("[Detected]\n%s", detect);
    printf("[System]\n%s", syst);
    return 1; /* FAIL! */
  }

  return 0;
}
