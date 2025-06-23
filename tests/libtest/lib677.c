/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "first.h"

#include "memdebug.h"

static CURLcode test_lib677(char *URL)
{
  static const char testcmd[] = "A1 IDLE\r\n";
  static char testbuf[1024];

  CURLM *mcurl;
  CURL *curl = NULL;
  int mrun;
  curl_socket_t sock = CURL_SOCKET_BAD;
  time_t start = time(NULL);
  int state = 0;
  ssize_t pos = 0;
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_DEFAULT);
  multi_init(mcurl);
  easy_init(curl);

  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
  if(curl_multi_add_handle(mcurl, curl))
    goto test_cleanup;

  while(time(NULL) - start < 5) {
    struct curl_waitfd waitfd;

    multi_perform(mcurl, &mrun);
    for(;;) {
      int i;
      struct CURLMsg *m = curl_multi_info_read(mcurl, &i);

      if(!m)
        break;
      if(m->msg == CURLMSG_DONE && m->easy_handle == curl) {
        curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sock);
        if(sock == CURL_SOCKET_BAD)
          goto test_cleanup;
        curl_mprintf("Connected fine, extracted socket. Moving on\n");
      }
    }

    if(sock != CURL_SOCKET_BAD) {
      waitfd.events = state ? CURL_WAIT_POLLIN : CURL_WAIT_POLLOUT;
      waitfd.revents = 0;
      curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sock);
      waitfd.fd = sock;
    }
    curl_multi_wait(mcurl, &waitfd, sock == CURL_SOCKET_BAD ? 0 : 1, 50,
                    &mrun);
    if((sock != CURL_SOCKET_BAD) && (waitfd.revents & waitfd.events)) {
      size_t len = 0;

      if(!state) {
        CURLcode ec;
        ec = curl_easy_send(curl, testcmd + pos,
                            sizeof(testcmd) - 1 - pos, &len);
        if(ec == CURLE_AGAIN) {
          continue;
        }
        else if(ec) {
          curl_mfprintf(stderr, "curl_easy_send() failed, with code %d (%s)\n",
                        (int)ec, curl_easy_strerror(ec));
          res = ec;
          goto test_cleanup;
        }
        if(len > 0)
          pos += len;
        else
          pos = 0;
        if(pos == sizeof(testcmd) - 1) {
          state++;
          pos = 0;
        }
      }
      else if(pos < (ssize_t)sizeof(testbuf)) {
        CURLcode ec;
        ec = curl_easy_recv(curl, testbuf + pos, sizeof(testbuf) - pos, &len);
        if(ec == CURLE_AGAIN) {
          continue;
        }
        else if(ec) {
          curl_mfprintf(stderr, "curl_easy_recv() failed, with code %d (%s)\n",
                        (int)ec, curl_easy_strerror(ec));
          res = ec;
          goto test_cleanup;
        }
        if(len > 0)
          pos += len;
      }
      if(len <= 0)
        sock = CURL_SOCKET_BAD;
    }
  }

  if(state) {
    fwrite(testbuf, pos, 1, stdout);
    putchar('\n');
  }

  curl_multi_remove_handle(mcurl, curl);
test_cleanup:
  curl_easy_cleanup(curl);
  curl_multi_cleanup(mcurl);

  curl_global_cleanup();
  return res;
}
