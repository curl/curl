/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

static const char cmd[] = "A1 IDLE\r\n";
static char buf[1024];

int test(char *URL)
{
  CURLM *mcurl;
  CURL *curl = NULL;
  int mrun;
  curl_socket_t sock = CURL_SOCKET_BAD;
  time_t start = time(NULL);
  int state = 0;
  ssize_t pos = 0;

  curl_global_init(CURL_GLOBAL_DEFAULT);
  mcurl = curl_multi_init();
  if(!mcurl)
    goto fail;
  curl = curl_easy_init();
  if(!curl)
    goto fail;

  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  if(curl_easy_setopt(curl, CURLOPT_URL, URL))
    goto fail;
  curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
  if(curl_multi_add_handle(mcurl, curl))
    goto fail;

  while(time(NULL) - start < 5) {
    struct curl_waitfd waitfd;

    if(curl_multi_perform(mcurl, &mrun))
      goto fail;
    for(;;) {
      int i;
      struct CURLMsg *m = curl_multi_info_read(mcurl, &i);

      if(!m)
        break;
      if(m->msg == CURLMSG_DONE && m->easy_handle == curl) {
        curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sock);
        if(sock == CURL_SOCKET_BAD)
          goto fail;
        printf("Connected fine, extracted socket. Moving on\n");
      }
    }

    if(sock != CURL_SOCKET_BAD) {
      waitfd.events = state ? CURL_WAIT_POLLIN : CURL_WAIT_POLLOUT;
      waitfd.revents = 0;
      curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sock);
      waitfd.fd = sock;
    }
    curl_multi_wait(mcurl, &waitfd, sock == CURL_SOCKET_BAD ? 0 : 1, 500,
                    &mrun);
    if((sock != CURL_SOCKET_BAD) && (waitfd.revents & waitfd.events)) {
      size_t len = 0;

      if(!state) {
        curl_easy_send(curl, cmd + pos, sizeof(cmd) - 1 - pos, &len);
        if(len > 0)
          pos += len;
        else
          pos = 0;
        if(pos == sizeof(cmd) - 1) {
          state++;
          pos = 0;
        }
      }
      else if(pos < (ssize_t)sizeof(buf)) {
        curl_easy_recv(curl, buf + pos, sizeof(buf) - pos, &len);
        if(len > 0)
          pos += len;
      }
      if(len <= 0)
        sock = CURL_SOCKET_BAD;
    }
  }

  if(state) {
    fwrite(buf, pos, 1, stdout);
    putchar('\n');
  }

  curl_multi_remove_handle(mcurl, curl);
  fail:
  curl_easy_cleanup(curl);
  curl_multi_cleanup(mcurl);

  curl_global_cleanup();
  return 0;
}

