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
#include "unitcheck.h"
#include "tool_cfgable.h"
#include "tool_operate.h"
#include "tool_cb_rea.h"
#include "tool_cb_wrt.h"
#include "tool_cb_prg.h"
#include "tool_progress.h"

static CURLcode test_tool3501(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(_WIN32) && defined(HAVE_PIPE) && defined(HAVE_FCNTL_H)
  struct OperationConfig config;
  struct per_transfer a, b;
  int fds[2];
  int flags;
  int i;
  char buffer[1];
  FILE *stream;

  memset(&config, 0, sizeof(config));
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  abort_unless(pipe(fds) == 0, "create input pipe");
  flags = fcntl(fds[0], F_GETFL, 0);
  if(flags < 0 || fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) < 0) {
    curlx_close(fds[0]);
    curlx_close(fds[1]);
    fail("make input nonblocking");
    goto unit_test_abort;
  }
  stream = curlx_fopen("/dev/null", "r+b");
  if(!stream) {
    curlx_close(fds[0]);
    curlx_close(fds[1]);
    fail("create output stream");
    goto unit_test_abort;
  }
  a.config = b.config = &config;
  a.infd = fds[0];
  b.infd = fileno(stream);
  a.uploadfilesize = b.uploadfilesize = -1;
  if(globalconf_init()) {
    fail("initialize configuration");
    goto cleanup;
  }
  a.curl = curl_easy_init();
  b.curl = curl_easy_init();
  b.progressbar.out = stream;
  b.outs.stream = stream;
  if(!a.curl || !b.curl) {
    fail("initialize handles and configuration");
    goto cleanup;
  }

  for(i = 0; i < 5; ++i) {
    fail_unless(tool_read_cb(buffer, 1, sizeof(buffer), &a) ==
                CURL_READFUNC_PAUSE, "empty pipe pauses transfer A");
    fail_unless(a.readbusy, "A has a pending resume");
    switch(i) {
    case 0:
      xferinfo_cb(&b, 0, 0, 0, 0);
      break;
    case 1:
      tool_readbusy_cb(&b, 0, 0, 0, 0);
      break;
    case 2:
      tool_progress_cb(&b, 0, 0, 0, 0);
      break;
    case 3:
      tool_write_cb(buffer, 1, 0, &b);
      break;
    default:
      tool_read_cb(buffer, 1, sizeof(buffer), &b);
      break;
    }
    fail_unless(a.readbusy, "B must not consume A's pending resume");
    xferinfo_cb(&a, 0, 0, 0, 0);
    fail_if(a.readbusy, "A consumes its own pending resume");
  }

  fail_unless(write(fds[1], "x", 1) == 1, "supply upload data");
  fail_unless(tool_read_cb(buffer, 1, sizeof(buffer), &a) == 1,
              "ordinary input remains readable");
  fail_unless(buffer[0] == 'x', "upload data is unchanged");
  fail_if(a.readbusy, "successful read leaves no pending resume");

cleanup:
  curl_easy_cleanup(a.curl);
  curl_easy_cleanup(b.curl);
  globalconf_free();
  curlx_fclose(stream);
  curlx_close(fds[0]);
  curlx_close(fds[1]);
#endif

  UNITTEST_END_SIMPLE
}
