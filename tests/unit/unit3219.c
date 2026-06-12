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
#include "protocol.h"

static CURLcode test_unit3219(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  fail_unless((CURLPROTO_MASK & CURLPROTO_HTTP) == CURLPROTO_HTTP,
              "mask should include HTTP");
  fail_unless((CURLPROTO_MASK & CURLPROTO_GOPHERS) == CURLPROTO_GOPHERS,
              "mask should include the highest public protocol bit");
  fail_unless((CURLPROTO_MASK & CURLPROTO_WS) == 0,
              "mask should exclude websocket protocol bits");
  fail_unless((CURLPROTO_MASK & CURLPROTO_WSS) == 0,
              "mask should exclude secure websocket protocol bits");
  fail_unless((CURLPROTO_MASK & CURLPROTO_MQTTS) == 0,
              "mask should exclude internal-only protocols");

  UNITTEST_END_SIMPLE
}
