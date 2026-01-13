#ifndef HEADER_CURL_SIGPIPE_H
#define HEADER_CURL_SIGPIPE_H
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
#include "curl_setup.h"

#if defined(HAVE_SIGACTION) && \
  (defined(USE_OPENSSL) || defined(USE_MBEDTLS) || defined(USE_WOLFSSL))
#include <signal.h>

struct Curl_sigpipe_ctx {
  struct sigaction old_pipe_act;
  BIT(no_signal);
};

static CURL_INLINE void sigpipe_init(struct Curl_sigpipe_ctx *ig)
{
  memset(ig, 0, sizeof(*ig));
  ig->no_signal = TRUE;
}

/*
 * sigpipe_ignore() makes sure we ignore SIGPIPE while running libcurl
 * internals, and then sigpipe_restore() will restore the situation when we
 * return from libcurl again.
 */
static CURL_INLINE void sigpipe_ignore(struct Curl_easy *data,
                                       struct Curl_sigpipe_ctx *ig)
{
  /* get a local copy of no_signal because the Curl_easy might not be
     around when we restore */
  ig->no_signal = data->set.no_signal;
  if(!data->set.no_signal) {
    struct sigaction action;
    /* first, extract the existing situation */
    sigaction(SIGPIPE, NULL, &ig->old_pipe_act);
    action = ig->old_pipe_act;
    /* ignore this signal */
    action.sa_handler = SIG_IGN;
    /* clear SA_SIGINFO flag since we are using sa_handler */
    action.sa_flags &= ~SA_SIGINFO;
    sigaction(SIGPIPE, &action, NULL);
  }
}

/*
 * sigpipe_restore() puts back the outside world's opinion of signal handler
 * and SIGPIPE handling. It MUST only be called after a corresponding
 * sigpipe_ignore() was used.
 */
static CURL_INLINE void sigpipe_restore(struct Curl_sigpipe_ctx *ig)
{
  if(!ig->no_signal)
    /* restore the outside state */
    sigaction(SIGPIPE, &ig->old_pipe_act, NULL);
}

static CURL_INLINE void sigpipe_apply(struct Curl_easy *data,
                                      struct Curl_sigpipe_ctx *ig)
{
  if(data && (data->set.no_signal != ig->no_signal)) {
    sigpipe_restore(ig);
    sigpipe_ignore(data, ig);
  }
}

#else
/* for systems without sigaction */
#define sigpipe_ignore(x, y) do { (void)x; (void)y; } while(0)
#define sigpipe_apply(x, y)  do { (void)x; (void)y; } while(0)
#define sigpipe_init(x)      do { (void)x; } while(0)
#define sigpipe_restore(x)   do { (void)x; } while(0)

struct Curl_sigpipe_ctx {
  bool dummy;
};

#endif

#endif /* HEADER_CURL_SIGPIPE_H */
