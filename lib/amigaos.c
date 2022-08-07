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

#include "curl_setup.h"

#ifdef __AMIGA__
#  include "amigaos.h"
#  if defined(HAVE_PROTO_BSDSOCKET_H) && !defined(USE_AMISSL)
#    include <amitcp/socketbasetags.h>
#  endif
#  ifdef __libnix__
#    include <stabs.h>
#  endif
#endif

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#ifdef __AMIGA__

#ifdef __amigaos4__

#ifdef USE_AMISSL
int Curl_amiga_select(int nfds, fd_set *readfds, fd_set *writefds,
                      fd_set *errorfds, struct timeval *timeout)
{
  int r = WaitSelect(nfds, readfds, writefds, errorfds, timeout, 0);
  /* Ensure Ctrl-C signal is actioned */
  if((r == -1) && (SOCKERRNO == EINTR))
    raise(SIGINT);
  return r;
}
#endif /* USE_AMISSL */

#elif defined(HAVE_PROTO_BSDSOCKET_H) && !defined(USE_AMISSL)
struct Library *SocketBase = NULL;
extern int errno, h_errno;

#ifdef __libnix__
void __request(const char *msg);
#else
# define __request(msg)       Printf(msg "\n\a")
#endif

void Curl_amiga_cleanup()
{
  if(SocketBase) {
    CloseLibrary(SocketBase);
    SocketBase = NULL;
  }
}

bool Curl_amiga_init()
{
  if(!SocketBase)
    SocketBase = OpenLibrary("bsdsocket.library", 4);

  if(!SocketBase) {
    __request("No TCP/IP Stack running!");
    return FALSE;
  }

  if(SocketBaseTags(SBTM_SETVAL(SBTC_ERRNOPTR(sizeof(errno))), (ULONG) &errno,
                    SBTM_SETVAL(SBTC_LOGTAGPTR), (ULONG) "curl",
                    TAG_DONE)) {
    __request("SocketBaseTags ERROR");
    return FALSE;
  }

#ifndef __libnix__
  atexit(Curl_amiga_cleanup);
#endif

  return TRUE;
}

#ifdef __libnix__
ADD2EXIT(Curl_amiga_cleanup, -50);
#endif

#endif /* HAVE_PROTO_BSDSOCKET_H */

#endif /* __AMIGA__ */

