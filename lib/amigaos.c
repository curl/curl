/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(__AMIGA__) && !defined(__ixemul__)

#include <amitcp/socketbasetags.h>

#include "amigaos.h"

struct Library *SocketBase = NULL;
extern int errno, h_errno;

#ifdef __libnix__
#include <stabs.h>
void __request(const char *msg);
#else
# define __request( msg )       Printf( msg "\n\a")
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
                    SBTM_SETVAL(SBTC_LOGTAGPTR), (ULONG) "cURL",
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
ADD2EXIT(Curl_amiga_cleanup,-50);
#endif

#endif /* __AMIGA__ && ! __ixemul__ */
