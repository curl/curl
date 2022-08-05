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

#if defined(__AMIGA__)

#include "hostip.h"
#include "amigaos.h"

#if defined(HAVE_PROTO_BSDSOCKET_H)
#  if defined(__amigaos4__)
#    include <bsdsocket/socketbasetags.h>
#  elif !defined(USE_AMISSL)
#    include <amitcp/socketbasetags.h>
#  endif
#endif

#if defined(__libnix__)
#  include <stabs.h>
#endif

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#if defined(HAVE_PROTO_BSDSOCKET_H)

#if defined(__amigaos4__)
/*
 * AmigaOS 4.x specific code
 */

/*
 * hostip4.c - Curl_ipv4_resolve_r() replacement code
 *
 * Logic that needs to be considered are the following build cases:
 * - newlib networking
 * - clib2 networking
 * - direct bsdsocket.library networking (usually AmiSSL builds)
 * Each with the threaded resolver enabled or not.
 *
 * With the threaded resolver enabled, try to use gethostbyname_r() where
 * available, otherwise (re)open bsdsocket.library and fallback to
 * gethostbyname().
 */

#include <proto/bsdsocket.h>

static struct SocketIFace *__CurlISocket = NULL;
static uint32 SocketFeatures = 0;

#define HAVE_BSDSOCKET_GETHOSTBYNAME_R 0x01
#define HAVE_BSDSOCKET_GETADDRINFO     0x02

CURLcode Curl_amiga_init(void)
{
  struct SocketIFace *ISocket;
  struct Library *base = OpenLibrary("bsdsocket.library", 4);

  if(base) {
    ISocket = (struct SocketIFace *)GetInterface(base, "main", 1, NULL);
    if(ISocket) {
      ULONG enabled = 0;

      SocketBaseTags(SBTM_SETVAL(SBTC_CAN_SHARE_LIBRARY_BASES), TRUE,
                     SBTM_GETREF(SBTC_HAVE_GETHOSTADDR_R_API), (ULONG)&enabled,
                     TAG_DONE);

      if(enabled) {
        SocketFeatures |= HAVE_BSDSOCKET_GETHOSTBYNAME_R;
      }

      __CurlISocket = ISocket;

      atexit(Curl_amiga_cleanup);

      return CURLE_OK;
    }
    CloseLibrary(base);
  }

  return CURLE_FAILED_INIT;
}

void Curl_amiga_cleanup(void)
{
  if(__CurlISocket) {
    struct Library *base = __CurlISocket->Data.LibBase;
    DropInterface((struct Interface *)__CurlISocket);
    CloseLibrary(base);
    __CurlISocket = NULL;
  }
}

#if defined(CURLRES_AMIGA)
/*
 * Because we need to handle the different cases in hostip4.c at run-time,
 * not at compile-time, based on what was detected in Curl_amiga_init(),
 * we replace it completely with our own as to not complicate the baseline code
 */

struct Curl_addrinfo *Curl_ipv4_resolve_r(const char *hostname,
                                          int port)
{
  struct Curl_addrinfo *ai = NULL;
  struct hostent *h;
  struct SocketIFace *ISocket = __CurlISocket;

  if(SocketFeatures & HAVE_BSDSOCKET_GETHOSTBYNAME_R) {
    LONG h_errnop = 0;
    struct hostent *buf;

    /* Don't use malloc/calloc/free as they are not necessarily threadsafe */
    buf = AllocVecTags(CURL_HOSTENT_SIZE,
                       AVT_Type, MEMF_SHARED,
                       AVT_Lock, FALSE,
                       AVT_ClearWithValue, 0,
                       TAG_DONE);
    if(buf) {
      h = gethostbyname_r((STRPTR)hostname, buf,
                          (char *)buf + sizeof(struct hostent),
                          CURL_HOSTENT_SIZE - sizeof(struct hostent),
                          &h_errnop);
      if(h) {
        ai = Curl_he2ai(h, port);
      }
      FreeVec(buf);
    }
  }
  else {
    #if defined(CURLRES_THREADED)
    /* gethostbyname() is not thread safe, so we need to reopen bsdsocket
     * on the thread's context
     */
    struct Library *base = OpenLibrary("bsdsocket.library", 4);
    if(base) {
      ISocket = (struct SocketIFace *)GetInterface(base, "main", 1, NULL);
      if(ISocket) {
        h = gethostbyname((STRPTR)hostname);
        if(h) {
          ai = Curl_he2ai(h, port);
        }
        DropInterface((struct Interface *)ISocket);
      }
      CloseLibrary(base);
    }
    #else
    /* not using threaded resolver - safe to use this as-is */
    h = gethostbyname(hostname);
    if(h) {
      ai = Curl_he2ai(h, port);
    }
    #endif
  }

  return ai;
}
#endif /* defined(CURLRES_AMIGA) */

#if defined(USE_AMISSL)
int Curl_amiga_select(int nfds, fd_set *readfds, fd_set *writefds,
                      fd_set *errorfds, struct timeval *timeout)
{
  int r = WaitSelect(nfds, readfds, writefds, errorfds, timeout, 0);
  /* Ensure Ctrl-C signal is actioned */
  if((r == -1) && (SOCKERRNO == EINTR))
    raise(SIGINT);
  return r;
}
#endif

#if defined(HAVE_GETADDRINFO_RUNTIME_COND)
bool Curl_getaddrinfo_is_available(bool in_thread)
{
  /* Curl_getaddrinfo_ex() uses malloc() which may not be threadsafe  */
  #if defined(__NEWLIB__)
  if(SocketFeatures & HAVE_BSDSOCKET_GETADDRINFO)
    return TRUE;
  #else
  if((SocketFeatures & HAVE_BSDSOCKET_GETADDRINFO) && !in_thread)
    return TRUE;
  #endif
  return FALSE
}
#endif /* HAVE_GETADDRINFO_RUNTIME_COND */

#elif !defined(USE_AMISSL) /* defined(__amigaos4__) */
/*
 * Amiga OS3 specific code
 */

struct Library *SocketBase = NULL;
extern int errno, h_errno;

#ifdef __libnix__
void __request(const char *msg);
#else
# define __request(msg)       Printf(msg "\n\a")
#endif

void Curl_amiga_cleanup(void)
{
  if(SocketBase) {
    CloseLibrary(SocketBase);
    SocketBase = NULL;
  }
}

CURLcode Curl_amiga_init(void)
{
  if(!SocketBase)
    SocketBase = OpenLibrary("bsdsocket.library", 4);

  if(!SocketBase) {
    __request("No TCP/IP Stack running!");
    return CURLE_FAILED_INIT;
  }

  if(SocketBaseTags(SBTM_SETVAL(SBTC_ERRNOPTR(sizeof(errno))), (ULONG) &errno,
                    SBTM_SETVAL(SBTC_LOGTAGPTR), (ULONG) "curl",
                    TAG_DONE)) {
    __request("SocketBaseTags ERROR");
    return CURLE_FAILED_INIT;
  }

#ifndef __libnix__
  atexit(Curl_amiga_cleanup);
#endif

  return CURLE_OK;
}

#ifdef __libnix__
ADD2EXIT(Curl_amiga_cleanup, -50);
#endif

#endif /* !defined(USE_AMISSL) */

#endif /* defined(PROTO_BSDSOCKET_H) */

#endif /* defined(__AMIGA__) */
