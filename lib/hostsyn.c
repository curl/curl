/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"

#include <string.h>
#include <errno.h>

#define _REENTRANT

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <malloc.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>	/* required for free() prototypes */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>     /* for the close() proto */
#endif
#ifdef	VMS
#include <in.h>
#include <inet.h>
#include <stdlib.h>
#endif
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#ifdef WIN32
#include <process.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "strerror.h"
#include "url.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

#include "memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/***********************************************************************
 * Only for builds using synchronous name resolves
 **********************************************************************/
#ifdef CURLRES_SYNCH

/*
 * Curl_wait_for_resolv() for synch-builds.  Curl_resolv() can never return
 * wait==TRUE, so this function will never be called. If it still gets called,
 * we return failure at once.
 *
 * We provide this function only to allow multi.c to remain unaware if we are
 * doing asynch resolves or not.
 */
CURLcode Curl_wait_for_resolv(struct connectdata *conn,
                              struct Curl_dns_entry **entry)
{
  (void)conn;
  *entry=NULL;
  return CURLE_COULDNT_RESOLVE_HOST;
}

/*
 * This function will never be called when synch-built. If it still gets
 * called, we return failure at once.
 *
 * We provide this function only to allow multi.c to remain unaware if we are
 * doing asynch resolves or not.
 */
CURLcode Curl_is_resolved(struct connectdata *conn,
                          struct Curl_dns_entry **dns)
{
  (void)conn;
  *dns = NULL;

  return CURLE_COULDNT_RESOLVE_HOST;
}

/*
 * We just return OK, this function is never actually used for synch builds.
 * It is present here to keep #ifdefs out from multi.c
 */

CURLcode Curl_fdset(struct connectdata *conn,
                    fd_set *read_fd_set,
                    fd_set *write_fd_set,
                    int *max_fdp)
{
  (void)conn;
  (void)read_fd_set;
  (void)write_fd_set;
  (void)max_fdp;

  return CURLE_OK;
}

#endif /* truly sync */
