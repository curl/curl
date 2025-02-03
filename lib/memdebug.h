#ifndef HEADER_FETCH_MEMDEBUG_H
#define HEADER_FETCH_MEMDEBUG_H
#ifdef FETCHDEBUG
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/*
 * CAUTION: this header is designed to work when included by the app-side
 * as well as the library. Do not mix with library internals!
 */

#include <fetch/fetch.h>
#include "functypes.h"

#if defined(__GNUC__) && __GNUC__ >= 3
#  define ALLOC_FUNC __attribute__((__malloc__))
#  define ALLOC_SIZE(s) __attribute__((__alloc_size__(s)))
#  define ALLOC_SIZE2(n, s) __attribute__((__alloc_size__(n, s)))
#elif defined(_MSC_VER)
#  define ALLOC_FUNC __declspec(restrict)
#  define ALLOC_SIZE(s)
#  define ALLOC_SIZE2(n, s)
#else
#  define ALLOC_FUNC
#  define ALLOC_SIZE(s)
#  define ALLOC_SIZE2(n, s)
#endif

#define FETCH_MT_LOGFNAME_BUFSIZE 512

extern FILE *fetch_dbg_logfile;

/* memory functions */
FETCH_EXTERN ALLOC_FUNC ALLOC_SIZE(1) void *fetch_dbg_malloc(size_t size,
                                                           int line,
                                                           const char *source);
FETCH_EXTERN ALLOC_FUNC ALLOC_SIZE2(1, 2) void *fetch_dbg_calloc(size_t elements,
                                   size_t size, int line, const char *source);
FETCH_EXTERN ALLOC_SIZE(2) void *fetch_dbg_realloc(void *ptr,
                                                 size_t size,
                                                 int line,
                                                 const char *source);
FETCH_EXTERN void fetch_dbg_free(void *ptr, int line, const char *source);
FETCH_EXTERN ALLOC_FUNC char *fetch_dbg_strdup(const char *str, int line,
                                             const char *src);
#if defined(_WIN32) && defined(UNICODE)
FETCH_EXTERN ALLOC_FUNC wchar_t *fetch_dbg_wcsdup(const wchar_t *str,
                                                int line,
                                                const char *source);
#endif

FETCH_EXTERN void fetch_dbg_memdebug(const char *logname);
FETCH_EXTERN void fetch_dbg_memlimit(long limit);
FETCH_EXTERN void fetch_dbg_log(const char *format, ...) FETCH_PRINTF(1, 2);

/* file descriptor manipulators */
FETCH_EXTERN fetch_socket_t fetch_dbg_socket(int domain, int type, int protocol,
                                          int line, const char *source);
FETCH_EXTERN void fetch_dbg_mark_sclose(fetch_socket_t sockfd,
                                      int line, const char *source);
FETCH_EXTERN int fetch_dbg_sclose(fetch_socket_t sockfd,
                                int line, const char *source);
FETCH_EXTERN fetch_socket_t fetch_dbg_accept(fetch_socket_t s, void *a, void *alen,
                                          int line, const char *source);
#ifdef HAVE_SOCKETPAIR
FETCH_EXTERN int fetch_dbg_socketpair(int domain, int type, int protocol,
                                    fetch_socket_t socket_vector[2],
                                    int line, const char *source);
#endif

/* send/receive sockets */
FETCH_EXTERN SEND_TYPE_RETV fetch_dbg_send(SEND_TYPE_ARG1 sockfd,
                                         SEND_QUAL_ARG2 SEND_TYPE_ARG2 buf,
                                         SEND_TYPE_ARG3 len,
                                         SEND_TYPE_ARG4 flags, int line,
                                         const char *source);
FETCH_EXTERN RECV_TYPE_RETV fetch_dbg_recv(RECV_TYPE_ARG1 sockfd,
                                         RECV_TYPE_ARG2 buf,
                                         RECV_TYPE_ARG3 len,
                                         RECV_TYPE_ARG4 flags, int line,
                                         const char *source);

/* FILE functions */
FETCH_EXTERN ALLOC_FUNC FILE *fetch_dbg_fopen(const char *file, const char *mode,
                                  int line, const char *source);
FETCH_EXTERN ALLOC_FUNC FILE *fetch_dbg_fdopen(int filedes, const char *mode,
                                             int line, const char *source);

FETCH_EXTERN int fetch_dbg_fclose(FILE *file, int line, const char *source);

#ifndef MEMDEBUG_NODEFINES

/* Set this symbol on the command-line, recompile all lib-sources */
#undef strdup
#define strdup(ptr) fetch_dbg_strdup(ptr, __LINE__, __FILE__)
#undef malloc
#define malloc(size) fetch_dbg_malloc(size, __LINE__, __FILE__)
#undef calloc
#define calloc(nbelem,size) fetch_dbg_calloc(nbelem, size, __LINE__, __FILE__)
#undef realloc
#define realloc(ptr,size) fetch_dbg_realloc(ptr, size, __LINE__, __FILE__)
#undef free
#define free(ptr) fetch_dbg_free(ptr, __LINE__, __FILE__)
#undef send
#define send(a,b,c,d) fetch_dbg_send(a,b,c,d, __LINE__, __FILE__)
#undef recv
#define recv(a,b,c,d) fetch_dbg_recv(a,b,c,d, __LINE__, __FILE__)

#ifdef _WIN32
#  ifdef UNICODE
#    undef wcsdup
#    define wcsdup(ptr) fetch_dbg_wcsdup(ptr, __LINE__, __FILE__)
#    undef _wcsdup
#    define _wcsdup(ptr) fetch_dbg_wcsdup(ptr, __LINE__, __FILE__)
#    undef _tcsdup
#    define _tcsdup(ptr) fetch_dbg_wcsdup(ptr, __LINE__, __FILE__)
#  else
#    undef _tcsdup
#    define _tcsdup(ptr) fetch_dbg_strdup(ptr, __LINE__, __FILE__)
#  endif
#endif

#undef socket
#define socket(domain,type,protocol)\
 fetch_dbg_socket((int)domain, type, protocol, __LINE__, __FILE__)
#undef accept /* for those with accept as a macro */
#define accept(sock,addr,len)\
 fetch_dbg_accept(sock, addr, len, __LINE__, __FILE__)
#ifdef HAVE_SOCKETPAIR
#define socketpair(domain,type,protocol,socket_vector)\
 fetch_dbg_socketpair((int)domain, type, protocol, socket_vector, \
                     __LINE__, __FILE__)
#endif

#ifndef FETCH_NO_GETADDRINFO_OVERRIDE
#ifdef HAVE_GETADDRINFO
#if defined(getaddrinfo) && defined(__osf__)
/* OSF/1 and Tru64 have getaddrinfo as a define already, so we cannot define
   our macro as for other platforms. Instead, we redefine the new name they
   define getaddrinfo to become! */
#define ogetaddrinfo(host,serv,hint,res) \
  fetch_dbg_getaddrinfo(host, serv, hint, res, __LINE__, __FILE__)
#else
#undef getaddrinfo
#define getaddrinfo(host,serv,hint,res) \
  fetch_dbg_getaddrinfo(host, serv, hint, res, __LINE__, __FILE__)
#endif
#endif /* HAVE_GETADDRINFO */

#ifdef HAVE_FREEADDRINFO
#undef freeaddrinfo
#define freeaddrinfo(data) \
  fetch_dbg_freeaddrinfo(data, __LINE__, __FILE__)
#endif /* HAVE_FREEADDRINFO */
#endif /* !FETCH_NO_GETADDRINFO_OVERRIDE */

/* sclose is probably already defined, redefine it! */
#undef sclose
#define sclose(sockfd) fetch_dbg_sclose(sockfd,__LINE__,__FILE__)

#define fake_sclose(sockfd) fetch_dbg_mark_sclose(sockfd,__LINE__,__FILE__)

#undef fopen
#define fopen(file,mode) fetch_dbg_fopen(file,mode,__LINE__,__FILE__)
#undef fdopen
#define fdopen(file,mode) fetch_dbg_fdopen(file,mode,__LINE__,__FILE__)
#define fclose(file) fetch_dbg_fclose(file,__LINE__,__FILE__)

#endif /* MEMDEBUG_NODEFINES */

#endif /* FETCHDEBUG */

/*
** Following section applies even when FETCHDEBUG is not defined.
*/

#ifndef fake_sclose
#define fake_sclose(x)  Curl_nop_stmt
#endif

/*
 * Curl_safefree defined as a macro to allow MemoryTracking feature
 * to log free() calls at same location where Curl_safefree is used.
 * This macro also assigns NULL to given pointer when free'd.
 */

#define Curl_safefree(ptr) \
  do { free((ptr)); (ptr) = NULL;} while(0)

#endif /* HEADER_FETCH_MEMDEBUG_H */
