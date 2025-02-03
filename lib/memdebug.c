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

#include "fetch_setup.h"

#ifdef FETCHDEBUG

#include <fetch/fetch.h>

#include "urldata.h"

#define MEMDEBUG_NODEFINES /* do not redefine the standard functions */

/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

struct memdebug {
  size_t size;
  union {
    fetch_off_t o;
    double d;
    void *p;
  } mem[1];
  /* I am hoping this is the thing with the strictest alignment
   * requirements. That also means we waste some space :-( */
};

/*
 * Note that these debug functions are simple and they are meant to remain so.
 * For advanced analysis, record a log file and write perl scripts to analyze
 * them!
 *
 * Do not use these with multithreaded test programs!
 */

FILE *fetch_dbg_logfile = NULL;
static bool registered_cleanup = FALSE; /* atexit registered cleanup */
static bool memlimit = FALSE; /* enable memory limit */
static long memsize = 0;  /* set number of mallocs allowed */

/* LeakSantizier (LSAN) calls _exit() instead of exit() when a leak is detected
   on exit so the logfile must be closed explicitly or data could be lost.
   Though _exit() does not call atexit handlers such as this, LSAN's call to
   _exit() comes after the atexit handlers are called. fetch/fetch#6620 */
static void fetch_dbg_cleanup(void)
{
  if(fetch_dbg_logfile &&
     fetch_dbg_logfile != stderr &&
     fetch_dbg_logfile != stdout) {
    fclose(fetch_dbg_logfile);
  }
  fetch_dbg_logfile = NULL;
}

/* this sets the log filename */
void fetch_dbg_memdebug(const char *logname)
{
  if(!fetch_dbg_logfile) {
    if(logname && *logname)
      fetch_dbg_logfile = fopen(logname, FOPEN_WRITETEXT);
    else
      fetch_dbg_logfile = stderr;
#ifdef MEMDEBUG_LOG_SYNC
    /* Flush the log file after every line so the log is not lost in a crash */
    if(fetch_dbg_logfile)
      setbuf(fetch_dbg_logfile, (char *)NULL);
#endif
  }
  if(!registered_cleanup)
    registered_cleanup = !atexit(fetch_dbg_cleanup);
}

/* This function sets the number of malloc() calls that should return
   successfully! */
void fetch_dbg_memlimit(long limit)
{
  if(!memlimit) {
    memlimit = TRUE;
    memsize = limit;
  }
}

/* returns TRUE if this is not allowed! */
static bool countcheck(const char *func, int line, const char *source)
{
  /* if source is NULL, then the call is made internally and this check
     should not be made */
  if(memlimit && source) {
    if(!memsize) {
      /* log to file */
      fetch_dbg_log("LIMIT %s:%d %s reached memlimit\n",
                   source, line, func);
      /* log to stderr also */
      fprintf(stderr, "LIMIT %s:%d %s reached memlimit\n",
              source, line, func);
      fflush(fetch_dbg_logfile); /* because it might crash now */
      errno = ENOMEM;
      return TRUE; /* RETURN ERROR! */
    }
    else
      memsize--; /* countdown */


  }

  return FALSE; /* allow this */
}

ALLOC_FUNC void *fetch_dbg_malloc(size_t wantedsize,
                                 int line, const char *source)
{
  struct memdebug *mem;
  size_t size;

  DEBUGASSERT(wantedsize != 0);

  if(countcheck("malloc", line, source))
    return NULL;

  /* alloc at least 64 bytes */
  size = sizeof(struct memdebug) + wantedsize;

  mem = (Curl_cmalloc)(size);
  if(mem) {
    mem->size = wantedsize;
  }

  if(source)
    fetch_dbg_log("MEM %s:%d malloc(%zu) = %p\n",
                 source, line, wantedsize,
                 mem ? (void *)mem->mem : (void *)0);

  return mem ? mem->mem : NULL;
}

ALLOC_FUNC void *fetch_dbg_calloc(size_t wanted_elements, size_t wanted_size,
                                 int line, const char *source)
{
  struct memdebug *mem;
  size_t size, user_size;

  DEBUGASSERT(wanted_elements != 0);
  DEBUGASSERT(wanted_size != 0);

  if(countcheck("calloc", line, source))
    return NULL;

  /* alloc at least 64 bytes */
  user_size = wanted_size * wanted_elements;
  size = sizeof(struct memdebug) + user_size;

  mem = (Curl_ccalloc)(1, size);
  if(mem)
    mem->size = user_size;

  if(source)
    fetch_dbg_log("MEM %s:%d calloc(%zu,%zu) = %p\n",
                 source, line, wanted_elements, wanted_size,
                 mem ? (void *)mem->mem : (void *)0);

  return mem ? mem->mem : NULL;
}

ALLOC_FUNC char *fetch_dbg_strdup(const char *str,
                                 int line, const char *source)
{
  char *mem;
  size_t len;

  DEBUGASSERT(str != NULL);

  if(countcheck("strdup", line, source))
    return NULL;

  len = strlen(str) + 1;

  mem = fetch_dbg_malloc(len, 0, NULL); /* NULL prevents logging */
  if(mem)
    memcpy(mem, str, len);

  if(source)
    fetch_dbg_log("MEM %s:%d strdup(%p) (%zu) = %p\n",
                 source, line, (const void *)str, len, (const void *)mem);

  return mem;
}

#if defined(_WIN32) && defined(UNICODE)
ALLOC_FUNC wchar_t *fetch_dbg_wcsdup(const wchar_t *str,
                                    int line, const char *source)
{
  wchar_t *mem;
  size_t wsiz, bsiz;

  DEBUGASSERT(str != NULL);

  if(countcheck("wcsdup", line, source))
    return NULL;

  wsiz = wcslen(str) + 1;
  bsiz = wsiz * sizeof(wchar_t);

  mem = fetch_dbg_malloc(bsiz, 0, NULL); /* NULL prevents logging */
  if(mem)
    memcpy(mem, str, bsiz);

  if(source)
    fetch_dbg_log("MEM %s:%d wcsdup(%p) (%zu) = %p\n",
                source, line, (void *)str, bsiz, (void *)mem);

  return mem;
}
#endif

/* We provide a realloc() that accepts a NULL as pointer, which then
   performs a malloc(). In order to work with ares. */
void *fetch_dbg_realloc(void *ptr, size_t wantedsize,
                      int line, const char *source)
{
  struct memdebug *mem = NULL;

  size_t size = sizeof(struct memdebug) + wantedsize;

  DEBUGASSERT(wantedsize != 0);

  if(countcheck("realloc", line, source))
    return NULL;

#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:1684)
   /* 1684: conversion from pointer to same-sized integral type */
#endif

  if(ptr)
    mem = (void *)((char *)ptr - offsetof(struct memdebug, mem));

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif

  mem = (Curl_crealloc)(mem, size);
  if(source)
    fetch_dbg_log("MEM %s:%d realloc(%p, %zu) = %p\n",
                source, line, (void *)ptr, wantedsize,
                mem ? (void *)mem->mem : (void *)0);

  if(mem) {
    mem->size = wantedsize;
    return mem->mem;
  }

  return NULL;
}

void fetch_dbg_free(void *ptr, int line, const char *source)
{
  if(ptr) {
    struct memdebug *mem;

#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:1684)
   /* 1684: conversion from pointer to same-sized integral type */
#endif

    mem = (void *)((char *)ptr - offsetof(struct memdebug, mem));

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif

    /* free for real */
    (Curl_cfree)(mem);
  }

  if(source && ptr)
    fetch_dbg_log("MEM %s:%d free(%p)\n", source, line, (void *)ptr);
}

fetch_socket_t fetch_dbg_socket(int domain, int type, int protocol,
                             int line, const char *source)
{
  fetch_socket_t sockfd;

  if(countcheck("socket", line, source))
    return FETCH_SOCKET_BAD;

  sockfd = socket(domain, type, protocol);

  if(source && (sockfd != FETCH_SOCKET_BAD))
    fetch_dbg_log("FD %s:%d socket() = %" FMT_SOCKET_T "\n",
                 source, line, sockfd);

  return sockfd;
}

SEND_TYPE_RETV fetch_dbg_send(SEND_TYPE_ARG1 sockfd,
                            SEND_QUAL_ARG2 SEND_TYPE_ARG2 buf,
                            SEND_TYPE_ARG3 len, SEND_TYPE_ARG4 flags, int line,
                            const char *source)
{
  SEND_TYPE_RETV rc;
  if(countcheck("send", line, source))
    return -1;
  rc = send(sockfd, buf, len, flags);
  if(source)
    fetch_dbg_log("SEND %s:%d send(%lu) = %ld\n",
                source, line, (unsigned long)len, (long)rc);
  return rc;
}

RECV_TYPE_RETV fetch_dbg_recv(RECV_TYPE_ARG1 sockfd, RECV_TYPE_ARG2 buf,
                            RECV_TYPE_ARG3 len, RECV_TYPE_ARG4 flags, int line,
                            const char *source)
{
  RECV_TYPE_RETV rc;
  if(countcheck("recv", line, source))
    return -1;
  rc = recv(sockfd, buf, len, flags);
  if(source)
    fetch_dbg_log("RECV %s:%d recv(%lu) = %ld\n",
                source, line, (unsigned long)len, (long)rc);
  return rc;
}

#ifdef HAVE_SOCKETPAIR
int fetch_dbg_socketpair(int domain, int type, int protocol,
                       fetch_socket_t socket_vector[2],
                       int line, const char *source)
{
  int res = socketpair(domain, type, protocol, socket_vector);

  if(source && (0 == res))
    fetch_dbg_log("FD %s:%d socketpair() = "
                 "%" FMT_SOCKET_T " %" FMT_SOCKET_T "\n",
                 source, line, socket_vector[0], socket_vector[1]);

  return res;
}
#endif

fetch_socket_t fetch_dbg_accept(fetch_socket_t s, void *saddr, void *saddrlen,
                             int line, const char *source)
{
  struct sockaddr *addr = (struct sockaddr *)saddr;
  fetch_socklen_t *addrlen = (fetch_socklen_t *)saddrlen;

  fetch_socket_t sockfd = accept(s, addr, addrlen);

  if(source && (sockfd != FETCH_SOCKET_BAD))
    fetch_dbg_log("FD %s:%d accept() = %" FMT_SOCKET_T "\n",
                 source, line, sockfd);

  return sockfd;
}

/* separate function to allow libfetch to mark a "faked" close */
void fetch_dbg_mark_sclose(fetch_socket_t sockfd, int line, const char *source)
{
  if(source)
    fetch_dbg_log("FD %s:%d sclose(%" FMT_SOCKET_T ")\n",
                 source, line, sockfd);
}

/* this is our own defined way to close sockets on *ALL* platforms */
int fetch_dbg_sclose(fetch_socket_t sockfd, int line, const char *source)
{
  int res = sclose(sockfd);
  fetch_dbg_mark_sclose(sockfd, line, source);
  return res;
}

ALLOC_FUNC FILE *fetch_dbg_fopen(const char *file, const char *mode,
                                int line, const char *source)
{
  FILE *res = fopen(file, mode);

  if(source)
    fetch_dbg_log("FILE %s:%d fopen(\"%s\",\"%s\") = %p\n",
                source, line, file, mode, (void *)res);

  return res;
}

ALLOC_FUNC FILE *fetch_dbg_fdopen(int filedes, const char *mode,
                                 int line, const char *source)
{
  FILE *res = fdopen(filedes, mode);
  if(source)
    fetch_dbg_log("FILE %s:%d fdopen(\"%d\",\"%s\") = %p\n",
                 source, line, filedes, mode, (void *)res);
  return res;
}

int fetch_dbg_fclose(FILE *file, int line, const char *source)
{
  int res;

  DEBUGASSERT(file != NULL);

  if(source)
    fetch_dbg_log("FILE %s:%d fclose(%p)\n",
                 source, line, (void *)file);

  res = fclose(file);

  return res;
}

#define LOGLINE_BUFSIZE  1024

/* this does the writing to the memory tracking log file */
void fetch_dbg_log(const char *format, ...)
{
  char *buf;
  int nchars;
  va_list ap;

  if(!fetch_dbg_logfile)
    return;

  buf = (Curl_cmalloc)(LOGLINE_BUFSIZE);
  if(!buf)
    return;

  va_start(ap, format);
  nchars = mvsnprintf(buf, LOGLINE_BUFSIZE, format, ap);
  va_end(ap);

  if(nchars > LOGLINE_BUFSIZE - 1)
    nchars = LOGLINE_BUFSIZE - 1;

  if(nchars > 0)
    fwrite(buf, 1, (size_t)nchars, fetch_dbg_logfile);

  (Curl_cfree)(buf);
}

#endif /* FETCHDEBUG */
