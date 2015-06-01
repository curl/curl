/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifdef CURLDEBUG

#include <curl/curl.h>

#include "curl_printf.h"
#include "urldata.h"

#define MEMDEBUG_NODEFINES /* don't redefine the standard functions */
#include "curl_memory.h"
#include "memdebug.h"

#ifndef HAVE_ASSERT_H
#  define assert(x) Curl_nop_stmt
#endif

/*
 * Until 2011-08-17 libcurl's Memory Tracking feature also performed
 * automatic malloc and free filling operations using 0xA5 and 0x13
 * values. Our own preinitialization of dynamically allocated memory
 * might be useful when not using third party memory debuggers, but
 * on the other hand this would fool memory debuggers into thinking
 * that all dynamically allocated memory is properly initialized.
 *
 * As a default setting, libcurl's Memory Tracking feature no longer
 * performs preinitialization of dynamically allocated memory on its
 * own. If you know what you are doing, and really want to retain old
 * behavior, you can achieve this compiling with preprocessor symbols
 * CURL_MT_MALLOC_FILL and CURL_MT_FREE_FILL defined with appropriate
 * values.
 */

#ifdef CURL_MT_MALLOC_FILL
# if (CURL_MT_MALLOC_FILL < 0) || (CURL_MT_MALLOC_FILL > 0xff)
#   error "invalid CURL_MT_MALLOC_FILL or out of range"
# endif
#endif

#ifdef CURL_MT_FREE_FILL
# if (CURL_MT_FREE_FILL < 0) || (CURL_MT_FREE_FILL > 0xff)
#   error "invalid CURL_MT_FREE_FILL or out of range"
# endif
#endif

#if defined(CURL_MT_MALLOC_FILL) && defined(CURL_MT_FREE_FILL)
# if (CURL_MT_MALLOC_FILL == CURL_MT_FREE_FILL)
#   error "CURL_MT_MALLOC_FILL same as CURL_MT_FREE_FILL"
# endif
#endif

#ifdef CURL_MT_MALLOC_FILL
#  define mt_malloc_fill(buf,len) memset((buf), CURL_MT_MALLOC_FILL, (len))
#else
#  define mt_malloc_fill(buf,len) Curl_nop_stmt
#endif

#ifdef CURL_MT_FREE_FILL
#  define mt_free_fill(buf,len) memset((buf), CURL_MT_FREE_FILL, (len))
#else
#  define mt_free_fill(buf,len) Curl_nop_stmt
#endif

struct memdebug {
  size_t size;
  union {
    curl_off_t o;
    double d;
    void * p;
  } mem[1];
  /* I'm hoping this is the thing with the strictest alignment
   * requirements.  That also means we waste some space :-( */
};

/*
 * Note that these debug functions are very simple and they are meant to
 * remain so. For advanced analysis, record a log file and write perl scripts
 * to analyze them!
 *
 * Don't use these with multithreaded test programs!
 */

#define logfile curl_debuglogfile
FILE *curl_debuglogfile = NULL;
static bool memlimit = FALSE; /* enable memory limit */
static long memsize = 0;  /* set number of mallocs allowed */

/* this sets the log file name */
void curl_memdebug(const char *logname)
{
  if(!logfile) {
    if(logname && *logname)
      logfile = fopen(logname, FOPEN_WRITETEXT);
    else
      logfile = stderr;
#ifdef MEMDEBUG_LOG_SYNC
    /* Flush the log file after every line so the log isn't lost in a crash */
    setvbuf(logfile, (char *)NULL, _IOLBF, 0);
#endif
  }
}

/* This function sets the number of malloc() calls that should return
   successfully! */
void curl_memlimit(long limit)
{
  if(!memlimit) {
    memlimit = TRUE;
    memsize = limit;
  }
}

/* returns TRUE if this isn't allowed! */
static bool countcheck(const char *func, int line, const char *source)
{
  /* if source is NULL, then the call is made internally and this check
     should not be made */
  if(memlimit && source) {
    if(!memsize) {
      if(source) {
        /* log to file */
        curl_memlog("LIMIT %s:%d %s reached memlimit\n",
                    source, line, func);
        /* log to stderr also */
        fprintf(stderr, "LIMIT %s:%d %s reached memlimit\n",
                source, line, func);
      }
      SET_ERRNO(ENOMEM);
      return TRUE; /* RETURN ERROR! */
    }
    else
      memsize--; /* countdown */

    /* log the countdown */
    if(source)
      curl_memlog("LIMIT %s:%d %ld ALLOCS left\n",
                  source, line, memsize);

  }

  return FALSE; /* allow this */
}

void *curl_domalloc(size_t wantedsize, int line, const char *source)
{
  struct memdebug *mem;
  size_t size;

  assert(wantedsize != 0);

  if(countcheck("malloc", line, source))
    return NULL;

  /* alloc at least 64 bytes */
  size = sizeof(struct memdebug)+wantedsize;

  mem = (Curl_cmalloc)(size);
  if(mem) {
    /* fill memory with junk */
    mt_malloc_fill(mem->mem, wantedsize);
    mem->size = wantedsize;
  }

  if(source)
    curl_memlog("MEM %s:%d malloc(%zu) = %p\n",
                source, line, wantedsize,
                mem ? (void *)mem->mem : (void *)0);

  return (mem ? mem->mem : NULL);
}

void *curl_docalloc(size_t wanted_elements, size_t wanted_size,
                    int line, const char *source)
{
  struct memdebug *mem;
  size_t size, user_size;

  assert(wanted_elements != 0);
  assert(wanted_size != 0);

  if(countcheck("calloc", line, source))
    return NULL;

  /* alloc at least 64 bytes */
  user_size = wanted_size * wanted_elements;
  size = sizeof(struct memdebug) + user_size;

  mem = (Curl_ccalloc)(1, size);
  if(mem)
    mem->size = user_size;

  if(source)
    curl_memlog("MEM %s:%d calloc(%zu,%zu) = %p\n",
                source, line, wanted_elements, wanted_size,
                mem ? (void *)mem->mem : (void *)0);

  return (mem ? mem->mem : NULL);
}

char *curl_dostrdup(const char *str, int line, const char *source)
{
  char *mem;
  size_t len;

  assert(str != NULL);

  if(countcheck("strdup", line, source))
    return NULL;

  len=strlen(str)+1;

  mem=curl_domalloc(len, 0, NULL); /* NULL prevents logging */
  if(mem)
    memcpy(mem, str, len);

  if(source)
    curl_memlog("MEM %s:%d strdup(%p) (%zu) = %p\n",
                source, line, (void *)str, len, (void *)mem);

  return mem;
}

#if defined(WIN32) && defined(UNICODE)
wchar_t *curl_dowcsdup(const wchar_t *str, int line, const char *source)
{
  wchar_t *mem;
  size_t wsiz, bsiz;

  assert(str != NULL);

  if(countcheck("wcsdup", line, source))
    return NULL;

  wsiz = wcslen(str) + 1;
  bsiz = wsiz * sizeof(wchar_t);

  mem = curl_domalloc(bsiz, 0, NULL); /* NULL prevents logging */
  if(mem)
    memcpy(mem, str, bsiz);

  if(source)
    curl_memlog("MEM %s:%d wcsdup(%p) (%zu) = %p\n",
                source, line, (void *)str, bsiz, (void *)mem);

  return mem;
}
#endif

/* We provide a realloc() that accepts a NULL as pointer, which then
   performs a malloc(). In order to work with ares. */
void *curl_dorealloc(void *ptr, size_t wantedsize,
                     int line, const char *source)
{
  struct memdebug *mem=NULL;

  size_t size = sizeof(struct memdebug)+wantedsize;

  assert(wantedsize != 0);

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
    curl_memlog("MEM %s:%d realloc(%p, %zu) = %p\n",
                source, line, (void *)ptr, wantedsize,
                mem ? (void *)mem->mem : (void *)0);

  if(mem) {
    mem->size = wantedsize;
    return mem->mem;
  }

  return NULL;
}

void curl_dofree(void *ptr, int line, const char *source)
{
  struct memdebug *mem;

  if(ptr) {

#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:1684)
   /* 1684: conversion from pointer to same-sized integral type */
#endif

    mem = (void *)((char *)ptr - offsetof(struct memdebug, mem));

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif

    /* destroy */
    mt_free_fill(mem->mem, mem->size);

    /* free for real */
    (Curl_cfree)(mem);
  }

  if(source)
    curl_memlog("MEM %s:%d free(%p)\n", source, line, (void *)ptr);
}

curl_socket_t curl_socket(int domain, int type, int protocol,
                          int line, const char *source)
{
  const char *fmt = (sizeof(curl_socket_t) == sizeof(int)) ?
    "FD %s:%d socket() = %d\n" :
    (sizeof(curl_socket_t) == sizeof(long)) ?
    "FD %s:%d socket() = %ld\n" :
    "FD %s:%d socket() = %zd\n";

  curl_socket_t sockfd = socket(domain, type, protocol);

  if(source && (sockfd != CURL_SOCKET_BAD))
    curl_memlog(fmt, source, line, sockfd);

  return sockfd;
}

#ifdef HAVE_SOCKETPAIR
int curl_socketpair(int domain, int type, int protocol,
                    curl_socket_t socket_vector[2],
                    int line, const char *source)
{
  const char *fmt = (sizeof(curl_socket_t) == sizeof(int)) ?
    "FD %s:%d socketpair() = %d %d\n" :
    (sizeof(curl_socket_t) == sizeof(long)) ?
    "FD %s:%d socketpair() = %ld %ld\n" :
    "FD %s:%d socketpair() = %zd %zd\n";

  int res = socketpair(domain, type, protocol, socket_vector);

  if(source && (0 == res))
    curl_memlog(fmt, source, line, socket_vector[0], socket_vector[1]);

  return res;
}
#endif

curl_socket_t curl_accept(curl_socket_t s, void *saddr, void *saddrlen,
                          int line, const char *source)
{
  const char *fmt = (sizeof(curl_socket_t) == sizeof(int)) ?
    "FD %s:%d accept() = %d\n" :
    (sizeof(curl_socket_t) == sizeof(long)) ?
    "FD %s:%d accept() = %ld\n" :
    "FD %s:%d accept() = %zd\n";

  struct sockaddr *addr = (struct sockaddr *)saddr;
  curl_socklen_t *addrlen = (curl_socklen_t *)saddrlen;

  curl_socket_t sockfd = accept(s, addr, addrlen);

  if(source && (sockfd != CURL_SOCKET_BAD))
    curl_memlog(fmt, source, line, sockfd);

  return sockfd;
}

/* separate function to allow libcurl to mark a "faked" close */
void curl_mark_sclose(curl_socket_t sockfd, int line, const char *source)
{
  const char *fmt = (sizeof(curl_socket_t) == sizeof(int)) ?
    "FD %s:%d sclose(%d)\n":
    (sizeof(curl_socket_t) == sizeof(long)) ?
    "FD %s:%d sclose(%ld)\n":
    "FD %s:%d sclose(%zd)\n";

  if(source)
    curl_memlog(fmt, source, line, sockfd);
}

/* this is our own defined way to close sockets on *ALL* platforms */
int curl_sclose(curl_socket_t sockfd, int line, const char *source)
{
  int res=sclose(sockfd);
  curl_mark_sclose(sockfd, line, source);
  return res;
}

FILE *curl_fopen(const char *file, const char *mode,
                 int line, const char *source)
{
  FILE *res=fopen(file, mode);

  if(source)
    curl_memlog("FILE %s:%d fopen(\"%s\",\"%s\") = %p\n",
                source, line, file, mode, (void *)res);

  return res;
}

#ifdef HAVE_FDOPEN
FILE *curl_fdopen(int filedes, const char *mode,
                  int line, const char *source)
{
  FILE *res=fdopen(filedes, mode);

  if(source)
    curl_memlog("FILE %s:%d fdopen(\"%d\",\"%s\") = %p\n",
                source, line, filedes, mode, (void *)res);

  return res;
}
#endif

int curl_fclose(FILE *file, int line, const char *source)
{
  int res;

  assert(file != NULL);

  res=fclose(file);

  if(source)
    curl_memlog("FILE %s:%d fclose(%p)\n",
                source, line, (void *)file);

  return res;
}

#define LOGLINE_BUFSIZE  1024

/* this does the writting to the memory tracking log file */
void curl_memlog(const char *format, ...)
{
  char *buf;
  int nchars;
  va_list ap;

  if(!logfile)
    return;

  buf = (Curl_cmalloc)(LOGLINE_BUFSIZE);
  if(!buf)
    return;

  va_start(ap, format);
  nchars = vsnprintf(buf, LOGLINE_BUFSIZE, format, ap);
  va_end(ap);

  if(nchars > LOGLINE_BUFSIZE - 1)
    nchars = LOGLINE_BUFSIZE - 1;

  if(nchars > 0)
    fwrite(buf, 1, nchars, logfile);

  (Curl_cfree)(buf);
}

#endif /* CURLDEBUG */
