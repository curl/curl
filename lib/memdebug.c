/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef CURLDEBUG
#include <curl/curl.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#define _MPRINTF_REPLACE
#include <curl/mprintf.h>
#include "urldata.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define MEMDEBUG_NODEFINES /* don't redefine the standard functions */
#include "curl_memory.h"
#include "memdebug.h"

#ifndef HAVE_ASSERT_H
#  define assert(x) do { } while (0)
#endif

struct memdebug {
  size_t size;
  union {
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
    if(logname)
      logfile = fopen(logname, "w");
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
    memset(mem->mem, 0xA5, wantedsize);
    mem->size = wantedsize;
  }

  if(source)
    curl_memlog("MEM %s:%d malloc(%zd) = %p\n",
                source, line, wantedsize, mem ? mem->mem : 0);
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

  mem = (Curl_cmalloc)(size);
  if(mem) {
    /* fill memory with zeroes */
    memset(mem->mem, 0, user_size);
    mem->size = user_size;
  }

  if(source)
    curl_memlog("MEM %s:%d calloc(%zu,%zu) = %p\n",
                source, line, wanted_elements, wanted_size, mem?mem->mem:0);
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
                source, line, str, len, mem);

  return mem;
}

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
                source, line, ptr, wantedsize, mem?mem->mem:NULL);

  if(mem) {
    mem->size = wantedsize;
    return mem->mem;
  }

  return NULL;
}

void curl_dofree(void *ptr, int line, const char *source)
{
  struct memdebug *mem;

  assert(ptr != NULL);

#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:1684)
   /* 1684: conversion from pointer to same-sized integral type */
#endif

  mem = (void *)((char *)ptr - offsetof(struct memdebug, mem));

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif

  /* destroy  */
  memset(mem->mem, 0x13, mem->size);

  /* free for real */
  (Curl_cfree)(mem);

  if(source)
    curl_memlog("MEM %s:%d free(%p)\n", source, line, ptr);
}

curl_socket_t curl_socket(int domain, int type, int protocol,
                          int line, const char *source)
{
  const char *fmt = (sizeof(curl_socket_t) == sizeof(int)) ?
                    "FD %s:%d socket() = %d\n" :
                    (sizeof(curl_socket_t) == sizeof(long)) ?
                    "FD %s:%d socket() = %ld\n" :
                    "FD %s:%d socket() = %zd\n" ;

  curl_socket_t sockfd = socket(domain, type, protocol);
  if(source && (sockfd != CURL_SOCKET_BAD))
    curl_memlog(fmt, source, line, sockfd);
  return sockfd;
}

curl_socket_t curl_accept(curl_socket_t s, void *saddr, void *saddrlen,
                          int line, const char *source)
{
  const char *fmt = (sizeof(curl_socket_t) == sizeof(int)) ?
                    "FD %s:%d accept() = %d\n" :
                    (sizeof(curl_socket_t) == sizeof(long)) ?
                    "FD %s:%d accept() = %ld\n" :
                    "FD %s:%d accept() = %zd\n" ;

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
                    "FD %s:%d sclose(%d)\n" :
                    (sizeof(curl_socket_t) == sizeof(long)) ?
                    "FD %s:%d sclose(%ld)\n" :
                    "FD %s:%d sclose(%zd)\n" ;

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
                source, line, file, mode, res);
  return res;
}

#ifdef HAVE_FDOPEN
FILE *curl_fdopen(int filedes, const char *mode,
                  int line, const char *source)
{
  FILE *res=fdopen(filedes, mode);
  if(source)
    curl_memlog("FILE %s:%d fdopen(\"%d\",\"%s\") = %p\n",
                source, line, filedes, mode, res);
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
                source, line, file);
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
