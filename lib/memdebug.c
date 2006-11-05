#ifdef CURLDEBUG
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define MEMDEBUG_NODEFINES /* don't redefine the standard functions */
#include "memory.h"
#include "memdebug.h"

struct memdebug {
  size_t size;
  double mem[1];
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
  if (!logfile) {
    if(logname)
      logfile = fopen(logname, "w");
    else
      logfile = stderr;
  }
}

/* This function sets the number of malloc() calls that should return
   successfully! */
void curl_memlimit(long limit)
{
  if (!memlimit) {
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
      if(logfile && source)
        fprintf(logfile, "LIMIT %s:%d %s reached memlimit\n",
                source, line, func);
      if(source)
        fprintf(stderr, "LIMIT %s:%d %s reached memlimit\n",
                source, line, func);
      errno = ENOMEM;
      return TRUE; /* RETURN ERROR! */
    }
    else
      memsize--; /* countdown */

    /* log the countdown */
    if(logfile && source)
      fprintf(logfile, "LIMIT %s:%d %ld ALLOCS left\n",
              source, line, memsize);

  }

  return FALSE; /* allow this */
}

void *curl_domalloc(size_t wantedsize, int line, const char *source)
{
  struct memdebug *mem;
  size_t size;

  if(countcheck("malloc", line, source))
    return NULL;

  /* alloc at least 64 bytes */
  size = sizeof(struct memdebug)+wantedsize;

  mem=(struct memdebug *)(Curl_cmalloc)(size);
  if(mem) {
    /* fill memory with junk */
    memset(mem->mem, 0xA5, wantedsize);
    mem->size = wantedsize;
  }

  if(logfile && source)
    fprintf(logfile, "MEM %s:%d malloc(%zd) = %p\n",
            source, line, wantedsize, mem ? mem->mem : 0);
  return (mem ? mem->mem : NULL);
}

void *curl_docalloc(size_t wanted_elements, size_t wanted_size,
                    int line, const char *source)
{
  struct memdebug *mem;
  size_t size, user_size;

  if(countcheck("calloc", line, source))
    return NULL;

  /* alloc at least 64 bytes */
  user_size = wanted_size * wanted_elements;
  size = sizeof(struct memdebug) + user_size;

  mem = (struct memdebug *)(Curl_cmalloc)(size);
  if(mem) {
    /* fill memory with zeroes */
    memset(mem->mem, 0, user_size);
    mem->size = user_size;
  }

  if(logfile && source)
    fprintf(logfile, "MEM %s:%d calloc(%u,%u) = %p\n",
            source, line, wanted_elements, wanted_size, mem ? mem->mem : 0);
  return (mem ? mem->mem : NULL);
}

char *curl_dostrdup(const char *str, int line, const char *source)
{
  char *mem;
  size_t len;

  curlassert(str != NULL);

  if(countcheck("strdup", line, source))
    return NULL;

  len=strlen(str)+1;

  mem=curl_domalloc(len, 0, NULL); /* NULL prevents logging */
  if (mem)
  memcpy(mem, str, len);

  if(logfile)
    fprintf(logfile, "MEM %s:%d strdup(%p) (%zd) = %p\n",
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

  if(countcheck("realloc", line, source))
    return NULL;

  if(ptr)
    mem = (struct memdebug *)((char *)ptr - offsetof(struct memdebug, mem));

  mem=(struct memdebug *)(Curl_crealloc)(mem, size);
  if(logfile)
    fprintf(logfile, "MEM %s:%d realloc(%p, %zd) = %p\n",
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

  curlassert(ptr != NULL);

  mem = (struct memdebug *)((char *)ptr - offsetof(struct memdebug, mem));

  /* destroy  */
  memset(mem->mem, 0x13, mem->size);

  /* free for real */
  (Curl_cfree)(mem);

  if(logfile)
    fprintf(logfile, "MEM %s:%d free(%p)\n", source, line, ptr);
}

int curl_socket(int domain, int type, int protocol, int line,
                const char *source)
{
  int sockfd=(socket)(domain, type, protocol);
  if(logfile && (sockfd!=-1))
    fprintf(logfile, "FD %s:%d socket() = %d\n",
            source, line, sockfd);
  return sockfd;
}

int curl_accept(int s, void *saddr, void *saddrlen,
                int line, const char *source)
{
  struct sockaddr *addr = (struct sockaddr *)saddr;
  socklen_t *addrlen = (socklen_t *)saddrlen;
  int sockfd=(accept)(s, addr, addrlen);
  if(logfile)
    fprintf(logfile, "FD %s:%d accept() = %d\n",
            source, line, sockfd);
  return sockfd;
}

/* this is our own defined way to close sockets on *ALL* platforms */
int curl_sclose(int sockfd, int line, const char *source)
{
  int res=sclose(sockfd);
  if(logfile)
    fprintf(logfile, "FD %s:%d sclose(%d)\n",
            source, line, sockfd);
  return res;
}

FILE *curl_fopen(const char *file, const char *mode,
                 int line, const char *source)
{
  FILE *res=(fopen)(file, mode);
  if(logfile)
    fprintf(logfile, "FILE %s:%d fopen(\"%s\",\"%s\") = %p\n",
            source, line, file, mode, res);
  return res;
}

int curl_fclose(FILE *file, int line, const char *source)
{
  int res;

  curlassert(file != NULL);

  res=(fclose)(file);
  if(logfile)
    fprintf(logfile, "FILE %s:%d fclose(%p)\n",
            source, line, file);
  return res;
}
#else
#ifdef VMS
int VOID_VAR_MEMDEBUG;
#else
/* we provide a fake do-nothing function here to avoid compiler warnings */
void curl_memdebug(void) {}
#endif /* VMS */
#endif /* CURLDEBUG */
