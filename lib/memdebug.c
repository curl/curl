#ifdef MALLOCDEBUG
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#else /* some kind of unix */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
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

/* DONT include memdebug.h here! */

struct memdebug {
  int size;
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

FILE *logfile;

/* this sets the log file name */
void curl_memdebug(const char *logname)
{
  if(logname)
    logfile = fopen(logname, "w");
  else
    logfile = stderr;
}


void *curl_domalloc(size_t wantedsize, int line, const char *source)
{
  struct memdebug *mem;
  size_t size;

  /* alloc at least 64 bytes */
  size = sizeof(struct memdebug)+wantedsize;

  mem=(struct memdebug *)(malloc)(size);
  if(mem) {
    /* fill memory with junk */
    memset(mem->mem, 0xA5, wantedsize);
    mem->size = wantedsize;
  }

  if(logfile && source)
    fprintf(logfile, "MEM %s:%d malloc(%d) = %p\n",
            source, line, wantedsize, mem->mem);
  return mem->mem;
}

char *curl_dostrdup(const char *str, int line, const char *source)
{
  char *mem;
  size_t len;
  
  if(NULL ==str) {
    fprintf(stderr, "ILLEGAL strdup() on NULL at %s:%d\n",
            source, line);
    exit(2);
  }

  len=strlen(str)+1;

  mem=curl_domalloc(len, 0, NULL); /* NULL prevents logging */
  memcpy(mem, str, len);

  if(logfile)
    fprintf(logfile, "MEM %s:%d strdup(%p) (%d) = %p\n",
            source, line, str, len, mem);

  return mem;
}

void *curl_dorealloc(void *ptr, size_t wantedsize,
                     int line, const char *source)
{
  struct memdebug *mem;

  size_t size = sizeof(struct memdebug)+wantedsize;

  mem = (struct memdebug *)((char *)ptr - offsetof(struct memdebug, mem));

  mem=(struct memdebug *)(realloc)(mem, size);
  if(logfile)
    fprintf(logfile, "MEM %s:%d realloc(%p, %d) = %p\n",
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

  if(NULL == ptr) {
    fprintf(stderr, "ILLEGAL free() on NULL at %s:%d\n",
            source, line);
    exit(2);
  }
  mem = (struct memdebug *)((char *)ptr - offsetof(struct memdebug, mem));

  /* destroy  */
  memset(mem->mem, 0x13, mem->size);
  
  /* free for real */
  (free)(mem);

  if(logfile)
    fprintf(logfile, "MEM %s:%d free(%p)\n", source, line, ptr);
}

int curl_socket(int domain, int type, int protocol, int line, char *source)
{
  int sockfd=(socket)(domain, type, protocol);
  if(logfile)
    fprintf(logfile, "FD %s:%d socket() = %d\n",
            source, line, sockfd);
  return sockfd;
}

int curl_accept(int s, struct sockaddr *addr, socklen_t *addrlen,
                int line, const char *source)
{
  int sockfd=(accept)(s, addr, addrlen);
  if(logfile)
    fprintf(logfile, "FD %s:%d accept() = %d\n",
            source, line, sockfd);
  return sockfd;
}

/* this is our own defined way to close sockets on *ALL* platforms */
int curl_sclose(int sockfd, int line, char *source)
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
    fprintf(logfile, "FILE %s:%d fopen(\"%s\") = %p\n",
            source, line, file, res);
  return res;
}

int curl_fclose(FILE *file, int line, const char *source)
{
  int res;

  if(NULL == file) {
    fprintf(stderr, "ILLEGAL flose() on NULL at %s:%d\n",
            source, line);
    exit(2);
  }

  res=(fclose)(file);
  if(logfile)
    fprintf(logfile, "FILE %s:%d fclose(%p)\n",
            source, line, file);
  return res;
}
#else
#ifdef VMS
int VOID_VAR_MEMDEBUG;	
#endif
#endif /* MALLOCDEBUG */

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
