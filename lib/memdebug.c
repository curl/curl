#ifdef MALLOCDEBUG
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1999.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

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

/*
 * Note that these debug functions are very simple and they are meant to
 * remain so. For advanced analysis, record a log file and write perl scripts
 * to analyze them!
 *
 * Don't use these with multithreaded test programs!
 */

FILE *logfile;

/* this sets the log file name */
void curl_memdebug(char *logname)
{
  logfile = fopen(logname, "w");
}


void *curl_domalloc(size_t size, int line, char *source)
{
  void *mem=(malloc)(size);
  fprintf(logfile?logfile:stderr, "MEM %s:%d malloc(%d) = %p\n",
          source, line, size, mem);
  return mem;
}

char *curl_dostrdup(char *str, int line, char *source)
{
  char *mem;
  size_t len;
  
  if(NULL ==str) {
    fprintf(stderr, "ILLEGAL strdup() on NULL at %s:%d\n",
            source, line);
    exit(2);
  }

  mem=(strdup)(str);
  len=strlen(str)+1;
  fprintf(logfile?logfile:stderr, "MEM %s:%d strdup(%p) (%d) = %p\n",
          source, line, str, len, mem);
  return mem;
}

void *curl_dorealloc(void *ptr, size_t size, int line, char *source)
{
  void *mem=(realloc)(ptr, size);
  fprintf(logfile?logfile:stderr, "MEM %s:%d realloc(%p, %d) = %p\n",
          source, line, ptr, size, mem);
  return mem;
}

void curl_dofree(void *ptr, int line, char *source)
{
  if(NULL == ptr) {
    fprintf(stderr, "ILLEGAL free() on NULL at %s:%d\n",
            source, line);
    exit(2);
  }

  (free)(ptr);

  fprintf(logfile?logfile:stderr, "MEM %s:%d free(%p)\n",
          source, line, ptr);
}

int curl_socket(int domain, int type, int protocol, int line, char *source)
{
  int sockfd=(socket)(domain, type, protocol);
  fprintf(logfile?logfile:stderr, "FD %s:%d socket() = %d\n",
          source, line, sockfd);
  return sockfd;
}

int curl_accept(int s, struct sockaddr *addr, int *addrlen,
                int line, char *source)
{
  int sockfd=(accept)(s, addr, addrlen);
  fprintf(logfile?logfile:stderr, "FD %s:%d accept() = %d\n",
          source, line, sockfd);
  return sockfd;
}

/* this is our own defined way to close sockets on *ALL* platforms */
int curl_sclose(int sockfd, int line, char *source)
{
  int res=sclose(sockfd);
  fprintf(logfile?logfile:stderr, "FD %s:%d sclose(%d)\n",
          source, line, sockfd);
  return sockfd;
}

FILE *curl_fopen(char *file, char *mode, int line, char *source)
{
  FILE *res=(fopen)(file, mode);
  fprintf(logfile?logfile:stderr, "FILE %s:%d fopen(\"%s\") = %p\n",
          source, line, file, res);
  return res;
}

int curl_fclose(FILE *file, int line, char *source)
{
  int res=(fclose)(file);
  fprintf(logfile?logfile:stderr, "FILE %s:%d fclose(%p)\n",
          source, line, file);
  return res;
}

#endif /* MALLOCDEBUG */
