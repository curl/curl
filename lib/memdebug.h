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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <stdio.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

extern FILE *logfile;

/* memory functions */
void *curl_domalloc(size_t size, int line, const char *source);
void *curl_dorealloc(void *ptr, size_t size, int line, const char *source);
void curl_dofree(void *ptr, int line, const char *source);
char *curl_dostrdup(const char *str, int line, const char *source);
void curl_memdebug(const char *logname);

/* file descriptor manipulators */
int curl_socket(int domain, int type, int protocol, int, const char *);
int curl_sclose(int sockfd, int, const char *source);
int curl_accept(int s, struct sockaddr *addr, socklen_t *addrlen,
                int line, const char *source);

/* FILE functions */
FILE *curl_fopen(const char *file, const char *mode, int line,
                 const char *source);
int curl_fclose(FILE *file, int line, const char *source);

/* Set this symbol on the command-line, recompile all lib-sources */
#undef strdup
#define strdup(ptr) curl_dostrdup(ptr, __LINE__, __FILE__)
#define malloc(size) curl_domalloc(size, __LINE__, __FILE__)
#define realloc(ptr,size) curl_dorealloc(ptr, size, __LINE__, __FILE__)
#define free(ptr) curl_dofree(ptr, __LINE__, __FILE__)

#define socket(domain,type,protocol)\
 curl_socket(domain,type,protocol,__LINE__,__FILE__)
#define accept(sock,addr,len)\
 curl_accept(sock,addr,len,__LINE__,__FILE__)

#define getaddrinfo(host,serv,hint,res) \
  curl_getaddrinfo(host,serv,hint,res,__LINE__,__FILE__)
#define freeaddrinfo(data) \
  curl_freeaddrinfo(data,__LINE__,__FILE__)

/* sclose is probably already defined, redefine it! */
#undef sclose
#define sclose(sockfd) curl_sclose(sockfd,__LINE__,__FILE__)

#undef fopen
#define fopen(file,mode) curl_fopen(file,mode,__LINE__,__FILE__)
#define fclose(file) curl_fclose(file,__LINE__,__FILE__)

#endif
