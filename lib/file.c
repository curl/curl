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

#ifndef CURL_DISABLE_FILE
/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#include <time.h>
#include <io.h>
#include <fcntl.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <sys/time.h>
#include <sys/resource.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <sys/ioctl.h>
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif


#endif

#include "urldata.h"
#include <curl/curl.h>
#include "progress.h"
#include "sendf.h"
#include "escape.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/* Emulate a connect-then-transfer protocol. We connect to the file here */
CURLcode Curl_file_connect(struct connectdata *conn)
{
  char *actual_path = curl_unescape(conn->path, 0);
  struct FILE *file;
  int fd;
#if defined(WIN32) || defined(__EMX__)
  int i;
#endif

  file = (struct FILE *)malloc(sizeof(struct FILE));
  if(!file)
    return CURLE_OUT_OF_MEMORY;

  memset(file, 0, sizeof(struct FILE));
  conn->proto.file = file;

#if defined(WIN32) || defined(__EMX__)
  /* change path separators from '/' to '\\' for Windows and OS/2 */
  for (i=0; actual_path[i] != '\0'; ++i)
    if (actual_path[i] == '/')
      actual_path[i] = '\\';

  fd = open(actual_path, O_RDONLY | O_BINARY);	/* no CR/LF translation! */
#else
  fd = open(actual_path, O_RDONLY);
#endif
  free(actual_path);

  if(fd == -1) {
    failf(conn->data, "Couldn't open file %s", conn->path);
    return CURLE_FILE_COULDNT_READ_FILE;
  }
  file->fd = fd;

  return CURLE_OK;
}

/* This is the do-phase, separated from the connect-phase above */

CURLcode Curl_file(struct connectdata *conn)
{
  /* This implementation ignores the host name in conformance with 
     RFC 1738. Only local files (reachable via the standard file system)
     are supported. This means that files on remotely mounted directories
     (via NFS, Samba, NT sharing) can be accessed through a file:// URL
  */
  CURLcode res = CURLE_OK;
  struct stat statbuf;
  double expected_size=-1;
  ssize_t nread;
  struct SessionHandle *data = conn->data;
  char *buf = data->state.buffer;
  int bytecount = 0;
  struct timeval start = Curl_tvnow();
  struct timeval now = start;
  int fd;

  /* get the fd from the connection phase */
  fd = conn->proto.file->fd;

/*VMS?? -- This only works reliable for STREAMLF files */
  if( -1 != fstat(fd, &statbuf)) {
    /* we could stat it, then read out the size */
    expected_size = (double)statbuf.st_size;
  }

  /* Added by Dolbneff A.V & Spiridonoff A.V */
  if (conn->resume_from <= expected_size)
    expected_size -= conn->resume_from;
  else
    /* Is this error code suitable in such situation? */
    return CURLE_FTP_BAD_DOWNLOAD_RESUME;

  if (expected_size == 0)
    return CURLE_OK;

  /* The following is a shortcut implementation of file reading
     this is both more efficient than the former call to download() and
     it avoids problems with select() and recv() on file descriptors
     in Winsock */
  if(expected_size != -1)
    Curl_pgrsSetDownloadSize(data, expected_size);

  if(conn->resume_from)
    /* Added by Dolbneff A.V & Spiridonoff A.V */
    lseek(fd, conn->resume_from, SEEK_SET);

  while (res == CURLE_OK) {
    nread = read(fd, buf, BUFSIZE-1);

    if ( nread > 0)
      buf[nread] = 0;

    if (nread <= 0)
      break;

    bytecount += nread;
    /* NOTE: The following call to fwrite does CR/LF translation on
       Windows systems if the target is stdout. Use -O or -o parameters
       to prevent CR/LF translation (this then goes to a binary mode
       file descriptor). */

    res = Curl_client_write(data, CLIENTWRITE_BODY, buf, nread);
    if(res)
      return res;

    now = Curl_tvnow();
    if(Curl_pgrsUpdate(conn))
      res = CURLE_ABORTED_BY_CALLBACK;
  }
  now = Curl_tvnow();
  if(Curl_pgrsUpdate(conn))
    res = CURLE_ABORTED_BY_CALLBACK;

  close(fd);

  return res;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
#endif
