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

CURLcode file(struct connectdata *conn)
{
  /* This implementation ignores the host name in conformance with 
     RFC 1738. Only local files (reachable via the standard file system)
     are supported. This means that files on remotely mounted directories
     (via NFS, Samba, NT sharing) can be accessed through a file:// URL
  */
  CURLcode res = CURLE_OK;
  char *path = conn->path;
  struct stat statbuf;
  size_t expected_size=-1;
  size_t nread;
  struct UrlData *data = conn->data;
  char *buf = data->buffer;
  int bytecount = 0;
  struct timeval start = tvnow();
  struct timeval now = start;
  int fd;
  char *actual_path = curl_unescape(path, 0);

#if defined(WIN32) || defined(__EMX__)
  int i;

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
    failf(data, "Couldn't open file %s", path);
    return CURLE_FILE_COULDNT_READ_FILE;
  }
  if( -1 != fstat(fd, &statbuf)) {
    /* we could stat it, then read out the size */
    expected_size = statbuf.st_size;
  }

  /* The following is a shortcut implementation of file reading
     this is both more efficient than the former call to download() and
     it avoids problems with select() and recv() on file descriptors
     in Winsock */
#if 0
  ProgressInit (data, expected_size);
#endif
  if(expected_size != -1)
    pgrsSetDownloadSize(data, expected_size);

  while (res == CURLE_OK) {
    nread = read(fd, buf, BUFSIZE-1);

    if (0 <= nread)
      buf[nread] = 0;

    if (nread <= 0)
      break;
    bytecount += nread;
    /* NOTE: The following call to fwrite does CR/LF translation on
       Windows systems if the target is stdout. Use -O or -o parameters
       to prevent CR/LF translation (this then goes to a binary mode
       file descriptor). */

    res = client_write(data, CLIENTWRITE_BODY, buf, nread);
    if(res)
      return res;

    now = tvnow();
    if(pgrsUpdate(data))
      res = CURLE_ABORTED_BY_CALLBACK;
  }
  now = tvnow();
  if(pgrsUpdate(data))
    res = CURLE_ABORTED_BY_CALLBACK;

  close(fd);

  return res;
}
