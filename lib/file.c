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
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
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

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#include "setup.h"

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#include <time.h>
#include <io.h>
#include <fcntl.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>
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


UrgError file(struct UrlData *data, char *path, long *bytecountp)
{
  /* This implementation ignores the host name in conformance with 
     RFC 1738. Only local files (reachable via the standard file system)
     are supported. This means that files on remotely mounted directories
     (via NFS, Samba, NT sharing) can be accessed through a file:// URL
  */

  struct stat statbuf;
  size_t expected_size=-1;
  size_t nread;
  char *buf = data->buffer;
  int bytecount = 0;
  struct timeval start = tvnow();
  struct timeval now = start;
  int fd;
  char *actual_path = curl_unescape(path);

#ifdef WIN32
  int i;

  /* change path separators from '/' to '\\' for Windows */
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
    return URG_FILE_COULDNT_READ_FILE;
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

  while (1) {
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
    if(nread != data->fwrite (buf, 1, nread, data->out)) {
      failf (data, "Failed writing output");
      return URG_WRITE_ERROR;
    }
    now = tvnow();
    pgrsUpdate(data);
#if 0
    ProgressShow (data, bytecount, start, now, FALSE);
#endif
  }
  now = tvnow();
#if 0
  ProgressShow (data, bytecount, start, now, TRUE);
#endif
  pgrsUpdate(data);

  close(fd);

  return URG_OK;
}
