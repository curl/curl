/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef WIN32
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
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
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

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#endif

#include "urldata.h"
#include <curl/curl.h>
#include "progress.h"
#include "sendf.h"
#include "escape.h"
#include "file.h"
#include "speedcheck.h"
#include "getinfo.h"
#include "transfer.h"
#include "url.h"
#include "memory.h"
#include "parsedate.h" /* for the week day and month names */

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/*
 * Curl_file_connect() gets called from Curl_protocol_connect() to allow us to
 * do protocol-specific actions at connect-time.  We emulate a
 * connect-then-transfer protocol and "connect" to the file here
 */
CURLcode Curl_file_connect(struct connectdata *conn)
{
  char *real_path = curl_easy_unescape(conn->data, conn->data->reqdata.path, 0, NULL);
  struct FILEPROTO *file;
  int fd;
#if defined(WIN32) || defined(MSDOS) || defined(__EMX__)
  int i;
  char *actual_path;
#endif

  if(!real_path)
    return CURLE_OUT_OF_MEMORY;

  file = (struct FILEPROTO *)calloc(sizeof(struct FILEPROTO), 1);
  if(!file) {
    free(real_path);
    return CURLE_OUT_OF_MEMORY;
  }

  if (conn->data->reqdata.proto.file) {
    free(conn->data->reqdata.proto.file);
  }

  conn->data->reqdata.proto.file = file;

#if defined(WIN32) || defined(MSDOS) || defined(__EMX__)
  /* If the first character is a slash, and there's
     something that looks like a drive at the beginning of
     the path, skip the slash.  If we remove the initial
     slash in all cases, paths without drive letters end up
     relative to the current directory which isn't how
     browsers work.

     Some browsers accept | instead of : as the drive letter
     separator, so we do too.

     On other platforms, we need the slash to indicate an
     absolute pathname.  On Windows, absolute paths start
     with a drive letter.
  */
  actual_path = real_path;
  if ((actual_path[0] == '/') &&
      actual_path[1] &&
      (actual_path[2] == ':' || actual_path[2] == '|'))
  {
    actual_path[2] = ':';
    actual_path++;
  }

  /* change path separators from '/' to '\\' for DOS, Windows and OS/2 */
  for (i=0; actual_path[i] != '\0'; ++i)
    if (actual_path[i] == '/')
      actual_path[i] = '\\';

  fd = open(actual_path, O_RDONLY | O_BINARY);  /* no CR/LF translation! */
  file->path = actual_path;
#else
  fd = open(real_path, O_RDONLY);
  file->path = real_path;
#endif
  file->freepath = real_path; /* free this when done */

  file->fd = fd;
  if(!conn->data->set.upload && (fd == -1)) {
    failf(conn->data, "Couldn't open file %s", conn->data->reqdata.path);
    Curl_file_done(conn, CURLE_FILE_COULDNT_READ_FILE, FALSE);
    return CURLE_FILE_COULDNT_READ_FILE;
  }

  return CURLE_OK;
}

CURLcode Curl_file_done(struct connectdata *conn,
                        CURLcode status, bool premature)
{
  struct FILEPROTO *file = conn->data->reqdata.proto.file;
  (void)status; /* not used */
  (void)premature; /* not used */
  Curl_safefree(file->freepath);

  if(file->fd != -1)
    close(file->fd);

  return CURLE_OK;
}

#if defined(WIN32) || defined(MSDOS) || defined(__EMX__)
#define DIRSEP '\\'
#else
#define DIRSEP '/'
#endif

static CURLcode file_upload(struct connectdata *conn)
{
  struct FILEPROTO *file = conn->data->reqdata.proto.file;
  char *dir = strchr(file->path, DIRSEP);
  FILE *fp;
  CURLcode res=CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *buf = data->state.buffer;
  size_t nread;
  size_t nwrite;
  curl_off_t bytecount = 0;
  struct timeval now = Curl_tvnow();

  /*
   * Since FILE: doesn't do the full init, we need to provide some extra
   * assignments here.
   */
  conn->fread = data->set.fread;
  conn->fread_in = data->set.in;
  conn->data->reqdata.upload_fromhere = buf;

  if(!dir)
    return CURLE_FILE_COULDNT_READ_FILE; /* fix: better error code */

  if(!dir[1])
     return CURLE_FILE_COULDNT_READ_FILE; /* fix: better error code */

  fp = fopen(file->path, "wb");
  if(!fp) {
    failf(data, "Can't open %s for writing", file->path);
    return CURLE_WRITE_ERROR;
  }

  if(-1 != data->set.infilesize)
    /* known size of data to "upload" */
    Curl_pgrsSetUploadSize(data, data->set.infilesize);

  while (res == CURLE_OK) {
    int readcount;
    res = Curl_fillreadbuffer(conn, BUFSIZE, &readcount);
    if(res)
      break;

    if (readcount <= 0)  /* fix questionable compare error. curlvms */
      break;

    nread = (size_t)readcount;

    /* write the data to the target */
    nwrite = fwrite(buf, 1, nread, fp);
    if(nwrite != nread) {
      res = CURLE_SEND_ERROR;
      break;
    }

    bytecount += nread;

    Curl_pgrsSetUploadCounter(data, bytecount);

    if(Curl_pgrsUpdate(conn))
      res = CURLE_ABORTED_BY_CALLBACK;
    else
      res = Curl_speedcheck(data, now);
  }
  if(!res && Curl_pgrsUpdate(conn))
    res = CURLE_ABORTED_BY_CALLBACK;

  fclose(fp);

  return res;
}

/*
 * Curl_file() is the protocol-specific function for the do-phase, separated
 * from the connect-phase above. Other protocols merely setup the transfer in
 * the do-phase, to have it done in the main transfer loop but since some
 * platforms we support don't allow select()ing etc on file handles (as
 * opposed to sockets) we instead perform the whole do-operation in this
 * function.
 */
CURLcode Curl_file(struct connectdata *conn, bool *done)
{
  /* This implementation ignores the host name in conformance with
     RFC 1738. Only local files (reachable via the standard file system)
     are supported. This means that files on remotely mounted directories
     (via NFS, Samba, NT sharing) can be accessed through a file:// URL
  */
  CURLcode res = CURLE_OK;
  struct_stat statbuf; /* struct_stat instead of struct stat just to allow the
                          Windows version to have a different struct without
                          having to redefine the simple word 'stat' */
  curl_off_t expected_size=0;
  bool fstated=FALSE;
  ssize_t nread;
  struct SessionHandle *data = conn->data;
  char *buf = data->state.buffer;
  curl_off_t bytecount = 0;
  int fd;
  struct timeval now = Curl_tvnow();

  *done = TRUE; /* unconditionally */

  Curl_readwrite_init(conn);
  Curl_initinfo(data);
  Curl_pgrsStartNow(data);

  if(data->set.upload)
    return file_upload(conn);

  /* get the fd from the connection phase */
  fd = conn->data->reqdata.proto.file->fd;

  /* VMS: This only works reliable for STREAMLF files */
  if( -1 != fstat(fd, &statbuf)) {
    /* we could stat it, then read out the size */
    expected_size = statbuf.st_size;
    fstated = TRUE;
  }

  /* If we have selected NOBODY and HEADER, it means that we only want file
     information. Which for FILE can't be much more than the file size and
     date. */
  if(conn->bits.no_body && data->set.include_header && fstated) {
    CURLcode result;
    snprintf(buf, sizeof(data->state.buffer),
             "Content-Length: %" FORMAT_OFF_T "\r\n", expected_size);
    result = Curl_client_write(conn, CLIENTWRITE_BOTH, buf, 0);
    if(result)
      return result;

    result = Curl_client_write(conn, CLIENTWRITE_BOTH,
                               (char *)"Accept-ranges: bytes\r\n", 0);
    if(result)
      return result;

    if(fstated) {
      struct tm *tm;
      time_t clock = (time_t)statbuf.st_mtime;
#ifdef HAVE_GMTIME_R
      struct tm buffer;
      tm = (struct tm *)gmtime_r(&clock, &buffer);
#else
      tm = gmtime(&clock);
#endif
      /* format: "Tue, 15 Nov 1994 12:45:26 GMT" */
      snprintf(buf, BUFSIZE-1,
               "Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n",
               Curl_wkday[tm->tm_wday?tm->tm_wday-1:6],
               tm->tm_mday,
               Curl_month[tm->tm_mon],
               tm->tm_year + 1900,
               tm->tm_hour,
               tm->tm_min,
               tm->tm_sec);
      result = Curl_client_write(conn, CLIENTWRITE_BOTH, buf, 0);
    }
    return result;
  }

  if (data->reqdata.resume_from <= expected_size)
    expected_size -= data->reqdata.resume_from;
  else {
    failf(data, "failed to resume file:// transfer");
    return CURLE_BAD_DOWNLOAD_RESUME;
  }

  if (fstated && (expected_size == 0))
    return CURLE_OK;

  /* The following is a shortcut implementation of file reading
     this is both more efficient than the former call to download() and
     it avoids problems with select() and recv() on file descriptors
     in Winsock */
  if(fstated)
    Curl_pgrsSetDownloadSize(data, expected_size);

  if(data->reqdata.resume_from) {
    if(data->reqdata.resume_from !=
       lseek(fd, data->reqdata.resume_from, SEEK_SET))
      return CURLE_BAD_DOWNLOAD_RESUME;
  }

  Curl_pgrsTime(data, TIMER_STARTTRANSFER);

  while (res == CURLE_OK) {
    nread = read(fd, buf, BUFSIZE-1);

    if ( nread > 0)
      buf[nread] = 0;

    if (nread <= 0)
      break;

    bytecount += nread;

    res = Curl_client_write(conn, CLIENTWRITE_BODY, buf, nread);
    if(res)
      return res;

    Curl_pgrsSetDownloadCounter(data, bytecount);

    if(Curl_pgrsUpdate(conn))
      res = CURLE_ABORTED_BY_CALLBACK;
    else
      res = Curl_speedcheck(data, now);
  }
  if(Curl_pgrsUpdate(conn))
    res = CURLE_ABORTED_BY_CALLBACK;

  return res;
}

#endif
