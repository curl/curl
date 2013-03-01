/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifndef CURL_DISABLE_FILE

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "strtoofft.h"
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
#include "curl_memory.h"
#include "parsedate.h" /* for the week day and month names */
#include "warnless.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

#if defined(WIN32) || defined(MSDOS) || defined(__EMX__) || \
  defined(__SYMBIAN32__)
#define DOS_FILESYSTEM 1
#endif

#ifdef OPEN_NEEDS_ARG3
#  define open_readonly(p,f) open((p),(f),(0))
#else
#  define open_readonly(p,f) open((p),(f))
#endif

/*
 * Forward declarations.
 */

static CURLcode file_do(struct connectdata *, bool *done);
static CURLcode file_done(struct connectdata *conn,
                          CURLcode status, bool premature);
static CURLcode file_connect(struct connectdata *conn, bool *done);
static CURLcode file_disconnect(struct connectdata *conn,
                                bool dead_connection);


/*
 * FILE scheme handler.
 */

const struct Curl_handler Curl_handler_file = {
  "FILE",                               /* scheme */
  ZERO_NULL,                            /* setup_connection */
  file_do,                              /* do_it */
  file_done,                            /* done */
  ZERO_NULL,                            /* do_more */
  file_connect,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  file_disconnect,                      /* disconnect */
  ZERO_NULL,                            /* readwrite */
  0,                                    /* defport */
  CURLPROTO_FILE,                       /* protocol */
  PROTOPT_NONETWORK | PROTOPT_NOURLQUERY /* flags */
};


 /*
  Check if this is a range download, and if so, set the internal variables
  properly. This code is copied from the FTP implementation and might as
  well be factored out.
 */
static CURLcode file_range(struct connectdata *conn)
{
  curl_off_t from, to;
  curl_off_t totalsize=-1;
  char *ptr;
  char *ptr2;
  struct SessionHandle *data = conn->data;

  if(data->state.use_range && data->state.range) {
    from=curlx_strtoofft(data->state.range, &ptr, 0);
    while(*ptr && (ISSPACE(*ptr) || (*ptr=='-')))
      ptr++;
    to=curlx_strtoofft(ptr, &ptr2, 0);
    if(ptr == ptr2) {
      /* we didn't get any digit */
      to=-1;
    }
    if((-1 == to) && (from>=0)) {
      /* X - */
      data->state.resume_from = from;
      DEBUGF(infof(data, "RANGE %" FORMAT_OFF_T " to end of file\n",
                   from));
    }
    else if(from < 0) {
      /* -Y */
      data->req.maxdownload = -from;
      data->state.resume_from = from;
      DEBUGF(infof(data, "RANGE the last %" FORMAT_OFF_T " bytes\n",
                   -from));
    }
    else {
      /* X-Y */
      totalsize = to-from;
      data->req.maxdownload = totalsize+1; /* include last byte */
      data->state.resume_from = from;
      DEBUGF(infof(data, "RANGE from %" FORMAT_OFF_T
                   " getting %" FORMAT_OFF_T " bytes\n",
                   from, data->req.maxdownload));
    }
    DEBUGF(infof(data, "range-download from %" FORMAT_OFF_T
                 " to %" FORMAT_OFF_T ", totally %" FORMAT_OFF_T " bytes\n",
                 from, to, data->req.maxdownload));
  }
  else
    data->req.maxdownload = -1;
  return CURLE_OK;
}

/*
 * file_connect() gets called from Curl_protocol_connect() to allow us to
 * do protocol-specific actions at connect-time.  We emulate a
 * connect-then-transfer protocol and "connect" to the file here
 */
static CURLcode file_connect(struct connectdata *conn, bool *done)
{
  struct SessionHandle *data = conn->data;
  char *real_path;
  struct FILEPROTO *file;
  int fd;
#ifdef DOS_FILESYSTEM
  int i;
  char *actual_path;
#endif

  /* If there already is a protocol-specific struct allocated for this
     sessionhandle, deal with it */
  Curl_reset_reqproto(conn);

  real_path = curl_easy_unescape(data, data->state.path, 0, NULL);
  if(!real_path)
    return CURLE_OUT_OF_MEMORY;

  if(!data->state.proto.file) {
    file = calloc(1, sizeof(struct FILEPROTO));
    if(!file) {
      free(real_path);
      return CURLE_OUT_OF_MEMORY;
    }
    data->state.proto.file = file;
  }
  else {
    /* file is not a protocol that can deal with "persistancy" */
    file = data->state.proto.file;
    Curl_safefree(file->freepath);
    file->path = NULL;
    if(file->fd != -1)
      close(file->fd);
    file->fd = -1;
  }

#ifdef DOS_FILESYSTEM
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
  if((actual_path[0] == '/') &&
      actual_path[1] &&
     (actual_path[2] == ':' || actual_path[2] == '|')) {
    actual_path[2] = ':';
    actual_path++;
  }

  /* change path separators from '/' to '\\' for DOS, Windows and OS/2 */
  for(i=0; actual_path[i] != '\0'; ++i)
    if(actual_path[i] == '/')
      actual_path[i] = '\\';

  fd = open_readonly(actual_path, O_RDONLY|O_BINARY);
  file->path = actual_path;
#else
  fd = open_readonly(real_path, O_RDONLY);
  file->path = real_path;
#endif
  file->freepath = real_path; /* free this when done */

  file->fd = fd;
  if(!data->set.upload && (fd == -1)) {
    failf(data, "Couldn't open file %s", data->state.path);
    file_done(conn, CURLE_FILE_COULDNT_READ_FILE, FALSE);
    return CURLE_FILE_COULDNT_READ_FILE;
  }
  *done = TRUE;

  return CURLE_OK;
}

static CURLcode file_done(struct connectdata *conn,
                               CURLcode status, bool premature)
{
  struct FILEPROTO *file = conn->data->state.proto.file;
  (void)status; /* not used */
  (void)premature; /* not used */

  if(file) {
    Curl_safefree(file->freepath);
    file->path = NULL;
    if(file->fd != -1)
      close(file->fd);
    file->fd = -1;
  }

  return CURLE_OK;
}

static CURLcode file_disconnect(struct connectdata *conn,
                                bool dead_connection)
{
  struct FILEPROTO *file = conn->data->state.proto.file;
  (void)dead_connection; /* not used */

  if(file) {
    Curl_safefree(file->freepath);
    file->path = NULL;
    if(file->fd != -1)
      close(file->fd);
    file->fd = -1;
  }

  return CURLE_OK;
}

#ifdef DOS_FILESYSTEM
#define DIRSEP '\\'
#else
#define DIRSEP '/'
#endif

static CURLcode file_upload(struct connectdata *conn)
{
  struct FILEPROTO *file = conn->data->state.proto.file;
  const char *dir = strchr(file->path, DIRSEP);
  int fd;
  int mode;
  CURLcode res=CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *buf = data->state.buffer;
  size_t nread;
  size_t nwrite;
  curl_off_t bytecount = 0;
  struct timeval now = Curl_tvnow();
  struct_stat file_stat;
  const char* buf2;

  /*
   * Since FILE: doesn't do the full init, we need to provide some extra
   * assignments here.
   */
  conn->fread_func = data->set.fread_func;
  conn->fread_in = data->set.in;
  conn->data->req.upload_fromhere = buf;

  if(!dir)
    return CURLE_FILE_COULDNT_READ_FILE; /* fix: better error code */

  if(!dir[1])
    return CURLE_FILE_COULDNT_READ_FILE; /* fix: better error code */

#ifdef O_BINARY
#define MODE_DEFAULT O_WRONLY|O_CREAT|O_BINARY
#else
#define MODE_DEFAULT O_WRONLY|O_CREAT
#endif

  if(data->state.resume_from)
    mode = MODE_DEFAULT|O_APPEND;
  else
    mode = MODE_DEFAULT|O_TRUNC;

  fd = open(file->path, mode, conn->data->set.new_file_perms);
  if(fd < 0) {
    failf(data, "Can't open %s for writing", file->path);
    return CURLE_WRITE_ERROR;
  }

  if(-1 != data->set.infilesize)
    /* known size of data to "upload" */
    Curl_pgrsSetUploadSize(data, data->set.infilesize);

  /* treat the negative resume offset value as the case of "-" */
  if(data->state.resume_from < 0) {
    if(fstat(fd, &file_stat)) {
      close(fd);
      failf(data, "Can't get the size of %s", file->path);
      return CURLE_WRITE_ERROR;
    }
    else
      data->state.resume_from = (curl_off_t)file_stat.st_size;
  }

  while(res == CURLE_OK) {
    int readcount;
    res = Curl_fillreadbuffer(conn, BUFSIZE, &readcount);
    if(res)
      break;

    if(readcount <= 0)  /* fix questionable compare error. curlvms */
      break;

    nread = (size_t)readcount;

    /*skip bytes before resume point*/
    if(data->state.resume_from) {
      if((curl_off_t)nread <= data->state.resume_from ) {
        data->state.resume_from -= nread;
        nread = 0;
        buf2 = buf;
      }
      else {
        buf2 = buf + data->state.resume_from;
        nread -= (size_t)data->state.resume_from;
        data->state.resume_from = 0;
      }
    }
    else
      buf2 = buf;

    /* write the data to the target */
    nwrite = write(fd, buf2, nread);
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

  close(fd);

  return res;
}

/*
 * file_do() is the protocol-specific function for the do-phase, separated
 * from the connect-phase above. Other protocols merely setup the transfer in
 * the do-phase, to have it done in the main transfer loop but since some
 * platforms we support don't allow select()ing etc on file handles (as
 * opposed to sockets) we instead perform the whole do-operation in this
 * function.
 */
static CURLcode file_do(struct connectdata *conn, bool *done)
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

  Curl_initinfo(data);
  Curl_pgrsStartNow(data);

  if(data->set.upload)
    return file_upload(conn);

  /* get the fd from the connection phase */
  fd = conn->data->state.proto.file->fd;

  /* VMS: This only works reliable for STREAMLF files */
  if(-1 != fstat(fd, &statbuf)) {
    /* we could stat it, then read out the size */
    expected_size = statbuf.st_size;
    /* and store the modification time */
    data->info.filetime = (long)statbuf.st_mtime;
    fstated = TRUE;
  }

  if(fstated && !data->state.range && data->set.timecondition) {
    if(!Curl_meets_timecondition(data, (time_t)data->info.filetime)) {
      *done = TRUE;
      return CURLE_OK;
    }
  }

  /* If we have selected NOBODY and HEADER, it means that we only want file
     information. Which for FILE can't be much more than the file size and
     date. */
  if(data->set.opt_no_body && data->set.include_header && fstated) {
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
      time_t filetime = (time_t)statbuf.st_mtime;
      struct tm buffer;
      const struct tm *tm = &buffer;
      result = Curl_gmtime(filetime, &buffer);
      if(result)
        return result;

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
    /* if we fstat()ed the file, set the file size to make it available post-
       transfer */
    if(fstated)
      Curl_pgrsSetDownloadSize(data, expected_size);
    return result;
  }

  /* Check whether file range has been specified */
  file_range(conn);

  /* Adjust the start offset in case we want to get the N last bytes
   * of the stream iff the filesize could be determined */
  if(data->state.resume_from < 0) {
    if(!fstated) {
      failf(data, "Can't get the size of file.");
      return CURLE_READ_ERROR;
    }
    else
      data->state.resume_from += (curl_off_t)statbuf.st_size;
  }

  if(data->state.resume_from <= expected_size)
    expected_size -= data->state.resume_from;
  else {
    failf(data, "failed to resume file:// transfer");
    return CURLE_BAD_DOWNLOAD_RESUME;
  }

  /* A high water mark has been specified so we obey... */
  if(data->req.maxdownload > 0)
    expected_size = data->req.maxdownload;

  if(fstated && (expected_size == 0))
    return CURLE_OK;

  /* The following is a shortcut implementation of file reading
     this is both more efficient than the former call to download() and
     it avoids problems with select() and recv() on file descriptors
     in Winsock */
  if(fstated)
    Curl_pgrsSetDownloadSize(data, expected_size);

  if(data->state.resume_from) {
    if(data->state.resume_from !=
       lseek(fd, data->state.resume_from, SEEK_SET))
      return CURLE_BAD_DOWNLOAD_RESUME;
  }

  Curl_pgrsTime(data, TIMER_STARTTRANSFER);

  while(res == CURLE_OK) {
    /* Don't fill a whole buffer if we want less than all data */
    size_t bytestoread =
      (expected_size < CURL_OFF_T_C(BUFSIZE) - CURL_OFF_T_C(1)) ?
      curlx_sotouz(expected_size) : BUFSIZE - 1;

    nread = read(fd, buf, bytestoread);

    if(nread > 0)
      buf[nread] = 0;

    if(nread <= 0 || expected_size == 0)
      break;

    bytecount += nread;
    expected_size -= nread;

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
