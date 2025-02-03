/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifndef FETCH_DISABLE_FILE

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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include "strtoofft.h"
#include "urldata.h"
#include <fetch/fetch.h>
#include "progress.h"
#include "sendf.h"
#include "escape.h"
#include "file.h"
#include "speedcheck.h"
#include "getinfo.h"
#include "multiif.h"
#include "transfer.h"
#include "url.h"
#include "parsedate.h" /* for the week day and month names */
#include "warnless.h"
#include "fetch_range.h"
/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

#if defined(_WIN32) || defined(MSDOS)
#define DOS_FILESYSTEM 1
#elif defined(__amigaos4__)
#define AMIGA_FILESYSTEM 1
#endif

/*
 * Forward declarations.
 */

static FETCHcode file_do(struct Fetch_easy *data, bool *done);
static FETCHcode file_done(struct Fetch_easy *data,
                           FETCHcode status, bool premature);
static FETCHcode file_connect(struct Fetch_easy *data, bool *done);
static FETCHcode file_disconnect(struct Fetch_easy *data,
                                 struct connectdata *conn,
                                 bool dead_connection);
static FETCHcode file_setup_connection(struct Fetch_easy *data,
                                       struct connectdata *conn);

/*
 * FILE scheme handler.
 */

const struct Fetch_handler Fetch_handler_file = {
    "file",                                /* scheme */
    file_setup_connection,                 /* setup_connection */
    file_do,                               /* do_it */
    file_done,                             /* done */
    ZERO_NULL,                             /* do_more */
    file_connect,                          /* connect_it */
    ZERO_NULL,                             /* connecting */
    ZERO_NULL,                             /* doing */
    ZERO_NULL,                             /* proto_getsock */
    ZERO_NULL,                             /* doing_getsock */
    ZERO_NULL,                             /* domore_getsock */
    ZERO_NULL,                             /* perform_getsock */
    file_disconnect,                       /* disconnect */
    ZERO_NULL,                             /* write_resp */
    ZERO_NULL,                             /* write_resp_hd */
    ZERO_NULL,                             /* connection_check */
    ZERO_NULL,                             /* attach connection */
    ZERO_NULL,                             /* follow */
    0,                                     /* defport */
    FETCHPROTO_FILE,                       /* protocol */
    FETCHPROTO_FILE,                       /* family */
    PROTOPT_NONETWORK | PROTOPT_NOURLQUERY /* flags */
};

static FETCHcode file_setup_connection(struct Fetch_easy *data,
                                       struct connectdata *conn)
{
  (void)conn;
  /* allocate the FILE specific struct */
  data->req.p.file = calloc(1, sizeof(struct FILEPROTO));
  if (!data->req.p.file)
    return FETCHE_OUT_OF_MEMORY;

  return FETCHE_OK;
}

/*
 * file_connect() gets called from Fetch_protocol_connect() to allow us to
 * do protocol-specific actions at connect-time. We emulate a
 * connect-then-transfer protocol and "connect" to the file here
 */
static FETCHcode file_connect(struct Fetch_easy *data, bool *done)
{
  char *real_path;
  struct FILEPROTO *file = data->req.p.file;
  int fd;
#ifdef DOS_FILESYSTEM
  size_t i;
  char *actual_path;
#endif
  size_t real_path_len;
  FETCHcode result;

  if (file->path)
  {
    /* already connected.
     * the handler->connect_it() is normally only called once, but
     * FILE does a special check on setting up the connection which
     * calls this explicitly. */
    *done = TRUE;
    return FETCHE_OK;
  }

  result = Fetch_urldecode(data->state.up.path, 0, &real_path,
                          &real_path_len, REJECT_ZERO);
  if (result)
    return result;

#ifdef DOS_FILESYSTEM
  /* If the first character is a slash, and there is
     something that looks like a drive at the beginning of
     the path, skip the slash. If we remove the initial
     slash in all cases, paths without drive letters end up
     relative to the current directory which is not how
     browsers work.

     Some browsers accept | instead of : as the drive letter
     separator, so we do too.

     On other platforms, we need the slash to indicate an
     absolute pathname. On Windows, absolute paths start
     with a drive letter.
  */
  actual_path = real_path;
  if ((actual_path[0] == '/') &&
      actual_path[1] &&
      (actual_path[2] == ':' || actual_path[2] == '|'))
  {
    actual_path[2] = ':';
    actual_path++;
    real_path_len--;
  }

  /* change path separators from '/' to '\\' for DOS, Windows and OS/2 */
  for (i = 0; i < real_path_len; ++i)
    if (actual_path[i] == '/')
      actual_path[i] = '\\';
    else if (!actual_path[i])
    { /* binary zero */
      Fetch_safefree(real_path);
      return FETCHE_URL_MALFORMAT;
    }

  fd = open(actual_path, O_RDONLY | FETCH_O_BINARY);
  file->path = actual_path;
#else
  if (memchr(real_path, 0, real_path_len))
  {
    /* binary zeroes indicate foul play */
    Fetch_safefree(real_path);
    return FETCHE_URL_MALFORMAT;
  }

#ifdef AMIGA_FILESYSTEM
  /*
   * A leading slash in an AmigaDOS path denotes the parent
   * directory, and hence we block this as it is relative.
   * Absolute paths start with 'volumename:', so we check for
   * this first. Failing that, we treat the path as a real Unix
   * path, but only if the application was compiled with -lunix.
   */
  fd = -1;
  file->path = real_path;

  if (real_path[0] == '/')
  {
    extern int __unix_path_semantics;
    if (strchr(real_path + 1, ':'))
    {
      /* Amiga absolute path */
      fd = open(real_path + 1, O_RDONLY);
      file->path++;
    }
    else if (__unix_path_semantics)
    {
      /* -lunix fallback */
      fd = open(real_path, O_RDONLY);
    }
  }
#else
  fd = open(real_path, O_RDONLY);
  file->path = real_path;
#endif
#endif
  Fetch_safefree(file->freepath);
  file->freepath = real_path; /* free this when done */

  file->fd = fd;
  if (!data->state.upload && (fd == -1))
  {
    failf(data, "Couldn't open file %s", data->state.up.path);
    file_done(data, FETCHE_FILE_COULDNT_READ_FILE, FALSE);
    return FETCHE_FILE_COULDNT_READ_FILE;
  }
  *done = TRUE;

  return FETCHE_OK;
}

static FETCHcode file_done(struct Fetch_easy *data,
                           FETCHcode status, bool premature)
{
  struct FILEPROTO *file = data->req.p.file;
  (void)status;    /* not used */
  (void)premature; /* not used */

  if (file)
  {
    Fetch_safefree(file->freepath);
    file->path = NULL;
    if (file->fd != -1)
      close(file->fd);
    file->fd = -1;
  }

  return FETCHE_OK;
}

static FETCHcode file_disconnect(struct Fetch_easy *data,
                                 struct connectdata *conn,
                                 bool dead_connection)
{
  (void)dead_connection; /* not used */
  (void)conn;
  return file_done(data, FETCHE_OK, FALSE);
}

#ifdef DOS_FILESYSTEM
#define DIRSEP '\\'
#else
#define DIRSEP '/'
#endif

static FETCHcode file_upload(struct Fetch_easy *data)
{
  struct FILEPROTO *file = data->req.p.file;
  const char *dir = strchr(file->path, DIRSEP);
  int fd;
  int mode;
  FETCHcode result = FETCHE_OK;
  char *xfer_ulbuf;
  size_t xfer_ulblen;
  fetch_off_t bytecount = 0;
  struct_stat file_stat;
  const char *sendbuf;
  bool eos = FALSE;

  /*
   * Since FILE: does not do the full init, we need to provide some extra
   * assignments here.
   */

  if (!dir)
    return FETCHE_FILE_COULDNT_READ_FILE; /* fix: better error code */

  if (!dir[1])
    return FETCHE_FILE_COULDNT_READ_FILE; /* fix: better error code */

  mode = O_WRONLY | O_CREAT | FETCH_O_BINARY;
  if (data->state.resume_from)
    mode |= O_APPEND;
  else
    mode |= O_TRUNC;

#if (defined(ANDROID) || defined(__ANDROID__)) && \
    (defined(__i386__) || defined(__arm__))
  fd = open(file->path, mode, (mode_t)data->set.new_file_perms);
#else
  fd = open(file->path, mode, data->set.new_file_perms);
#endif
  if (fd < 0)
  {
    failf(data, "cannot open %s for writing", file->path);
    return FETCHE_WRITE_ERROR;
  }

  if (-1 != data->state.infilesize)
    /* known size of data to "upload" */
    Fetch_pgrsSetUploadSize(data, data->state.infilesize);

  /* treat the negative resume offset value as the case of "-" */
  if (data->state.resume_from < 0)
  {
    if (fstat(fd, &file_stat))
    {
      close(fd);
      failf(data, "cannot get the size of %s", file->path);
      return FETCHE_WRITE_ERROR;
    }
    data->state.resume_from = (fetch_off_t)file_stat.st_size;
  }

  result = Fetch_multi_xfer_ulbuf_borrow(data, &xfer_ulbuf, &xfer_ulblen);
  if (result)
    goto out;

  while (!result && !eos)
  {
    size_t nread;
    ssize_t nwrite;
    size_t readcount;

    result = Fetch_client_read(data, xfer_ulbuf, xfer_ulblen, &readcount, &eos);
    if (result)
      break;

    if (!readcount)
      break;

    nread = readcount;

    /* skip bytes before resume point */
    if (data->state.resume_from)
    {
      if ((fetch_off_t)nread <= data->state.resume_from)
      {
        data->state.resume_from -= nread;
        nread = 0;
        sendbuf = xfer_ulbuf;
      }
      else
      {
        sendbuf = xfer_ulbuf + data->state.resume_from;
        nread -= (size_t)data->state.resume_from;
        data->state.resume_from = 0;
      }
    }
    else
      sendbuf = xfer_ulbuf;

    /* write the data to the target */
    nwrite = write(fd, sendbuf, nread);
    if ((size_t)nwrite != nread)
    {
      result = FETCHE_SEND_ERROR;
      break;
    }

    bytecount += nread;

    Fetch_pgrsSetUploadCounter(data, bytecount);

    if (Fetch_pgrsUpdate(data))
      result = FETCHE_ABORTED_BY_CALLBACK;
    else
      result = Fetch_speedcheck(data, Fetch_now());
  }
  if (!result && Fetch_pgrsUpdate(data))
    result = FETCHE_ABORTED_BY_CALLBACK;

out:
  close(fd);
  Fetch_multi_xfer_ulbuf_release(data, xfer_ulbuf);

  return result;
}

/*
 * file_do() is the protocol-specific function for the do-phase, separated
 * from the connect-phase above. Other protocols merely setup the transfer in
 * the do-phase, to have it done in the main transfer loop but since some
 * platforms we support do not allow select()ing etc on file handles (as
 * opposed to sockets) we instead perform the whole do-operation in this
 * function.
 */
static FETCHcode file_do(struct Fetch_easy *data, bool *done)
{
  /* This implementation ignores the hostname in conformance with
     RFC 1738. Only local files (reachable via the standard file system)
     are supported. This means that files on remotely mounted directories
     (via NFS, Samba, NT sharing) can be accessed through a file:// URL
  */
  FETCHcode result = FETCHE_OK;
  struct_stat statbuf; /* struct_stat instead of struct stat just to allow the
                          Windows version to have a different struct without
                          having to redefine the simple word 'stat' */
  fetch_off_t expected_size = -1;
  bool size_known;
  bool fstated = FALSE;
  int fd;
  struct FILEPROTO *file;
  char *xfer_buf;
  size_t xfer_blen;

  *done = TRUE; /* unconditionally */

  if (data->state.upload)
    return file_upload(data);

  file = data->req.p.file;

  /* get the fd from the connection phase */
  fd = file->fd;

  /* VMS: This only works reliable for STREAMLF files */
  if (-1 != fstat(fd, &statbuf))
  {
    if (!S_ISDIR(statbuf.st_mode))
      expected_size = statbuf.st_size;
    /* and store the modification time */
    data->info.filetime = statbuf.st_mtime;
    fstated = TRUE;
  }

  if (fstated && !data->state.range && data->set.timecondition &&
      !Fetch_meets_timecondition(data, data->info.filetime))
    return FETCHE_OK;

  if (fstated)
  {
    time_t filetime;
    struct tm buffer;
    const struct tm *tm = &buffer;
    char header[80];
    int headerlen;
    static const char accept_ranges[] = {"Accept-ranges: bytes\r\n"};
    if (expected_size >= 0)
    {
      headerlen =
          msnprintf(header, sizeof(header), "Content-Length: %" FMT_OFF_T "\r\n",
                    expected_size);
      result = Fetch_client_write(data, CLIENTWRITE_HEADER, header, headerlen);
      if (result)
        return result;

      result = Fetch_client_write(data, CLIENTWRITE_HEADER,
                                 accept_ranges, sizeof(accept_ranges) - 1);
      if (result != FETCHE_OK)
        return result;
    }

    filetime = (time_t)statbuf.st_mtime;
    result = Fetch_gmtime(filetime, &buffer);
    if (result)
      return result;

    /* format: "Tue, 15 Nov 1994 12:45:26 GMT" */
    headerlen =
        msnprintf(header, sizeof(header),
                  "Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n",
                  Fetch_wkday[tm->tm_wday ? tm->tm_wday - 1 : 6],
                  tm->tm_mday,
                  Fetch_month[tm->tm_mon],
                  tm->tm_year + 1900,
                  tm->tm_hour,
                  tm->tm_min,
                  tm->tm_sec);
    result = Fetch_client_write(data, CLIENTWRITE_HEADER, header, headerlen);
    if (!result)
      /* end of headers */
      result = Fetch_client_write(data, CLIENTWRITE_HEADER, "\r\n", 2);
    if (result)
      return result;
    /* set the file size to make it available post transfer */
    Fetch_pgrsSetDownloadSize(data, expected_size);
    if (data->req.no_body)
      return FETCHE_OK;
  }

  /* Check whether file range has been specified */
  result = Fetch_range(data);
  if (result)
    return result;

  /* Adjust the start offset in case we want to get the N last bytes
   * of the stream if the filesize could be determined */
  if (data->state.resume_from < 0)
  {
    if (!fstated)
    {
      failf(data, "cannot get the size of file.");
      return FETCHE_READ_ERROR;
    }
    data->state.resume_from += (fetch_off_t)statbuf.st_size;
  }

  if (data->state.resume_from > 0)
  {
    /* We check explicitly if we have a start offset, because
     * expected_size may be -1 if we do not know how large the file is,
     * in which case we should not adjust it. */
    if (data->state.resume_from <= expected_size)
      expected_size -= data->state.resume_from;
    else
    {
      failf(data, "failed to resume file:// transfer");
      return FETCHE_BAD_DOWNLOAD_RESUME;
    }
  }

  /* A high water mark has been specified so we obey... */
  if (data->req.maxdownload > 0)
    expected_size = data->req.maxdownload;

  if (!fstated || (expected_size <= 0))
    size_known = FALSE;
  else
    size_known = TRUE;

  /* The following is a shortcut implementation of file reading
     this is both more efficient than the former call to download() and
     it avoids problems with select() and recv() on file descriptors
     in Winsock */
  if (size_known)
    Fetch_pgrsSetDownloadSize(data, expected_size);

  if (data->state.resume_from)
  {
    if (!S_ISDIR(statbuf.st_mode))
    {
#ifdef __AMIGA__
      if (data->state.resume_from !=
          lseek(fd, (off_t)data->state.resume_from, SEEK_SET))
#else
      if (data->state.resume_from !=
          lseek(fd, data->state.resume_from, SEEK_SET))
#endif
        return FETCHE_BAD_DOWNLOAD_RESUME;
    }
    else
    {
      return FETCHE_BAD_DOWNLOAD_RESUME;
    }
  }

  result = Fetch_multi_xfer_buf_borrow(data, &xfer_buf, &xfer_blen);
  if (result)
    goto out;

  if (!S_ISDIR(statbuf.st_mode))
  {
    while (!result)
    {
      ssize_t nread;
      /* Do not fill a whole buffer if we want less than all data */
      size_t bytestoread;

      if (size_known)
      {
        bytestoread = (expected_size < (fetch_off_t)(xfer_blen - 1)) ? fetchx_sotouz(expected_size) : (xfer_blen - 1);
      }
      else
        bytestoread = xfer_blen - 1;

      nread = read(fd, xfer_buf, bytestoread);

      if (nread > 0)
        xfer_buf[nread] = 0;

      if (nread <= 0 || (size_known && (expected_size == 0)))
        break;

      if (size_known)
        expected_size -= nread;

      result = Fetch_client_write(data, CLIENTWRITE_BODY, xfer_buf, nread);
      if (result)
        goto out;

      if (Fetch_pgrsUpdate(data))
        result = FETCHE_ABORTED_BY_CALLBACK;
      else
        result = Fetch_speedcheck(data, Fetch_now());
      if (result)
        goto out;
    }
  }
  else
  {
#ifdef HAVE_OPENDIR
    DIR *dir = opendir(file->path);
    struct dirent *entry;

    if (!dir)
    {
      result = FETCHE_READ_ERROR;
      goto out;
    }
    else
    {
      while ((entry = readdir(dir)))
      {
        if (entry->d_name[0] != '.')
        {
          result = Fetch_client_write(data, CLIENTWRITE_BODY,
                                     entry->d_name, strlen(entry->d_name));
          if (result)
            break;
          result = Fetch_client_write(data, CLIENTWRITE_BODY, "\n", 1);
          if (result)
            break;
        }
      }
      closedir(dir);
    }
#else
    failf(data, "Directory listing not yet implemented on this platform.");
    result = FETCHE_READ_ERROR;
#endif
  }

  if (Fetch_pgrsUpdate(data))
    result = FETCHE_ABORTED_BY_CALLBACK;

out:
  Fetch_multi_xfer_buf_release(data, xfer_buf);
  return result;
}

#endif
