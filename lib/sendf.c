/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"

#define _MPRINTF_REPLACE /* use the internal *printf() functions */
#include <curl/mprintf.h>

#ifdef KRB4
#include "security.h"
#endif
#include <string.h>
/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/* infof() is for info message along the way */

void Curl_infof(struct UrlData *data, char *fmt, ...)
{
  va_list ap;
  if(data->bits.verbose) {
    va_start(ap, fmt);
    fputs("* ", data->err);
    vfprintf(data->err, fmt, ap);
    va_end(ap);
  }
}

/* failf() is for messages stating why we failed, the LAST one will be
   returned for the user (if requested) */

void Curl_failf(struct UrlData *data, char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if(data->errorbuffer)
    vsnprintf(data->errorbuffer, CURL_ERROR_SIZE, fmt, ap);
  else /* no errorbuffer receives this, write to data->err instead */
    vfprintf(data->err, fmt, ap);
  va_end(ap);
}

/* Curl_sendf() sends formated data to the server */
size_t Curl_sendf(int sockfd, struct connectdata *conn,
                  char *fmt, ...)
{
  struct UrlData *data = conn->data;
  size_t bytes_written;
  char *s;
  va_list ap;
  va_start(ap, fmt);
  s = vaprintf(fmt, ap); /* returns an allocated string */
  va_end(ap);
  if(!s)
    return 0; /* failure */
  if(data->bits.verbose)
    fprintf(data->err, "> %s", s);

  /* Write the buffer to the socket */
  Curl_write(conn, sockfd, s, strlen(s), &bytes_written);

  free(s); /* free the output string */

  return bytes_written;
}

/*
 * Curl_write() is an internal write function that sends plain (binary) data
 * to the server. Works with plain sockets, SSL or kerberos.
 *
 */
CURLcode Curl_write(struct connectdata *conn, int sockfd,
                    void *mem, size_t len,
                    size_t *written)
{
  size_t bytes_written;
  struct UrlData *data=conn->data; /* conn knows data, not vice versa */

#ifdef USE_SSLEAY
  if (data->ssl.use) {
    int loop=100; /* just a precaution to never loop endlessly */
    while(loop--) {
      bytes_written = SSL_write(data->ssl.handle, mem, len);
      if((-1 != bytes_written) ||
         (SSL_ERROR_WANT_WRITE != SSL_get_error(data->ssl.handle,
                                                bytes_written) ))
        break;
    }
  }
  else {
#endif
#ifdef KRB4
    if(conn->sec_complete) {
      bytes_written = sec_write(conn, sockfd, mem, len);
    }
    else
#endif /* KRB4 */
      bytes_written = swrite(sockfd, mem, len);
#ifdef USE_SSLEAY
  }
#endif

  *written = bytes_written;
  return CURLE_OK;
}

/*
 * External write-function, writes to the data-socket.
 * Takes care of plain sockets, SSL or kerberos transparently.
 */
CURLcode curl_write(CURLconnect *c_conn, char *buf, size_t amount,
                   size_t *n)
{
  struct connectdata *conn = (struct connectdata *)c_conn;

  if(!n || !conn || (conn->handle != STRUCT_CONNECT))
    return CURLE_FAILED_INIT;

  return Curl_write(conn, conn->sockfd, buf, amount, n);
}



/* client_write() sends data to the write callback(s)

   The bit pattern defines to what "streams" to write to. Body and/or header.
   The defines are in sendf.h of course.
 */
CURLcode Curl_client_write(struct UrlData *data,
                           int type,
                           char *ptr,
                           size_t len)
{
  size_t wrote;

  if(0 == len)
    len = strlen(ptr);

  if(type & CLIENTWRITE_BODY) {
    wrote = data->fwrite(ptr, 1, len, data->out);
    if(wrote != len) {
      failf (data, "Failed writing body");
      return CURLE_WRITE_ERROR;
    }
  }
  if((type & CLIENTWRITE_HEADER) && data->writeheader) {
    wrote = data->fwrite(ptr, 1, len, data->writeheader);
    if(wrote != len) {
      failf (data, "Failed writing header");
      return CURLE_WRITE_ERROR;
    }
  }
  
  return CURLE_OK;
}


/*
 * Internal read-from-socket function. This is meant to deal with plain
 * sockets, SSL sockets and kerberos sockets.
 */
CURLcode Curl_read(struct connectdata *conn, int sockfd,
                   char *buf, size_t buffersize,
                   ssize_t *n)
{
  struct UrlData *data = conn->data;
  ssize_t nread;

#ifdef USE_SSLEAY
  if (data->ssl.use) {
    int loop=100; /* just a precaution to never loop endlessly */
    while(loop--) {
      nread = SSL_read(data->ssl.handle, buf, buffersize);
      if((-1 != nread) ||
         (SSL_ERROR_WANT_READ != SSL_get_error(data->ssl.handle, nread) ))
        break;
    }
  }
  else {
#endif
#ifdef KRB4
    if(conn->sec_complete)
      nread = sec_read(conn, sockfd, buf, buffersize);
    else
#endif
      nread = sread (sockfd, buf, buffersize);
#ifdef USE_SSLEAY
  }
#endif /* USE_SSLEAY */
  *n = nread;
  return CURLE_OK;
}

/*
 * The public read function reads from the 'sockfd' file descriptor only.
 * Use the Curl_read() internally when you want to specify fd.
 */

CURLcode curl_read(CURLconnect *c_conn, char *buf, size_t buffersize,
                   ssize_t *n)
{
  struct connectdata *conn = (struct connectdata *)c_conn;

  if(!n || !conn || (conn->handle != STRUCT_CONNECT))
    return CURLE_FAILED_INIT;

  return Curl_read(conn, conn->sockfd, buf, buffersize, n);
}

