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

void infof(struct UrlData *data, char *fmt, ...)
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

void failf(struct UrlData *data, char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if(data->errorbuffer)
    vsnprintf(data->errorbuffer, CURL_ERROR_SIZE, fmt, ap);
  else /* no errorbuffer receives this, write to data->err instead */
    vfprintf(data->err, fmt, ap);
  va_end(ap);
}

/* sendf() sends the formated data to the server */
size_t sendf(int fd, struct UrlData *data, char *fmt, ...)
{
  size_t bytes_written;
  char *s;
  va_list ap;
  va_start(ap, fmt);
  s = mvaprintf(fmt, ap);
  va_end(ap);
  if(!s)
    return 0; /* failure */
  if(data->bits.verbose)
    fprintf(data->err, "> %s", s);

#ifndef USE_SSLEAY
  bytes_written = swrite(fd, s, strlen(s));
#else /* USE_SSLEAY */
  if (data->ssl.use) {
    bytes_written = SSL_write(data->ssl.handle, s, strlen(s));
  } else {
    bytes_written = swrite(fd, s, strlen(s));
  }
#endif /* USE_SSLEAY */
  free(s); /* free the output string */
  return(bytes_written);
}

/*
 * ftpsendf() sends the formated string as a ftp command to a ftp server
 *
 * NOTE: we build the command in a fixed-length buffer, which sets length
 * restrictions on the command!
 *
 */
size_t ftpsendf(int fd, struct connectdata *conn, char *fmt, ...)
{
  size_t bytes_written;
  char s[256];

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(s, 250, fmt, ap);
  va_end(ap);

  if(conn->data->bits.verbose)
    fprintf(conn->data->err, "> %s\n", s);

  strcat(s, "\r\n"); /* append a trailing CRLF */

#ifdef KRB4
  if(conn->sec_complete && conn->data->cmdchannel) {
    bytes_written = sec_fprintf(conn, conn->data->cmdchannel, s);
    fflush(conn->data->cmdchannel);
  }
  else
#endif /* KRB4 */
    {
      bytes_written = swrite(fd, s, strlen(s));
    }
  return(bytes_written);
}

/* ssend() sends plain (binary) data to the server */
size_t ssend(int fd, struct connectdata *conn, void *mem, size_t len)
{
  size_t bytes_written;
  struct UrlData *data=conn->data; /* conn knows data, not vice versa */

#ifdef USE_SSLEAY
  if (data->ssl.use) {
    bytes_written = SSL_write(data->ssl.handle, mem, len);
  }
  else {
#endif
#ifdef KRB4
    if(conn->sec_complete) {
      bytes_written = sec_write(conn, fd, mem, len);
    }
    else
#endif /* KRB4 */
      bytes_written = swrite(fd, mem, len);
#ifdef USE_SSLEAY
  }
#endif

  return bytes_written;
}

/* client_write() sends data to the write callback(s)

   The bit pattern defines to what "streams" to write to. Body and/or header.
   The defines are in sendf.h of course.
 */
CURLcode client_write(struct UrlData *data,
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
 * add_buffer_init() returns a fine buffer struct
 */
send_buffer *add_buffer_init(void)
{
  send_buffer *blonk;
  blonk=(send_buffer *)malloc(sizeof(send_buffer));
  if(blonk) {
    memset(blonk, 0, sizeof(send_buffer));
    return blonk;
  }
  return NULL; /* failed, go home */
}

/*
 * add_buffer_send() sends a buffer and frees all associated memory.
 */
size_t add_buffer_send(int sockfd, struct connectdata *conn, send_buffer *in)
{
  size_t amount;
  if(conn->data->bits.verbose) {
    fputs("> ", conn->data->err);
    /* this data _may_ contain binary stuff */
    fwrite(in->buffer, in->size_used, 1, conn->data->err);
  }

  amount = ssend(sockfd, conn, in->buffer, in->size_used);

  if(in->buffer)
    free(in->buffer);
  free(in);

  return amount;
}


/* 
 * add_bufferf() builds a buffer from the formatted input
 */
CURLcode add_bufferf(send_buffer *in, char *fmt, ...)
{
  CURLcode result = CURLE_OUT_OF_MEMORY;
  char *s;
  va_list ap;
  va_start(ap, fmt);
  s = mvaprintf(fmt, ap); /* this allocs a new string to append */
  va_end(ap);

  if(s) {
    result = add_buffer(in, s, strlen(s));
    free(s);
  }
  return result;
}

/*
 * add_buffer() appends a memory chunk to the existing one
 */
CURLcode add_buffer(send_buffer *in, void *inptr, size_t size)
{
  char *new_rb;
  int new_size;

  if(size > 0) {
    if(!in->buffer ||
       ((in->size_used + size) > (in->size_max - 1))) {
      new_size = (in->size_used+size)*2;
      if(in->buffer)
        /* we have a buffer, enlarge the existing one */
        new_rb = (char *)realloc(in->buffer, new_size);
      else
        /* create a new buffer */
        new_rb = (char *)malloc(new_size);

      if(!new_rb)
        return CURLE_OUT_OF_MEMORY;

      in->buffer = new_rb;
      in->size_max = new_size;
    }
    memcpy(&in->buffer[in->size_used], inptr, size);
      
    in->size_used += size;
  }

  return CURLE_OK;
}

