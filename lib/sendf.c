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
 *  Portions created by the Initial Developer are Copyright (C) 1998.
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

#include <curl/mprintf.h>

#ifdef KRB4
#include "security.h"
#include <string.h>
#endif
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
    vsprintf(data->errorbuffer, fmt, ap);
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
  if (data->use_ssl) {
    bytes_written = SSL_write(data->ssl, s, strlen(s));
  } else {
    bytes_written = swrite(fd, s, strlen(s));
  }
#endif /* USE_SSLEAY */
  free(s); /* free the output string */
  return(bytes_written);
}

/*
 * ftpsendf() sends the formated string as a ftp command to a ftp server
 */
size_t ftpsendf(int fd, struct connectdata *conn, char *fmt, ...)
{
  size_t bytes_written;
  char *s;
  va_list ap;
  va_start(ap, fmt);
  s = mvaprintf(fmt, ap);
  va_end(ap);
  if(!s)
    return 0; /* failure */
  if(conn->data->bits.verbose)
    fprintf(conn->data->err, "> %s\n", s);

#ifdef KRB4
  if(conn->sec_complete && conn->data->cmdchannel) {
    bytes_written = sec_fprintf(conn, conn->data->cmdchannel, s);
    bytes_written += fprintf(conn->data->cmdchannel, "\r\n");
    fflush(conn->data->cmdchannel);
  }
  else
#endif /* KRB4 */
    {
      bytes_written = swrite(fd, s, strlen(s));
      bytes_written += swrite(fd, "\r\n", 2);
    }
  free(s); /* free the output string */
  return(bytes_written);
}


/* ssend() sends plain (binary) data to the server */
size_t ssend(int fd, struct connectdata *conn, void *mem, size_t len)
{
  size_t bytes_written;
  struct UrlData *data=conn->data; /* conn knows data, not vice versa */

#ifdef USE_SSLEAY
  if (data->use_ssl) {
    bytes_written = SSL_write(data->ssl, mem, len);
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

