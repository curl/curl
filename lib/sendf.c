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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h> /* required for send() & recv() prototypes */
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "connect.h" /* for the Curl_sockerrno() proto */
#include "sslgen.h"
#include "ssh.h"
#include "multiif.h"

#define _MPRINTF_REPLACE /* use the internal *printf() functions */
#include <curl/mprintf.h>

#ifdef HAVE_KRB4
#include "krb4.h"
#else
#define Curl_sec_send(a,b,c,d) -1
#define Curl_sec_read(a,b,c,d) -1
#endif

#include <string.h>
#include "memory.h"
#include "strerror.h"
#include "easyif.h" /* for the Curl_convert_from_network prototype */
/* The last #include file should be: */
#include "memdebug.h"

/* returns last node in linked list */
static struct curl_slist *slist_get_last(struct curl_slist *list)
{
  struct curl_slist     *item;

  /* if caller passed us a NULL, return now */
  if (!list)
    return NULL;

  /* loop through to find the last item */
  item = list;
  while (item->next) {
    item = item->next;
  }
  return item;
}

/*
 * curl_slist_append() appends a string to the linked list. It always retunrs
 * the address of the first record, so that you can sure this function as an
 * initialization function as well as an append function. If you find this
 * bothersome, then simply create a separate _init function and call it
 * appropriately from within the proram.
 */
struct curl_slist *curl_slist_append(struct curl_slist *list,
                                     const char *data)
{
  struct curl_slist     *last;
  struct curl_slist     *new_item;

  new_item = (struct curl_slist *) malloc(sizeof(struct curl_slist));
  if (new_item) {
    char *dup = strdup(data);
    if(dup) {
      new_item->next = NULL;
      new_item->data = dup;
    }
    else {
      free(new_item);
      return NULL;
    }
  }
  else
    return NULL;

  if (list) {
    last = slist_get_last(list);
    last->next = new_item;
    return list;
  }

  /* if this is the first item, then new_item *is* the list */
  return new_item;
}

/* be nice and clean up resources */
void curl_slist_free_all(struct curl_slist *list)
{
  struct curl_slist     *next;
  struct curl_slist     *item;

  if (!list)
    return;

  item = list;
  do {
    next = item->next;

    if (item->data) {
      free(item->data);
    }
    free(item);
    item = next;
  } while (next);
}

#ifdef CURL_DO_LINEEND_CONV
/*
 * convert_lineends() changes CRLF (\r\n) end-of-line markers to a single LF
 * (\n), with special processing for CRLF sequences that are split between two
 * blocks of data.  Remaining, bare CRs are changed to LFs.  The possibly new
 * size of the data is returned.
 */
static size_t convert_lineends(struct SessionHandle *data,
                               char *startPtr, size_t size)
{
  char *inPtr, *outPtr;

  /* sanity check */
  if ((startPtr == NULL) || (size < 1)) {
    return(size);
  }

  if (data->state.prev_block_had_trailing_cr == TRUE) {
    /* The previous block of incoming data
       had a trailing CR, which was turned into a LF. */
    if (*startPtr == '\n') {
      /* This block of incoming data starts with the
         previous block's LF so get rid of it */
      memcpy(startPtr, startPtr+1, size-1);
      size--;
      /* and it wasn't a bare CR but a CRLF conversion instead */
      data->state.crlf_conversions++;
    }
    data->state.prev_block_had_trailing_cr = FALSE; /* reset the flag */
  }

  /* find 1st CR, if any */
  inPtr = outPtr = memchr(startPtr, '\r', size);
  if (inPtr) {
    /* at least one CR, now look for CRLF */
    while (inPtr < (startPtr+size-1)) {
      /* note that it's size-1, so we'll never look past the last byte */
      if (memcmp(inPtr, "\r\n", 2) == 0) {
        /* CRLF found, bump past the CR and copy the NL */
        inPtr++;
        *outPtr = *inPtr;
        /* keep track of how many CRLFs we converted */
        data->state.crlf_conversions++;
      }
      else {
        if (*inPtr == '\r') {
          /* lone CR, move LF instead */
          *outPtr = '\n';
        }
        else {
          /* not a CRLF nor a CR, just copy whatever it is */
          *outPtr = *inPtr;
        }
      }
      outPtr++;
      inPtr++;
    } /* end of while loop */

    if (inPtr < startPtr+size) {
      /* handle last byte */
      if (*inPtr == '\r') {
        /* deal with a CR at the end of the buffer */
        *outPtr = '\n'; /* copy a NL instead */
        /* note that a CRLF might be split across two blocks */
        data->state.prev_block_had_trailing_cr = TRUE;
      }
      else {
        /* copy last byte */
        *outPtr = *inPtr;
      }
      outPtr++;
      inPtr++;
    }
    if (outPtr < startPtr+size) {
      /* tidy up by null terminating the now shorter data */
      *outPtr = '\0';
    }
    return(outPtr - startPtr);
  }
  return(size);
}
#endif /* CURL_DO_LINEEND_CONV */

/* Curl_infof() is for info message along the way */

void Curl_infof(struct SessionHandle *data, const char *fmt, ...)
{
  if(data && data->set.verbose) {
    va_list ap;
    size_t len;
    char print_buffer[1024 + 1];
    va_start(ap, fmt);
    vsnprintf(print_buffer, 1024, fmt, ap);
    va_end(ap);
    len = strlen(print_buffer);
    Curl_debug(data, CURLINFO_TEXT, print_buffer, len, NULL);
  }
}

/* Curl_failf() is for messages stating why we failed.
 * The message SHALL NOT include any LF or CR.
 */

void Curl_failf(struct SessionHandle *data, const char *fmt, ...)
{
  va_list ap;
  size_t len;
  va_start(ap, fmt);

  vsnprintf(data->state.buffer, BUFSIZE, fmt, ap);

  if(data->set.errorbuffer && !data->state.errorbuf) {
    snprintf(data->set.errorbuffer, CURL_ERROR_SIZE, "%s", data->state.buffer);
    data->state.errorbuf = TRUE; /* wrote error string */
  }
  if(data->set.verbose) {
    len = strlen(data->state.buffer);
    if(len < BUFSIZE - 1) {
      data->state.buffer[len] = '\n';
      data->state.buffer[++len] = '\0';
    }
    Curl_debug(data, CURLINFO_TEXT, data->state.buffer, len, NULL);
  }

  va_end(ap);
}

/* Curl_sendf() sends formated data to the server */
CURLcode Curl_sendf(curl_socket_t sockfd, struct connectdata *conn,
                    const char *fmt, ...)
{
  struct SessionHandle *data = conn->data;
  ssize_t bytes_written;
  size_t write_len;
  CURLcode res = CURLE_OK;
  char *s;
  char *sptr;
  va_list ap;
  va_start(ap, fmt);
  s = vaprintf(fmt, ap); /* returns an allocated string */
  va_end(ap);
  if(!s)
    return CURLE_OUT_OF_MEMORY; /* failure */

  bytes_written=0;
  write_len = strlen(s);
  sptr = s;

  while (1) {
    /* Write the buffer to the socket */
    res = Curl_write(conn, sockfd, sptr, write_len, &bytes_written);

    if(CURLE_OK != res)
      break;

    if(data->set.verbose)
      Curl_debug(data, CURLINFO_DATA_OUT, sptr, (size_t)bytes_written, conn);

    if((size_t)bytes_written != write_len) {
      /* if not all was written at once, we must advance the pointer, decrease
         the size left and try again! */
      write_len -= bytes_written;
      sptr += bytes_written;
    }
    else
      break;
  }

  free(s); /* free the output string */

  return res;
}

static ssize_t Curl_plain_send(struct connectdata *conn,
                               int num,
                               void *mem,
                               size_t len)
{
  curl_socket_t sockfd = conn->sock[num];
  ssize_t bytes_written = swrite(sockfd, mem, len);

  if(-1 == bytes_written) {
    int err = Curl_sockerrno();

    if(
#ifdef WSAEWOULDBLOCK
      /* This is how Windows does it */
      (WSAEWOULDBLOCK == err)
#else
      /* errno may be EWOULDBLOCK or on some systems EAGAIN when it returned
         due to its inability to send off data without blocking. We therefor
         treat both error codes the same here */
      (EWOULDBLOCK == err) || (EAGAIN == err) || (EINTR == err)
#endif
      )
      /* this is just a case of EWOULDBLOCK */
      bytes_written=0;
    else
      failf(conn->data, "Send failure: %s",
            Curl_strerror(conn, err));
  }
  return bytes_written;
}

/*
 * Curl_write() is an internal write function that sends data to the
 * server. Works with plain sockets, SCP, SSL or kerberos.
 */
CURLcode Curl_write(struct connectdata *conn,
                    curl_socket_t sockfd,
                    void *mem,
                    size_t len,
                    ssize_t *written)
{
  ssize_t bytes_written;
  CURLcode retcode;
  int num = (sockfd == conn->sock[SECONDARYSOCKET]);

  if (conn->ssl[num].use)
    /* only TRUE if SSL enabled */
    bytes_written = Curl_ssl_send(conn, num, mem, len);
#ifdef USE_LIBSSH2
  else if (conn->protocol & PROT_SCP)
    bytes_written = Curl_scp_send(conn, num, mem, len);
  else if (conn->protocol & PROT_SFTP)
    bytes_written = Curl_sftp_send(conn, num, mem, len);
#endif /* !USE_LIBSSH2 */
  else if(conn->sec_complete)
    /* only TRUE if krb4 enabled */
    bytes_written = Curl_sec_send(conn, num, mem, len);
  else
    bytes_written = Curl_plain_send(conn, num, mem, len);

  *written = bytes_written;
  retcode = (-1 != bytes_written)?CURLE_OK:CURLE_SEND_ERROR;

  return retcode;
}

/* client_write() sends data to the write callback(s)

   The bit pattern defines to what "streams" to write to. Body and/or header.
   The defines are in sendf.h of course.
 */
CURLcode Curl_client_write(struct connectdata *conn,
                           int type,
                           char *ptr,
                           size_t len)
{
  struct SessionHandle *data = conn->data;
  size_t wrote;

  if (data->state.cancelled) {
      /* We just suck everything into a black hole */
      return CURLE_OK;
  }

  if(0 == len)
    len = strlen(ptr);

  if(type & CLIENTWRITE_BODY) {
    if((conn->protocol&PROT_FTP) && conn->proto.ftpc.transfertype == 'A') {
#ifdef CURL_DOES_CONVERSIONS
      /* convert from the network encoding */
      size_t rc;
      rc = Curl_convert_from_network(data, ptr, len);
      /* Curl_convert_from_network calls failf if unsuccessful */
      if(rc != CURLE_OK)
        return rc;
#endif /* CURL_DOES_CONVERSIONS */

#ifdef CURL_DO_LINEEND_CONV
      /* convert end-of-line markers */
      len = convert_lineends(data, ptr, len);
#endif /* CURL_DO_LINEEND_CONV */
    }
    /* If the previous block of data ended with CR and this block of data is
       just a NL, then the length might be zero */
    if (len) {
      wrote = data->set.fwrite(ptr, 1, len, data->set.out);
    }
    else {
      wrote = len;
    }

    if(wrote != len) {
      failf (data, "Failed writing body");
      return CURLE_WRITE_ERROR;
    }
  }

  if((type & CLIENTWRITE_HEADER) &&
     (data->set.fwrite_header || data->set.writeheader) ) {
    /*
     * Write headers to the same callback or to the especially setup
     * header callback function (added after version 7.7.1).
     */
    curl_write_callback writeit=
      data->set.fwrite_header?data->set.fwrite_header:data->set.fwrite;

    /* Note: The header is in the host encoding
       regardless of the ftp transfer mode (ASCII/Image) */

    wrote = writeit(ptr, 1, len, data->set.writeheader);
    if(wrote != len) {
      failf (data, "Failed writing header");
      return CURLE_WRITE_ERROR;
    }
  }

  return CURLE_OK;
}

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

/*
 * Internal read-from-socket function. This is meant to deal with plain
 * sockets, SSL sockets and kerberos sockets.
 *
 * If the read would block (EWOULDBLOCK) we return -1. Otherwise we return
 * a regular CURLcode value.
 */
int Curl_read(struct connectdata *conn, /* connection data */
              curl_socket_t sockfd,     /* read from this socket */
              char *buf,                /* store read data here */
              size_t sizerequested,     /* max amount to read */
              ssize_t *n)               /* amount bytes read */
{
  ssize_t nread;
  size_t bytesfromsocket = 0;
  char *buffertofill = NULL;
  bool pipelining = (bool)(conn->data->multi &&
                     Curl_multi_canPipeline(conn->data->multi));

  /* Set 'num' to 0 or 1, depending on which socket that has been sent here.
     If it is the second socket, we set num to 1. Otherwise to 0. This lets
     us use the correct ssl handle. */
  int num = (sockfd == conn->sock[SECONDARYSOCKET]);

  *n=0; /* reset amount to zero */

  /* If session can pipeline, check connection buffer  */
  if(pipelining) {
    size_t bytestocopy = MIN(conn->buf_len - conn->read_pos, sizerequested);

    /* Copy from our master buffer first if we have some unread data there*/
    if (bytestocopy > 0) {
      memcpy(buf, conn->master_buffer + conn->read_pos, bytestocopy);
      conn->read_pos += bytestocopy;
      conn->bits.stream_was_rewound = FALSE;

      *n = (ssize_t)bytestocopy;
      return CURLE_OK;
    }
    /* If we come here, it means that there is no data to read from the buffer,
     * so we read from the socket */
    bytesfromsocket = MIN(sizerequested, sizeof(conn->master_buffer));
    buffertofill = conn->master_buffer;
  }
  else {
    bytesfromsocket = MIN((long)sizerequested, conn->data->set.buffer_size ?
                          conn->data->set.buffer_size : BUFSIZE);
    buffertofill = buf;
  }

  if(conn->ssl[num].use) {
    nread = Curl_ssl_recv(conn, num, buffertofill, bytesfromsocket);

    if(nread == -1) {
      return -1; /* -1 from Curl_ssl_recv() means EWOULDBLOCK */
    }
  }
#ifdef USE_LIBSSH2
  else if (conn->protocol & PROT_SCP) {
    nread = Curl_scp_recv(conn, num, buffertofill, bytesfromsocket);
    /* TODO: return CURLE_OK also for nread <= 0
             read failures and timeouts ? */
  }
  else if (conn->protocol & PROT_SFTP) {
    nread = Curl_sftp_recv(conn, num, buffertofill, bytesfromsocket);
  }
#endif /* !USE_LIBSSH2 */
  else {
    if(conn->sec_complete)
      nread = Curl_sec_read(conn, sockfd, buffertofill,
                            bytesfromsocket);
    else
      nread = sread(sockfd, buffertofill, bytesfromsocket);

    if(-1 == nread) {
      int err = Curl_sockerrno();
#ifdef USE_WINSOCK
      if(WSAEWOULDBLOCK == err)
#else
      if((EWOULDBLOCK == err) || (EAGAIN == err) || (EINTR == err))
#endif
        return -1;
    }
  }

  if (nread >= 0) {
    if(pipelining) {
      memcpy(buf, conn->master_buffer, nread);
      conn->buf_len = nread;
      conn->read_pos = nread;
    }

    *n += nread;
  }

  return CURLE_OK;
}

/* return 0 on success */
static int showit(struct SessionHandle *data, curl_infotype type,
                  char *ptr, size_t size)
{
  static const char * const s_infotype[CURLINFO_END] = {
    "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };

#ifdef CURL_DOES_CONVERSIONS
  char buf[BUFSIZE+1];
  size_t conv_size = 0;

  switch(type) {
  case CURLINFO_HEADER_OUT:
    /* assume output headers are ASCII */
    /* copy the data into my buffer so the original is unchanged */
    if (size > BUFSIZE) {
      size = BUFSIZE; /* truncate if necessary */
      buf[BUFSIZE] = '\0';
    }
    conv_size = size;
    memcpy(buf, ptr, size);
    /* Special processing is needed for this block if it
     * contains both headers and data (separated by CRLFCRLF).
     * We want to convert just the headers, leaving the data as-is.
     */
    if(size > 4) {
      size_t i;
      for(i = 0; i < size-4; i++) {
        if(memcmp(&buf[i], "\x0d\x0a\x0d\x0a", 4) == 0) {
          /* convert everthing through this CRLFCRLF but no further */
          conv_size = i + 4;
          break;
        }
      }
    }

    Curl_convert_from_network(data, buf, conv_size);
    /* Curl_convert_from_network calls failf if unsuccessful */
    /* we might as well continue even if it fails...   */
    ptr = buf; /* switch pointer to use my buffer instead */
    break;
  default:
    /* leave everything else as-is */
    break;
  }
#endif /* CURL_DOES_CONVERSIONS */

  if(data->set.fdebug)
    return (*data->set.fdebug)(data, type, ptr, size,
                               data->set.debugdata);

  switch(type) {
  case CURLINFO_TEXT:
  case CURLINFO_HEADER_OUT:
  case CURLINFO_HEADER_IN:
    fwrite(s_infotype[type], 2, 1, data->set.err);
    fwrite(ptr, size, 1, data->set.err);
#ifdef CURL_DOES_CONVERSIONS
    if(size != conv_size) {
      /* we had untranslated data so we need an explicit newline */
      fwrite("\n", 1, 1, data->set.err);
    }
#endif
    break;
  default: /* nada */
    break;
  }
  return 0;
}

int Curl_debug(struct SessionHandle *data, curl_infotype type,
               char *ptr, size_t size,
               struct connectdata *conn)
{
  int rc;
  if(data->set.printhost && conn && conn->host.dispname) {
    char buffer[160];
    const char *t=NULL;
    const char *w="Data";
    switch (type) {
    case CURLINFO_HEADER_IN:
      w = "Header";
    case CURLINFO_DATA_IN:
      t = "from";
      break;
    case CURLINFO_HEADER_OUT:
      w = "Header";
    case CURLINFO_DATA_OUT:
      t = "to";
      break;
    default:
      break;
    }

    if(t) {
      snprintf(buffer, sizeof(buffer), "[%s %s %s]", w, t,
               conn->host.dispname);
      rc = showit(data, CURLINFO_TEXT, buffer, strlen(buffer));
      if(rc)
        return rc;
    }
  }
  rc = showit(data, type, ptr, size);
  return rc;
}
