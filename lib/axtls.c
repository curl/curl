/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, DirecTV
 * contact: Eric Hu <ehu@directv.com>
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

/*
 * Source file for all axTLS-specific code for the TLS/SSL layer. No code
 * but sslgen.c should ever call or use these functions.
 */

#include "setup.h"
#ifdef USE_AXTLS
#include <axTLS/ssl.h>
#include "axtls.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "sendf.h"
#include "inet_pton.h"
#include "sslgen.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>
#include "memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Global axTLS init, called from Curl_ssl_init() */
int Curl_axtls_init(void)
{
  return 1;
}

int Curl_axtls_cleanup(void)
{
  return 1;
}

/*
 * This function is called after the TCP connect has completed. Setup the TLS
 * layer and do all necessary magic.
 */
CURLcode
Curl_axtls_connect(struct connectdata *conn,
                  int sockindex)

{
  return CURLE_OK;
}


/* return number of sent (non-SSL) bytes */
ssize_t Curl_axtls_send(struct connectdata *conn,
                       int sockindex,
                       const void *mem,
                       size_t len)
{
  return 0;
}

void Curl_axtls_close_all(struct SessionHandle *data)
{
}

void Curl_axtls_close(struct connectdata *conn, int sockindex)
{
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
int Curl_axtls_shutdown(struct connectdata *conn, int sockindex)
{
  return 0;
}

/*
 * If the read would block we return -1 and set 'wouldblock' to TRUE.
 * Otherwise we return the amount of data read. Other errors should return -1
 * and set 'wouldblock' to FALSE.
 */
ssize_t Curl_axtls_recv(struct connectdata *conn, /* connection data */
                       int num,                  /* socketindex */
                       char *buf,                /* store read data here */
                       size_t buffersize,        /* max amount to read */
                       bool *wouldblock)
{
  return 0;
}

/*
 * This function uses SSL_peek to determine connection status.
 *
 * Return codes:
 *     1 means the connection is still in place
 *     0 means the connection has been closed
 *    -1 means the connection status is unknown
 */
int Curl_axtls_check_cxn(struct connectdata *conn)
{
   return 0;
}

void Curl_axtls_session_free(void *ptr)
{
}

size_t Curl_axtls_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "axTLS/1.2.7");
}

#endif /* USE_AXTLS */
