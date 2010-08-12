/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

#ifndef CURL_DISABLE_GOPHER

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef WIN32
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
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
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif


#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"

#include "progress.h"
#include "strequal.h"
#include "gopher.h"
#include "rawstr.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"


/*
 * Forward declarations.
 */

static CURLcode gopher_do(struct connectdata *conn, bool *done);

/*
 * Gopher protocol handler.
 * This is also a nice simple template to build off for simple
 * connect-command-download protocols.
 */

const struct Curl_handler Curl_handler_gopher = {
  "GOPHER",                             /* scheme */
  ZERO_NULL,                            /* setup_connection */
  gopher_do,                            /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  PORT_GOPHER,                          /* defport */
  PROT_GOPHER                           /* protocol */
};

static CURLcode gopher_do(struct connectdata *conn, bool *done)
{
  CURLcode result=CURLE_OK;
  struct SessionHandle *data=conn->data;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];

  curl_off_t *bytecount = &data->req.bytecount;
  char *path = data->state.path;

  char *sel;

  *done = TRUE; /* unconditionally */

  /* Create selector. Degenerate cases: / and /1 => convert to "" */
  if (strlen(path) <= 2)
    sel = (char *)"";
  else {
    char *newp;
    int i, j, len;

    /* Otherwise, drop / and the first character (i.e., item type) ... */
    newp = path;
    newp+=2;

    /* ... then turn ? into TAB for search servers, Veronica, etc. ... */
    j = strlen(newp);
    if (j)
      for(i=0; i<j; i++)
        newp[i] = ((newp[i] == '?') ? '\x09' : newp[i]);

    /* ... and finally unescape */
    sel = curl_easy_unescape(data, newp, 0, &len);
    if (!sel)
      return CURLE_OUT_OF_MEMORY;
  }

  result = Curl_sendf(sockfd, conn, "%s\r\n", sel);

  if(result) {
    failf(data, "Failed sending Gopher request");
    return result;
  }
  Curl_setup_transfer(conn, FIRSTSOCKET, -1, FALSE, bytecount,
                      -1, NULL); /* no upload */
  return CURLE_OK;
}
#endif /*CURL_DISABLE_GOPHER*/
