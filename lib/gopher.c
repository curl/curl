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

#include "setup.h"

#ifndef CURL_DISABLE_GOPHER

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"

#include "progress.h"
#include "strequal.h"
#include "gopher.h"
#include "rawstr.h"
#include "select.h"
#include "url.h"
#include "warnless.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
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
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_GOPHER,                          /* defport */
  CURLPROTO_GOPHER,                     /* protocol */
  PROTOPT_NONE                          /* flags */
};

static CURLcode gopher_do(struct connectdata *conn, bool *done)
{
  CURLcode result=CURLE_OK;
  struct SessionHandle *data=conn->data;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];

  curl_off_t *bytecount = &data->req.bytecount;
  char *path = data->state.path;
  char *sel;
  char *sel_org = NULL;
  ssize_t amount, k;

  *done = TRUE; /* unconditionally */

  /* Create selector. Degenerate cases: / and /1 => convert to "" */
  if(strlen(path) <= 2)
    sel = (char *)"";
  else {
    char *newp;
    size_t j, i;
    int len;

    /* Otherwise, drop / and the first character (i.e., item type) ... */
    newp = path;
    newp+=2;

    /* ... then turn ? into TAB for search servers, Veronica, etc. ... */
    j = strlen(newp);
    for(i=0; i<j; i++)
      if(newp[i] == '?')
        newp[i] = '\x09';

    /* ... and finally unescape */
    sel = curl_easy_unescape(data, newp, 0, &len);
    if(!sel)
      return CURLE_OUT_OF_MEMORY;
    sel_org = sel;
  }

  /* We use Curl_write instead of Curl_sendf to make sure the entire buffer is
     sent, which could be sizeable with long selectors. */
  k = curlx_uztosz(strlen(sel));

  for(;;) {
    result = Curl_write(conn, sockfd, sel, k, &amount);
    if(CURLE_OK == result) { /* Which may not have written it all! */
      result = Curl_client_write(conn, CLIENTWRITE_HEADER, sel, amount);
      if(result) {
        Curl_safefree(sel_org);
        return result;
      }
      k -= amount;
      sel += amount;
      if(k < 1)
        break; /* but it did write it all */
    }
    else {
      failf(data, "Failed sending Gopher request");
      Curl_safefree(sel_org);
      return result;
    }
    /* Don't busyloop. The entire loop thing is a work-around as it causes a
       BLOCKING behavior which is a NO-NO. This function should rather be
       split up in a do and a doing piece where the pieces that aren't
       possible to send now will be sent in the doing function repeatedly
       until the entire request is sent.

       Wait a while for the socket to be writable. Note that this doesn't
       acknowledge the timeout.
    */
    Curl_socket_ready(CURL_SOCKET_BAD, sockfd, 100);
  }

  Curl_safefree(sel_org);

  /* We can use Curl_sendf to send the terminal \r\n relatively safely and
     save allocing another string/doing another _write loop. */
  result = Curl_sendf(sockfd, conn, "\r\n");
  if(result != CURLE_OK) {
    failf(data, "Failed sending Gopher request");
    return result;
  }
  result = Curl_client_write(conn, CLIENTWRITE_HEADER, (char *)"\r\n", 2);
  if(result)
    return result;

  Curl_setup_transfer(conn, FIRSTSOCKET, -1, FALSE, bytecount,
                      -1, NULL); /* no upload */
  return CURLE_OK;
}
#endif /*CURL_DISABLE_GOPHER*/
