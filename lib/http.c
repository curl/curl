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
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
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

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#include "setup.h"

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>
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
#include <sys/ioctl.h>
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif


#endif

#include "urldata.h"
#include <curl/curl.h>
#include "download.h"
#include "sendf.h"
#include "formdata.h"
#include "progress.h"
#include "base64.h"
#include "cookie.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/*
 * This function checks the linked list of custom HTTP headers for a particular
 * header (prefix).
 */
bool static checkheaders(struct UrlData *data, char *thisheader)
{
  struct HttpHeader *head;
  size_t thislen = strlen(thisheader);

  for(head = data->headers; head; head=head->next) {
    if(strnequal(head->header, thisheader, thislen)) {
      return TRUE;
    }
  }
  return FALSE;
}

UrgError http(struct UrlData *data, char *ppath, char *host, long *bytecount)
{
  /* Send the GET line to the HTTP server */

  struct FormData *sendit=NULL;
  int postsize=0;
  UrgError result;
  char *buf;
  struct Cookie *co = NULL;
  char *p_pragma = NULL;
  char *p_accept = NULL;
  long readbytecount;
  long writebytecount;

  buf = data->buffer; /* this is our buffer */

  if ( (data->conf&(CONF_HTTP|CONF_FTP)) &&
       (data->conf&CONF_UPLOAD)) {
    data->conf |= CONF_PUT;
  }
#if 0 /* old version */
  if((data->conf&(CONF_HTTP|CONF_UPLOAD)) ==
     (CONF_HTTP|CONF_UPLOAD)) {
    /* enable PUT! */
    data->conf |= CONF_PUT;
  }
#endif
  
  /* The User-Agent string has been built in url.c already, because it might
     have been used in the proxy connect, but if we have got a header with
     the user-agent string specified, we erase the previously made string
     here. */
  if(checkheaders(data, "User-Agent:") && data->ptr_uagent) {
    free(data->ptr_uagent);
    data->ptr_uagent=NULL;
  }

  if((data->conf & CONF_USERPWD) && !checkheaders(data, "Authorization:")) {
    char authorization[512];
    sprintf(data->buffer, "%s:%s", data->user, data->passwd);
    base64Encode(data->buffer, authorization);
    data->ptr_userpwd = maprintf( "Authorization: Basic %s\015\012",
                                  authorization);
  }
  if((data->conf & CONF_RANGE) && !checkheaders(data, "Range:")) {
    data->ptr_rangeline = maprintf("Range: bytes=%s\015\012", data->range);
  }
  if((data->conf & CONF_REFERER) && !checkheaders(data, "Referer:")) {
    data->ptr_ref = maprintf("Referer: %s\015\012", data->referer);
  }
  if(data->cookie && !checkheaders(data, "Cookie:")) {
    data->ptr_cookie = maprintf("Cookie: %s\015\012", data->cookie);
  }

  if(data->cookies) {
    co = cookie_getlist(data->cookies,
                        host,
                        ppath,
                        data->conf&CONF_HTTPS?TRUE:FALSE);
  }
  if ((data->conf & CONF_PROXY) && (!(data->conf & CONF_HTTPS)))  {
    /* The path sent to the proxy is in fact the entire URL */
    strncpy(ppath, data->url, URL_MAX_LENGTH-1);
  }
  if(data->conf & CONF_HTTPPOST) {
    /* we must build the whole darned post sequence first, so that we have
       a size of the whole shebang before we start to send it */
    sendit = getFormData(data->httppost, &postsize);
  }

  if(!checkheaders(data, "Host:"))
    data->ptr_host = maprintf("Host: %s\r\n", host);


  if(!checkheaders(data, "Pragma:"))
    p_pragma = "Pragma: no-cache\r\n";

  if(!checkheaders(data, "Accept:"))
    p_accept = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*\r\n";

  do {
    sendf(data->firstsocket, data,
          "%s " /* GET/HEAD/POST/PUT */
          "%s HTTP/1.0\r\n" /* path */
          "%s" /* proxyuserpwd */
          "%s" /* userpwd */
          "%s" /* range */
          "%s" /* user agent */
          "%s" /* cookie */
          "%s" /* host */
          "%s" /* pragma */
          "%s" /* accept */
          "%s", /* referer */

          data->customrequest?data->customrequest:
          (data->conf&CONF_NOBODY?"HEAD":
           (data->conf&(CONF_POST|CONF_HTTPPOST))?"POST":
           (data->conf&CONF_PUT)?"PUT":"GET"),
          ppath,
          (data->conf&CONF_PROXYUSERPWD && data->ptr_proxyuserpwd)?data->ptr_proxyuserpwd:"",
          (data->conf&CONF_USERPWD && data->ptr_userpwd)?data->ptr_userpwd:"",
          (data->conf&CONF_RANGE && data->ptr_rangeline)?data->ptr_rangeline:"",
          (data->useragent && *data->useragent && data->ptr_uagent)?data->ptr_uagent:"",
          (data->ptr_cookie?data->ptr_cookie:""), /* Cookie: <data> */
          (data->ptr_host?data->ptr_host:""), /* Host: host */
          p_pragma?p_pragma:"",
          p_accept?p_accept:"",
          (data->conf&CONF_REFERER && data->ptr_ref)?data->ptr_ref:"" /* Referer: <data> <CRLF> */
          );

    if(co) {
      int count=0;
      /* now loop through all cookies that matched */
      while(co) {
        if(co->value && strlen(co->value)) {
          if(0 == count) {
            sendf(data->firstsocket, data,
                  "Cookie:");
          }
          count++;
          sendf(data->firstsocket, data,
                " %s=%s;", co->name, co->value);
        }
        co = co->next; /* next cookie please */
      }
      if(count) {
        sendf(data->firstsocket, data,
              "\r\n");
      }
      cookie_freelist(co); /* free the cookie list */
      co=NULL;
    }

    if(data->timecondition) {
      struct tm *thistime;

      thistime = localtime(&data->timevalue);

#if defined(HAVE_STRFTIME) || defined(WIN32)
      /* format: "Tue, 15 Nov 1994 12:45:26 GMT" */
      strftime(buf, BUFSIZE-1, "%a, %d %b %Y %H:%M:%S %Z", thistime);
#else
      /* TODO: Right, we *could* write a replacement here */
      strcpy(buf, "no strftime() support");
#endif
      switch(data->timecondition) {
      case TIMECOND_IFMODSINCE:
      default:
        sendf(data->firstsocket, data,
              "If-Modified-Since: %s\r\n", buf);
        break;
      case TIMECOND_IFUNMODSINCE:
        sendf(data->firstsocket, data,
              "If-Unmodified-Since: %s\r\n", buf);
        break;
      case TIMECOND_LASTMOD:
        sendf(data->firstsocket, data,
              "Last-Modified: %s\r\n", buf);
        break;
      }
    }

    while(data->headers) {
      sendf(data->firstsocket, data,
            "%s\015\012",
            data->headers->header);
      data->headers = data->headers->next;
    }

    if(data->conf&(CONF_POST|CONF_HTTPPOST)) {
      if(data->conf & CONF_POST) {
        /* this is the simple x-www-form-urlencoded style */
        sendf(data->firstsocket, data,
              "Content-Length: %d\015\012"
              "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
              "%s\015\012",
              strlen(data->postfields),
              data->postfields );
      }
      else {
        struct Form form;
        size_t (*storefread)(char *, size_t , size_t , FILE *);
        FILE *in;
        long conf;

        if(FormInit(&form, sendit)) {
          failf(data, "Internal HTTP POST error!\n");
          return URG_HTTP_POST_ERROR;
        }

        storefread = data->fread; /* backup */
        in = data->in; /* backup */
          
        data->fread =
          (size_t (*)(char *, size_t, size_t, FILE *))
          FormReader; /* set the read function to read from the
                         generated form data */
        data->in = (FILE *)&form;

        sendf(data->firstsocket, data,
              "Content-Length: %d\r\n",
              postsize-2);

	pgrsSetUploadSize(data, postsize);
#if 0
        ProgressInit(data, postsize);
#endif

        result = Transfer(data, data->firstsocket, -1, TRUE, &readbytecount,
                          data->firstsocket, &writebytecount);
        *bytecount = readbytecount + writebytecount;

        FormFree(sendit); /* Now free that whole lot */

        if(result)
          return result;
	
        data->fread = storefread; /* restore */
        data->in = in; /* restore */

	sendf(data->firstsocket, data,
	      "\r\n\r\n");
      }
    }
    else if(data->conf&CONF_PUT) {
      /* Let's PUT the data to the server! */
      long conf;

      if(data->infilesize>0) {
        sendf(data->firstsocket, data,
              "Content-Length: %d\r\n\r\n", /* file size */
              data->infilesize );
      }
      else
        sendf(data->firstsocket, data,
              "\015\012");

#if 0        
      ProgressInit(data, data->infilesize);
#endif
      pgrsSetUploadSize(data, data->infilesize);

      result = Transfer(data, data->firstsocket, -1, TRUE, &readbytecount,
                        data->firstsocket, &writebytecount);
      
      *bytecount = readbytecount + writebytecount;

      if(result)
        return result;

    }
    else {
      sendf(data->firstsocket, data, "\r\n");
    }
    if(0 == *bytecount) {
      /* HTTP GET/HEAD download: */
      result = Transfer(data, data->firstsocket, -1, TRUE, bytecount,
                        -1, NULL); /* nothing to upload */
    }
    if(result)
      return result;

#if 0      
    ProgressEnd(data);
#endif
    pgrsDone(data);

  } while (0); /* this is just a left-over from the multiple document download
                  attempts */

  return URG_OK;
}

