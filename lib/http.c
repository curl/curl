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

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <sys/time.h>

#ifdef HAVE_TIME_H
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#endif

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
#include "transfer.h"
#include "sendf.h"
#include "formdata.h"
#include "progress.h"
#include "base64.h"
#include "cookie.h"
#include "strequal.h"
#include "ssluse.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/* ------------------------------------------------------------------------- */
/*
 * The add_buffer series of functions are used to build one large memory chunk
 * from repeated function invokes. Used so that the entire HTTP request can
 * be sent in one go.
 */
static CURLcode
 add_buffer(send_buffer *in, const void *inptr, size_t size);

/*
 * add_buffer_init() returns a fine buffer struct
 */
static
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
static
size_t add_buffer_send(int sockfd, struct connectdata *conn, send_buffer *in)
{
  size_t amount;
  if(conn->data->set.verbose) {
    fputs("> ", conn->data->set.err);
    /* this data _may_ contain binary stuff */
    fwrite(in->buffer, in->size_used, 1, conn->data->set.err);
  }

  Curl_write(conn, sockfd, in->buffer, in->size_used, &amount);

  if(in->buffer)
    free(in->buffer);
  free(in);

  return amount;
}


/* 
 * add_bufferf() builds a buffer from the formatted input
 */
static
CURLcode add_bufferf(send_buffer *in, const char *fmt, ...)
{
  CURLcode result = CURLE_OUT_OF_MEMORY;
  char *s;
  va_list ap;
  va_start(ap, fmt);
  s = vaprintf(fmt, ap); /* this allocs a new string to append */
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
static
CURLcode add_buffer(send_buffer *in, const void *inptr, size_t size)
{
  char *new_rb;
  int new_size;

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

  return CURLE_OK;
}

/* end of the add_buffer functions */
/* ------------------------------------------------------------------------- */

/*
 * Read everything until a newline.
 */

static
int GetLine(int sockfd, char *ptr, struct connectdata *conn)
{
  ssize_t nread;

  /* get us a full line, terminated with a newline */
  for(nread=0; (nread<BUFSIZE); nread++, ptr++) {
    if((CURLE_OK != Curl_read(conn, sockfd, ptr, 1, &nread)) ||
       (nread <= 0) || (*ptr == '\n'))
      break;
  }
  *ptr=0; /* zero terminate */
  
  return nread>0?nread:0;
}



/*
 * This function checks the linked list of custom HTTP headers for a particular
 * header (prefix).
 */
static bool checkheaders(struct SessionHandle *data, const char *thisheader)
{
  struct curl_slist *head;
  size_t thislen = strlen(thisheader);

  for(head = data->set.headers; head; head=head->next) {
    if(strnequal(head->data, thisheader, thislen)) {
      return TRUE;
    }
  }
  return FALSE;
}

/*
 * ConnectHTTPProxyTunnel() requires that we're connected to a HTTP proxy. This
 * function will issue the necessary commands to get a seamless tunnel through
 * this proxy. After that, the socket can be used just as a normal socket.
 */

CURLcode Curl_ConnectHTTPProxyTunnel(struct connectdata *conn,
                                     int tunnelsocket,
                                     char *hostname, int remote_port)
{
  int httperror=0;
  int subversion=0;
  struct SessionHandle *data=conn->data;

  infof(data, "Establish HTTP proxy tunnel to %s:%d\n", hostname, remote_port);

  /* OK, now send the connect request to the proxy */
  Curl_sendf(tunnelsocket, conn,
             "CONNECT %s:%d HTTP/1.0\015\012"
             "%s"
             "%s"
             "\r\n",
             hostname, remote_port,
             (conn->bits.proxy_user_passwd)?conn->allocptr.proxyuserpwd:"",
             (data->set.useragent?conn->allocptr.uagent:"")
             );

  /* wait for the proxy to send us a HTTP/1.0 200 OK header */
  while(GetLine(tunnelsocket, data->state.buffer, conn)) {
    if('\r' == data->state.buffer[0])
      break; /* end of headers */
    if(data->set.verbose)
      fprintf(data->set.err, "< %s\n", data->state.buffer);

    if(2 == sscanf(data->state.buffer, "HTTP/1.%d %d",
                   &subversion,
                   &httperror)) {
      ;
    }
  }
  if(200 != httperror) {
    if(407 == httperror)
      /* Added Nov 6 1998 */
      failf(data, "Proxy requires authorization!");
    else 
      failf(data, "Received error code %d from proxy", httperror);
    return CURLE_READ_ERROR;
  }

  infof (data, "Proxy replied to CONNECT request\n");
  return CURLE_OK;
}

/*
 * HTTP stuff to do at connect-time.
 */
CURLcode Curl_http_connect(struct connectdata *conn)
{
  struct SessionHandle *data;
  CURLcode result;

  data=conn->data;

  /* If we are not using a proxy and we want a secure connection,
   * perform SSL initialization & connection now.
   * If using a proxy with https, then we must tell the proxy to CONNECT
   * us to the host we want to talk to.  Only after the connect
   * has occured, can we start talking SSL
   */
  if (conn->protocol & PROT_HTTPS) {
    if (data->change.proxy) {
      /* HTTPS through a proxy can only be done with a tunnel */
      result = Curl_ConnectHTTPProxyTunnel(conn, conn->firstsocket,
                                           conn->hostname, conn->remote_port);
      if(CURLE_OK != result)
        return result;
    }

    /* now, perform the SSL initialization for this socket */
    result = Curl_SSLConnect(conn);
    if(result)
      return result;
  }

  if(conn->bits.user_passwd && !data->state.this_is_a_follow) {
    /* Authorization: is requested, this is not a followed location, get the
       original host name */
    data->state.auth_host = strdup(conn->hostname);
  }

  return CURLE_OK;
}

CURLcode Curl_http_done(struct connectdata *conn)
{
  struct SessionHandle *data;
  long *bytecount = &conn->bytecount;
  struct HTTP *http;

  data=conn->data;
  http=conn->proto.http;

  if(HTTPREQ_POST_FORM == data->set.httpreq) {
    *bytecount = http->readbytecount + http->writebytecount;
      
    Curl_formclean(http->sendit); /* Now free that whole lot */

    data->set.fread = http->storefread; /* restore */
    data->set.in = http->in; /* restore */
  }
  else if(HTTPREQ_PUT == data->set.httpreq) {
    *bytecount = http->readbytecount + http->writebytecount;
  }

  if(0 == (http->readbytecount + conn->headerbytecount)) {
    /* nothing was read from the HTTP server, this can't be right
       so we return an error here */
    failf(data, "Empty reply from server\n");
    return CURLE_GOT_NOTHING;
  }

  return CURLE_OK;
}


CURLcode Curl_http(struct connectdata *conn)
{
  struct SessionHandle *data=conn->data;
  char *buf = data->state.buffer; /* this is a short cut to the buffer */
  CURLcode result=CURLE_OK;
  struct HTTP *http;
  struct Cookie *co=NULL; /* no cookies from start */
  char *ppath = conn->ppath; /* three previous function arguments */
  char *host = conn->name;
  long *bytecount = &conn->bytecount;

  if(!conn->proto.http) {
    /* Only allocate this struct if we don't already have it! */

    http = (struct HTTP *)malloc(sizeof(struct HTTP));
    if(!http)
      return CURLE_OUT_OF_MEMORY;
    memset(http, 0, sizeof(struct HTTP));
    conn->proto.http = http;
  }
  else
    http = conn->proto.http;

  /* We default to persistant connections */
  conn->bits.close = FALSE;

  if ( (conn->protocol&(PROT_HTTP|PROT_FTP)) &&
       data->set.upload) {
    data->set.httpreq = HTTPREQ_PUT;
  }
  
  /* The User-Agent string has been built in url.c already, because it might
     have been used in the proxy connect, but if we have got a header with
     the user-agent string specified, we erase the previously made string
     here. */
  if(checkheaders(data, "User-Agent:") && conn->allocptr.uagent) {
    free(conn->allocptr.uagent);
    conn->allocptr.uagent=NULL;
  }

  if((conn->bits.user_passwd) && !checkheaders(data, "Authorization:")) {
    char *authorization;

    /* To prevent the user+password to get sent to other than the original
       host due to a location-follow, we do some weirdo checks here */
    if(!data->state.this_is_a_follow ||
       !data->state.auth_host ||
       strequal(data->state.auth_host, conn->hostname)) {
      sprintf(data->state.buffer, "%s:%s",
              data->state.user, data->state.passwd);
      if(Curl_base64_encode(data->state.buffer, strlen(data->state.buffer),
                            &authorization) >= 0) {
        if(conn->allocptr.userpwd)
          free(conn->allocptr.userpwd);
        conn->allocptr.userpwd = aprintf( "Authorization: Basic %s\015\012",
                                          authorization);
        free(authorization);
      }
    }
  }
  if((data->change.referer) && !checkheaders(data, "Referer:")) {
    if(conn->allocptr.ref)
      free(conn->allocptr.ref);
    conn->allocptr.ref = aprintf("Referer: %s\015\012", data->change.referer);
  }
  if(data->set.cookie && !checkheaders(data, "Cookie:")) {
    if(conn->allocptr.cookie)
      free(conn->allocptr.cookie);
    conn->allocptr.cookie = aprintf("Cookie: %s\015\012", data->set.cookie);
  }

  if(data->cookies) {
    co = Curl_cookie_getlist(data->cookies,
                             host, ppath,
                             conn->protocol&PROT_HTTPS?TRUE:FALSE);
  }
  if ((data->change.proxy) && !(conn->protocol&PROT_HTTPS))  {
    /* The path sent to the proxy is in fact the entire URL */
    ppath = data->change.url;
  }
  if(HTTPREQ_POST_FORM == data->set.httpreq) {
    /* we must build the whole darned post sequence first, so that we have
       a size of the whole shebang before we start to send it */
    http->sendit = Curl_getFormData(data->set.httppost, &http->postsize);
  }

  if(!checkheaders(data, "Host:")) {
    /* if ptr_host is already set, it is almost OK since we only re-use
       connections to the very same host and port, but when we use a HTTP
       proxy we have a persistant connect and yet we must change the Host:
       header! */

    if(conn->allocptr.host)
      free(conn->allocptr.host);

    if(((conn->protocol&PROT_HTTPS) && (conn->remote_port == PORT_HTTPS)) ||
       (!(conn->protocol&PROT_HTTPS) && (conn->remote_port == PORT_HTTP)) )
      /* If (HTTPS on port 443) OR (non-HTTPS on port 80) then don't include
         the port number in the host string */
      conn->allocptr.host = aprintf("Host: %s\r\n", host);
    else
      conn->allocptr.host = aprintf("Host: %s:%d\r\n", host,
                                    conn->remote_port);
  }

  if(!checkheaders(data, "Pragma:"))
    http->p_pragma = "Pragma: no-cache\r\n";

  if(!checkheaders(data, "Accept:"))
    http->p_accept = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*\r\n";

  if(( (HTTPREQ_POST == data->set.httpreq) ||
       (HTTPREQ_POST_FORM == data->set.httpreq) ||
       (HTTPREQ_PUT == data->set.httpreq) ) &&
     conn->resume_from) {
    /**********************************************************************
     * Resuming upload in HTTP means that we PUT or POST and that we have
     * got a resume_from value set. The resume value has already created
     * a Range: header that will be passed along. We need to "fast forward"
     * the file the given number of bytes and decrease the assume upload
     * file size before we continue this venture in the dark lands of HTTP.
     *********************************************************************/
   
    if(conn->resume_from < 0 ) {
      /*
       * This is meant to get the size of the present remote-file by itself.
       * We don't support this now. Bail out!
       */
       conn->resume_from = 0;
    }

    if(conn->resume_from) {
      /* do we still game? */
      int passed=0;

      /* Now, let's read off the proper amount of bytes from the
         input. If we knew it was a proper file we could've just
         fseek()ed but we only have a stream here */
      do {
        int readthisamountnow = (conn->resume_from - passed);
        int actuallyread;

        if(readthisamountnow > BUFSIZE)
          readthisamountnow = BUFSIZE;

        actuallyread =
          data->set.fread(data->state.buffer, 1, readthisamountnow,
                          data->set.in);

        passed += actuallyread;
        if(actuallyread != readthisamountnow) {
          failf(data, "Could only read %d bytes from the input\n",
                passed);
          return CURLE_READ_ERROR;
        }
      } while(passed != conn->resume_from); /* loop until done */

      /* now, decrease the size of the read */
      if(data->set.infilesize>0) {
        data->set.infilesize -= conn->resume_from;

        if(data->set.infilesize <= 0) {
          failf(data, "File already completely uploaded\n");
          return CURLE_PARTIAL_FILE;
        }
      }
      /* we've passed, proceed as normal */
    }
  }
  if(conn->bits.use_range) {
    /*
     * A range is selected. We use different headers whether we're downloading
     * or uploading and we always let customized headers override our internal
     * ones if any such are specified.
     */
    if((data->set.httpreq == HTTPREQ_GET) &&
       !checkheaders(data, "Range:")) {
      conn->allocptr.rangeline = aprintf("Range: bytes=%s\r\n", conn->range);
    }
    else if((data->set.httpreq != HTTPREQ_GET) &&
            !checkheaders(data, "Content-Range:")) {

      if(conn->resume_from) {
        /* This is because "resume" was selected */
        long total_expected_size= conn->resume_from + data->set.infilesize;
        conn->allocptr.rangeline = aprintf("Content-Range: bytes %s%ld/%ld\r\n",
                                      conn->range, total_expected_size-1,
                                      total_expected_size);
      }
      else {
        /* Range was selected and then we just pass the incoming range and 
           append total size */
        conn->allocptr.rangeline = aprintf("Content-Range: bytes %s/%d\r\n",
                                      conn->range, data->set.infilesize);
      }
    }
  }

  do {
    /* Use 1.1 unless the use specificly asked for 1.0 */
    const char *httpstring=
      data->set.httpversion==CURL_HTTP_VERSION_1_0?"1.0":"1.1";

    send_buffer *req_buffer;
    struct curl_slist *headers=data->set.headers;

    /* initialize a dynamic send-buffer */
    req_buffer = add_buffer_init();

    /* add the main request stuff */
    add_bufferf(req_buffer,
                "%s " /* GET/HEAD/POST/PUT */
                "%s HTTP/%s\r\n" /* path */
                "%s" /* proxyuserpwd */
                "%s" /* userpwd */
                "%s" /* range */
                "%s" /* user agent */
                "%s" /* cookie */
                "%s" /* host */
                "%s" /* pragma */
                "%s" /* accept */
                "%s", /* referer */

                data->set.customrequest?data->set.customrequest:
                (data->set.no_body?"HEAD":
                 ((HTTPREQ_POST == data->set.httpreq) ||
                  (HTTPREQ_POST_FORM == data->set.httpreq))?"POST":
                 (HTTPREQ_PUT == data->set.httpreq)?"PUT":"GET"),
                ppath, httpstring,
                (conn->bits.proxy_user_passwd &&
                 conn->allocptr.proxyuserpwd)?conn->allocptr.proxyuserpwd:"",
                (conn->bits.user_passwd && conn->allocptr.userpwd)?
                conn->allocptr.userpwd:"",
                (conn->bits.use_range && conn->allocptr.rangeline)?
                conn->allocptr.rangeline:"",
                (data->set.useragent && *data->set.useragent && conn->allocptr.uagent)?
                conn->allocptr.uagent:"",
                (conn->allocptr.cookie?conn->allocptr.cookie:""), /* Cookie: <data> */
                (conn->allocptr.host?conn->allocptr.host:""), /* Host: host */
                http->p_pragma?http->p_pragma:"",
                http->p_accept?http->p_accept:"",
                (data->change.referer && conn->allocptr.ref)?conn->allocptr.ref:"" /* Referer: <data> <CRLF> */
                );

    if(co) {
      int count=0;
      struct Cookie *store=co;
      /* now loop through all cookies that matched */
      while(co) {
        if(co->value && strlen(co->value)) {
          if(0 == count) {
            add_bufferf(req_buffer, "Cookie: ");
          }
          add_bufferf(req_buffer,
                      "%s%s=%s", count?"; ":"", co->name, co->value);
          count++;
        }
        co = co->next; /* next cookie please */
      }
      if(count) {
        add_buffer(req_buffer, "\r\n", 2);
      }
      Curl_cookie_freelist(store); /* free the cookie list */
      co=NULL;
    }

    if(data->set.timecondition) {
      struct tm *thistime;

      /* Phil Karn (Fri, 13 Apr 2001) pointed out that the If-Modified-Since
       * header family should have their times set in GMT as RFC2616 defines:
       * "All HTTP date/time stamps MUST be represented in Greenwich Mean Time
       * (GMT), without exception. For the purposes of HTTP, GMT is exactly
       * equal to UTC (Coordinated Universal Time)." (see page 20 of RFC2616).
       */

#ifdef HAVE_LOCALTIME_R
      /* thread-safe version */
      /* We assume that the presense of localtime_r() proves the presense
         of gmtime_r() which is a bit ugly but might work */
      struct tm keeptime;
      thistime = (struct tm *)gmtime_r(&data->set.timevalue, &keeptime);
#else
      thistime = gmtime(&data->set.timevalue);
#endif
      if(NULL == thistime) {
        failf(data, "localtime() failed!");
        return CURLE_OUT_OF_MEMORY;
      }

#ifdef HAVE_STRFTIME
      /* format: "Tue, 15 Nov 1994 12:45:26 GMT" */
      strftime(buf, BUFSIZE-1, "%a, %d %b %Y %H:%M:%S %Z", thistime);
#else
      /* TODO: Right, we *could* write a replacement here */
      strcpy(buf, "no strftime() support");
#endif
      switch(data->set.timecondition) {
      case TIMECOND_IFMODSINCE:
      default:
        add_bufferf(req_buffer,
                    "If-Modified-Since: %s\r\n", buf);
        break;
      case TIMECOND_IFUNMODSINCE:
        add_bufferf(req_buffer,
                    "If-Unmodified-Since: %s\r\n", buf);
        break;
      case TIMECOND_LASTMOD:
        add_bufferf(req_buffer,
                    "Last-Modified: %s\r\n", buf);
        break;
      }
    }

    while(headers) {
      char *ptr = strchr(headers->data, ':');
      if(ptr) {
        /* we require a colon for this to be a true header */

        ptr++; /* pass the colon */
        while(*ptr && isspace((int)*ptr))
          ptr++;

        if(*ptr) {
          /* only send this if the contents was non-blank */

          add_bufferf(req_buffer, "%s\r\n", headers->data);
        }
      }
      headers = headers->next;
    }

    if(HTTPREQ_POST_FORM == data->set.httpreq) {
      char contentType[256];
      int linelength=0;
      if(Curl_FormInit(&http->form, http->sendit)) {
        failf(data, "Internal HTTP POST error!\n");
        return CURLE_HTTP_POST_ERROR;
      }

      http->storefread = data->set.fread; /* backup */
      http->in = data->set.in; /* backup */
          
      data->set.fread = (curl_read_callback)
        Curl_FormReader; /* set the read function to read from the
                            generated form data */
      data->set.in = (FILE *)&http->form;

      add_bufferf(req_buffer,
                  "Content-Length: %d\r\n", http->postsize-2);

      if(!checkheaders(data, "Expect:")) {
        /* if not disabled explicitly we add a Expect: 100-continue
           to the headers which actually speeds up post operations (as
           there is one packet coming back from the web server) */
        add_bufferf(req_buffer,
                    "Expect: 100-continue\r\n");
        data->set.expect100header = TRUE;

        /* Get Content-Type: line from Curl_FormReadOneLine, which happens
           to always be the first line. We can know this for sure since
           we always build the formpost linked list the same way! */
        linelength = Curl_FormReadOneLine (contentType,
                                           sizeof(contentType),
                                           1,
                                           (FILE *)&http->form);
        if(linelength == -1) {
          failf(data, "Could not get Content-Type header line!\n");
          return CURLE_HTTP_POST_ERROR;
        }
        add_buffer(req_buffer, contentType, linelength);
      }

      /* set upload size to the progress meter */
      Curl_pgrsSetUploadSize(data, http->postsize);

      /* fire away the whole request to the server */
      data->info.request_size = 
        add_buffer_send(conn->firstsocket, conn, req_buffer);

      /* setup variables for the upcoming transfer */
      result = Curl_Transfer(conn, conn->firstsocket, -1, TRUE,
                             &http->readbytecount,
                             conn->firstsocket,
                             &http->writebytecount);
      if(result) {
        Curl_formclean(http->sendit); /* free that whole lot */
        return result;
      }
    }
    else if(HTTPREQ_PUT == data->set.httpreq) {
      /* Let's PUT the data to the server! */

      if(data->set.infilesize>0) {
        add_bufferf(req_buffer,
                    "Content-Length: %d\r\n\r\n", /* file size */
                    data->set.infilesize );
      }
      else
        add_bufferf(req_buffer, "\015\012");

      /* set the upload size to the progress meter */
      Curl_pgrsSetUploadSize(data, data->set.infilesize);

      /* this sends the buffer and frees all the buffer resources */
      data->info.request_size = 
        add_buffer_send(conn->firstsocket, conn, req_buffer);

      /* prepare for transfer */
      result = Curl_Transfer(conn, conn->firstsocket, -1, TRUE,
                        &http->readbytecount,
                        conn->firstsocket,
                        &http->writebytecount);
      if(result)
        return result;
      
    }
    else {
      if(HTTPREQ_POST == data->set.httpreq) {
        /* this is the simple POST, using x-www-form-urlencoded style */

        if(!data->set.postfields) {
          /*
           * This is an attempt to do a POST without having anything to
           * actually send. Let's make a NULL pointer equal "" here. Good/bad
           * ?
           */
          data->set.postfields = (char *)"";
          data->set.postfieldsize = 0; /* it might been set to something illegal,
                                      anything > 0 would be! */
        }

        if(!checkheaders(data, "Content-Length:"))
          /* we allow replacing this header, although it isn't very wise to
             actually set your own */
          add_bufferf(req_buffer,
                      "Content-Length: %d\r\n",
                      (data->set.postfieldsize?data->set.postfieldsize:
                       strlen(data->set.postfields)) );

        if(!checkheaders(data, "Content-Type:"))
          add_bufferf(req_buffer,
                      "Content-Type: application/x-www-form-urlencoded\r\n");

        /* and here comes the actual data */
        if(data->set.postfieldsize) {
          add_buffer(req_buffer, "\r\n", 2);
          add_buffer(req_buffer, data->set.postfields,
                     data->set.postfieldsize);
          add_buffer(req_buffer, "\r\n", 2);
        }
        else {
          add_bufferf(req_buffer,
                      "\r\n"
                      "%s\r\n",
                      data->set.postfields );
        }
      }
      else
        add_buffer(req_buffer, "\r\n", 2);

      /* issue the request */
      data->info.request_size = 
        add_buffer_send(conn->firstsocket, conn, req_buffer);

      /* HTTP GET/HEAD download: */
      result = Curl_Transfer(conn, conn->firstsocket, -1, TRUE, bytecount,
                        -1, NULL); /* nothing to upload */
    }
    if(result)
      return result;
  } while (0); /* this is just a left-over from the multiple document download
                  attempts */

  return CURLE_OK;
}


/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
