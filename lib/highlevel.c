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
#include "strequal.h"

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

#ifndef HAVE_VPRINTF
#error "We can't compile without vprintf() support!"
#endif
#ifndef HAVE_SELECT
#error "We can't compile without select() support!"
#endif
#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
#endif

#endif

#include "urldata.h"
#include <curl/curl.h>
#include <curl/types.h>
#include "netrc.h"

#include "getenv.h"
#include "hostip.h"
#include "download.h"
#include "sendf.h"
#include "speedcheck.h"
#include "getpass.h"
#include "progress.h"
#include "getdate.h"
#include "writeout.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

CURLcode 
_Transfer(struct connectdata *c_conn)
{
  size_t nread;                 /* number of bytes read */
  int bytecount = 0;            /* total number of bytes read */
  int writebytecount = 0;       /* number of bytes written */
  long contentlength=0;         /* size of incoming data */
  struct timeval start = tvnow();
  struct timeval now = start;   /* current time */
  bool header = TRUE;		/* incoming data has HTTP header */
  int headerline = 0;		/* counts header lines to better track the
                                   first one */
  char *hbufp;			/* points at *end* of header line */
  int hbuflen = 0;
  char *str;			/* within buf */
  char *str_start;		/* within buf */
  char *end_ptr;		/* within buf */
  char *p;			/* within headerbuff */
  bool content_range = FALSE;	/* set TRUE if Content-Range: was found */
  int offset = 0;		/* possible resume offset read from the
                                   Content-Range: header */
  int code = 0;			/* error code from the 'HTTP/1.? XXX' line */

  /* for the low speed checks: */
  CURLcode urg;
  time_t timeofdoc=0;
  long bodywrites=0;

  char newurl[URL_MAX_LENGTH];		/* buffer for Location: URL */

  /* the highest fd we use + 1 */
  struct UrlData *data;
  struct connectdata *conn = (struct connectdata *)c_conn;
  char *buf;
  int maxfd;

  if(!conn || (conn->handle != STRUCT_CONNECT))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  
  data = conn->data; /* there's the root struct */
  buf = data->buffer;
  maxfd = (conn->sockfd>conn->writesockfd?conn->sockfd:conn->writesockfd)+1;

  hbufp = data->headerbuff;

  myalarm (0);			/* switch off the alarm-style timeout */

  now = tvnow();
  start = now;

#define KEEP_READ  1
#define KEEP_WRITE 2

  pgrsTime(data, TIMER_PRETRANSFER);

  if (!conn->getheader) {
    header = FALSE;
    if(conn->size > 0)
      pgrsSetDownloadSize(data, conn->size);
  }
  {
    fd_set readfd;
    fd_set writefd;
    fd_set rkeepfd;
    fd_set wkeepfd;
    struct timeval interval;
    int keepon=0;

    /* timeout every X second
       - makes a better progressmeter (i.e even when no data is read, the
       meter can be updated and reflect reality)
       - allows removal of the alarm() crap
       - variable timeout is easier
     */

    FD_ZERO (&readfd);		/* clear it */
    if(conn->sockfd != -1) {
      FD_SET (conn->sockfd, &readfd); /* read socket */
      keepon |= KEEP_READ;
    }

    FD_ZERO (&writefd);		/* clear it */
    if(conn->writesockfd != -1) {
      FD_SET (conn->writesockfd, &writefd); /* write socket */
      keepon |= KEEP_WRITE;
    }

    /* get these in backup variables to be able to restore them on each lap in
       the select() loop */
    rkeepfd = readfd;
    wkeepfd = writefd;

    while (keepon) {
      readfd = rkeepfd;		/* set those every lap in the loop */
      writefd = wkeepfd;
      interval.tv_sec = 1;
      interval.tv_usec = 0;

      switch (select (maxfd, &readfd, &writefd, NULL, &interval)) {
      case -1:			/* select() error, stop reading */
#ifdef EINTR
        /* The EINTR is not serious, and it seems you might get this more
           ofen when using the lib in a multi-threaded environment! */
        if(errno == EINTR)
          ;
        else
#endif
          keepon = 0; /* no more read or write */
	continue;
      case 0:			/* timeout */
	break;
      default:
        if((keepon & KEEP_READ) && FD_ISSET(conn->sockfd, &readfd)) {
          /* read! */
          urg = curl_read(conn, buf, BUFSIZE -1, &nread);

          /* NULL terminate, allowing string ops to be used */
          if (0 < (signed int) nread)
            buf[nread] = 0;

          /* if we receive 0 or less here, the server closed the connection and
             we bail out from this! */
          else if (0 >= (signed int) nread) {
            keepon &= ~KEEP_READ;
            break;
          }

          str = buf;		/* Default buffer to use when we write the
                                   buffer, it may be changed in the flow below
                                   before the actual storing is done. */

          /* Since this is a two-state thing, we check if we are parsing
             headers at the moment or not. */
          
          if (header) {
            /* we are in parse-the-header-mode */

            /* header line within buffer loop */
            do {
              int hbufp_index;
              
              str_start = str;	/* str_start is start of line within buf */
              
              end_ptr = strchr (str_start, '\n');
              
              if (!end_ptr) {
                /* no more complete header lines within buffer */
                /* copy what is remaining into headerbuff */
                int str_length = (int)strlen(str);
                
                if (hbuflen + (int)str_length >= data->headersize) {
                  char *newbuff;
                  long newsize=MAX((hbuflen+str_length)*3/2,
                                   data->headersize*2);
                  hbufp_index = hbufp - data->headerbuff;
                  newbuff = (char *)realloc(data->headerbuff, newsize);
                  if(!newbuff) {
                    failf (data, "Failed to alloc memory for big header!");
                    return CURLE_READ_ERROR;
                  }
                  data->headersize=newsize;
                  data->headerbuff = newbuff;
                  hbufp = data->headerbuff + hbufp_index;
                }
                strcpy (hbufp, str);
                hbufp += strlen (str);
                hbuflen += strlen (str);
                break;		/* read more and try again */
              }

              str = end_ptr + 1;	/* move just past new line */

              if (hbuflen + (str - str_start) >= data->headersize) {
                char *newbuff;
                long newsize=MAX((hbuflen+(str-str_start))*3/2,
                                 data->headersize*2);
                hbufp_index = hbufp - data->headerbuff;
                newbuff = (char *)realloc(data->headerbuff, newsize);
                if(!newbuff) {
                  failf (data, "Failed to alloc memory for big header!");
                  return CURLE_READ_ERROR;
                }
                data->headersize= newsize;
                data->headerbuff = newbuff;
                hbufp = data->headerbuff + hbufp_index;
              }

              /* copy to end of line */
              strncpy (hbufp, str_start, str - str_start);
              hbufp += str - str_start;
              hbuflen += str - str_start;
              *hbufp = 0;
              
              p = data->headerbuff;
              
              /* we now have a full line that p points to */
              if (('\n' == *p) || ('\r' == *p)) {
                /* Zero-length line means end of header! */
                if (-1 != conn->size)	/* if known */
                  conn->size += bytecount; /* we append the already read size */


                if ('\r' == *p)
                  p++;		/* pass the \r byte */
                if ('\n' == *p)
                  p++;		/* pass the \n byte */

                pgrsSetDownloadSize(data, conn->size);

                header = FALSE;	/* no more header to parse! */

                /* now, only output this if the header AND body are requested:
                 */
                if (data->bits.http_include_header) {
                  if((p - data->headerbuff) !=
                     data->fwrite (data->headerbuff, 1,
                                   p - data->headerbuff, data->out)) {
                    failf (data, "Failed writing output");
                    return CURLE_WRITE_ERROR;
                  }
                }
                if(data->writeheader) {
                  /* obviously, the header is requested to be written to
                     this file: */
                  if((p - data->headerbuff) !=
                     data->fwrite (data->headerbuff, 1, p - data->headerbuff,
                                   data->writeheader)) {
                    failf (data, "Failed writing output");
                    return CURLE_WRITE_ERROR;
                  }
                }
                break;		/* exit header line loop */
              }
              
              if (!headerline++) {
                /* This is the first header, it MUST be the error code line
                   or else we consiser this to be the body right away! */
                if (sscanf (p, " HTTP/1.%*c %3d", &code)) {
                  /* 404 -> URL not found! */
                  if (
                      ( ((data->bits.http_follow_location) && (code >= 400))
                        ||
                        (!data->bits.http_follow_location && (code >= 300)))
                      && (data->bits.http_fail_on_error)) {
                    /* If we have been told to fail hard on HTTP-errors,
                       here is the check for that: */
                    /* serious error, go home! */
                    failf (data, "The requested file was not found");
                    return CURLE_HTTP_NOT_FOUND;
                  }
                  data->progress.httpcode = code;
                }
                else {
                  header = FALSE;	/* this is not a header line */
                  break;
                }
              }
              /* check for Content-Length: header lines to get size */
              if (strnequal("Content-Length", p, 14) &&
                  sscanf (p+14, ": %ld", &contentlength))
                conn->size = contentlength;
              else if (strnequal("Content-Range", p, 13) &&
                       sscanf (p+13, ": bytes %d-", &offset)) {
                if (data->resume_from == offset) {
                  /* we asked for a resume and we got it */
                  content_range = TRUE;
                }
              }
              else if(data->cookies &&
                      strnequal("Set-Cookie: ", p, 11)) {
                cookie_add(data->cookies, TRUE, &p[12]);
              }
              else if(strnequal("Last-Modified:", p,
                                strlen("Last-Modified:")) &&
                      data->timecondition) {
                time_t secs=time(NULL);
                timeofdoc = curl_getdate(p+strlen("Last-Modified:"), &secs);
              }
              else if ((code >= 300 && code < 400) &&
                       (data->bits.http_follow_location) &&
                       strnequal("Location", p, 8) &&
                       sscanf (p+8, ": %" URL_MAX_LENGTH_TXT "s",
                               newurl)) {
                /* this is the URL that the server advices us to get
                   instead */
                data->newurl = strdup (newurl);
              }
              
              if (data->bits.http_include_header) {
                if(hbuflen != data->fwrite (p, 1, hbuflen, data->out)) {
                  failf (data, "Failed writing output");
                  return CURLE_WRITE_ERROR;
                }
              }
              if(data->writeheader) {
                /* the header is requested to be written to this file */
                if(hbuflen != data->fwrite (p, 1, hbuflen,
                                            data->writeheader)) {
                  failf (data, "Failed writing output");
                  return CURLE_WRITE_ERROR;
                }
              }
              
              /* reset hbufp pointer && hbuflen */
              hbufp = data->headerbuff;
              hbuflen = 0;
            }
            while (*str);		/* header line within buffer */

            /* We might have reached the end of the header part here, but
               there might be a non-header part left in the end of the read
               buffer. */

            if (!header) {
              /* the next token and forward is not part of
                 the header! */

              /* we subtract the remaining header size from the buffer */
              nread -= (str - buf);
            }

          }			/* end if header mode */

          /* This is not an 'else if' since it may be a rest from the header
             parsing, where the beginning of the buffer is headers and the end
             is non-headers. */
          if (str && !header && ((signed int)nread > 0)) {
            
            if(0 == bodywrites) {
              /* These checks are only made the first time we are about to
                 write a chunk of the body */
              if(conn->protocol&PROT_HTTP) {
                /* HTTP-only checks */
                if (data->resume_from && !content_range ) {
                  /* we wanted to resume a download, although the server
                     doesn't seem to support this */
                  failf (data, "HTTP server doesn't seem to support byte ranges. Cannot resume.");
                  return CURLE_HTTP_RANGE_ERROR;
                }
                else if (data->newurl) {
                  /* abort after the headers if "follow Location" is set */
                  infof (data, "Follow to new URL: %s\n", data->newurl);
                  return CURLE_OK;
                }
                else if(data->timecondition && !data->range) {
                  /* A time condition has been set AND no ranges have been
                     requested. This seems to be what chapter 13.3.4 of
                     RFC 2616 defines to be the correct action for a
                     HTTP/1.1 client */
                  if((timeofdoc > 0) && (data->timevalue > 0)) {
                    switch(data->timecondition) {
                    case TIMECOND_IFMODSINCE:
                    default:
                      if(timeofdoc < data->timevalue) {
                        infof(data,
                              "The requested document is not new enough");
                        return CURLE_OK;
                      }
                      break;
                    case TIMECOND_IFUNMODSINCE:
                      if(timeofdoc > data->timevalue) {
                        infof(data,
                              "The requested document is not old enough");
                        return CURLE_OK;
                      }
                      break;
                    } /* switch */
                  } /* two valid time strings */
                } /* we have a time condition */
              } /* this is HTTP */
            } /* this is the first time we write a body part */
            bodywrites++;

            if(data->maxdownload &&
               (bytecount + nread > data->maxdownload)) {
              nread = data->maxdownload - bytecount;
              if((signed int)nread < 0 ) /* this should be unusual */
                nread = 0;
              keepon &= ~KEEP_READ; /* we're done reading */
            }

            bytecount += nread;

            pgrsSetDownloadCounter(data, (double)bytecount);
            
            if (nread != data->fwrite (str, 1, nread, data->out)) {
              failf (data, "Failed writing output");
              return CURLE_WRITE_ERROR;
            }

          } /* if (! header and data to read ) */
        } /* if( read from socket ) */

        if((keepon & KEEP_WRITE) && FD_ISSET(conn->writesockfd, &writefd)) {
          /* write */

          char scratch[BUFSIZE * 2];
          int i, si;
          int bytes_written;

          if(data->crlf)
            buf = data->buffer; /* put it back on the buffer */

          nread = data->fread(buf, 1, BUFSIZE, data->in);

          /* the signed int typecase of nread of for systems that has
             unsigned size_t */
          if ((signed int)nread<=0) {
            /* done */
            keepon &= ~KEEP_WRITE; /* we're done writing */
            break;
          }
          writebytecount += nread;
          pgrsSetUploadCounter(data, (double)writebytecount);            

          /* convert LF to CRLF if so asked */
          if (data->crlf) {
            for(i = 0, si = 0; i < (int)nread; i++, si++) {
              if (buf[i] == 0x0a) {
                scratch[si++] = 0x0d;
                scratch[si] = 0x0a;
              }
              else {
                scratch[si] = buf[i];
              }
            }
            nread = si;
            buf = scratch; /* point to the new buffer */
          }

          /* write to socket */
          urg = curl_write(conn, buf, nread, &bytes_written);

          if(nread != bytes_written) {
            failf(data, "Failed uploading data");
            return CURLE_WRITE_ERROR;
          }

        }

        break;
      }

      now = tvnow();
      if(pgrsUpdate(data))
        urg = CURLE_ABORTED_BY_CALLBACK;
      else
        urg = speedcheck (data, now);
      if (urg)
	return urg;

      if (data->timeout && (tvdiff (now, start) > data->timeout)) {
	failf (data, "Operation timed out with %d out of %d bytes received",
	       bytecount, conn->size);
	return CURLE_OPERATION_TIMEOUTED;
      }
    }
  }
  if(!(data->bits.no_body) && contentlength &&
     (bytecount != contentlength)) {
    failf(data, "transfer closed with %d bytes remaining to read",
          contentlength-bytecount);
    return CURLE_PARTIAL_FILE;
  }
  if(pgrsUpdate(data))
    return CURLE_ABORTED_BY_CALLBACK;

  if(conn->bytecountp)
    *conn->bytecountp = bytecount; /* read count */
  if(conn->writebytecountp)
    *conn->writebytecountp = writebytecount; /* write count */

  return CURLE_OK;
}

typedef int (*func_T)(void);

CURLcode curl_transfer(CURL *curl)
{
  CURLcode res;
  struct UrlData *data = curl;
  struct connectdata *c_connect;

  pgrsStartNow(data);

  do {
    res = curl_connect(curl, (CURLconnect **)&c_connect);
    if(res == CURLE_OK) {
      res = curl_do(c_connect);
      if(res == CURLE_OK) {
        res = _Transfer(c_connect); /* now fetch that URL please */
        if(res == CURLE_OK)
          res = curl_done(c_connect);
      }

      if((res == CURLE_OK) && data->newurl) {
        /* Location: redirect */
        char prot[16];
        char path[URL_MAX_LENGTH];

        if(data->bits.http_auto_referer) {
          /* We are asked to automatically set the previous URL as the
             referer when we get the next URL. We pick the ->url field,
             which may or may not be 100% correct */

          if(data->free_referer) {
            /* If we already have an allocated referer, free this first */
            free(data->referer);
          }

          data->referer = strdup(data->url);
          data->free_referer = TRUE; /* yes, free this later */
          data->bits.http_set_referer = TRUE; /* might have been false */
        }

        if(2 != sscanf(data->newurl, "%15[^:]://%" URL_MAX_LENGTH_TXT
                       "s", prot, path)) {
          /***
           *DANG* this is an RFC 2068 violation. The URL is supposed
           to be absolute and this doesn't seem to be that!
           ***
           Instead, we have to TRY to append this new path to the old URL
           to the right of the host part. Oh crap, this is doomed to cause
           problems in the future...
          */
          char *protsep;
          char *pathsep;
          char *newest;

          /* protsep points to the start of the host name */
          protsep=strstr(data->url, "//");
          if(!protsep)
            protsep=data->url;
          else {
            /* TBD: set the port with curl_setopt() */
            data->port=0; /* we got a full URL and then we should reset the
                             port number here to re-initiate it later */
            protsep+=2; /* pass the slashes */
          }

          if('/' != data->newurl[0]) {
            /* First we need to find out if there's a ?-letter in the URL,
               and cut it and the right-side of that off */
            pathsep = strrchr(protsep, '?');
            if(pathsep)
              *pathsep=0;

            /* we have a relative path to append to the last slash if
               there's one available */
            pathsep = strrchr(protsep, '/');
            if(pathsep)
              *pathsep=0;
          }
          else {
            /* We got a new absolute path for this server, cut off from the
               first slash */
            pathsep = strchr(protsep, '/');
            if(pathsep)
              *pathsep=0;
          }

          newest=(char *)malloc( strlen(data->url) +
                                 1 + /* possible slash */
                                 strlen(data->newurl) + 1/* zero byte */);

          if(!newest)
            return CURLE_OUT_OF_MEMORY;
          sprintf(newest, "%s%s%s", data->url, ('/' == data->newurl[0])?"":"/",
                  data->newurl);
          free(data->newurl);
          data->newurl = newest;
        }
        else {
          /* This was an absolute URL, clear the port number! */
          /* TBD: set the port with curl_setopt() */
          data->port = 0;
        }
      
        /* TBD: set the URL with curl_setopt() */
        data->url = data->newurl;
        data->newurl = NULL; /* don't show! */

        /* Disable both types of POSTs, since doing a second POST when
           following isn't what anyone would want! */
        data->bits.http_post = FALSE;
        data->bits.http_formpost = FALSE;

        infof(data, "Follows Location: to new URL: '%s'\n", data->url);

        curl_disconnect(c_connect);
        continue;
      }

      curl_disconnect(c_connect);
    }
    break; /* it only reaches here when this shouldn't loop */

  } while(1); /* loop if Location: */

  if(data->newurl)
    free(data->newurl);

  if((CURLE_OK == res) && data->writeinfo) {
    /* Time to output some info to stdout */
    WriteOut(data);
  }
  return res;
}

