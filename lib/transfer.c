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

#include "hostip.h"
#include "transfer.h"
#include "sendf.h"
#include "speedcheck.h"
#include "getpass.h"
#include "progress.h"
#include "getdate.h"
#include "http.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

#ifndef min
#define min(a, b)   ((a) < (b) ? (a) : (b))
#endif

/* Parts of this function was written by the friendly Mark Butler
   <butlerm@xmission.com>. */

CURLcode static
Transfer(struct connectdata *c_conn)
{
  ssize_t nread;                /* number of bytes read */
  int bytecount = 0;            /* total number of bytes read */
  int writebytecount = 0;       /* number of bytes written */
  long contentlength=0;         /* size of incoming data */
  struct timeval start = Curl_tvnow();
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
  int httpcode = 0;		/* error code from the 'HTTP/1.? XXX' line */
  int httpversion = -1;         /* the last digit in the HTTP/1.1 string */

  /* for the low speed checks: */
  CURLcode urg;
  time_t timeofdoc=0;
  long bodywrites=0;
  int writetype;

  /* the highest fd we use + 1 */
  struct UrlData *data;
  struct connectdata *conn = (struct connectdata *)c_conn;
  char *buf;
  int maxfd;

  data = conn->data; /* there's the root struct */
  buf = data->buffer;
  maxfd = (conn->sockfd>conn->writesockfd?conn->sockfd:conn->writesockfd)+1;

  hbufp = data->headerbuff;

  myalarm (0);			/* switch off the alarm-style timeout */

  now = Curl_tvnow();
  start = now;

#define KEEP_READ  1
#define KEEP_WRITE 2

  Curl_pgrsTime(data, TIMER_PRETRANSFER);
  Curl_speedinit(data);

  if((conn->sockfd == -1) &&
     (conn->writesockfd == -1)) {
    /* nothing to read, nothing to write, we're already OK! */
    return CURLE_OK;
  }

  if (!conn->getheader) {
    header = FALSE;
    if(conn->size > 0)
      Curl_pgrsSetDownloadSize(data, conn->size);
  }
  /* we want header and/or body, if neither then don't do this! */
  if(conn->getheader ||
     !data->bits.no_body) {
    fd_set readfd;
    fd_set writefd;
    fd_set rkeepfd;
    fd_set wkeepfd;
    struct timeval interval;
    int keepon=0;

    /* timeout every X second
       - makes a better progress meter (i.e even when no data is read, the
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
          urg = Curl_read(conn, conn->sockfd, buf, BUFSIZE -1, &nread);

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
#if 0
                if (-1 != conn->size)	/* if known */
                  conn->size += bytecount; /* we append the already read
                                              size */
#endif


                if ('\r' == *p)
                  p++;		/* pass the \r byte */
                if ('\n' == *p)
                  p++;		/* pass the \n byte */
#if 0 /* headers are not included in the size */
                Curl_pgrsSetDownloadSize(data, conn->size);
#endif

                if(100 == httpcode) {
                  /*
                   * we have made a HTTP PUT or POST and this is 1.1-lingo
                   * that tells us that the server is OK with this and ready
                   * to receive our stuff.
                   * However, we'll get more headers now so we must get
                   * back into the header-parsing state!
                   */
                  header = TRUE;
                  headerline = 0; /* we restart the header line counter */
                }
                else
                  header = FALSE;	/* no more header to parse! */

                /* now, only output this if the header AND body are requested:
                 */
                writetype = CLIENTWRITE_HEADER;
                if (data->bits.http_include_header)
                  writetype |= CLIENTWRITE_BODY;

                urg = Curl_client_write(data, writetype, data->headerbuff,
                                        p - data->headerbuff);
                if(urg)
                  return urg;

                data->header_size += p - data->headerbuff;

                if(!header) {
                  /*
                   * end-of-headers.
                   *
                   * If we requested a "no body", this is a good time to get
                   * out and return home.
                   */
                  if(data->bits.no_body)
                    return CURLE_OK;

                  if(!conn->bits.close) {
                    /* If this is not the last request before a close, we must
                       set the maximum download size to the size of the
                       expected document or else, we won't know when to stop
                       reading! */
                    if(-1 != conn->size)
                      conn->maxdownload = conn->size;

                    /* If max download size is *zero* (nothing) we already
                       have nothing and can safely return ok now! */
                    if(0 == conn->maxdownload)
                      return CURLE_OK;
                    
                    /* What to do if the size is *not* known? */
                  }
                  break;		/* exit header line loop */
                }

                /* We continue reading headers, so reset the line-based
                   header parsing variables hbufp && hbuflen */
                hbufp = data->headerbuff;
                hbuflen = 0;
                continue;
              }
              
              if (!headerline++) {
                /* This is the first header, it MUST be the error code line
                   or else we consiser this to be the body right away! */
                if (2 == sscanf (p, " HTTP/1.%d %3d", &httpversion,
                                 &httpcode)) {
                  /* 404 -> URL not found! */
                  if (
                      ( ((data->bits.http_follow_location) &&
                         (httpcode >= 400))
                        ||
                        (!data->bits.http_follow_location &&
                         (httpcode >= 300)))
                      && (data->bits.http_fail_on_error)) {
                    /* If we have been told to fail hard on HTTP-errors,
                       here is the check for that: */
                    /* serious error, go home! */
                    failf (data, "The requested file was not found");
                    return CURLE_HTTP_NOT_FOUND;
                  }
                  data->progress.httpcode = httpcode;
                  data->progress.httpversion = httpversion;

                  if(httpversion == 0)
                    /* Default action for HTTP/1.0 must be to close, unless
                       we get one of those fancy headers that tell us the
                       server keeps it open for us! */
                    conn->bits.close = TRUE;

                  if (httpcode == 304)
                    /* (quote from RFC2616, section 10.3.5):
                     *  The 304 response MUST NOT contain a
                     * message-body, and thus is always
                     * terminated by the first empty line
                     * after the header fields.
                     */
                    conn->size=0;
                }
                else {
                  header = FALSE;	/* this is not a header line */
                  break;
                }
              }
              /* check for Content-Length: header lines to get size */
              if (strnequal("Content-Length", p, 14) &&
                  sscanf (p+14, ": %ld", &contentlength)) {
                conn->size = contentlength;
                Curl_pgrsSetDownloadSize(data, contentlength);
              }
              else if((httpversion == 0) &&
                      conn->bits.httpproxy &&
                      strnequal("Proxy-Connection: keep-alive", p,
                                strlen("Proxy-Connection: keep-alive"))) {
                /*
                 * When a HTTP/1.0 reply comes when using a proxy, the
                 * 'Proxy-Connection: keep-alive' line tells us the
                 * connection will be kept alive for our pleasure.
                 * Default action for 1.0 is to close.
                 */
                conn->bits.close = FALSE; /* don't close when done */
                infof(data, "HTTP/1.0 proxy connection set to keep alive!\n");
              }
              else if((httpversion == 0) &&
                      strnequal("Connection: keep-alive", p,
                                strlen("Connection: keep-alive"))) {
                /*
                 * A HTTP/1.0 reply with the 'Connection: keep-alive' line
                 * tells us the connection will be kept alive for our
                 * pleasure.  Default action for 1.0 is to close.
                 *
                 * [RFC2068, section 19.7.1] */
                conn->bits.close = FALSE; /* don't close when done */
                infof(data, "HTTP/1.0 connection set to keep alive!\n");
              }
              else if (strnequal("Connection: close", p,
                                 strlen("Connection: close"))) {
                /*
                 * [RFC 2616, section 8.1.2.1]
                 * "Connection: close" is HTTP/1.1 language and means that
                 * the connection will close when this request has been
                 * served.
                 */
                conn->bits.close = TRUE; /* close when done */
              }
              else if (strnequal("Transfer-Encoding: chunked", p,
                                 strlen("Transfer-Encoding: chunked"))) {
                /*
                 * [RFC 2616, section 3.6.1] A 'chunked' transfer encoding
                 * means that the server will send a series of "chunks". Each
                 * chunk starts with line with info (including size of the
                 * coming block) (terminated with CRLF), then a block of data
                 * with the previously mentioned size. There can be any amount
                 * of chunks, and a chunk-data set to zero signals the
                 * end-of-chunks. */
                conn->bits.chunk = TRUE; /* chunks coming our way */

                /* init our chunky engine */
                Curl_httpchunk_init(conn);
              }
              else if (strnequal("Content-Range", p, 13)) {
                if (sscanf (p+13, ": bytes %d-", &offset) ||
                    sscanf (p+13, ": bytes: %d-", &offset)) {
                  /* This second format was added August 1st 2000 by Igor
                     Khristophorov since Sun's webserver JavaWebServer/1.1.1
                     obviously sends the header this way! :-( */
                  if (conn->resume_from == offset) {
                    /* we asked for a resume and we got it */
                    content_range = TRUE;
                  }
                }
              }
              else if(data->cookies &&
                      strnequal("Set-Cookie: ", p, 11)) {
                Curl_cookie_add(data->cookies, TRUE, &p[12]);
              }
              else if(strnequal("Last-Modified:", p,
                                strlen("Last-Modified:")) &&
                      (data->timecondition || data->bits.get_filetime) ) {
                time_t secs=time(NULL);
                timeofdoc = curl_getdate(p+strlen("Last-Modified:"), &secs);
                if(data->bits.get_filetime)
                  data->progress.filetime = timeofdoc;
              }
              else if ((httpcode >= 300 && httpcode < 400) &&
                       (data->bits.http_follow_location) &&
                       strnequal("Location: ", p, 10)) {
                /* this is the URL that the server advices us to get instead */
                char *ptr;
                char *start=p;
                char backup;

                start += 10; /* pass "Location: " */
                ptr = start; /* start scanning here */
                /* scan through the string to find the end */
                while(*ptr && !isspace((int)*ptr))
                  ptr++;
                backup = *ptr; /* store the ending letter */
                *ptr = '\0';   /* zero terminate */
                conn->newurl = strdup(start); /* clone string */
                *ptr = backup; /* restore ending letter */
              }

              writetype = CLIENTWRITE_HEADER;
              if (data->bits.http_include_header)
                writetype |= CLIENTWRITE_BODY;

              urg = Curl_client_write(data, writetype, p, hbuflen);
              if(urg)
                return urg;

              data->header_size += hbuflen;
              
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
                 write a piece of the body */
              if(conn->protocol&PROT_HTTP) {
                /* HTTP-only checks */
                if (conn->newurl) {
                  /* abort after the headers if "follow Location" is set */
                  infof (data, "Follow to new URL: %s\n", conn->newurl);
                  return CURLE_OK;
                }
                else if (conn->resume_from &&
                         !content_range &&
                         (data->httpreq==HTTPREQ_GET)) {
                  /* we wanted to resume a download, although the server
                     doesn't seem to support this and we did this with a GET
                     (if it wasn't a GET we did a POST or PUT resume) */
                  failf (data, "HTTP server doesn't seem to support "
                         "byte ranges. Cannot resume.");
                  return CURLE_HTTP_RANGE_ERROR;
                }
                else if(data->timecondition && !conn->range) {
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
                              "The requested document is not new enough\n");
                        return CURLE_OK;
                      }
                      break;
                    case TIMECOND_IFUNMODSINCE:
                      if(timeofdoc > data->timevalue) {
                        infof(data,
                              "The requested document is not old enough\n");
                        return CURLE_OK;
                      }
                      break;
                    } /* switch */
                  } /* two valid time strings */
                } /* we have a time condition */

              } /* this is HTTP */
            } /* this is the first time we write a body part */
            bodywrites++;

            if(conn->bits.chunk) {
              /*
               * Bless me father for I have sinned. Here comes a chunked
               * transfer flying and we need to decode this properly.  While
               * the name says read, this function both reads and writes away
               * the data. The returned 'nread' holds the number of actual
               * data it wrote to the client.  */
              CHUNKcode res =
                Curl_httpchunk_read(conn, str, nread, &nread);

              if(CHUNKE_OK < res) {
                failf(data, "Receeived problem in the chunky parser");
                return CURLE_READ_ERROR;
              }
              else if(CHUNKE_STOP == res) {
                /* we're done reading chunks! */
                keepon &= ~KEEP_READ; /* read no more */

                /* There are now possibly N number of bytes at the end of the
                   str buffer that weren't written to the client, but we don't
                   care about them right now. */
              }
              /* If it returned OK, we just keep going */
            }

            if((-1 != conn->maxdownload) &&
               (bytecount + nread >= conn->maxdownload)) {
              nread = conn->maxdownload - bytecount;
              if((signed int)nread < 0 ) /* this should be unusual */
                nread = 0;
              keepon &= ~KEEP_READ; /* we're done reading */
            }

            bytecount += nread;

            Curl_pgrsSetDownloadCounter(data, (double)bytecount);
            
            if(!conn->bits.chunk && nread) {
              /* If this is chunky transfer, it was already written */
              urg = Curl_client_write(data, CLIENTWRITE_BODY, str, nread);
              if(urg)
                return urg;
            }

          } /* if (! header and data to read ) */
        } /* if( read from socket ) */

        if((keepon & KEEP_WRITE) && FD_ISSET(conn->writesockfd, &writefd)) {
          /* write */

          char scratch[BUFSIZE * 2];
          int i, si;
          size_t bytes_written;

          if(data->crlf)
            buf = data->buffer; /* put it back on the buffer */

          nread = data->fread(buf, 1, conn->upload_bufsize, data->in);

          /* the signed int typecase of nread of for systems that has
             unsigned size_t */
          if ((signed int)nread<=0) {
            /* done */
            keepon &= ~KEEP_WRITE; /* we're done writing */
            break;
          }
          writebytecount += nread;
          Curl_pgrsSetUploadCounter(data, (double)writebytecount);            

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
          urg = Curl_write(conn, conn->writesockfd, buf, nread,
                           &bytes_written);

          if(nread != bytes_written) {
            failf(data, "Failed uploading data");
            return CURLE_WRITE_ERROR;
          }

        }

        break;
      }

      now = Curl_tvnow();
      if(Curl_pgrsUpdate(conn))
        urg = CURLE_ABORTED_BY_CALLBACK;
      else
        urg = Curl_speedcheck (data, now);
      if (urg)
	return urg;

      if(data->progress.ulspeed > conn->upload_bufsize) {
        /* If we're transfering more data per second than fits in our buffer,
           we increase the buffer size to adjust to the current
           speed. However, we must not set it larger than BUFSIZE. We don't
           adjust it downwards again since we don't see any point in that!
        */
        conn->upload_bufsize=(long)min(data->progress.ulspeed, BUFSIZE);
      }

      if (data->timeout && (Curl_tvdiff (now, start) > data->timeout)) {
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
  else if(conn->bits.chunk && conn->proto.http->chunk.datasize) {
    failf(data, "transfer closed with at least %d bytes remaining",
          conn->proto.http->chunk.datasize);
    return CURLE_PARTIAL_FILE;
  }
  if(Curl_pgrsUpdate(conn))
    return CURLE_ABORTED_BY_CALLBACK;

  if(conn->bytecountp)
    *conn->bytecountp = bytecount; /* read count */
  if(conn->writebytecountp)
    *conn->writebytecountp = writebytecount; /* write count */

  return CURLE_OK;
}

CURLcode Curl_perform(CURL *curl)
{
  CURLcode res;
  struct UrlData *data = (struct UrlData *)curl;
  struct connectdata *conn=NULL;
  bool port=TRUE; /* allow data->use_port to set port to use */
  char *newurl = NULL; /* possibly a new URL to follow to! */

  if(!data->url)
    /* we can't do anything wihout URL */
    return CURLE_URL_MALFORMAT;

  data->followlocation=0; /* reset the location-follow counter */
  data->bits.this_is_a_follow = FALSE; /* reset this */

  Curl_pgrsStartNow(data);

  do {
    Curl_pgrsTime(data, TIMER_STARTSINGLE);
    res = Curl_connect(data, &conn, port);
    if(res == CURLE_OK) {
      res = Curl_do(conn);
      if(res == CURLE_OK) {
        res = Transfer(conn); /* now fetch that URL please */
        if(res == CURLE_OK) {
          /*
           * We must duplicate the new URL here as the connection data
           * may be free()ed in the Curl_done() function.
           */
          newurl = conn->newurl?strdup(conn->newurl):NULL;

          res = Curl_done(conn);
        }
      }

      /*
       * Important: 'conn' cannot be used here, since it may have been closed
       * in 'Curl_done' or other functions.
       */

      if((res == CURLE_OK) && newurl) {
        /* Location: redirect
 
           This is assumed to happen for HTTP(S) only!
        */
        char prot[16]; /* URL protocol string storage */
        char letter;   /* used for a silly sscanf */

        port=TRUE; /* by default we use the user set port number even after
                      a Location: */

	if (data->maxredirs && (data->followlocation >= data->maxredirs)) {
	  failf(data,"Maximum (%d) redirects followed", data->maxredirs);
          res=CURLE_TOO_MANY_REDIRECTS;
	  break;
	}

        /* mark the next request as a followed location: */
        data->bits.this_is_a_follow = TRUE;

        data->followlocation++; /* count location-followers */

        if(data->bits.http_auto_referer) {
          /* We are asked to automatically set the previous URL as the
             referer when we get the next URL. We pick the ->url field,
             which may or may not be 100% correct */

          if(data->free_referer) {
            /* If we already have an allocated referer, free this first */
            free(data->referer);
          }

          data->referer = strdup(data->url);
          data->free_referer = TRUE;          /* yes, free this later */
          data->bits.http_set_referer = TRUE; /* might have been false */
        }

        if(2 != sscanf(newurl, "%15[^:]://%c", prot, &letter)) {
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

          /* we must make our own copy of the URL to play with, as it may
             point to read-only data */
          char *url_clone=strdup(data->url);

          if(!url_clone)
            return CURLE_OUT_OF_MEMORY;

          /* protsep points to the start of the host name */
          protsep=strstr(url_clone, "//");
          if(!protsep)
            protsep=url_clone;
          else
            protsep+=2; /* pass the slashes */

          if('/' != newurl[0]) {
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

          newest=(char *)malloc( strlen(url_clone) +
                                 1 + /* possible slash */
                                 strlen(newurl) + 1/* zero byte */);

          if(!newest)
            return CURLE_OUT_OF_MEMORY;
          sprintf(newest, "%s%s%s", url_clone, ('/' == newurl[0])?"":"/",
                  newurl);
          free(newurl);
          free(url_clone);
          newurl = newest;
        }
        else {
          /* This is an absolute URL, don't use the custom port number */
          port = FALSE;
        }

        if(data->bits.urlstringalloc)
          free(data->url);
      
        /* TBD: set the URL with curl_setopt() */
        data->url = newurl;

        data->bits.urlstringalloc = TRUE; /* the URL is allocated */

        infof(data, "Follows Location: to new URL: '%s'\n", data->url);

        /*
         * We get here when the HTTP code is 300-399. We need to perform
         * differently based on exactly what return code there was.
         * Discussed on the curl mailing list and posted about on the 26th
         * of January 2001.
         */
        switch(data->progress.httpcode) {
        case 300: /* Multiple Choices */
        case 301: /* Moved Permanently */
        case 306: /* Not used */
        case 307: /* Temporary Redirect */
        default:  /* for all unknown ones */
          /* These are explicitly mention since I've checked RFC2616 and they
           * seem to be OK to POST to.
           */
          break;
        case 302: /* Found */
          /* (From 10.3.3)

            Note: RFC 1945 and RFC 2068 specify that the client is not allowed
            to change the method on the redirected request.  However, most
            existing user agent implementations treat 302 as if it were a 303
            response, performing a GET on the Location field-value regardless
            of the original request method. The status codes 303 and 307 have
            been added for servers that wish to make unambiguously clear which
            kind of reaction is expected of the client.

            (From 10.3.4)

            Note: Many pre-HTTP/1.1 user agents do not understand the 303
            status. When interoperability with such clients is a concern, the
            302 status code may be used instead, since most user agents react
            to a 302 response as described here for 303.             
          */
        case 303: /* See Other */
          /* Disable both types of POSTs, since doing a second POST when
           * following isn't what anyone would want! */
          data->bits.http_post = FALSE;
          data->bits.http_formpost = FALSE;
          data->httpreq = HTTPREQ_GET; /* enfore GET request */
          infof(data, "Disables POST\n");
          break;
        case 304: /* Not Modified */
          /* 304 means we did a conditional request and it was "Not modified".
           * We shouldn't get any Location: header in this response!
           */
          break;
        case 305: /* Use Proxy */
          /* (quote from RFC2616, section 10.3.6):
           * "The requested resource MUST be accessed through the proxy given
           * by the Location field. The Location field gives the URI of the
           * proxy.  The recipient is expected to repeat this single request
           * via the proxy. 305 responses MUST only be generated by origin
           * servers."
           */
          break;
        }
        continue;
      }
    }
    break; /* it only reaches here when this shouldn't loop */

  } while(1); /* loop if Location: */

  if(newurl)
    free(newurl);

  /* make sure the alarm is switched off! */
  if(data->timeout || data->connecttimeout)
    myalarm(0);

  return res;
}


CURLcode 
Curl_Transfer(struct connectdata *c_conn, /* connection data */
              int sockfd,	/* socket to read from or -1 */
              int size,		/* -1 if unknown at this point */
              bool getheader,	/* TRUE if header parsing is wanted */
              long *bytecountp,	/* return number of bytes read or NULL */
              int writesockfd,  /* socket to write to, it may very well be
                                   the same we read from. -1 disables */
              long *writebytecountp /* return number of bytes written or
                                       NULL */
              )
{
  struct connectdata *conn = (struct connectdata *)c_conn;
  if(!conn)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* now copy all input parameters */
  conn->sockfd = sockfd;
  conn->size = size;
  conn->getheader = getheader;
  conn->bytecountp = bytecountp;
  conn->writesockfd = writesockfd;
  conn->writebytecountp = writebytecountp;

  return CURLE_OK;

}
          
