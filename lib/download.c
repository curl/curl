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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "setup.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "urldata.h"
#include <curl/curl.h>

#ifdef __BEOS__
#include <net/socket.h>
#endif

#ifdef WIN32
#if !defined( __GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#endif
#include <time.h> /* for the time_t typedef! */

#if defined(__GNUC__) && defined(TIME_WITH_SYS_TIME)
#include <sys/time.h>
#endif

#endif

#include "progress.h"
#include "speedcheck.h"
#include "sendf.h"

#ifdef USE_ZLIB
#include <zlib.h>
#endif

#define MAX(x,y) ((x)>(y)?(x):(y))

/* --- download and upload a stream from/to a socket --- */

/* Parts of this function was brought to us by the friendly Mark Butler
   <butlerm@xmission.com>. */

UrgError 
Transfer (struct UrlData *data,
          /* READ stuff */
	  int sockfd,		/* socket to read from or -1 */
	  int size,		/* -1 if unknown at this point */
	  bool getheader,	/* TRUE if header parsing is wanted */
	  long *bytecountp,	/* return number of bytes read or NULL */
          
          /* WRITE stuff */
          int writesockfd,      /* socket to write to, it may very well be
                                   the same we read from. -1 disables */
          long *writebytecountp /* return number of bytes written or NULL */
          

)
{
  char *buf = data->buffer;
  size_t nread;
  int bytecount = 0; /* number of bytes read */
  int writebytecount = 0; /* number of bytes written */
  long contentlength=0; /* size of incoming data */
  struct timeval start = tvnow();
  struct timeval now = start;
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
  UrgError urg;
  time_t timeofdoc=0;
  long bodywrites=0;

  char newurl[URL_MAX_LENGTH];		/* buffer for Location: URL */

  /* the highest fd we use + 1 */
  int maxfd = (sockfd>writesockfd?sockfd:writesockfd)+1;

  hbufp = data->headerbuff;

  myalarm (0);			/* switch off the alarm-style timeout */

  now = tvnow();
  start = now;

#define KEEP_READ  1
#define KEEP_WRITE 2

  pgrsTime(data, TIMER_PRETRANSFER);

  if (!getheader) {
    header = FALSE;
    if(size > 0)
      pgrsSetDownloadSize(data, size);
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
    if(sockfd != -1) {
      FD_SET (sockfd, &readfd); /* read socket */
      keepon |= KEEP_READ;
    }

    FD_ZERO (&writefd);		/* clear it */
    if(writesockfd != -1) {
      FD_SET (writesockfd, &writefd); /* write socket */
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
	keepon = 0; /* no more read or write */
	continue;
      case 0:			/* timeout */
	break;
      default:
        if((keepon & KEEP_READ) && FD_ISSET(sockfd, &readfd)) {
          /* read! */
#ifdef USE_SSLEAY
          if (data->use_ssl) {
            nread = SSL_read (data->ssl, buf, BUFSIZE - 1);
          }
          else {
#endif
            nread = sread (sockfd, buf, BUFSIZE - 1);
#ifdef USE_SSLEAY
          }
#endif /* USE_SSLEAY */

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
                    return URG_READ_ERROR;
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
                  return URG_READ_ERROR;
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
                if (-1 != size)	/* if known */
                  size += bytecount;	/* we append the already read size */


                if ('\r' == *p)
                  p++;		/* pass the \r byte */
                if ('\n' == *p)
                  p++;		/* pass the \n byte */

                pgrsSetDownloadSize(data, size);

                header = FALSE;	/* no more header to parse! */

                /* now, only output this if the header AND body are requested:
                 */
                if ((data->conf & (CONF_HEADER | CONF_NOBODY)) ==
                    CONF_HEADER) {
                  if((p - data->headerbuff) !=
                     data->fwrite (data->headerbuff, 1,
                                   p - data->headerbuff, data->out)) {
                    failf (data, "Failed writing output");
                    return URG_WRITE_ERROR;
                  }
                }
                if(data->writeheader) {
                  /* obviously, the header is requested to be written to
                     this file: */
                  if((p - data->headerbuff) !=
                     fwrite (data->headerbuff, 1, p - data->headerbuff,
                             data->writeheader)) {
                    failf (data, "Failed writing output");
                    return URG_WRITE_ERROR;
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
                      ( ((data->conf & CONF_FOLLOWLOCATION) && (code >= 400))
                        ||
                        !(data->conf & CONF_FOLLOWLOCATION) && (code >= 300))
                      && (data->conf & CONF_FAILONERROR)) {
                    /* If we have been told to fail hard on HTTP-errors,
                       here is the check for that: */
                    /* serious error, go home! */
                    failf (data, "The requested file was not found");
                    return URG_HTTP_NOT_FOUND;
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
                size = contentlength;
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
                timeofdoc = get_date(p+strlen("Last-Modified:"), &secs);
              }
              else if ((code >= 300 && code < 400) &&
                       (data->conf & CONF_FOLLOWLOCATION) &&
                       strnequal("Location", p, 8) &&
                       sscanf (p+8, ": %" URL_MAX_LENGTH_TXT "s", newurl)) {
                /* this is the URL that the server advices us to get
                   instead */
                data->newurl = strdup (newurl);
              }
              
              if (data->conf & CONF_HEADER) {
                if(hbuflen != data->fwrite (p, 1, hbuflen, data->out)) {
                  failf (data, "Failed writing output");
                  return URG_WRITE_ERROR;
                }
              }
              if(data->writeheader) {
                /* the header is requested to be written to this file */
                if(hbuflen != fwrite (p, 1, hbuflen, data->writeheader)) {
                  failf (data, "Failed writing output");
                  return URG_WRITE_ERROR;
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
          if (str && !header && (nread > 0)) {
            
            if(0 == bodywrites) {
              /* These checks are only made the first time we are about to
                 write a chunk of the body */
              if(data->conf&CONF_HTTP) {
                /* HTTP-only checks */
                if (data->resume_from && !content_range ) {
                  /* we wanted to resume a download, although the server
                     doesn't seem to support this */
                  failf (data, "HTTP server doesn't seem to support byte ranges. Cannot resume.");
                  return URG_HTTP_RANGE_ERROR;
                }
                else if (data->newurl) {
                  /* abort after the headers if "follow Location" is set */
                  infof (data, "Follow to new URL: %s\n", data->newurl);
                  return URG_OK;
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
                        return URG_OK;
                      }
                      break;
                    case TIMECOND_IFUNMODSINCE:
                      if(timeofdoc > data->timevalue) {
                        infof(data,
                              "The requested document is not old enough");
                        return URG_OK;
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
              if(nread < 0 ) /* this should be unusual */
                nread = 0;
              keepon &= ~KEEP_READ; /* we're done reading */
            }

            bytecount += nread;

            pgrsSetDownloadCounter(data, (double)bytecount);
            
            if (nread != data->fwrite (str, 1, nread, data->out)) {
              failf (data, "Failed writing output");
              return URG_WRITE_ERROR;
            }

          } /* if (! header and data to read ) */
        } /* if( read from socket ) */

        if((keepon & KEEP_WRITE) && FD_ISSET(writesockfd, &writefd)) {
          /* write */

          char scratch[BUFSIZE * 2];
          int i, si;
          int bytes_written;

          if(data->crlf)
            buf = data->buffer; /* put it back on the buffer */

          nread = data->fread(buf, 1, BUFSIZE, data->in);
          writebytecount += nread;

          pgrsSetUploadCounter(data, (double)writebytecount);
            
          if (nread<=0) {
            /* done */
            keepon &= ~KEEP_WRITE; /* we're done writing */
            break;
          }

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
#ifdef USE_SSLEAY
          if (data->use_ssl) {
            bytes_written = SSL_write(data->ssl, buf, nread);
          }
          else {
#endif
            bytes_written = swrite(writesockfd, buf, nread);
#ifdef USE_SSLEAY
          }
#endif /* USE_SSLEAY */
          if(nread != bytes_written) {
            failf(data, "Failed uploading data");
            return URG_WRITE_ERROR;
          }

        }

        break;
      }

      now = tvnow();
      pgrsUpdate(data);

      urg = speedcheck (data, now);
      if (urg)
	return urg;

      if (data->timeout && (tvdiff (now, start) > data->timeout)) {
	failf (data, "Operation timed out with %d out of %d bytes received",
	       bytecount, size);
	return URG_OPERATION_TIMEOUTED;
      }
#ifdef MULTIDOC
      if(contentlength && bytecount >= contentlength) {
        /* we're done with this download, now stop it */
        break;
      }
#endif
    }
  }
  if(!(data->conf&CONF_NOBODY) && contentlength &&
     (bytecount != contentlength)) {
    failf(data, "transfer closed with %d bytes remaining to read",
          contentlength-bytecount);
    return URG_PARTIAL_FILE;
  }
  pgrsUpdate(data);

  if(bytecountp)
    *bytecountp = bytecount; /* read count */
  if(writebytecountp)
    *writebytecountp = writebytecount; /* write count */

  return URG_OK;
}


