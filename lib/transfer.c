/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <errno.h>

#include "strtoofft.h"
#include "strequal.h"

#ifdef WIN32
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
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
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
#endif

#endif

#include "urldata.h"
#include <curl/curl.h>
#include "netrc.h"

#include "content_encoding.h"
#include "hostip.h"
#include "transfer.h"
#include "sendf.h"
#include "speedcheck.h"
#include "progress.h"
#include "http.h"
#include "url.h"
#include "getinfo.h"
#include "sslgen.h"
#include "http_digest.h"
#include "http_ntlm.h"
#include "http_negotiate.h"
#include "share.h"
#include "memory.h"
#include "select.h"
#include "multiif.h"
#include "easyif.h" /* for Curl_convert_to_network prototype */

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

#define CURL_TIMEOUT_EXPECT_100 1000 /* counting ms here */

/*
 * This function will call the read callback to fill our buffer with data
 * to upload.
 */
CURLcode Curl_fillreadbuffer(struct connectdata *conn, int bytes, int *nreadp)
{
  struct SessionHandle *data = conn->data;
  size_t buffersize = (size_t)bytes;
  int nread;

  if(conn->bits.upload_chunky) {
    /* if chunked Transfer-Encoding */
    buffersize -= (8 + 2 + 2);   /* 32bit hex + CRLF + CRLF */
    data->reqdata.upload_fromhere += 10; /* 32bit hex + CRLF */
  }

  /* this function returns a size_t, so we typecast to int to prevent warnings
     with picky compilers */
  nread = (int)conn->fread(data->reqdata.upload_fromhere, 1,
                           buffersize, conn->fread_in);

  if(nread == CURL_READFUNC_ABORT) {
    failf(data, "operation aborted by callback\n");
    return CURLE_ABORTED_BY_CALLBACK;
  }

  if(!conn->bits.forbidchunk && conn->bits.upload_chunky) {
    /* if chunked Transfer-Encoding */
    char hexbuffer[11];
    int hexlen = snprintf(hexbuffer, sizeof(hexbuffer),
                          "%x\r\n", nread);
    /* move buffer pointer */
    data->reqdata.upload_fromhere -= hexlen;
    nread += hexlen;

    /* copy the prefix to the buffer */
    memcpy(data->reqdata.upload_fromhere, hexbuffer, hexlen);

    /* always append CRLF to the data */
    memcpy(data->reqdata.upload_fromhere + nread, "\r\n", 2);

    if((nread - hexlen) == 0) {
      /* mark this as done once this chunk is transfered */
      data->reqdata.keep.upload_done = TRUE;
    }

    nread+=2; /* for the added CRLF */
  }

  *nreadp = nread;

#ifdef CURL_DOES_CONVERSIONS
  if(data->set.prefer_ascii) {
    CURLcode res;
    res = Curl_convert_to_network(data, data->reqdata.upload_fromhere, nread);
    /* Curl_convert_to_network calls failf if unsuccessful */
    if(res != CURLE_OK) {
      return(res);
    }
  }
#endif /* CURL_DOES_CONVERSIONS */

  return CURLE_OK;
}

/*
 * checkhttpprefix()
 *
 * Returns TRUE if member of the list matches prefix of string
 */
static bool
checkhttpprefix(struct SessionHandle *data,
                const char *s)
{
  struct curl_slist *head = data->set.http200aliases;

  while (head) {
    if (checkprefix(head->data, s))
      return TRUE;
    head = head->next;
  }

  if(checkprefix("HTTP/", s))
    return TRUE;

  return FALSE;
}

/*
 * Curl_readrewind() rewinds the read stream. This typically (so far) only
 * used for HTTP POST/PUT with multi-pass authentication when a sending was
 * denied and a resend is necessary.
 */
CURLcode Curl_readrewind(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;

  conn->bits.rewindaftersend = FALSE; /* we rewind now */

  /* We have sent away data. If not using CURLOPT_POSTFIELDS or
     CURLOPT_HTTPPOST, call app to rewind
  */
  if(data->set.postfields ||
     (data->set.httpreq == HTTPREQ_POST_FORM))
    ; /* do nothing */
  else {
    if(data->set.ioctl) {
      curlioerr err;

      err = (data->set.ioctl) (data, CURLIOCMD_RESTARTREAD,
                            data->set.ioctl_client);
      infof(data, "the ioctl callback returned %d\n", (int)err);

      if(err) {
        /* FIXME: convert to a human readable error message */
        failf(data, "ioctl callback returned error %d\n", (int)err);
        return CURLE_SEND_FAIL_REWIND;
      }
    }
    else {
      /* If no CURLOPT_READFUNCTION is used, we know that we operate on a
         given FILE * stream and we can actually attempt to rewind that
         ourself with fseek() */
      if(data->set.fread == (curl_read_callback)fread) {
        if(-1 != fseek(data->set.in, 0, SEEK_SET))
          /* successful rewind */
          return CURLE_OK;
      }

      /* no callback set or failure aboe, makes us fail at once */
      failf(data, "necessary data rewind wasn't possible\n");
      return CURLE_SEND_FAIL_REWIND;
    }
  }
  return CURLE_OK;
}

#ifdef USE_SSLEAY
/* FIX: this is nasty OpenSSL-specific code that really shouldn't be here */
static int data_pending(struct connectdata *conn)
{
  if(conn->ssl[FIRSTSOCKET].handle)
    /* SSL is in use */
    return SSL_pending(conn->ssl[FIRSTSOCKET].handle);

  return 0; /* nothing */
}
#else
/* non-SSL never have pending data */
#define data_pending(x) 0
#endif

/*
 * Curl_readwrite() is the low-level function to be called when data is to
 * be read and written to/from the connection.
 */
CURLcode Curl_readwrite(struct connectdata *conn,
                        bool *done)
{
  struct SessionHandle *data = conn->data;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;
  CURLcode result;
  ssize_t nread; /* number of bytes read */
  int didwhat=0;

  curl_socket_t fd_read;
  curl_socket_t fd_write;
  int select_res;

  curl_off_t contentlength;

  if(k->keepon & KEEP_READ)
    fd_read = conn->sockfd;
  else
    fd_read = CURL_SOCKET_BAD;

  if(k->keepon & KEEP_WRITE)
    fd_write = conn->writesockfd;
  else
    fd_write = CURL_SOCKET_BAD;

  select_res = Curl_select(fd_read, fd_write, 0);
  if(select_res == CSELECT_ERR) {
    failf(data, "select/poll returned error");
    return CURLE_SEND_ERROR;
  }

  do {
    /* We go ahead and do a read if we have a readable socket or if
       the stream was rewound (in which case we have data in a
       buffer) */
    if((k->keepon & KEEP_READ) &&
       ((select_res & CSELECT_IN) || conn->bits.stream_was_rewound)) {
      /* read */
      bool is_empty_data = FALSE;

      /* This is where we loop until we have read everything there is to
         read or we get a EWOULDBLOCK */
      do {
        size_t buffersize = data->set.buffer_size?
          data->set.buffer_size : BUFSIZE;
        size_t bytestoread = buffersize;
        int readrc;

        if (k->size != -1 && !k->header)
          bytestoread = k->size - k->bytecount;

        /* receive data from the network! */
        readrc = Curl_read(conn, conn->sockfd, k->buf, bytestoread, &nread);

        /* subzero, this would've blocked */
        if(0 > readrc)
          break; /* get out of loop */

        /* get the CURLcode from the int */
        result = (CURLcode)readrc;

        if(result>0)
          return result;

        if ((k->bytecount == 0) && (k->writebytecount == 0)) {
          Curl_pgrsTime(data, TIMER_STARTTRANSFER);
          if(k->wait100_after_headers)
            /* set time stamp to compare with when waiting for the 100 */
            k->start100 = Curl_tvnow();
        }

        didwhat |= KEEP_READ;
        /* indicates data of zero size, i.e. empty file */
        is_empty_data = (bool)((nread == 0) && (k->bodywrites == 0));

        /* NULL terminate, allowing string ops to be used */
        if (0 < nread || is_empty_data) {
          k->buf[nread] = 0;
        }
        else if (0 >= nread) {
          /* if we receive 0 or less here, the server closed the connection
             and we bail out from this! */

          k->keepon &= ~KEEP_READ;
          break;
        }

        /* Default buffer to use when we write the buffer, it may be changed
           in the flow below before the actual storing is done. */
        k->str = k->buf;

        /* Since this is a two-state thing, we check if we are parsing
           headers at the moment or not. */
        if (k->header) {
          /* we are in parse-the-header-mode */
          bool stop_reading = FALSE;

          /* header line within buffer loop */
          do {
            size_t hbufp_index;
            size_t rest_length;
            size_t full_length;
            int writetype;

            /* str_start is start of line within buf */
            k->str_start = k->str;

            k->end_ptr = memchr(k->str_start, '\n', nread);

            if (!k->end_ptr) {
              /* Not a complete header line within buffer, append the data to
                 the end of the headerbuff. */

              if (k->hbuflen + nread >= data->state.headersize) {
                /* We enlarge the header buffer as it is too small */
                char *newbuff;
                size_t newsize=CURLMAX((k->hbuflen+nread)*3/2,
                                       data->state.headersize*2);
                hbufp_index = k->hbufp - data->state.headerbuff;
                newbuff = (char *)realloc(data->state.headerbuff, newsize);
                if(!newbuff) {
                  failf (data, "Failed to alloc memory for big header!");
                  return CURLE_OUT_OF_MEMORY;
                }
                data->state.headersize=newsize;
                data->state.headerbuff = newbuff;
                k->hbufp = data->state.headerbuff + hbufp_index;
              }
              memcpy(k->hbufp, k->str, nread);
              k->hbufp += nread;
              k->hbuflen += nread;
              if (!k->headerline && (k->hbuflen>5)) {
                /* make a first check that this looks like a HTTP header */
                if(!checkhttpprefix(data, data->state.headerbuff)) {
                  /* this is not the beginning of a HTTP first header line */
                  k->header = FALSE;
                  k->badheader = HEADER_ALLBAD;
                  break;
                }
              }

              break; /* read more and try again */
            }

            /* decrease the size of the remaining (supposed) header line */
            rest_length = (k->end_ptr - k->str)+1;
            nread -= (ssize_t)rest_length;

            k->str = k->end_ptr + 1; /* move past new line */

            full_length = k->str - k->str_start;

            /*
             * We're about to copy a chunk of data to the end of the
             * already received header. We make sure that the full string
             * fit in the allocated header buffer, or else we enlarge
             * it.
             */
            if (k->hbuflen + full_length >=
                data->state.headersize) {
              char *newbuff;
              size_t newsize=CURLMAX((k->hbuflen+full_length)*3/2,
                                     data->state.headersize*2);
              hbufp_index = k->hbufp - data->state.headerbuff;
              newbuff = (char *)realloc(data->state.headerbuff, newsize);
              if(!newbuff) {
                failf (data, "Failed to alloc memory for big header!");
                return CURLE_OUT_OF_MEMORY;
              }
              data->state.headersize= newsize;
              data->state.headerbuff = newbuff;
              k->hbufp = data->state.headerbuff + hbufp_index;
            }

            /* copy to end of line */
            memcpy(k->hbufp, k->str_start, full_length);
            k->hbufp += full_length;
            k->hbuflen += full_length;
            *k->hbufp = 0;
            k->end_ptr = k->hbufp;

            k->p = data->state.headerbuff;

            /****
             * We now have a FULL header line that p points to
             *****/

            if(!k->headerline) {
              /* the first read header */
              if((k->hbuflen>5) &&
                 !checkhttpprefix(data, data->state.headerbuff)) {
                /* this is not the beginning of a HTTP first header line */
                k->header = FALSE;
                if(nread)
                  /* since there's more, this is a partial bad header */
                  k->badheader = HEADER_PARTHEADER;
                else {
                  /* this was all we read so its all a bad header */
                  k->badheader = HEADER_ALLBAD;
                  nread = (ssize_t)rest_length;
                }
                break;
              }
            }

            if (('\n' == *k->p) || ('\r' == *k->p)) {
              size_t headerlen;
              /* Zero-length header line means end of headers! */

              if ('\r' == *k->p)
                k->p++; /* pass the \r byte */
              if ('\n' == *k->p)
                k->p++; /* pass the \n byte */

              if(100 == k->httpcode) {
                /*
                 * We have made a HTTP PUT or POST and this is 1.1-lingo
                 * that tells us that the server is OK with this and ready
                 * to receive the data.
                 * However, we'll get more headers now so we must get
                 * back into the header-parsing state!
                 */
                k->header = TRUE;
                k->headerline = 0; /* restart the header line counter */
                /* if we did wait for this do enable write now! */
                if (k->write_after_100_header) {

                  k->write_after_100_header = FALSE;
                  k->keepon |= KEEP_WRITE;
                }
              }
              else
                k->header = FALSE; /* no more header to parse! */

              if (417 == k->httpcode) {
                /*
                 * we got: "417 Expectation Failed" this means:
                 * we have made a HTTP call and our Expect Header
                 * seems to cause a problem => abort the write operations
                 * (or prevent them from starting).
                 */
                k->write_after_100_header = FALSE;
                k->keepon &= ~KEEP_WRITE;
              }

#ifndef CURL_DISABLE_HTTP
              /*
               * When all the headers have been parsed, see if we should give
               * up and return an error.
               */
              if (Curl_http_should_fail(conn)) {
                failf (data, "The requested URL returned error: %d",
                       k->httpcode);
                return CURLE_HTTP_RETURNED_ERROR;
              }
#endif   /* CURL_DISABLE_HTTP */

              /* now, only output this if the header AND body are requested:
               */
              writetype = CLIENTWRITE_HEADER;
              if (data->set.include_header)
                writetype |= CLIENTWRITE_BODY;

              headerlen = k->p - data->state.headerbuff;

              result = Curl_client_write(conn, writetype,
                                         data->state.headerbuff,
                                         headerlen);
              if(result)
                return result;

              data->info.header_size += (long)headerlen;
              k->headerbytecount += (long)headerlen;

              k->deductheadercount =
                (100 == k->httpcode)?k->headerbytecount:0;

              if (data->reqdata.resume_from &&
                  (data->set.httpreq==HTTPREQ_GET) &&
                  (k->httpcode == 416)) {
                /* "Requested Range Not Satisfiable" */
                stop_reading = TRUE;
              }

#ifndef CURL_DISABLE_HTTP
              if(!stop_reading) {
                /* Curl_http_auth_act() checks what authentication methods
                 * that are available and decides which one (if any) to
                 * use. It will set 'newurl' if an auth metod was picked. */
                result = Curl_http_auth_act(conn);

                if(result)
                  return result;

                if(conn->bits.rewindaftersend) {
                  /* We rewind after a complete send, so thus we continue
                     sending now */
                  infof(data, "Keep sending data to get tossed away!\n");
                  k->keepon |= KEEP_WRITE;
                }
              }
#endif   /* CURL_DISABLE_HTTP */

              if(!k->header) {
                /*
                 * really end-of-headers.
                 *
                 * If we requested a "no body", this is a good time to get
                 * out and return home.
                 */
                if(conn->bits.no_body)
                  stop_reading = TRUE;
                else {
                  /* If we know the expected size of this document, we set the
                     maximum download size to the size of the expected
                     document or else, we won't know when to stop reading!

                     Note that we set the download maximum even if we read a
                     "Connection: close" header, to make sure that
                     "Content-Length: 0" still prevents us from attempting to
                     read the (missing) response-body.
                  */
                  /* According to RFC2616 section 4.4, we MUST ignore
                     Content-Length: headers if we are now receiving data
                     using chunked Transfer-Encoding.
                  */
                  if(conn->bits.chunk)
                    k->size=-1;

                }
                if(-1 != k->size) {
                  /* We do this operation even if no_body is true, since this
                     data might be retrieved later with curl_easy_getinfo()
                     and its CURLINFO_CONTENT_LENGTH_DOWNLOAD option. */

                  Curl_pgrsSetDownloadSize(data, k->size);
                  k->maxdownload = k->size;
                }
                /* If max download size is *zero* (nothing) we already
                   have nothing and can safely return ok now! */
                if(0 == k->maxdownload)
                  stop_reading = TRUE;

                if(stop_reading) {
                  /* we make sure that this socket isn't read more now */
                  k->keepon &= ~KEEP_READ;
                }

                break;          /* exit header line loop */
              }

              /* We continue reading headers, so reset the line-based
                 header parsing variables hbufp && hbuflen */
              k->hbufp = data->state.headerbuff;
              k->hbuflen = 0;
              continue;
            }

            /*
             * Checks for special headers coming up.
             */

            if (!k->headerline++) {
              /* This is the first header, it MUST be the error code line
                 or else we consiser this to be the body right away! */
              int httpversion_major;
              int nc=sscanf(k->p, " HTTP/%d.%d %3d",
                            &httpversion_major,
                            &k->httpversion,
                            &k->httpcode);
              if (nc==3) {
                k->httpversion += 10 * httpversion_major;
              }
              else {
                /* this is the real world, not a Nirvana
                   NCSA 1.5.x returns this crap when asked for HTTP/1.1
                */
                nc=sscanf(k->p, " HTTP %3d", &k->httpcode);
                k->httpversion = 10;

               /* If user has set option HTTP200ALIASES,
                  compare header line against list of aliases
               */
                if (!nc) {
                  if (checkhttpprefix(data, k->p)) {
                    nc = 1;
                    k->httpcode = 200;
                    k->httpversion =
                      (data->set.httpversion==CURL_HTTP_VERSION_1_0)? 10 : 11;
                  }
                }
              }

              if (nc) {
                data->info.httpcode = k->httpcode;
                data->info.httpversion = k->httpversion;

                /*
                 * This code executes as part of processing the header.  As a
                 * result, it's not totally clear how to interpret the
                 * response code yet as that depends on what other headers may
                 * be present.  401 and 407 may be errors, but may be OK
                 * depending on how authentication is working.  Other codes
                 * are definitely errors, so give up here.
                 */
                if (data->set.http_fail_on_error &&
                    (k->httpcode >= 400) &&
                    (k->httpcode != 401) &&
                    (k->httpcode != 407)) {

                  if (data->reqdata.resume_from &&
                      (data->set.httpreq==HTTPREQ_GET) &&
                      (k->httpcode == 416)) {
                    /* "Requested Range Not Satisfiable", just proceed and
                       pretend this is no error */
                  }
                  else {
                    /* serious error, go home! */
                    failf (data, "The requested URL returned error: %d",
                           k->httpcode);
                    return CURLE_HTTP_RETURNED_ERROR;
                  }
                }

                if(k->httpversion == 10)
                  /* Default action for HTTP/1.0 must be to close, unless
                     we get one of those fancy headers that tell us the
                     server keeps it open for us! */
                  conn->bits.close = TRUE;

                switch(k->httpcode) {
                case 204:
                  /* (quote from RFC2616, section 10.2.5): The server has
                   * fulfilled the request but does not need to return an
                   * entity-body ... The 204 response MUST NOT include a
                   * message-body, and thus is always terminated by the first
                   * empty line after the header fields. */
                  /* FALLTHROUGH */
                case 416: /* Requested Range Not Satisfiable, it has the
                             Content-Length: set as the "real" document but no
                             actual response is sent. */
                case 304:
                  /* (quote from RFC2616, section 10.3.5): The 304 response
                   * MUST NOT contain a message-body, and thus is always
                   * terminated by the first empty line after the header
                   * fields.  */
                  k->size=0;
                  k->maxdownload=0;
                  k->ignorecl = TRUE; /* ignore Content-Length headers */
                  break;
                default:
                  /* nothing */
                  break;
                }
              }
              else {
                k->header = FALSE;   /* this is not a header line */
                break;
              }
            }

            /* Check for Content-Length: header lines to get size. Ignore
               the header completely if we get a 416 response as then we're
               resuming a document that we don't get, and this header contains
               info about the true size of the document we didn't get now. */
            if (!k->ignorecl && !data->set.ignorecl &&
                checkprefix("Content-Length:", k->p)) {
              contentlength = curlx_strtoofft(k->p+15, NULL, 10);
              if (data->set.max_filesize &&
                  contentlength > data->set.max_filesize) {
                failf(data, "Maximum file size exceeded");
                return CURLE_FILESIZE_EXCEEDED;
              }
              if(contentlength >= 0)
                k->size = contentlength;
              else {
                /* Negative Content-Length is really odd, and we know it
                   happens for example when older Apache servers send large
                   files */
                conn->bits.close = TRUE;
                infof(data, "Negative content-length: %" FORMAT_OFF_T
                      ", closing after transfer\n", contentlength);
              }
            }
            /* check for Content-Type: header lines to get the mime-type */
            else if (checkprefix("Content-Type:", k->p)) {
              char *start;
              char *end;
              size_t len;

              /* Find the first non-space letter */
              for(start=k->p+13;
                  *start && ISSPACE(*start);
                  start++)
                ;  /* empty loop */

              end = strchr(start, '\r');
              if(!end)
                end = strchr(start, '\n');

              if(end) {
                /* skip all trailing space letters */
                for(; ISSPACE(*end) && (end > start); end--)
                  ;  /* empty loop */

                /* get length of the type */
                len = end-start+1;

                /* allocate memory of a cloned copy */
                Curl_safefree(data->info.contenttype);

                data->info.contenttype = malloc(len + 1);
                if (NULL == data->info.contenttype)
                  return CURLE_OUT_OF_MEMORY;

                /* copy the content-type string */
                memcpy(data->info.contenttype, start, len);
                data->info.contenttype[len] = 0; /* zero terminate */
              }
            }
#ifndef CURL_DISABLE_HTTP
            else if((k->httpversion == 10) &&
                    conn->bits.httpproxy &&
                    Curl_compareheader(k->p,
                                       "Proxy-Connection:", "keep-alive")) {
              /*
               * When a HTTP/1.0 reply comes when using a proxy, the
               * 'Proxy-Connection: keep-alive' line tells us the
               * connection will be kept alive for our pleasure.
               * Default action for 1.0 is to close.
               */
              conn->bits.close = FALSE; /* don't close when done */
              infof(data, "HTTP/1.0 proxy connection set to keep alive!\n");
            }
            else if((k->httpversion == 11) &&
                    conn->bits.httpproxy &&
                    Curl_compareheader(k->p,
                                       "Proxy-Connection:", "close")) {
              /*
               * We get a HTTP/1.1 response from a proxy and it says it'll
               * close down after this transfer.
               */
              conn->bits.close = TRUE; /* close when done */
              infof(data, "HTTP/1.1 proxy connection set close!\n");
            }
            else if((k->httpversion == 10) &&
                    Curl_compareheader(k->p, "Connection:", "keep-alive")) {
              /*
               * A HTTP/1.0 reply with the 'Connection: keep-alive' line
               * tells us the connection will be kept alive for our
               * pleasure.  Default action for 1.0 is to close.
               *
               * [RFC2068, section 19.7.1] */
              conn->bits.close = FALSE; /* don't close when done */
              infof(data, "HTTP/1.0 connection set to keep alive!\n");
            }
            else if (Curl_compareheader(k->p, "Connection:", "close")) {
              /*
               * [RFC 2616, section 8.1.2.1]
               * "Connection: close" is HTTP/1.1 language and means that
               * the connection will close when this request has been
               * served.
               */
              conn->bits.close = TRUE; /* close when done */
            }
            else if (Curl_compareheader(k->p,
                                        "Transfer-Encoding:", "chunked")) {
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

            else if (checkprefix("Trailer:", k->p) ||
                     checkprefix("Trailers:", k->p)) {
              /*
               * This test helps Curl_httpchunk_read() to determine to look
               * for well formed trailers after the zero chunksize record. In
               * this case a CRLF is required after the zero chunksize record
               * when no trailers are sent, or after the last trailer record.
               *
               * It seems both Trailer: and Trailers: occur in the wild.
               */
              conn->bits.trailerHdrPresent = TRUE;
            }

            else if (checkprefix("Content-Encoding:", k->p) &&
                     data->set.encoding) {
              /*
               * Process Content-Encoding. Look for the values: identity,
               * gzip, deflate, compress, x-gzip and x-compress. x-gzip and
               * x-compress are the same as gzip and compress. (Sec 3.5 RFC
               * 2616). zlib cannot handle compress.  However, errors are
               * handled further down when the response body is processed
               */
              char *start;

              /* Find the first non-space letter */
              for(start=k->p+17;
                  *start && ISSPACE(*start);
                  start++)
                ;  /* empty loop */

              /* Record the content-encoding for later use */
              if (checkprefix("identity", start))
                k->content_encoding = IDENTITY;
              else if (checkprefix("deflate", start))
                k->content_encoding = DEFLATE;
              else if (checkprefix("gzip", start)
                       || checkprefix("x-gzip", start))
                k->content_encoding = GZIP;
              else if (checkprefix("compress", start)
                       || checkprefix("x-compress", start))
                k->content_encoding = COMPRESS;
            }
            else if (Curl_compareheader(k->p, "Content-Range:", "bytes")) {
              /* Content-Range: bytes [num]-
                 Content-Range: bytes: [num]-

                 The second format was added since Sun's webserver
                 JavaWebServer/1.1.1 obviously sends the header this way!
              */

              char *ptr = Curl_strcasestr(k->p, "bytes");
              ptr+=5;

              if(*ptr == ':')
                /* stupid colon skip */
                ptr++;

              k->offset = curlx_strtoofft(ptr, NULL, 10);

              if (data->reqdata.resume_from == k->offset)
                /* we asked for a resume and we got it */
                k->content_range = TRUE;
            }
#if !defined(CURL_DISABLE_COOKIES)
            else if(data->cookies &&
                    checkprefix("Set-Cookie:", k->p)) {
              Curl_share_lock(data, CURL_LOCK_DATA_COOKIE,
                              CURL_LOCK_ACCESS_SINGLE);
              Curl_cookie_add(data,
                              data->cookies, TRUE, k->p+11,
                              /* If there is a custom-set Host: name, use it
                                 here, or else use real peer host name. */
                              conn->allocptr.cookiehost?
                              conn->allocptr.cookiehost:conn->host.name,
                              data->reqdata.path);
              Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
            }
#endif
            else if(checkprefix("Last-Modified:", k->p) &&
                    (data->set.timecondition || data->set.get_filetime) ) {
              time_t secs=time(NULL);
              k->timeofdoc = curl_getdate(k->p+strlen("Last-Modified:"),
                                          &secs);
              if(data->set.get_filetime)
                data->info.filetime = (long)k->timeofdoc;
            }
            else if((checkprefix("WWW-Authenticate:", k->p) &&
                     (401 == k->httpcode)) ||
                    (checkprefix("Proxy-authenticate:", k->p) &&
                     (407 == k->httpcode))) {
              result = Curl_http_input_auth(conn, k->httpcode, k->p);
              if(result)
                return result;
            }
            else if ((k->httpcode >= 300 && k->httpcode < 400) &&
                     checkprefix("Location:", k->p)) {
              if(data->set.http_follow_location) {
                /* this is the URL that the server advices us to get instead */
                char *ptr;
                char *start=k->p;
                char backup;

                start += 9; /* pass "Location:" */

                /* Skip spaces and tabs. We do this to support multiple
                   white spaces after the "Location:" keyword. */
                while(*start && ISSPACE(*start ))
                  start++;

                /* Scan through the string from the end to find the last
                   non-space. k->end_ptr points to the actual terminating zero
                   letter, move pointer one letter back and start from
                   there. This logic strips off trailing whitespace, but keeps
                   any embedded whitespace. */
                ptr = k->end_ptr-1;
                while((ptr>=start) && ISSPACE(*ptr))
                  ptr--;
                ptr++;

                backup = *ptr; /* store the ending letter */
                if(ptr != start) {
                  *ptr = '\0';   /* zero terminate */
                  data->reqdata.newurl = strdup(start); /* clone string */
                  *ptr = backup; /* restore ending letter */
                  if(!data->reqdata.newurl)
                    return CURLE_OUT_OF_MEMORY;
                }
              }
            }
#endif   /* CURL_DISABLE_HTTP */

            /*
             * End of header-checks. Write them to the client.
             */

            writetype = CLIENTWRITE_HEADER;
            if (data->set.include_header)
              writetype |= CLIENTWRITE_BODY;

            if(data->set.verbose)
              Curl_debug(data, CURLINFO_HEADER_IN,
                         k->p, (size_t)k->hbuflen, conn);

            result = Curl_client_write(conn, writetype, k->p, k->hbuflen);
            if(result)
              return result;

            data->info.header_size += (long)k->hbuflen;
            k->headerbytecount += (long)k->hbuflen;

            /* reset hbufp pointer && hbuflen */
            k->hbufp = data->state.headerbuff;
            k->hbuflen = 0;
          }
          while (!stop_reading && *k->str); /* header line within buffer */

          if(stop_reading)
            /* We've stopped dealing with input, get out of the do-while loop */
            break;

          /* We might have reached the end of the header part here, but
             there might be a non-header part left in the end of the read
             buffer. */

        }                       /* end if header mode */

        /* This is not an 'else if' since it may be a rest from the header
           parsing, where the beginning of the buffer is headers and the end
           is non-headers. */
        if (k->str && !k->header && (nread > 0 || is_empty_data)) {

          if(0 == k->bodywrites && !is_empty_data) {
            /* These checks are only made the first time we are about to
               write a piece of the body */
            if(conn->protocol&PROT_HTTP) {
              /* HTTP-only checks */

              if (data->reqdata.newurl) {
                if(conn->bits.close) {
                  /* Abort after the headers if "follow Location" is set
                     and we're set to close anyway. */
                  k->keepon &= ~KEEP_READ;
                  *done = TRUE;
                  return CURLE_OK;
                }
                /* We have a new url to load, but since we want to be able
                   to re-use this connection properly, we read the full
                   response in "ignore more" */
                k->ignorebody = TRUE;
                infof(data, "Ignoring the response-body\n");
              }
              if (data->reqdata.resume_from && !k->content_range &&
                  (data->set.httpreq==HTTPREQ_GET) &&
                  !k->ignorebody) {
                /* we wanted to resume a download, although the server doesn't
                 * seem to support this and we did this with a GET (if it
                 * wasn't a GET we did a POST or PUT resume) */
                failf(data, "HTTP server doesn't seem to support "
                      "byte ranges. Cannot resume.");
                return CURLE_HTTP_RANGE_ERROR;
              }

              if(data->set.timecondition && !data->reqdata.range) {
                /* A time condition has been set AND no ranges have been
                   requested. This seems to be what chapter 13.3.4 of
                   RFC 2616 defines to be the correct action for a
                   HTTP/1.1 client */
                if((k->timeofdoc > 0) && (data->set.timevalue > 0)) {
                  switch(data->set.timecondition) {
                  case CURL_TIMECOND_IFMODSINCE:
                  default:
                    if(k->timeofdoc < data->set.timevalue) {
                      infof(data,
                            "The requested document is not new enough\n");
                      *done = TRUE;
                      return CURLE_OK;
                    }
                    break;
                  case CURL_TIMECOND_IFUNMODSINCE:
                    if(k->timeofdoc > data->set.timevalue) {
                      infof(data,
                            "The requested document is not old enough\n");
                      *done = TRUE;
                      return CURLE_OK;
                    }
                    break;
                  } /* switch */
                } /* two valid time strings */
              } /* we have a time condition */

            } /* this is HTTP */
          } /* this is the first time we write a body part */
          k->bodywrites++;

          /* pass data to the debug function before it gets "dechunked" */
          if(data->set.verbose) {
            if(k->badheader) {
              Curl_debug(data, CURLINFO_DATA_IN, data->state.headerbuff,
                         (size_t)k->hbuflen, conn);
              if(k->badheader == HEADER_PARTHEADER)
                Curl_debug(data, CURLINFO_DATA_IN, 
                           k->str, (size_t)nread, conn);
            }
            else
              Curl_debug(data, CURLINFO_DATA_IN, 
                         k->str, (size_t)nread, conn);
          }

#ifndef CURL_DISABLE_HTTP
          if(conn->bits.chunk) {
            /*
             * Bless me father for I have sinned. Here comes a chunked
             * transfer flying and we need to decode this properly.  While
             * the name says read, this function both reads and writes away
             * the data. The returned 'nread' holds the number of actual
             * data it wrote to the client.  */

            CHUNKcode res =
              Curl_httpchunk_read(conn, k->str, nread, &nread);

            if(CHUNKE_OK < res) {
              if(CHUNKE_WRITE_ERROR == res) {
                failf(data, "Failed writing data");
                return CURLE_WRITE_ERROR;
              }
              failf(data, "Received problem %d in the chunky parser", res);
              return CURLE_RECV_ERROR;
            }
            else if(CHUNKE_STOP == res) {
              /* we're done reading chunks! */
              k->keepon &= ~KEEP_READ; /* read no more */

              /* There are now possibly N number of bytes at the end of the
                 str buffer that weren't written to the client, but we don't
                 care about them right now. */
            }
            /* If it returned OK, we just keep going */
          }
#endif   /* CURL_DISABLE_HTTP */

          if((-1 != k->maxdownload) &&
             (k->bytecount + nread >= k->maxdownload)) {
            size_t excess = k->bytecount + nread - k->maxdownload;

            if (excess > 0) {
                infof(data, "Rewinding stream by : %d bytes\n", excess);
                Curl_read_rewind(conn, excess);
                conn->bits.stream_was_rewound = TRUE;
            }

            nread = (ssize_t) (k->maxdownload - k->bytecount);
            if(nread < 0 ) /* this should be unusual */
              nread = 0;

            k->keepon &= ~KEEP_READ; /* we're done reading */
          }

          k->bytecount += nread;

          Curl_pgrsSetDownloadCounter(data, k->bytecount);

          if(!conn->bits.chunk && (nread || k->badheader || is_empty_data)) {
            /* If this is chunky transfer, it was already written */

            if(k->badheader && !k->ignorebody) {
              /* we parsed a piece of data wrongly assuming it was a header
                 and now we output it as body instead */
              result = Curl_client_write(conn, CLIENTWRITE_BODY,
                                         data->state.headerbuff,
                                         k->hbuflen);
              if(result)
                return result;
            }
            if(k->badheader < HEADER_ALLBAD) {
              /* This switch handles various content encodings. If there's an
                 error here, be sure to check over the almost identical code
                 in http_chunks.c.
                 Make sure that ALL_CONTENT_ENCODINGS contains all the
                 encodings handled here. */
#ifdef HAVE_LIBZ
              switch (k->content_encoding) {
              case IDENTITY:
#endif
                /* This is the default when the server sends no
                   Content-Encoding header. See Curl_readwrite_init; the
                   memset() call initializes k->content_encoding to zero. */
                if(!k->ignorebody)
                  result = Curl_client_write(conn, CLIENTWRITE_BODY, k->str,
                                             nread);
#ifdef HAVE_LIBZ
                break;

              case DEFLATE:
                /* Assume CLIENTWRITE_BODY; headers are not encoded. */
                if(!k->ignorebody)
                  result = Curl_unencode_deflate_write(conn, k, nread);
                break;

              case GZIP:
                /* Assume CLIENTWRITE_BODY; headers are not encoded. */
                if(!k->ignorebody)
                  result = Curl_unencode_gzip_write(conn, k, nread);
                break;

              case COMPRESS:
              default:
                failf (data, "Unrecognized content encoding type. "
                       "libcurl understands `identity', `deflate' and `gzip' "
                       "content encodings.");
                result = CURLE_BAD_CONTENT_ENCODING;
                break;
              }
#endif
            }
            k->badheader = HEADER_NORMAL; /* taken care of now */

            if(result)
              return result;
          }

        } /* if (! header and data to read ) */

        if (is_empty_data) {
          /* if we received nothing, the server closed the connection and we
             are done */
          k->keepon &= ~KEEP_READ;
        }

      } while(data_pending(conn));

    } /* if( read from socket ) */

    /* If we still have writing to do, we check if we have a writable
       socket. */
    if((k->keepon & KEEP_WRITE) && (select_res & CSELECT_OUT)) {
      /* write */

      int i, si;
      ssize_t bytes_written;
      bool writedone=TRUE;

      if ((k->bytecount == 0) && (k->writebytecount == 0))
        Curl_pgrsTime(data, TIMER_STARTTRANSFER);

      didwhat |= KEEP_WRITE;

      /*
       * We loop here to do the READ and SEND loop until we run out of
       * data to send or until we get EWOULDBLOCK back
       */
      do {

        /* only read more data if there's no upload data already
           present in the upload buffer */
        if(0 == data->reqdata.upload_present) {
          /* init the "upload from here" pointer */
          data->reqdata.upload_fromhere = k->uploadbuf;

          if(!k->upload_done) {
            /* HTTP pollution, this should be written nicer to become more
               protocol agnostic. */
            int fillcount;

            if(k->wait100_after_headers &&
               (data->reqdata.proto.http->sending == HTTPSEND_BODY)) {
              /* If this call is to send body data, we must take some action:
                 We have sent off the full HTTP 1.1 request, and we shall now
                 go into the Expect: 100 state and await such a header */
              k->wait100_after_headers = FALSE; /* headers sent */
              k->write_after_100_header = TRUE; /* wait for the header */
              k->keepon &= ~KEEP_WRITE;         /* disable writing */
              k->start100 = Curl_tvnow();       /* timeout count starts now */
              didwhat &= ~KEEP_WRITE;  /* we didn't write anything actually */
              break;
            }

            result = Curl_fillreadbuffer(conn, BUFSIZE, &fillcount);
            if(result)
              return result;

            nread = (ssize_t)fillcount;
          }
          else
            nread = 0; /* we're done uploading/reading */

          /* the signed int typecase of nread of for systems that has
             unsigned size_t */
          if (nread<=0) {
            /* done */
            k->keepon &= ~KEEP_WRITE; /* we're done writing */
            writedone = TRUE;

            if(conn->bits.rewindaftersend) {
              result = Curl_readrewind(conn);
              if(result)
                return result;
            }
            break;
          }

          /* store number of bytes available for upload */
          data->reqdata.upload_present = nread;

          /* convert LF to CRLF if so asked */
#ifdef CURL_DO_LINEEND_CONV
          /* always convert if we're FTPing in ASCII mode */
          if ((data->set.crlf) || (data->set.prefer_ascii)) {
#else
          if (data->set.crlf) {
#endif /* CURL_DO_LINEEND_CONV */
              if(data->state.scratch == NULL)
                data->state.scratch = malloc(2*BUFSIZE);
              if(data->state.scratch == NULL) {
                failf (data, "Failed to alloc scratch buffer!");
                return CURLE_OUT_OF_MEMORY;
              }
              /*
               * ASCII/EBCDIC Note: This is presumably a text (not binary)
               * transfer so the data should already be in ASCII.
               * That means the hex values for ASCII CR (0x0d) & LF (0x0a)
               * must be used instead of the escape sequences \r & \n.
               */
            for(i = 0, si = 0; i < nread; i++, si++) {
              if (data->reqdata.upload_fromhere[i] == 0x0a) {
                data->state.scratch[si++] = 0x0d;
                data->state.scratch[si] = 0x0a;
                if (!data->set.crlf) {
                  /* we're here only because FTP is in ASCII mode...
                     bump infilesize for the LF we just added */
                  data->set.infilesize++;
                }
              }
              else
                data->state.scratch[si] = data->reqdata.upload_fromhere[i];
            }
            if(si != nread) {
              /* only perform the special operation if we really did replace
                 anything */
              nread = si;

              /* upload from the new (replaced) buffer instead */
              data->reqdata.upload_fromhere = data->state.scratch;

              /* set the new amount too */
              data->reqdata.upload_present = nread;
            }
          }
        }
        else {
          /* We have a partial buffer left from a previous "round". Use
             that instead of reading more data */
        }

        /* write to socket (send away data) */
        result = Curl_write(conn,
                            conn->writesockfd,     /* socket to send to */
                            data->reqdata.upload_fromhere, /* buffer pointer */
                            data->reqdata.upload_present,  /* buffer size */
                            &bytes_written);       /* actually send away */
        if(result)
          return result;

        if(data->set.verbose)
          /* show the data before we change the pointer upload_fromhere */
          Curl_debug(data, CURLINFO_DATA_OUT, data->reqdata.upload_fromhere,
                     (size_t)bytes_written, conn);

        if(data->reqdata.upload_present != bytes_written) {
          /* we only wrote a part of the buffer (if anything), deal with it! */

          /* store the amount of bytes left in the buffer to write */
          data->reqdata.upload_present -= bytes_written;

          /* advance the pointer where to find the buffer when the next send
             is to happen */
          data->reqdata.upload_fromhere += bytes_written;

          writedone = TRUE; /* we are done, stop the loop */
        }
        else {
          /* we've uploaded that buffer now */
          data->reqdata.upload_fromhere = k->uploadbuf;
          data->reqdata.upload_present = 0; /* no more bytes left */

          if(k->upload_done) {
            /* switch off writing, we're done! */
            k->keepon &= ~KEEP_WRITE; /* we're done writing */
            writedone = TRUE;
          }
        }

        k->writebytecount += bytes_written;
        Curl_pgrsSetUploadCounter(data, k->writebytecount);

      } while(!writedone); /* loop until we're done writing! */

    }

  } while(0); /* just to break out from! */

  k->now = Curl_tvnow();
  if(didwhat) {
    /* Update read/write counters */
    if(k->bytecountp)
      *k->bytecountp = k->bytecount; /* read count */
    if(k->writebytecountp)
      *k->writebytecountp = k->writebytecount; /* write count */
  }
  else {
    /* no read no write, this is a timeout? */
    if (k->write_after_100_header) {
      /* This should allow some time for the header to arrive, but only a
         very short time as otherwise it'll be too much wasted times too
         often. */

      /* Quoting RFC2616, section "8.2.3 Use of the 100 (Continue) Status":

      Therefore, when a client sends this header field to an origin server
      (possibly via a proxy) from which it has never seen a 100 (Continue)
      status, the client SHOULD NOT wait for an indefinite period before
      sending the request body.

      */

      long ms = Curl_tvdiff(k->now, k->start100);
      if(ms > CURL_TIMEOUT_EXPECT_100) {
        /* we've waited long enough, continue anyway */
        k->write_after_100_header = FALSE;
        k->keepon |= KEEP_WRITE;
      }
    }
  }

  if(Curl_pgrsUpdate(conn))
    result = CURLE_ABORTED_BY_CALLBACK;
  else
    result = Curl_speedcheck(data, k->now);
  if (result)
    return result;

  if (data->set.timeout &&
      ((Curl_tvdiff(k->now, k->start)/1000) >= data->set.timeout)) {
    if (k->size != -1) {
      failf(data, "Operation timed out after %d seconds with %"
            FORMAT_OFF_T " out of %" FORMAT_OFF_T " bytes received",
            data->set.timeout, k->bytecount, k->size);
    } else {
      failf(data, "Operation timed out after %d seconds with %"
            FORMAT_OFF_T " bytes received",
            data->set.timeout, k->bytecount);
    }
    return CURLE_OPERATION_TIMEOUTED;
  }

  if(!k->keepon) {
    /*
     * The transfer has been performed. Just make some general checks before
     * returning.
     */

    if(!(conn->bits.no_body) && (k->size != -1) &&
       (k->bytecount != k->size) &&
#ifdef CURL_DO_LINEEND_CONV
       /* Most FTP servers don't adjust their file SIZE response for CRLFs,
          so we'll check to see if the discrepancy can be explained
          by the number of CRLFs we've changed to LFs.
        */
       (k->bytecount != (k->size + data->state.crlf_conversions)) &&
#endif /* CURL_DO_LINEEND_CONV */
       !data->reqdata.newurl) {
      failf(data, "transfer closed with %" FORMAT_OFF_T
            " bytes remaining to read",
            k->size - k->bytecount);
      return CURLE_PARTIAL_FILE;
    }
    else if(!(conn->bits.no_body) &&
            conn->bits.chunk &&
            (data->reqdata.proto.http->chunk.state != CHUNK_STOP)) {
      /*
       * In chunked mode, return an error if the connection is closed prior to
       * the empty (terminiating) chunk is read.
       *
       * The condition above used to check for
       * conn->proto.http->chunk.datasize != 0 which is true after reading
       * *any* chunk, not just the empty chunk.
       *
       */
      failf(data, "transfer closed with outstanding read data remaining");
      return CURLE_PARTIAL_FILE;
    }
    if(Curl_pgrsUpdate(conn))
      return CURLE_ABORTED_BY_CALLBACK;
  }

  /* Now update the "done" boolean we return */
  *done = (bool)(0 == k->keepon);

  return CURLE_OK;
}


/*
 * Curl_readwrite_init() inits the readwrite session. This is inited each time for a
 * transfer, sometimes multiple times on the same SessionHandle
 */

CURLcode Curl_readwrite_init(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;

  /* NB: the content encoding software depends on this initialization of
     Curl_transfer_keeper.*/
  memset(k, 0, sizeof(struct Curl_transfer_keeper));

  k->start = Curl_tvnow(); /* start time */
  k->now = k->start;   /* current time is now */
  k->header = TRUE; /* assume header */
  k->httpversion = -1; /* unknown at this point */

  k->size = data->reqdata.size;
  k->maxdownload = data->reqdata.maxdownload;
  k->bytecountp = data->reqdata.bytecountp;
  k->writebytecountp = data->reqdata.writebytecountp;

  k->bytecount = 0;
  k->headerbytecount = 0;

  k->buf = data->state.buffer;
  k->uploadbuf = data->state.uploadbuffer;
  k->maxfd = (conn->sockfd>conn->writesockfd?
              conn->sockfd:conn->writesockfd)+1;
  k->hbufp = data->state.headerbuff;
  k->ignorebody=FALSE;

  Curl_pgrsTime(data, TIMER_PRETRANSFER);
  Curl_speedinit(data);

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);

  if (!conn->bits.getheader) {
    k->header = FALSE;
    if(k->size > 0)
      Curl_pgrsSetDownloadSize(data, k->size);
  }
  /* we want header and/or body, if neither then don't do this! */
  if(conn->bits.getheader || !conn->bits.no_body) {

    if(conn->sockfd != CURL_SOCKET_BAD) {
      k->keepon |= KEEP_READ;
    }

    if(conn->writesockfd != CURL_SOCKET_BAD) {
      /* HTTP 1.1 magic:

         Even if we require a 100-return code before uploading data, we might
         need to write data before that since the REQUEST may not have been
         finished sent off just yet.

         Thus, we must check if the request has been sent before we set the
         state info where we wait for the 100-return code
      */
      if (data->state.expect100header &&
          (data->reqdata.proto.http->sending == HTTPSEND_BODY)) {
        /* wait with write until we either got 100-continue or a timeout */
        k->write_after_100_header = TRUE;
        k->start100 = k->start;
      }
      else {
        if(data->state.expect100header)
          /* when we've sent off the rest of the headers, we must await a
             100-continue */
          k->wait100_after_headers = TRUE;
        k->keepon |= KEEP_WRITE;
      }
    }
  }

  return CURLE_OK;
}

/*
 * Curl_single_getsock() gets called by the multi interface code when the app
 * has requested to get the sockets for the current connection. This function
 * will then be called once for every connection that the multi interface
 * keeps track of. This function will only be called for connections that are
 * in the proper state to have this information available.
 */
int Curl_single_getsock(struct connectdata *conn,
                        curl_socket_t *sock, /* points to numsocks number
                                                of sockets */
                        int numsocks)
{
  struct SessionHandle *data = conn->data;
  int bitmap = GETSOCK_BLANK;
  int index = 0;

  if(numsocks < 2)
    /* simple check but we might need two slots */
    return GETSOCK_BLANK;

  if(data->reqdata.keep.keepon & KEEP_READ) {
    bitmap |= GETSOCK_READSOCK(index);
    sock[index] = conn->sockfd;
  }

  if(data->reqdata.keep.keepon & KEEP_WRITE) {

    if((conn->sockfd != conn->writesockfd) ||
       !(data->reqdata.keep.keepon & KEEP_READ)) {
      /* only if they are not the same socket or we didn't have a readable
         one, we increase index */
      if(data->reqdata.keep.keepon & KEEP_READ)
        index++; /* increase index if we need two entries */
      sock[index] = conn->writesockfd;
    }

    bitmap |= GETSOCK_WRITESOCK(index);
  }

  return bitmap;
}


/*
 * Transfer()
 *
 * This function is what performs the actual transfer. It is capable of
 * doing both ways simultaneously.
 * The transfer must already have been setup by a call to Curl_setup_transfer().
 *
 * Note that headers are created in a preallocated buffer of a default size.
 * That buffer can be enlarged on demand, but it is never shrunken again.
 *
 * Parts of this function was once written by the friendly Mark Butler
 * <butlerm@xmission.com>.
 */

static CURLcode
Transfer(struct connectdata *conn)
{
  CURLcode result;
  struct SessionHandle *data = conn->data;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;
  bool done=FALSE;

  if(!(conn->protocol & PROT_FILE))
    /* Only do this if we are not transferring FILE:, since the file: treatment
       is different*/
    Curl_readwrite_init(conn);

  if((conn->sockfd == CURL_SOCKET_BAD) &&
     (conn->writesockfd == CURL_SOCKET_BAD))
    /* nothing to read, nothing to write, we're already OK! */
    return CURLE_OK;

  /* we want header and/or body, if neither then don't do this! */
  if(!conn->bits.getheader && conn->bits.no_body)
    return CURLE_OK;

  while (!done) {
    curl_socket_t fd_read;
    curl_socket_t fd_write;
    int interval_ms;

    interval_ms = 1 * 1000;

    /* limit-rate logic: if speed exceeds threshold, then do not include fd in
       select set */
    if ( (conn->data->set.max_send_speed > 0) &&
         (conn->data->progress.ulspeed > conn->data->set.max_send_speed) )  {
      fd_write = CURL_SOCKET_BAD;
      Curl_pgrsUpdate(conn);
    }
    else {
      if(k->keepon & KEEP_WRITE)
        fd_write = conn->writesockfd;
      else
        fd_write = CURL_SOCKET_BAD;
    }

    if ( (conn->data->set.max_recv_speed > 0) &&
         (conn->data->progress.dlspeed > conn->data->set.max_recv_speed) ) {
      fd_read = CURL_SOCKET_BAD;
      Curl_pgrsUpdate(conn);
    }
    else {
      if(k->keepon & KEEP_READ)
        fd_read = conn->sockfd;
      else
        fd_read = CURL_SOCKET_BAD;
    }

    switch (Curl_select(fd_read, fd_write, interval_ms)) {
    case -1: /* select() error, stop reading */
#ifdef EINTR
      /* The EINTR is not serious, and it seems you might get this more
         ofen when using the lib in a multi-threaded environment! */
      if(errno == EINTR)
        ;
      else
#endif
        done = TRUE; /* no more read or write */
      continue;
    case 0:  /* timeout */
    default: /* readable descriptors */

      result = Curl_readwrite(conn, &done);
      break;
    }
    if(result)
      return result;

    /* "done" signals to us if the transfer(s) are ready */
  }

  return CURLE_OK;
}

/*
 * Curl_pretransfer() is called immediately before a transfer starts.
 */
CURLcode Curl_pretransfer(struct SessionHandle *data)
{
  CURLcode res;
  if(!data->change.url) {
    /* we can't do anything wihout URL */
    failf(data, "No URL set!\n");
    return CURLE_URL_MALFORMAT;
  }

  /* Init the SSL session ID cache here. We do it here since we want to do it
     after the *_setopt() calls (that could change the size of the cache) but
     before any transfer takes place. */
  res = Curl_ssl_initsessions(data, data->set.ssl.numsessions);
  if(res)
    return res;

  data->set.followlocation=0; /* reset the location-follow counter */
  data->state.this_is_a_follow = FALSE; /* reset this */
  data->state.errorbuf = FALSE; /* no error has occurred */

  data->state.authproblem = FALSE;
  data->state.authhost.want = data->set.httpauth;
  data->state.authproxy.want = data->set.proxyauth;

  /* If there is a list of cookie files to read, do it now! */
  if(data->change.cookielist) {
    Curl_cookie_loadfiles(data);
  }

 /* Allow data->set.use_port to set which port to use. This needs to be
  * disabled for example when we follow Location: headers to URLs using
  * different ports! */
  data->state.allow_port = TRUE;

#if defined(HAVE_SIGNAL) && defined(SIGPIPE) && !defined(HAVE_MSG_NOSIGNAL)
  /*************************************************************
   * Tell signal handler to ignore SIGPIPE
   *************************************************************/
  if(!data->set.no_signal)
    data->state.prev_signal = signal(SIGPIPE, SIG_IGN);
#endif

  Curl_initinfo(data); /* reset session-specific information "variables" */
  Curl_pgrsStartNow(data);

  return CURLE_OK;
}

/*
 * Curl_posttransfer() is called immediately after a transfer ends
 */
CURLcode Curl_posttransfer(struct SessionHandle *data)
{
#if defined(HAVE_SIGNAL) && defined(SIGPIPE) && !defined(HAVE_MSG_NOSIGNAL)
  /* restore the signal handler for SIGPIPE before we get back */
  if(!data->set.no_signal)
    signal(SIGPIPE, data->state.prev_signal);
#else
  (void)data; /* unused parameter */
#endif

  if(!(data->progress.flags & PGRS_HIDE) &&
     !data->progress.callback)
    /* only output if we don't use a progress callback and we're not hidden */
    fprintf(data->set.err, "\n");

  return CURLE_OK;
}

/*
 * strlen_url() returns the length of the given URL if the spaces within the
 * URL were properly URL encoded.
 */
static int strlen_url(char *url)
{
  char *ptr;
  int newlen=0;
  bool left=TRUE; /* left side of the ? */

  for(ptr=url; *ptr; ptr++) {
    switch(*ptr) {
    case '?':
      left=FALSE;
    default:
      newlen++;
      break;
    case ' ':
      if(left)
        newlen+=3;
      else
        newlen++;
      break;
    }
  }
  return newlen;
}

/* strcpy_url() copies a url to a output buffer and URL-encodes the spaces in
 * the source URL accordingly.
 */
static void strcpy_url(char *output, char *url)
{
  /* we must add this with whitespace-replacing */
  bool left=TRUE;
  char *iptr;
  char *optr = output;
  for(iptr = url;    /* read from here */
      *iptr;         /* until zero byte */
      iptr++) {
    switch(*iptr) {
    case '?':
      left=FALSE;
    default:
      *optr++=*iptr;
      break;
    case ' ':
      if(left) {
        *optr++='%'; /* add a '%' */
        *optr++='2'; /* add a '2' */
        *optr++='0'; /* add a '0' */
      }
      else
        *optr++='+'; /* add a '+' here */
      break;
    }
  }
  *optr=0; /* zero terminate output buffer */

}

/*
 * Curl_follow() handles the URL redirect magic. Pass in the 'newurl' string
 * as given by the remote server and set up the new URL to request.
 */
CURLcode Curl_follow(struct SessionHandle *data,
                     char *newurl, /* this 'newurl' is the Location: string,
                                      and it must be malloc()ed before passed
                                      here */
                     bool retry) /* set TRUE if this is a request retry as
                                    opposed to a real redirect following */
{
  /* Location: redirect */
  char prot[16]; /* URL protocol string storage */
  char letter;   /* used for a silly sscanf */
  size_t newlen;
  char *newest;

  if(!retry) {
    if ((data->set.maxredirs != -1) &&
        (data->set.followlocation >= data->set.maxredirs)) {
      failf(data,"Maximum (%d) redirects followed", data->set.maxredirs);
      return CURLE_TOO_MANY_REDIRECTS;
    }

    /* mark the next request as a followed location: */
    data->state.this_is_a_follow = TRUE;

    data->set.followlocation++; /* count location-followers */
  }

  if(data->set.http_auto_referer) {
    /* We are asked to automatically set the previous URL as the
       referer when we get the next URL. We pick the ->url field,
       which may or may not be 100% correct */

    if(data->change.referer_alloc)
      /* If we already have an allocated referer, free this first */
      free(data->change.referer);

    data->change.referer = strdup(data->change.url);
    data->change.referer_alloc = TRUE; /* yes, free this later */
  }

  if(2 != sscanf(newurl, "%15[^?&/:]://%c", prot, &letter)) {
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

    char *useurl = newurl;
    size_t urllen;

    /* we must make our own copy of the URL to play with, as it may
       point to read-only data */
    char *url_clone=strdup(data->change.url);

    if(!url_clone)
      return CURLE_OUT_OF_MEMORY; /* skip out of this NOW */

    /* protsep points to the start of the host name */
    protsep=strstr(url_clone, "//");
    if(!protsep)
      protsep=url_clone;
    else
      protsep+=2; /* pass the slashes */

    if('/' != newurl[0]) {
      int level=0;

      /* First we need to find out if there's a ?-letter in the URL,
         and cut it and the right-side of that off */
      pathsep = strchr(protsep, '?');
      if(pathsep)
        *pathsep=0;

      /* we have a relative path to append to the last slash if
         there's one available */
      pathsep = strrchr(protsep, '/');
      if(pathsep)
        *pathsep=0;

      /* Check if there's any slash after the host name, and if so,
         remember that position instead */
      pathsep = strchr(protsep, '/');
      if(pathsep)
        protsep = pathsep+1;
      else
        protsep = NULL;

      /* now deal with one "./" or any amount of "../" in the newurl
         and act accordingly */

      if((useurl[0] == '.') && (useurl[1] == '/'))
        useurl+=2; /* just skip the "./" */

      while((useurl[0] == '.') &&
            (useurl[1] == '.') &&
            (useurl[2] == '/')) {
        level++;
        useurl+=3; /* pass the "../" */
      }

      if(protsep) {
        while(level--) {
          /* cut off one more level from the right of the original URL */
          pathsep = strrchr(protsep, '/');
          if(pathsep)
            *pathsep=0;
          else {
            *protsep=0;
            break;
          }
        }
      }
    }
    else {
      /* We got a new absolute path for this server, cut off from the
         first slash */
      pathsep = strchr(protsep, '/');
      if(pathsep) {
        /* When people use badly formatted URLs, such as
           "http://www.url.com?dir=/home/daniel" we must not use the first
           slash, if there's a ?-letter before it! */
        char *sep = strchr(protsep, '?');
        if(sep && (sep < pathsep))
          pathsep = sep;
        *pathsep=0;
      }
      else {
        /* There was no slash. Now, since we might be operating on a badly
           formatted URL, such as "http://www.url.com?id=2380" which doesn't
           use a slash separator as it is supposed to, we need to check for a
           ?-letter as well! */
        pathsep = strchr(protsep, '?');
        if(pathsep)
          *pathsep=0;
      }
    }

    /* If the new part contains a space, this is a mighty stupid redirect
       but we still make an effort to do "right". To the left of a '?'
       letter we replace each space with %20 while it is replaced with '+'
       on the right side of the '?' letter.
    */
    newlen = strlen_url(useurl);

    urllen = strlen(url_clone);

    newest=(char *)malloc( urllen + 1 + /* possible slash */
                           newlen + 1 /* zero byte */);

    if(!newest) {
      free(url_clone); /* don't leak this */
      return CURLE_OUT_OF_MEMORY; /* go out from this */
    }

    /* copy over the root url part */
    memcpy(newest, url_clone, urllen);

    /* check if we need to append a slash */
    if(('/' == useurl[0]) || (protsep && !*protsep))
      ;
    else
      newest[urllen++]='/';

    /* then append the new piece on the right side */
    strcpy_url(&newest[urllen], useurl);

    free(newurl); /* newurl is the allocated pointer */
    free(url_clone);
    newurl = newest;
  }
  else {
    /* This is an absolute URL, don't allow the custom port number */
    data->state.allow_port = FALSE;

    if(strchr(newurl, ' ')) {
      /* This new URL contains at least one space, this is a mighty stupid
         redirect but we still make an effort to do "right". */
      newlen = strlen_url(newurl);

      newest = malloc(newlen+1); /* get memory for this */
      if(newest) {
        strcpy_url(newest, newurl); /* create a space-free URL */

        free(newurl); /* that was no good */
        newurl = newest; /* use this instead now */
      }
    }

  }

  if(data->change.url_alloc)
    free(data->change.url);
  else
    data->change.url_alloc = TRUE; /* the URL is allocated */

  data->change.url = newurl;
  newurl = NULL; /* don't free! */

  infof(data, "Issue another request to this URL: '%s'\n", data->change.url);

  /*
   * We get here when the HTTP code is 300-399 (and 401). We need to perform
   * differently based on exactly what return code there was.
   *
   * News from 7.10.6: we can also get here on a 401 or 407, in case we act on
   * a HTTP (proxy-) authentication scheme other than Basic.
   */
  switch(data->info.httpcode) {
    /* 401 - Act on a www-authentication, we keep on moving and do the
       Authorization: XXXX header in the HTTP request code snippet */
    /* 407 - Act on a proxy-authentication, we keep on moving and do the
       Proxy-Authorization: XXXX header in the HTTP request code snippet */
    /* 300 - Multiple Choices */
    /* 306 - Not used */
    /* 307 - Temporary Redirect */
  default:  /* for all above (and the unknown ones) */
    /* Some codes are explicitly mentioned since I've checked RFC2616 and they
     * seem to be OK to POST to.
     */
    break;
  case 301: /* Moved Permanently */
    /* (quote from RFC2616, section 10.3.2):
     *
     * Note: When automatically redirecting a POST request after receiving a
     * 301 status code, some existing HTTP/1.0 user agents will erroneously
     * change it into a GET request.
     *
     * ----
     *
     * Warning: Because most of importants user agents do this obvious RFC2616
     * violation, many webservers expect this misbehavior. So these servers
     * often answers to a POST request with an error page.  To be sure that
     * libcurl gets the page that most user agents would get, libcurl has to
     * force GET:
     */
    if( data->set.httpreq == HTTPREQ_POST
        || data->set.httpreq == HTTPREQ_POST_FORM) {
      infof(data,
            "Violate RFC 2616/10.3.2 and switch from POST to GET\n");
      data->set.httpreq = HTTPREQ_GET;
    }
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
    if(data->set.httpreq != HTTPREQ_GET) {
      data->set.httpreq = HTTPREQ_GET; /* enforce GET request */
      infof(data, "Disables POST, goes with %s\n",
            data->set.opt_no_body?"HEAD":"GET");
    }
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
  Curl_pgrsTime(data, TIMER_REDIRECT);
  Curl_pgrsResetTimes(data);

  return CURLE_OK;
}

static CURLcode
Curl_connect_host(struct SessionHandle *data,
                  struct connectdata **conn)
{
  CURLcode res = CURLE_OK;
  int urlchanged = FALSE;

  do {
    bool async;
    bool protocol_done=TRUE; /* will be TRUE always since this is only used
                                within the easy interface */
    Curl_pgrsTime(data, TIMER_STARTSINGLE);
    data->change.url_changed = FALSE;
    res = Curl_connect(data, conn, &async, &protocol_done);

    if((CURLE_OK == res) && async) {
      /* Now, if async is TRUE here, we need to wait for the name
         to resolve */
      res = Curl_wait_for_resolv(*conn, NULL);
      if(CURLE_OK == res)
        /* Resolved, continue with the connection */
        res = Curl_async_resolved(*conn, &protocol_done);
      else
        /* if we can't resolve, we kill this "connection" now */
        (void)Curl_disconnect(*conn);
    }
    if(res)
      break;

    /* If a callback (or something) has altered the URL we should use within
       the Curl_connect(), we detect it here and act as if we are redirected
       to the new URL */
    urlchanged = data->change.url_changed;
    if ((CURLE_OK == res) && urlchanged) {
      res = Curl_done(conn, res);
      if(CURLE_OK == res) {
        char *gotourl = strdup(data->change.url);
        res = Curl_follow(data, gotourl, FALSE);
        if(res)
          free(gotourl);
      }
    }
  } while (urlchanged && res == CURLE_OK);

  return res;
}

/* Returns TRUE and sets '*url' if a request retry is wanted */
bool Curl_retry_request(struct connectdata *conn,
                        char **url)
{
  bool retry = FALSE;
  struct SessionHandle *data = conn->data;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;

  if((data->reqdata.keep.bytecount+k->headerbytecount == 0) &&
     conn->bits.reuse &&
     !conn->bits.no_body) {
    /* We got no data, we attempted to re-use a connection and yet we want a
       "body". This might happen if the connection was left alive when we were
       done using it before, but that was closed when we wanted to read from
       it again. Bad luck. Retry the same request on a fresh connect! */
    infof(conn->data, "Connection died, retrying a fresh connect\n");
    *url = strdup(conn->data->change.url);

    conn->bits.close = TRUE; /* close this connection */
    conn->bits.retry = TRUE; /* mark this as a connection we're about
                                to retry. Marking it this way should
                                prevent i.e HTTP transfers to return
                                error just because nothing has been
                                transfered! */
    retry = TRUE;
  }

  return retry;
}

/*
 * Curl_perform() is the internal high-level function that gets called by the
 * external curl_easy_perform() function. It inits, performs and cleans up a
 * single file transfer.
 */
CURLcode Curl_perform(struct SessionHandle *data)
{
  CURLcode res;
  CURLcode res2;
  struct connectdata *conn=NULL;
  char *newurl = NULL; /* possibly a new URL to follow to! */
  bool retry = FALSE;

  data->state.used_interface = Curl_if_easy;

  res = Curl_pretransfer(data);
  if(res)
    return res;

  /*
   * It is important that there is NO 'return' from this function at any other
   * place than falling down to the end of the function! This is because we
   * have cleanup stuff that must be done before we get back, and that is only
   * performed after this do-while loop.
   */

  do {
    res = Curl_connect_host(data, &conn);   /* primary connection */

    if(res == CURLE_OK) {
      bool do_done;
      if(data->set.connect_only) {
        /* keep connection open for application to use the socket */
        conn->bits.close = FALSE;
        res = Curl_done(&conn, CURLE_OK);
        break;
      }
      res = Curl_do(&conn, &do_done);

      if(res == CURLE_OK) {
        res = Transfer(conn); /* now fetch that URL please */
        if(res == CURLE_OK) {
          retry = Curl_retry_request(conn, &newurl);

          if(!retry)
            /*
             * We must duplicate the new URL here as the connection data may
             * be free()ed in the Curl_done() function.
             */
            newurl = data->reqdata.newurl?strdup(data->reqdata.newurl):NULL;
        }
        else {
          /* The transfer phase returned error, we mark the connection to get
           * closed to prevent being re-used. This is becasue we can't
           * possibly know if the connection is in a good shape or not now. */
          conn->bits.close = TRUE;

          if(CURL_SOCKET_BAD != conn->sock[SECONDARYSOCKET]) {
            /* if we failed anywhere, we must clean up the secondary socket if
               it was used */
            sclose(conn->sock[SECONDARYSOCKET]);
            conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD;
          }
        }

        /* Always run Curl_done(), even if some of the previous calls
           failed, but return the previous (original) error code */
        res2 = Curl_done(&conn, res);

        if(CURLE_OK == res)
          res = res2;
      }
      else
        /* Curl_do() failed, clean up left-overs in the done-call */
        res2 = Curl_done(&conn, res);

      /*
       * Important: 'conn' cannot be used here, since it may have been closed
       * in 'Curl_done' or other functions.
       */

      if((res == CURLE_OK) && newurl) {
        res = Curl_follow(data, newurl, retry);
        if(CURLE_OK == res) {
          newurl = NULL;
          continue;
        }
      }
    }
    break; /* it only reaches here when this shouldn't loop */

  } while(1); /* loop if Location: */

  if(newurl)
    free(newurl);

  if(res && !data->state.errorbuf) {
    /*
     * As an extra precaution: if no error string has been set and there was
     * an error, use the strerror() string or if things are so bad that not
     * even that is good, set a bad string that mentions the error code.
     */
    const char *str = curl_easy_strerror(res);
    if(!str)
      failf(data, "unspecified error %d", (int)res);
    else
      failf(data, "%s", str);
  }

  /* run post-transfer uncondionally, but don't clobber the return code if
     we already have an error code recorder */
  res2 = Curl_posttransfer(data);
  if(!res && res2)
    res = res2;

  return res;
}

/*
 * Curl_setup_transfer() is called to setup some basic properties for the upcoming
 * transfer.
 */
CURLcode
Curl_setup_transfer(
    struct connectdata *c_conn, /* connection data */
    int sockindex,       /* socket index to read from or -1 */
    curl_off_t size,     /* -1 if unknown at this point */
    bool getheader,      /* TRUE if header parsing is wanted */
    curl_off_t *bytecountp, /* return number of bytes read or NULL */
    int writesockindex,  /* socket index to write to, it may very
                            well be the same we read from. -1
                            disables */
    curl_off_t *writecountp /* return number of bytes written or
                               NULL */
   )
{
  struct connectdata *conn = (struct connectdata *)c_conn;
  struct SessionHandle *data = conn->data;

  if(!conn)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  curlassert((sockindex <= 1) && (sockindex >= -1));

  /* now copy all input parameters */
  conn->sockfd = sockindex == -1 ?
      CURL_SOCKET_BAD : conn->sock[sockindex];
  conn->writesockfd = writesockindex == -1 ?
      CURL_SOCKET_BAD:conn->sock[writesockindex];
  conn->bits.getheader = getheader;

  data->reqdata.size = size;
  data->reqdata.bytecountp = bytecountp;
  data->reqdata.writebytecountp = writecountp;

  return CURLE_OK;
}
