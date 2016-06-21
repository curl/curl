/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include "strtoofft.h"
#include "strequal.h"
#include "rawstr.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
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
#include "vtls/vtls.h"
#include "select.h"
#include "multiif.h"
#include "connect.h"
#include "non-ascii.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * This function will call the read callback to fill our buffer with data
 * to upload.
 */
CURLcode Curl_fillreadbuffer(struct connectdata *conn, int bytes, int *nreadp)
{
  struct Curl_easy *data = conn->data;
  size_t buffersize = (size_t)bytes;
  int nread;
#ifdef CURL_DOES_CONVERSIONS
  bool sending_http_headers = FALSE;

  if(conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_RTSP)) {
    const struct HTTP *http = data->req.protop;

    if(http->sending == HTTPSEND_REQUEST)
      /* We're sending the HTTP request headers, not the data.
         Remember that so we don't re-translate them into garbage. */
      sending_http_headers = TRUE;
  }
#endif

  if(data->req.upload_chunky) {
    /* if chunked Transfer-Encoding */
    buffersize -= (8 + 2 + 2);   /* 32bit hex + CRLF + CRLF */
    data->req.upload_fromhere += (8 + 2); /* 32bit hex + CRLF */
  }

  /* this function returns a size_t, so we typecast to int to prevent warnings
     with picky compilers */
  nread = (int)data->state.fread_func(data->req.upload_fromhere, 1,
                                      buffersize, data->state.in);

  if(nread == CURL_READFUNC_ABORT) {
    failf(data, "operation aborted by callback");
    *nreadp = 0;
    return CURLE_ABORTED_BY_CALLBACK;
  }
  else if(nread == CURL_READFUNC_PAUSE) {

    if(conn->handler->flags & PROTOPT_NONETWORK) {
      /* protocols that work without network cannot be paused. This is
         actually only FILE:// just now, and it can't pause since the transfer
         isn't done using the "normal" procedure. */
      failf(data, "Read callback asked for PAUSE when not supported!");
      return CURLE_READ_ERROR;
    }
    else {
      struct SingleRequest *k = &data->req;
      /* CURL_READFUNC_PAUSE pauses read callbacks that feed socket writes */
      k->keepon |= KEEP_SEND_PAUSE; /* mark socket send as paused */
      if(data->req.upload_chunky) {
        /* Back out the preallocation done above */
        data->req.upload_fromhere -= (8 + 2);
      }
      *nreadp = 0;
    }
    return CURLE_OK; /* nothing was read */
  }
  else if((size_t)nread > buffersize) {
    /* the read function returned a too large value */
    *nreadp = 0;
    failf(data, "read function returned funny value");
    return CURLE_READ_ERROR;
  }

  if(!data->req.forbidchunk && data->req.upload_chunky) {
    /* if chunked Transfer-Encoding
     *    build chunk:
     *
     *        <HEX SIZE> CRLF
     *        <DATA> CRLF
     */
    /* On non-ASCII platforms the <DATA> may or may not be
       translated based on set.prefer_ascii while the protocol
       portion must always be translated to the network encoding.
       To further complicate matters, line end conversion might be
       done later on, so we need to prevent CRLFs from becoming
       CRCRLFs if that's the case.  To do this we use bare LFs
       here, knowing they'll become CRLFs later on.
     */

    char hexbuffer[11];
    const char *endofline_native;
    const char *endofline_network;
    int hexlen;

    if(
#ifdef CURL_DO_LINEEND_CONV
       (data->set.prefer_ascii) ||
#endif
       (data->set.crlf)) {
      /* \n will become \r\n later on */
      endofline_native  = "\n";
      endofline_network = "\x0a";
    }
    else {
      endofline_native  = "\r\n";
      endofline_network = "\x0d\x0a";
    }
    hexlen = snprintf(hexbuffer, sizeof(hexbuffer),
                      "%x%s", nread, endofline_native);

    /* move buffer pointer */
    data->req.upload_fromhere -= hexlen;
    nread += hexlen;

    /* copy the prefix to the buffer, leaving out the NUL */
    memcpy(data->req.upload_fromhere, hexbuffer, hexlen);

    /* always append ASCII CRLF to the data */
    memcpy(data->req.upload_fromhere + nread,
           endofline_network,
           strlen(endofline_network));

#ifdef CURL_DOES_CONVERSIONS
    CURLcode result;
    int length;
    if(data->set.prefer_ascii) {
      /* translate the protocol and data */
      length = nread;
    }
    else {
      /* just translate the protocol portion */
      length = strlen(hexbuffer);
    }
    result = Curl_convert_to_network(data, data->req.upload_fromhere, length);
    /* Curl_convert_to_network calls failf if unsuccessful */
    if(result)
      return result;
#endif /* CURL_DOES_CONVERSIONS */

    if((nread - hexlen) == 0)
      /* mark this as done once this chunk is transferred */
      data->req.upload_done = TRUE;

    nread+=(int)strlen(endofline_native); /* for the added end of line */
  }
#ifdef CURL_DOES_CONVERSIONS
  else if((data->set.prefer_ascii) && (!sending_http_headers)) {
    CURLcode result;
    result = Curl_convert_to_network(data, data->req.upload_fromhere, nread);
    /* Curl_convert_to_network calls failf if unsuccessful */
    if(result)
      return result;
  }
#endif /* CURL_DOES_CONVERSIONS */

  *nreadp = nread;

  return CURLE_OK;
}


/*
 * Curl_readrewind() rewinds the read stream. This is typically used for HTTP
 * POST/PUT with multi-pass authentication when a sending was denied and a
 * resend is necessary.
 */
CURLcode Curl_readrewind(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;

  conn->bits.rewindaftersend = FALSE; /* we rewind now */

  /* explicitly switch off sending data on this connection now since we are
     about to restart a new transfer and thus we want to avoid inadvertently
     sending more data on the existing connection until the next transfer
     starts */
  data->req.keepon &= ~KEEP_SEND;

  /* We have sent away data. If not using CURLOPT_POSTFIELDS or
     CURLOPT_HTTPPOST, call app to rewind
  */
  if(data->set.postfields ||
     (data->set.httpreq == HTTPREQ_POST_FORM))
    ; /* do nothing */
  else {
    if(data->set.seek_func) {
      int err;

      err = (data->set.seek_func)(data->set.seek_client, 0, SEEK_SET);
      if(err) {
        failf(data, "seek callback returned error %d", (int)err);
        return CURLE_SEND_FAIL_REWIND;
      }
    }
    else if(data->set.ioctl_func) {
      curlioerr err;

      err = (data->set.ioctl_func)(data, CURLIOCMD_RESTARTREAD,
                                   data->set.ioctl_client);
      infof(data, "the ioctl callback returned %d\n", (int)err);

      if(err) {
        /* FIXME: convert to a human readable error message */
        failf(data, "ioctl callback returned error %d", (int)err);
        return CURLE_SEND_FAIL_REWIND;
      }
    }
    else {
      /* If no CURLOPT_READFUNCTION is used, we know that we operate on a
         given FILE * stream and we can actually attempt to rewind that
         ourselves with fseek() */
      if(data->state.fread_func == (curl_read_callback)fread) {
        if(-1 != fseek(data->state.in, 0, SEEK_SET))
          /* successful rewind */
          return CURLE_OK;
      }

      /* no callback set or failure above, makes us fail at once */
      failf(data, "necessary data rewind wasn't possible");
      return CURLE_SEND_FAIL_REWIND;
    }
  }
  return CURLE_OK;
}

static int data_pending(const struct connectdata *conn)
{
  /* in the case of libssh2, we can never be really sure that we have emptied
     its internal buffers so we MUST always try until we get EAGAIN back */
  return conn->handler->protocol&(CURLPROTO_SCP|CURLPROTO_SFTP) ||
#if defined(USE_NGHTTP2)
    Curl_ssl_data_pending(conn, FIRSTSOCKET) ||
    /* For HTTP/2, we may read up everything including responde body
       with header fields in Curl_http_readwrite_headers. If no
       content-length is provided, curl waits for the connection
       close, which we emulate it using conn->proto.httpc.closed =
       TRUE. The thing is if we read everything, then http2_recv won't
       be called and we cannot signal the HTTP/2 stream has closed. As
       a workaround, we return nonzero here to call http2_recv. */
    ((conn->handler->protocol&PROTO_FAMILY_HTTP) && conn->httpversion == 20);
#else
    Curl_ssl_data_pending(conn, FIRSTSOCKET);
#endif
}

static void read_rewind(struct connectdata *conn,
                        size_t thismuch)
{
  DEBUGASSERT(conn->read_pos >= thismuch);

  conn->read_pos -= thismuch;
  conn->bits.stream_was_rewound = TRUE;

#ifdef DEBUGBUILD
  {
    char buf[512 + 1];
    size_t show;

    show = CURLMIN(conn->buf_len - conn->read_pos, sizeof(buf)-1);
    if(conn->master_buffer) {
      memcpy(buf, conn->master_buffer + conn->read_pos, show);
      buf[show] = '\0';
    }
    else {
      buf[0] = '\0';
    }

    DEBUGF(infof(conn->data,
                 "Buffer after stream rewind (read_pos = %zu): [%s]\n",
                 conn->read_pos, buf));
  }
#endif
}

/*
 * Check to see if CURLOPT_TIMECONDITION was met by comparing the time of the
 * remote document with the time provided by CURLOPT_TIMEVAL
 */
bool Curl_meets_timecondition(struct Curl_easy *data, time_t timeofdoc)
{
  if((timeofdoc == 0) || (data->set.timevalue == 0))
    return TRUE;

  switch(data->set.timecondition) {
  case CURL_TIMECOND_IFMODSINCE:
  default:
    if(timeofdoc <= data->set.timevalue) {
      infof(data,
            "The requested document is not new enough\n");
      data->info.timecond = TRUE;
      return FALSE;
    }
    break;
  case CURL_TIMECOND_IFUNMODSINCE:
    if(timeofdoc >= data->set.timevalue) {
      infof(data,
            "The requested document is not old enough\n");
      data->info.timecond = TRUE;
      return FALSE;
    }
    break;
  }

  return TRUE;
}

/*
 * Go ahead and do a read if we have a readable socket or if
 * the stream was rewound (in which case we have data in a
 * buffer)
 */
static CURLcode readwrite_data(struct Curl_easy *data,
                               struct connectdata *conn,
                               struct SingleRequest *k,
                               int *didwhat, bool *done)
{
  CURLcode result = CURLE_OK;
  ssize_t nread; /* number of bytes read */
  size_t excess = 0; /* excess bytes read */
  bool is_empty_data = FALSE;
  bool readmore = FALSE; /* used by RTP to signal for more data */
  int maxloops = 100;

  *done = FALSE;

  /* This is where we loop until we have read everything there is to
     read or we get a CURLE_AGAIN */
  do {
    size_t buffersize = data->set.buffer_size?
      data->set.buffer_size : BUFSIZE;
    size_t bytestoread = buffersize;

    if(
#if defined(USE_NGHTTP2)
       /* For HTTP/2, read data without caring about the content
          length. This is safe because body in HTTP/2 is always
          segmented thanks to its framing layer. Meanwhile, we have to
          call Curl_read to ensure that http2_handle_stream_close is
          called when we read all incoming bytes for a particular
          stream. */
       !((conn->handler->protocol & PROTO_FAMILY_HTTP) &&
         conn->httpversion == 20) &&
#endif
       k->size != -1 && !k->header) {
      /* make sure we don't read "too much" if we can help it since we
         might be pipelining and then someone else might want to read what
         follows! */
      curl_off_t totalleft = k->size - k->bytecount;
      if(totalleft < (curl_off_t)bytestoread)
        bytestoread = (size_t)totalleft;
    }

    if(bytestoread) {
      /* receive data from the network! */
      result = Curl_read(conn, conn->sockfd, k->buf, bytestoread, &nread);

      /* read would've blocked */
      if(CURLE_AGAIN == result)
        break; /* get out of loop */

      if(result>0)
        return result;
    }
    else {
      /* read nothing but since we wanted nothing we consider this an OK
         situation to proceed from */
      DEBUGF(infof(data, "readwrite_data: we're done!\n"));
      nread = 0;
    }

    if((k->bytecount == 0) && (k->writebytecount == 0)) {
      Curl_pgrsTime(data, TIMER_STARTTRANSFER);
      if(k->exp100 > EXP100_SEND_DATA)
        /* set time stamp to compare with when waiting for the 100 */
        k->start100 = Curl_tvnow();
    }

    *didwhat |= KEEP_RECV;
    /* indicates data of zero size, i.e. empty file */
    is_empty_data = ((nread == 0) && (k->bodywrites == 0)) ? TRUE : FALSE;

    /* NUL terminate, allowing string ops to be used */
    if(0 < nread || is_empty_data) {
      k->buf[nread] = 0;
    }
    else if(0 >= nread) {
      /* if we receive 0 or less here, the server closed the connection
         and we bail out from this! */
      DEBUGF(infof(data, "nread <= 0, server closed connection, bailing\n"));
      k->keepon &= ~KEEP_RECV;
      break;
    }

    /* Default buffer to use when we write the buffer, it may be changed
       in the flow below before the actual storing is done. */
    k->str = k->buf;

    if(conn->handler->readwrite) {
      result = conn->handler->readwrite(data, conn, &nread, &readmore);
      if(result)
        return result;
      if(readmore)
        break;
    }

#ifndef CURL_DISABLE_HTTP
    /* Since this is a two-state thing, we check if we are parsing
       headers at the moment or not. */
    if(k->header) {
      /* we are in parse-the-header-mode */
      bool stop_reading = FALSE;
      result = Curl_http_readwrite_headers(data, conn, &nread, &stop_reading);
      if(result)
        return result;

      if(conn->handler->readwrite &&
         (k->maxdownload <= 0 && nread > 0)) {
        result = conn->handler->readwrite(data, conn, &nread, &readmore);
        if(result)
          return result;
        if(readmore)
          break;
      }

      if(stop_reading) {
        /* We've stopped dealing with input, get out of the do-while loop */

        if(nread > 0) {
          if(Curl_pipeline_wanted(conn->data->multi, CURLPIPE_HTTP1)) {
            infof(data,
                  "Rewinding stream by : %zd"
                  " bytes on url %s (zero-length body)\n",
                  nread, data->state.path);
            read_rewind(conn, (size_t)nread);
          }
          else {
            infof(data,
                  "Excess found in a non pipelined read:"
                  " excess = %zd"
                  " url = %s (zero-length body)\n",
                  nread, data->state.path);
          }
        }

        break;
      }
    }
#endif /* CURL_DISABLE_HTTP */


    /* This is not an 'else if' since it may be a rest from the header
       parsing, where the beginning of the buffer is headers and the end
       is non-headers. */
    if(k->str && !k->header && (nread > 0 || is_empty_data)) {

#ifndef CURL_DISABLE_HTTP
      if(0 == k->bodywrites && !is_empty_data) {
        /* These checks are only made the first time we are about to
           write a piece of the body */
        if(conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_RTSP)) {
          /* HTTP-only checks */

          if(data->req.newurl) {
            if(conn->bits.close) {
              /* Abort after the headers if "follow Location" is set
                 and we're set to close anyway. */
              k->keepon &= ~KEEP_RECV;
              *done = TRUE;
              return CURLE_OK;
            }
            /* We have a new url to load, but since we want to be able
               to re-use this connection properly, we read the full
               response in "ignore more" */
            k->ignorebody = TRUE;
            infof(data, "Ignoring the response-body\n");
          }
          if(data->state.resume_from && !k->content_range &&
             (data->set.httpreq==HTTPREQ_GET) &&
             !k->ignorebody) {

            if(k->size == data->state.resume_from) {
              /* The resume point is at the end of file, consider this fine
                 even if it doesn't allow resume from here. */
              infof(data, "The entire document is already downloaded");
              connclose(conn, "already downloaded");
              /* Abort download */
              k->keepon &= ~KEEP_RECV;
              *done = TRUE;
              return CURLE_OK;
            }

            /* we wanted to resume a download, although the server doesn't
             * seem to support this and we did this with a GET (if it
             * wasn't a GET we did a POST or PUT resume) */
            failf(data, "HTTP server doesn't seem to support "
                  "byte ranges. Cannot resume.");
            return CURLE_RANGE_ERROR;
          }

          if(data->set.timecondition && !data->state.range) {
            /* A time condition has been set AND no ranges have been
               requested. This seems to be what chapter 13.3.4 of
               RFC 2616 defines to be the correct action for a
               HTTP/1.1 client */

            if(!Curl_meets_timecondition(data, k->timeofdoc)) {
              *done = TRUE;
              /* We're simulating a http 304 from server so we return
                 what should have been returned from the server */
              data->info.httpcode = 304;
              infof(data, "Simulate a HTTP 304 response!\n");
              /* we abort the transfer before it is completed == we ruin the
                 re-use ability. Close the connection */
              connclose(conn, "Simulated 304 handling");
              return CURLE_OK;
            }
          } /* we have a time condition */

        } /* this is HTTP or RTSP */
      } /* this is the first time we write a body part */
#endif /* CURL_DISABLE_HTTP */

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
      if(k->chunk) {
        /*
         * Here comes a chunked transfer flying and we need to decode this
         * properly.  While the name says read, this function both reads
         * and writes away the data. The returned 'nread' holds the number
         * of actual data it wrote to the client.
         */

        CHUNKcode res =
          Curl_httpchunk_read(conn, k->str, nread, &nread);

        if(CHUNKE_OK < res) {
          if(CHUNKE_WRITE_ERROR == res) {
            failf(data, "Failed writing data");
            return CURLE_WRITE_ERROR;
          }
          failf(data, "%s in chunked-encoding", Curl_chunked_strerror(res));
          return CURLE_RECV_ERROR;
        }
        else if(CHUNKE_STOP == res) {
          size_t dataleft;
          /* we're done reading chunks! */
          k->keepon &= ~KEEP_RECV; /* read no more */

          /* There are now possibly N number of bytes at the end of the
             str buffer that weren't written to the client.

             We DO care about this data if we are pipelining.
             Push it back to be read on the next pass. */

          dataleft = conn->chunk.dataleft;
          if(dataleft != 0) {
            infof(conn->data, "Leftovers after chunking: %zu bytes\n",
                  dataleft);
            if(Curl_pipeline_wanted(conn->data->multi, CURLPIPE_HTTP1)) {
              /* only attempt the rewind if we truly are pipelining */
              infof(conn->data, "Rewinding %zu bytes\n",dataleft);
              read_rewind(conn, dataleft);
            }
          }
        }
        /* If it returned OK, we just keep going */
      }
#endif   /* CURL_DISABLE_HTTP */

      /* Account for body content stored in the header buffer */
      if(k->badheader && !k->ignorebody) {
        DEBUGF(infof(data, "Increasing bytecount by %zu from hbuflen\n",
                     k->hbuflen));
        k->bytecount += k->hbuflen;
      }

      if((-1 != k->maxdownload) &&
         (k->bytecount + nread >= k->maxdownload)) {

        excess = (size_t)(k->bytecount + nread - k->maxdownload);
        if(excess > 0 && !k->ignorebody) {
          if(Curl_pipeline_wanted(conn->data->multi, CURLPIPE_HTTP1)) {
            /* The 'excess' amount below can't be more than BUFSIZE which
               always will fit in a size_t */
            infof(data,
                  "Rewinding stream by : %zu"
                  " bytes on url %s (size = %" CURL_FORMAT_CURL_OFF_T
                  ", maxdownload = %" CURL_FORMAT_CURL_OFF_T
                  ", bytecount = %" CURL_FORMAT_CURL_OFF_T ", nread = %zd)\n",
                  excess, data->state.path,
                  k->size, k->maxdownload, k->bytecount, nread);
            read_rewind(conn, excess);
          }
          else {
            infof(data,
                  "Excess found in a non pipelined read:"
                  " excess = %zu"
                  ", size = %" CURL_FORMAT_CURL_OFF_T
                  ", maxdownload = %" CURL_FORMAT_CURL_OFF_T
                  ", bytecount = %" CURL_FORMAT_CURL_OFF_T "\n",
                  excess, k->size, k->maxdownload, k->bytecount);
          }
        }

        nread = (ssize_t) (k->maxdownload - k->bytecount);
        if(nread < 0) /* this should be unusual */
          nread = 0;

        k->keepon &= ~KEEP_RECV; /* we're done reading */
      }

      k->bytecount += nread;

      Curl_pgrsSetDownloadCounter(data, k->bytecount);

      if(!k->chunk && (nread || k->badheader || is_empty_data)) {
        /* If this is chunky transfer, it was already written */

        if(k->badheader && !k->ignorebody) {
          /* we parsed a piece of data wrongly assuming it was a header
             and now we output it as body instead */

          /* Don't let excess data pollute body writes */
          if(k->maxdownload == -1 || (curl_off_t)k->hbuflen <= k->maxdownload)
            result = Curl_client_write(conn, CLIENTWRITE_BODY,
                                       data->state.headerbuff,
                                       k->hbuflen);
          else
            result = Curl_client_write(conn, CLIENTWRITE_BODY,
                                       data->state.headerbuff,
                                       (size_t)k->maxdownload);

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
          switch (conn->data->set.http_ce_skip ?
                  IDENTITY : k->auto_decoding) {
          case IDENTITY:
#endif
            /* This is the default when the server sends no
               Content-Encoding header. See Curl_readwrite_init; the
               memset() call initializes k->auto_decoding to zero. */
            if(!k->ignorebody) {

#ifndef CURL_DISABLE_POP3
              if(conn->handler->protocol&PROTO_FAMILY_POP3)
                result = Curl_pop3_write(conn, k->str, nread);
              else
#endif /* CURL_DISABLE_POP3 */

                result = Curl_client_write(conn, CLIENTWRITE_BODY, k->str,
                                           nread);
            }
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

    } /* if(!header and data to read) */

    if(conn->handler->readwrite &&
       (excess > 0 && !conn->bits.stream_was_rewound)) {
      /* Parse the excess data */
      k->str += nread;
      nread = (ssize_t)excess;

      result = conn->handler->readwrite(data, conn, &nread, &readmore);
      if(result)
        return result;

      if(readmore)
        k->keepon |= KEEP_RECV; /* we're not done reading */
      break;
    }

    if(is_empty_data) {
      /* if we received nothing, the server closed the connection and we
         are done */
      k->keepon &= ~KEEP_RECV;
    }

  } while(data_pending(conn) && maxloops--);

  if(((k->keepon & (KEEP_RECV|KEEP_SEND)) == KEEP_SEND) &&
     conn->bits.close) {
    /* When we've read the entire thing and the close bit is set, the server
       may now close the connection. If there's now any kind of sending going
       on from our side, we need to stop that immediately. */
    infof(data, "we are done reading and this is set to close, stop send\n");
    k->keepon &= ~KEEP_SEND; /* no writing anymore either */
  }

  return CURLE_OK;
}

static CURLcode done_sending(struct connectdata *conn,
                             struct SingleRequest *k)
{
  k->keepon &= ~KEEP_SEND; /* we're done writing */

  if(conn->bits.rewindaftersend) {
    CURLcode result = Curl_readrewind(conn);
    if(result)
      return result;
  }
  return CURLE_OK;
}


/*
 * Send data to upload to the server, when the socket is writable.
 */
static CURLcode readwrite_upload(struct Curl_easy *data,
                                 struct connectdata *conn,
                                 struct SingleRequest *k,
                                 int *didwhat)
{
  ssize_t i, si;
  ssize_t bytes_written;
  CURLcode result;
  ssize_t nread; /* number of bytes read */
  bool sending_http_headers = FALSE;

  if((k->bytecount == 0) && (k->writebytecount == 0))
    Curl_pgrsTime(data, TIMER_STARTTRANSFER);

  *didwhat |= KEEP_SEND;

  do {

    /* only read more data if there's no upload data already
       present in the upload buffer */
    if(0 == data->req.upload_present) {
      /* init the "upload from here" pointer */
      data->req.upload_fromhere = k->uploadbuf;

      if(!k->upload_done) {
        /* HTTP pollution, this should be written nicer to become more
           protocol agnostic. */
        int fillcount;
        struct HTTP *http = data->req.protop;

        if((k->exp100 == EXP100_SENDING_REQUEST) &&
           (http->sending == HTTPSEND_BODY)) {
          /* If this call is to send body data, we must take some action:
             We have sent off the full HTTP 1.1 request, and we shall now
             go into the Expect: 100 state and await such a header */
          k->exp100 = EXP100_AWAITING_CONTINUE; /* wait for the header */
          k->keepon &= ~KEEP_SEND;         /* disable writing */
          k->start100 = Curl_tvnow();       /* timeout count starts now */
          *didwhat &= ~KEEP_SEND;  /* we didn't write anything actually */

          /* set a timeout for the multi interface */
          Curl_expire(data, data->set.expect_100_timeout);
          break;
        }

        if(conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_RTSP)) {
          if(http->sending == HTTPSEND_REQUEST)
            /* We're sending the HTTP request headers, not the data.
               Remember that so we don't change the line endings. */
            sending_http_headers = TRUE;
          else
            sending_http_headers = FALSE;
        }

        result = Curl_fillreadbuffer(conn, BUFSIZE, &fillcount);
        if(result)
          return result;

        nread = (ssize_t)fillcount;
      }
      else
        nread = 0; /* we're done uploading/reading */

      if(!nread && (k->keepon & KEEP_SEND_PAUSE)) {
        /* this is a paused transfer */
        break;
      }
      else if(nread<=0) {
        result = done_sending(conn, k);
        if(result)
          return result;
        break;
      }

      /* store number of bytes available for upload */
      data->req.upload_present = nread;

      /* convert LF to CRLF if so asked */
      if((!sending_http_headers) && (
#ifdef CURL_DO_LINEEND_CONV
         /* always convert if we're FTPing in ASCII mode */
         (data->set.prefer_ascii) ||
#endif
         (data->set.crlf))) {
        /* Do we need to allocate a scratch buffer? */
        if(!data->state.scratch) {
          data->state.scratch = malloc(2 * BUFSIZE);
          if(!data->state.scratch) {
            failf(data, "Failed to alloc scratch buffer!");

            return CURLE_OUT_OF_MEMORY;
          }
        }

        /*
         * ASCII/EBCDIC Note: This is presumably a text (not binary)
         * transfer so the data should already be in ASCII.
         * That means the hex values for ASCII CR (0x0d) & LF (0x0a)
         * must be used instead of the escape sequences \r & \n.
         */
        for(i = 0, si = 0; i < nread; i++, si++) {
          if(data->req.upload_fromhere[i] == 0x0a) {
            data->state.scratch[si++] = 0x0d;
            data->state.scratch[si] = 0x0a;
            if(!data->set.crlf) {
              /* we're here only because FTP is in ASCII mode...
                 bump infilesize for the LF we just added */
              if(data->state.infilesize != -1)
                data->state.infilesize++;
            }
          }
          else
            data->state.scratch[si] = data->req.upload_fromhere[i];
        }

        if(si != nread) {
          /* only perform the special operation if we really did replace
             anything */
          nread = si;

          /* upload from the new (replaced) buffer instead */
          data->req.upload_fromhere = data->state.scratch;

          /* set the new amount too */
          data->req.upload_present = nread;
        }
      }

#ifndef CURL_DISABLE_SMTP
      if(conn->handler->protocol & PROTO_FAMILY_SMTP) {
        result = Curl_smtp_escape_eob(conn, nread);
        if(result)
          return result;
      }
#endif /* CURL_DISABLE_SMTP */
    } /* if 0 == data->req.upload_present */
    else {
      /* We have a partial buffer left from a previous "round". Use
         that instead of reading more data */
    }

    /* write to socket (send away data) */
    result = Curl_write(conn,
                        conn->writesockfd,     /* socket to send to */
                        data->req.upload_fromhere, /* buffer pointer */
                        data->req.upload_present,  /* buffer size */
                        &bytes_written);           /* actually sent */

    if(result)
      return result;

    if(data->set.verbose)
      /* show the data before we change the pointer upload_fromhere */
      Curl_debug(data, CURLINFO_DATA_OUT, data->req.upload_fromhere,
                 (size_t)bytes_written, conn);

    k->writebytecount += bytes_written;

    if(k->writebytecount == data->state.infilesize) {
      /* we have sent all data we were supposed to */
      k->upload_done = TRUE;
      infof(data, "We are completely uploaded and fine\n");
    }

    if(data->req.upload_present != bytes_written) {
      /* we only wrote a part of the buffer (if anything), deal with it! */

      /* store the amount of bytes left in the buffer to write */
      data->req.upload_present -= bytes_written;

      /* advance the pointer where to find the buffer when the next send
         is to happen */
      data->req.upload_fromhere += bytes_written;
    }
    else {
      /* we've uploaded that buffer now */
      data->req.upload_fromhere = k->uploadbuf;
      data->req.upload_present = 0; /* no more bytes left */

      if(k->upload_done) {
        result = done_sending(conn, k);
        if(result)
          return result;
      }
    }

    Curl_pgrsSetUploadCounter(data, k->writebytecount);

  } WHILE_FALSE; /* just to break out from! */

  return CURLE_OK;
}

/*
 * Curl_readwrite() is the low-level function to be called when data is to
 * be read and written to/from the connection.
 */
CURLcode Curl_readwrite(struct connectdata *conn,
                        struct Curl_easy *data,
                        bool *done)
{
  struct SingleRequest *k = &data->req;
  CURLcode result;
  int didwhat=0;

  curl_socket_t fd_read;
  curl_socket_t fd_write;
  int select_res = conn->cselect_bits;

  conn->cselect_bits = 0;

  /* only use the proper socket if the *_HOLD bit is not set simultaneously as
     then we are in rate limiting state in that transfer direction */

  if((k->keepon & KEEP_RECVBITS) == KEEP_RECV)
    fd_read = conn->sockfd;
  else
    fd_read = CURL_SOCKET_BAD;

  if((k->keepon & KEEP_SENDBITS) == KEEP_SEND)
    fd_write = conn->writesockfd;
  else
    fd_write = CURL_SOCKET_BAD;

  if(conn->data->state.drain) {
    select_res |= CURL_CSELECT_IN;
    DEBUGF(infof(data, "Curl_readwrite: forcibly told to drain data\n"));
  }

  if(!select_res) /* Call for select()/poll() only, if read/write/error
                     status is not known. */
    select_res = Curl_socket_ready(fd_read, fd_write, 0);

  if(select_res == CURL_CSELECT_ERR) {
    failf(data, "select/poll returned error");
    return CURLE_SEND_ERROR;
  }

  /* We go ahead and do a read if we have a readable socket or if
     the stream was rewound (in which case we have data in a
     buffer) */
  if((k->keepon & KEEP_RECV) &&
     ((select_res & CURL_CSELECT_IN) || conn->bits.stream_was_rewound)) {

    result = readwrite_data(data, conn, k, &didwhat, done);
    if(result || *done)
      return result;
  }

  /* If we still have writing to do, we check if we have a writable socket. */
  if((k->keepon & KEEP_SEND) && (select_res & CURL_CSELECT_OUT)) {
    /* write */

    result = readwrite_upload(data, conn, k, &didwhat);
    if(result)
      return result;
  }

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
    if(k->exp100 == EXP100_AWAITING_CONTINUE) {
      /* This should allow some time for the header to arrive, but only a
         very short time as otherwise it'll be too much wasted time too
         often. */

      /* Quoting RFC2616, section "8.2.3 Use of the 100 (Continue) Status":

         Therefore, when a client sends this header field to an origin server
         (possibly via a proxy) from which it has never seen a 100 (Continue)
         status, the client SHOULD NOT wait for an indefinite period before
         sending the request body.

      */

      long ms = Curl_tvdiff(k->now, k->start100);
      if(ms >= data->set.expect_100_timeout) {
        /* we've waited long enough, continue anyway */
        k->exp100 = EXP100_SEND_DATA;
        k->keepon |= KEEP_SEND;
        infof(data, "Done waiting for 100-continue\n");
      }
    }
  }

  if(Curl_pgrsUpdate(conn))
    result = CURLE_ABORTED_BY_CALLBACK;
  else
    result = Curl_speedcheck(data, k->now);
  if(result)
    return result;

  if(k->keepon) {
    if(0 > Curl_timeleft(data, &k->now, FALSE)) {
      if(k->size != -1) {
        failf(data, "Operation timed out after %ld milliseconds with %"
              CURL_FORMAT_CURL_OFF_T " out of %"
              CURL_FORMAT_CURL_OFF_T " bytes received",
              Curl_tvdiff(k->now, data->progress.t_startsingle), k->bytecount,
              k->size);
      }
      else {
        failf(data, "Operation timed out after %ld milliseconds with %"
              CURL_FORMAT_CURL_OFF_T " bytes received",
              Curl_tvdiff(k->now, data->progress.t_startsingle), k->bytecount);
      }
      return CURLE_OPERATION_TIMEDOUT;
    }
  }
  else {
    /*
     * The transfer has been performed. Just make some general checks before
     * returning.
     */

    if(!(data->set.opt_no_body) && (k->size != -1) &&
       (k->bytecount != k->size) &&
#ifdef CURL_DO_LINEEND_CONV
       /* Most FTP servers don't adjust their file SIZE response for CRLFs,
          so we'll check to see if the discrepancy can be explained
          by the number of CRLFs we've changed to LFs.
       */
       (k->bytecount != (k->size + data->state.crlf_conversions)) &&
#endif /* CURL_DO_LINEEND_CONV */
       !data->req.newurl) {
      failf(data, "transfer closed with %" CURL_FORMAT_CURL_OFF_T
            " bytes remaining to read",
            k->size - k->bytecount);
      return CURLE_PARTIAL_FILE;
    }
    else if(!(data->set.opt_no_body) &&
            k->chunk &&
            (conn->chunk.state != CHUNK_STOP)) {
      /*
       * In chunked mode, return an error if the connection is closed prior to
       * the empty (terminating) chunk is read.
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
  *done = (0 == (k->keepon&(KEEP_RECV|KEEP_SEND|
                            KEEP_RECV_PAUSE|KEEP_SEND_PAUSE))) ? TRUE : FALSE;

  return CURLE_OK;
}

/*
 * Curl_single_getsock() gets called by the multi interface code when the app
 * has requested to get the sockets for the current connection. This function
 * will then be called once for every connection that the multi interface
 * keeps track of. This function will only be called for connections that are
 * in the proper state to have this information available.
 */
int Curl_single_getsock(const struct connectdata *conn,
                        curl_socket_t *sock, /* points to numsocks number
                                                of sockets */
                        int numsocks)
{
  const struct Curl_easy *data = conn->data;
  int bitmap = GETSOCK_BLANK;
  unsigned sockindex = 0;

  if(conn->handler->perform_getsock)
    return conn->handler->perform_getsock(conn, sock, numsocks);

  if(numsocks < 2)
    /* simple check but we might need two slots */
    return GETSOCK_BLANK;

  /* don't include HOLD and PAUSE connections */
  if((data->req.keepon & KEEP_RECVBITS) == KEEP_RECV) {

    DEBUGASSERT(conn->sockfd != CURL_SOCKET_BAD);

    bitmap |= GETSOCK_READSOCK(sockindex);
    sock[sockindex] = conn->sockfd;
  }

  /* don't include HOLD and PAUSE connections */
  if((data->req.keepon & KEEP_SENDBITS) == KEEP_SEND) {

    if((conn->sockfd != conn->writesockfd) ||
       bitmap == GETSOCK_BLANK) {
      /* only if they are not the same socket and we have a readable
         one, we increase index */
      if(bitmap != GETSOCK_BLANK)
        sockindex++; /* increase index if we need two entries */

      DEBUGASSERT(conn->writesockfd != CURL_SOCKET_BAD);

      sock[sockindex] = conn->writesockfd;
    }

    bitmap |= GETSOCK_WRITESOCK(sockindex);
  }

  return bitmap;
}

/*
 * Determine optimum sleep time based on configured rate, current rate,
 * and packet size.
 * Returns value in milliseconds.
 *
 * The basic idea is to adjust the desired rate up/down in this method
 * based on whether we are running too slow or too fast.  Then, calculate
 * how many milliseconds to wait for the next packet to achieve this new
 * rate.
 */
long Curl_sleep_time(curl_off_t rate_bps, curl_off_t cur_rate_bps,
                             int pkt_size)
{
  curl_off_t min_sleep = 0;
  curl_off_t rv = 0;

  if(rate_bps == 0)
    return 0;

  /* If running faster than about .1% of the desired speed, slow
   * us down a bit.  Use shift instead of division as the 0.1%
   * cutoff is arbitrary anyway.
   */
  if(cur_rate_bps > (rate_bps + (rate_bps >> 10))) {
    /* running too fast, decrease target rate by 1/64th of rate */
    rate_bps -= rate_bps >> 6;
    min_sleep = 1;
  }
  else if(cur_rate_bps < (rate_bps - (rate_bps >> 10))) {
    /* running too slow, increase target rate by 1/64th of rate */
    rate_bps += rate_bps >> 6;
  }

  /* Determine number of milliseconds to wait until we do
   * the next packet at the adjusted rate.  We should wait
   * longer when using larger packets, for instance.
   */
  rv = ((curl_off_t)(pkt_size * 1000) / rate_bps);

  /* Catch rounding errors and always slow down at least 1ms if
   * we are running too fast.
   */
  if(rv < min_sleep)
    rv = min_sleep;

  /* Bound value to fit in 'long' on 32-bit platform.  That's
   * plenty long enough anyway!
   */
  if(rv > 0x7fffffff)
    rv = 0x7fffffff;

  return (long)rv;
}

/* Curl_init_CONNECT() gets called each time the handle switches to CONNECT
   which means this gets called once for each subsequent redirect etc */
void Curl_init_CONNECT(struct Curl_easy *data)
{
  data->state.fread_func = data->set.fread_func_set;
  data->state.in = data->set.in_set;
}

/*
 * Curl_pretransfer() is called immediately before a transfer starts, and only
 * once for one transfer no matter if it has redirects or do multi-pass
 * authentication etc.
 */
CURLcode Curl_pretransfer(struct Curl_easy *data)
{
  CURLcode result;
  if(!data->change.url) {
    /* we can't do anything without URL */
    failf(data, "No URL set!");
    return CURLE_URL_MALFORMAT;
  }

  /* Init the SSL session ID cache here. We do it here since we want to do it
     after the *_setopt() calls (that could specify the size of the cache) but
     before any transfer takes place. */
  result = Curl_ssl_initsessions(data, data->set.ssl.max_ssl_sessions);
  if(result)
    return result;

  data->set.followlocation=0; /* reset the location-follow counter */
  data->state.this_is_a_follow = FALSE; /* reset this */
  data->state.errorbuf = FALSE; /* no error has occurred */
  data->state.httpversion = 0; /* don't assume any particular server version */

  data->state.authproblem = FALSE;
  data->state.authhost.want = data->set.httpauth;
  data->state.authproxy.want = data->set.proxyauth;
  Curl_safefree(data->info.wouldredirect);
  data->info.wouldredirect = NULL;

  if(data->set.httpreq == HTTPREQ_PUT)
    data->state.infilesize = data->set.filesize;
  else
    data->state.infilesize = data->set.postfieldsize;

  /* If there is a list of cookie files to read, do it now! */
  if(data->change.cookielist)
    Curl_cookie_loadfiles(data);

  /* If there is a list of host pairs to deal with */
  if(data->change.resolve)
    result = Curl_loadhostpairs(data);

  if(!result) {
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
    Curl_pgrsResetTimesSizes(data);
    Curl_pgrsStartNow(data);

    if(data->set.timeout)
      Curl_expire(data, data->set.timeout);

    if(data->set.connecttimeout)
      Curl_expire(data, data->set.connecttimeout);

    /* In case the handle is re-used and an authentication method was picked
       in the session we need to make sure we only use the one(s) we now
       consider to be fine */
    data->state.authhost.picked &= data->state.authhost.want;
    data->state.authproxy.picked &= data->state.authproxy.want;

    if(data->set.wildcardmatch) {
      struct WildcardData *wc = &data->wildcard;
      if(!wc->filelist) {
        result = Curl_wildcard_init(wc); /* init wildcard structures */
        if(result)
          return CURLE_OUT_OF_MEMORY;
      }
    }

  }

  return result;
}

/*
 * Curl_posttransfer() is called immediately after a transfer ends
 */
CURLcode Curl_posttransfer(struct Curl_easy *data)
{
#if defined(HAVE_SIGNAL) && defined(SIGPIPE) && !defined(HAVE_MSG_NOSIGNAL)
  /* restore the signal handler for SIGPIPE before we get back */
  if(!data->set.no_signal)
    signal(SIGPIPE, data->state.prev_signal);
#else
  (void)data; /* unused parameter */
#endif

  return CURLE_OK;
}

#ifndef CURL_DISABLE_HTTP
/*
 * strlen_url() returns the length of the given URL if the spaces within the
 * URL were properly URL encoded.
 */
static size_t strlen_url(const char *url)
{
  const unsigned char *ptr;
  size_t newlen=0;
  bool left=TRUE; /* left side of the ? */

  for(ptr=(unsigned char *)url; *ptr; ptr++) {
    switch(*ptr) {
    case '?':
      left=FALSE;
      /* fall through */
    default:
      if(*ptr >= 0x80)
        newlen += 2;
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
static void strcpy_url(char *output, const char *url)
{
  /* we must add this with whitespace-replacing */
  bool left=TRUE;
  const unsigned char *iptr;
  char *optr = output;
  for(iptr = (unsigned char *)url;    /* read from here */
      *iptr;         /* until zero byte */
      iptr++) {
    switch(*iptr) {
    case '?':
      left=FALSE;
      /* fall through */
    default:
      if(*iptr >= 0x80) {
        snprintf(optr, 4, "%%%02x", *iptr);
        optr += 3;
      }
      else
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
 * Returns true if the given URL is absolute (as opposed to relative)
 */
static bool is_absolute_url(const char *url)
{
  char prot[16]; /* URL protocol string storage */
  char letter;   /* used for a silly sscanf */

  return (2 == sscanf(url, "%15[^?&/:]://%c", prot, &letter)) ? TRUE : FALSE;
}

/*
 * Concatenate a relative URL to a base URL making it absolute.
 * URL-encodes any spaces.
 * The returned pointer must be freed by the caller unless NULL
 * (returns NULL on out of memory).
 */
static char *concat_url(const char *base, const char *relurl)
{
  /***
   TRY to append this new path to the old URL
   to the right of the host part. Oh crap, this is doomed to cause
   problems in the future...
  */
  char *newest;
  char *protsep;
  char *pathsep;
  size_t newlen;

  const char *useurl = relurl;
  size_t urllen;

  /* we must make our own copy of the URL to play with, as it may
     point to read-only data */
  char *url_clone=strdup(base);

  if(!url_clone)
    return NULL; /* skip out of this NOW */

  /* protsep points to the start of the host name */
  protsep=strstr(url_clone, "//");
  if(!protsep)
    protsep=url_clone;
  else
    protsep+=2; /* pass the slashes */

  if('/' != relurl[0]) {
    int level=0;

    /* First we need to find out if there's a ?-letter in the URL,
       and cut it and the right-side of that off */
    pathsep = strchr(protsep, '?');
    if(pathsep)
      *pathsep=0;

    /* we have a relative path to append to the last slash if there's one
       available, or if the new URL is just a query string (starts with a
       '?')  we append the new one at the end of the entire currently worked
       out URL */
    if(useurl[0] != '?') {
      pathsep = strrchr(protsep, '/');
      if(pathsep)
        *pathsep=0;
    }

    /* Check if there's any slash after the host name, and if so, remember
       that position instead */
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
    /* We got a new absolute path for this server */

    if((relurl[0] == '/') && (relurl[1] == '/')) {
      /* the new URL starts with //, just keep the protocol part from the
         original one */
      *protsep=0;
      useurl = &relurl[2]; /* we keep the slashes from the original, so we
                              skip the new ones */
    }
    else {
      /* cut off the original URL from the first slash, or deal with URLs
         without slash */
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
  }

  /* If the new part contains a space, this is a mighty stupid redirect
     but we still make an effort to do "right". To the left of a '?'
     letter we replace each space with %20 while it is replaced with '+'
     on the right side of the '?' letter.
  */
  newlen = strlen_url(useurl);

  urllen = strlen(url_clone);

  newest = malloc(urllen + 1 + /* possible slash */
                  newlen + 1 /* zero byte */);

  if(!newest) {
    free(url_clone); /* don't leak this */
    return NULL;
  }

  /* copy over the root url part */
  memcpy(newest, url_clone, urllen);

  /* check if we need to append a slash */
  if(('/' == useurl[0]) || (protsep && !*protsep) || ('?' == useurl[0]))
    ;
  else
    newest[urllen++]='/';

  /* then append the new piece on the right side */
  strcpy_url(&newest[urllen], useurl);

  free(url_clone);

  return newest;
}
#endif /* CURL_DISABLE_HTTP */

/*
 * Curl_follow() handles the URL redirect magic. Pass in the 'newurl' string
 * as given by the remote server and set up the new URL to request.
 */
CURLcode Curl_follow(struct Curl_easy *data,
                     char *newurl, /* this 'newurl' is the Location: string,
                                      and it must be malloc()ed before passed
                                      here */
                     followtype type) /* see transfer.h */
{
#ifdef CURL_DISABLE_HTTP
  (void)data;
  (void)newurl;
  (void)type;
  /* Location: following will not happen when HTTP is disabled */
  return CURLE_TOO_MANY_REDIRECTS;
#else

  /* Location: redirect */
  bool disallowport = FALSE;

  if(type == FOLLOW_REDIR) {
    if((data->set.maxredirs != -1) &&
        (data->set.followlocation >= data->set.maxredirs)) {
      failf(data, "Maximum (%ld) redirects followed", data->set.maxredirs);
      return CURLE_TOO_MANY_REDIRECTS;
    }

    /* mark the next request as a followed location: */
    data->state.this_is_a_follow = TRUE;

    data->set.followlocation++; /* count location-followers */

    if(data->set.http_auto_referer) {
      /* We are asked to automatically set the previous URL as the referer
         when we get the next URL. We pick the ->url field, which may or may
         not be 100% correct */

      if(data->change.referer_alloc) {
        Curl_safefree(data->change.referer);
        data->change.referer_alloc = FALSE;
      }

      data->change.referer = strdup(data->change.url);
      if(!data->change.referer)
        return CURLE_OUT_OF_MEMORY;
      data->change.referer_alloc = TRUE; /* yes, free this later */
    }
  }

  if(!is_absolute_url(newurl))  {
    /***
     *DANG* this is an RFC 2068 violation. The URL is supposed
     to be absolute and this doesn't seem to be that!
     */
    char *absolute = concat_url(data->change.url, newurl);
    if(!absolute)
      return CURLE_OUT_OF_MEMORY;
    free(newurl);
    newurl = absolute;
  }
  else {
    /* The new URL MAY contain space or high byte values, that means a mighty
       stupid redirect URL but we still make an effort to do "right". */
    char *newest;
    size_t newlen = strlen_url(newurl);

    /* This is an absolute URL, don't allow the custom port number */
    disallowport = TRUE;

    newest = malloc(newlen+1); /* get memory for this */
    if(!newest)
      return CURLE_OUT_OF_MEMORY;
    strcpy_url(newest, newurl); /* create a space-free URL */

    free(newurl); /* that was no good */
    newurl = newest; /* use this instead now */

  }

  if(type == FOLLOW_FAKE) {
    /* we're only figuring out the new url if we would've followed locations
       but now we're done so we can get out! */
    data->info.wouldredirect = newurl;
    return CURLE_OK;
  }

  if(disallowport)
    data->state.allow_port = FALSE;

  if(data->change.url_alloc) {
    Curl_safefree(data->change.url);
    data->change.url_alloc = FALSE;
  }

  data->change.url = newurl;
  data->change.url_alloc = TRUE;
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
    /* 401 - Act on a WWW-Authenticate, we keep on moving and do the
       Authorization: XXXX header in the HTTP request code snippet */
    /* 407 - Act on a Proxy-Authenticate, we keep on moving and do the
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
    /* (quote from RFC7231, section 6.4.2)
     *
     * Note: For historical reasons, a user agent MAY change the request
     * method from POST to GET for the subsequent request.  If this
     * behavior is undesired, the 307 (Temporary Redirect) status code
     * can be used instead.
     *
     * ----
     *
     * Many webservers expect this, so these servers often answers to a POST
     * request with an error page. To be sure that libcurl gets the page that
     * most user agents would get, libcurl has to force GET.
     *
     * This behaviour is forbidden by RFC1945 and the obsolete RFC2616, and
     * can be overridden with CURLOPT_POSTREDIR.
     */
    if((data->set.httpreq == HTTPREQ_POST
        || data->set.httpreq == HTTPREQ_POST_FORM)
       && !(data->set.keep_post & CURL_REDIR_POST_301)) {
      infof(data, "Switch from POST to GET\n");
      data->set.httpreq = HTTPREQ_GET;
    }
    break;
  case 302: /* Found */
    /* (quote from RFC7231, section 6.4.3)
     *
     * Note: For historical reasons, a user agent MAY change the request
     * method from POST to GET for the subsequent request.  If this
     * behavior is undesired, the 307 (Temporary Redirect) status code
     * can be used instead.
     *
     * ----
     *
     * Many webservers expect this, so these servers often answers to a POST
     * request with an error page. To be sure that libcurl gets the page that
     * most user agents would get, libcurl has to force GET.
     *
     * This behaviour is forbidden by RFC1945 and the obsolete RFC2616, and
     * can be overridden with CURLOPT_POSTREDIR.
     */
    if((data->set.httpreq == HTTPREQ_POST
        || data->set.httpreq == HTTPREQ_POST_FORM)
       && !(data->set.keep_post & CURL_REDIR_POST_302)) {
      infof(data, "Switch from POST to GET\n");
      data->set.httpreq = HTTPREQ_GET;
    }
    break;

  case 303: /* See Other */
    /* Disable both types of POSTs, unless the user explicitely
       asks for POST after POST */
    if(data->set.httpreq != HTTPREQ_GET
      && !(data->set.keep_post & CURL_REDIR_POST_303)) {
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
  Curl_pgrsResetTimesSizes(data);

  return CURLE_OK;
#endif /* CURL_DISABLE_HTTP */
}

/* Returns CURLE_OK *and* sets '*url' if a request retry is wanted.

   NOTE: that the *url is malloc()ed. */
CURLcode Curl_retry_request(struct connectdata *conn,
                            char **url)
{
  struct Curl_easy *data = conn->data;

  *url = NULL;

  /* if we're talking upload, we can't do the checks below, unless the protocol
     is HTTP as when uploading over HTTP we will still get a response */
  if(data->set.upload &&
     !(conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_RTSP)))
    return CURLE_OK;

  if((data->req.bytecount + data->req.headerbytecount == 0) &&
      conn->bits.reuse &&
      !data->set.opt_no_body &&
      (data->set.rtspreq != RTSPREQ_RECEIVE)) {
    /* We got no data, we attempted to re-use a connection and yet we want a
       "body". This might happen if the connection was left alive when we were
       done using it before, but that was closed when we wanted to read from
       it again. Bad luck. Retry the same request on a fresh connect! */
    infof(conn->data, "Connection died, retrying a fresh connect\n");
    *url = strdup(conn->data->change.url);
    if(!*url)
      return CURLE_OUT_OF_MEMORY;

    connclose(conn, "retry"); /* close this connection */
    conn->bits.retry = TRUE; /* mark this as a connection we're about
                                to retry. Marking it this way should
                                prevent i.e HTTP transfers to return
                                error just because nothing has been
                                transferred! */


    if(conn->handler->protocol&PROTO_FAMILY_HTTP) {
      struct HTTP *http = data->req.protop;
      if(http->writebytecount)
        return Curl_readrewind(conn);
    }
  }
  return CURLE_OK;
}

/*
 * Curl_setup_transfer() is called to setup some basic properties for the
 * upcoming transfer.
 */
void
Curl_setup_transfer(
  struct connectdata *conn, /* connection data */
  int sockindex,            /* socket index to read from or -1 */
  curl_off_t size,          /* -1 if unknown at this point */
  bool getheader,           /* TRUE if header parsing is wanted */
  curl_off_t *bytecountp,   /* return number of bytes read or NULL */
  int writesockindex,       /* socket index to write to, it may very well be
                               the same we read from. -1 disables */
  curl_off_t *writecountp   /* return number of bytes written or NULL */
  )
{
  struct Curl_easy *data;
  struct SingleRequest *k;

  DEBUGASSERT(conn != NULL);

  data = conn->data;
  k = &data->req;

  DEBUGASSERT((sockindex <= 1) && (sockindex >= -1));

  /* now copy all input parameters */
  conn->sockfd = sockindex == -1 ?
      CURL_SOCKET_BAD : conn->sock[sockindex];
  conn->writesockfd = writesockindex == -1 ?
      CURL_SOCKET_BAD:conn->sock[writesockindex];
  k->getheader = getheader;

  k->size = size;
  k->bytecountp = bytecountp;
  k->writebytecountp = writecountp;

  /* The code sequence below is placed in this function just because all
     necessary input is not always known in do_complete() as this function may
     be called after that */

  if(!k->getheader) {
    k->header = FALSE;
    if(size > 0)
      Curl_pgrsSetDownloadSize(data, size);
  }
  /* we want header and/or body, if neither then don't do this! */
  if(k->getheader || !data->set.opt_no_body) {

    if(conn->sockfd != CURL_SOCKET_BAD)
      k->keepon |= KEEP_RECV;

    if(conn->writesockfd != CURL_SOCKET_BAD) {
      struct HTTP *http = data->req.protop;
      /* HTTP 1.1 magic:

         Even if we require a 100-return code before uploading data, we might
         need to write data before that since the REQUEST may not have been
         finished sent off just yet.

         Thus, we must check if the request has been sent before we set the
         state info where we wait for the 100-return code
      */
      if((data->state.expect100header) &&
         (conn->handler->protocol&PROTO_FAMILY_HTTP) &&
         (http->sending == HTTPSEND_BODY)) {
        /* wait with write until we either got 100-continue or a timeout */
        k->exp100 = EXP100_AWAITING_CONTINUE;
        k->start100 = Curl_tvnow();

        /* Set a timeout for the multi interface. Add the inaccuracy margin so
           that we don't fire slightly too early and get denied to run. */
        Curl_expire(data, data->set.expect_100_timeout);
      }
      else {
        if(data->state.expect100header)
          /* when we've sent off the rest of the headers, we must await a
             100-continue but first finish sending the request */
          k->exp100 = EXP100_SENDING_REQUEST;

        /* enable the write bit when we're not waiting for continue */
        k->keepon |= KEEP_SEND;
      }
    } /* if(conn->writesockfd != CURL_SOCKET_BAD) */
  } /* if(k->getheader || !data->set.opt_no_body) */

}
