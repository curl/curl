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
 *   'pingpong' is for generic back-and-forth support functions used by FTP,
 *   IMAP, POP3, SMTP and whatever more that likes them.
 *
 ***************************************************************************/

#include "setup.h"

#include "urldata.h"
#include "sendf.h"
#include "select.h"
#include "progress.h"
#include "speedcheck.h"
#include "pingpong.h"
#include "multiif.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

#ifdef USE_PINGPONG

/* Returns timeout in ms. 0 or negative number means the timeout has already
   triggered */
long Curl_pp_state_timeout(struct pingpong *pp)
{
  struct connectdata *conn = pp->conn;
  struct SessionHandle *data=conn->data;
  long timeout_ms; /* in milliseconds */
  long timeout2_ms; /* in milliseconds */
  long response_time= (data->set.server_response_timeout)?
    data->set.server_response_timeout: pp->response_time;

  /* if CURLOPT_SERVER_RESPONSE_TIMEOUT is set, use that to determine
     remaining time, or use pp->response because SERVER_RESPONSE_TIMEOUT is
     supposed to govern the response for any given server response, not for
     the time from connect to the given server response. */

  /* Without a requested timeout, we only wait 'response_time' seconds for the
     full response to arrive before we bail out */
  timeout_ms = response_time -
    Curl_tvdiff(Curl_tvnow(), pp->response); /* spent time */

  if(data->set.timeout) {
    /* if timeout is requested, find out how much remaining time we have */
    timeout2_ms = data->set.timeout - /* timeout time */
      Curl_tvdiff(Curl_tvnow(), conn->now); /* spent time */

    /* pick the lowest number */
    timeout_ms = CURLMIN(timeout_ms, timeout2_ms);
  }

  return timeout_ms;
}


/*
 * Curl_pp_multi_statemach()
 *
 * called repeatedly until done when the multi interface is used.
 */
CURLcode Curl_pp_multi_statemach(struct pingpong *pp)
{
  struct connectdata *conn = pp->conn;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int rc;
  struct SessionHandle *data=conn->data;
  CURLcode result = CURLE_OK;
  long timeout_ms = Curl_pp_state_timeout(pp);

  if(timeout_ms <= 0) {
    failf(data, "server response timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  rc = Curl_socket_ready(pp->sendleft?CURL_SOCKET_BAD:sock, /* reading */
                         pp->sendleft?sock:CURL_SOCKET_BAD, /* writing */
                         0);

  if(rc == -1) {
    failf(data, "select/poll error");
    return CURLE_OUT_OF_MEMORY;
  }
  else if(rc != 0)
    result = pp->statemach_act(conn);

  /* if rc == 0, then select() timed out */

  return result;
}

/*
 * Curl_pp_easy_statemach()
 *
 * called repeatedly until done when the easy interface is used.
 */
CURLcode Curl_pp_easy_statemach(struct pingpong *pp)
{
  struct connectdata *conn = pp->conn;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int rc;
  long interval_ms;
  long timeout_ms = Curl_pp_state_timeout(pp);
  struct SessionHandle *data=conn->data;
  CURLcode result;

  if(timeout_ms <=0 ) {
    failf(data, "server response timeout");
    return CURLE_OPERATION_TIMEDOUT; /* already too little time */
  }

  interval_ms = 1000;  /* use 1 second timeout intervals */
  if(timeout_ms < interval_ms)
    interval_ms = timeout_ms;

  rc = Curl_socket_ready(pp->sendleft?CURL_SOCKET_BAD:sock, /* reading */
                         pp->sendleft?sock:CURL_SOCKET_BAD, /* writing */
                         (int)interval_ms);

  if(Curl_pgrsUpdate(conn))
    result = CURLE_ABORTED_BY_CALLBACK;
  else
    result = Curl_speedcheck(data, Curl_tvnow());

  if(result)
    ;
  else if(rc == -1) {
    failf(data, "select/poll error");
    result = CURLE_OUT_OF_MEMORY;
  }
  else if(rc)
    result = pp->statemach_act(conn);

  return result;
}

/* initialize stuff to prepare for reading a fresh new response */
void Curl_pp_init(struct pingpong *pp)
{
  struct connectdata *conn = pp->conn;
  pp->nread_resp = 0;
  pp->linestart_resp = conn->data->state.buffer;
  pp->pending_resp = TRUE;
  pp->response = Curl_tvnow(); /* start response time-out now! */
}



/***********************************************************************
 *
 * Curl_pp_vsendf()
 *
 * Send the formated string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * NOTE: we build the command in a fixed-length buffer, which sets length
 * restrictions on the command!
 *
 * made to never block
 */
CURLcode Curl_pp_vsendf(struct pingpong *pp,
                        const char *fmt,
                        va_list args)
{
  ssize_t bytes_written;
/* may still not be big enough for some krb5 tokens */
#define SBUF_SIZE 1024
  char s[SBUF_SIZE];
  size_t write_len;
  char *sptr=s;
  CURLcode res = CURLE_OK;
  struct connectdata *conn = pp->conn;
  struct SessionHandle *data = conn->data;

#if defined(HAVE_KRB4) || defined(HAVE_GSSAPI)
  enum protection_level data_sec = conn->data_prot;
#endif

  vsnprintf(s, SBUF_SIZE-3, fmt, args);

  strcat(s, "\r\n"); /* append a trailing CRLF */

  bytes_written=0;
  write_len = strlen(s);

  Curl_pp_init(pp);

#ifdef CURL_DOES_CONVERSIONS
  res = Curl_convert_to_network(data, s, write_len);
  /* Curl_convert_to_network calls failf if unsuccessful */
  if(res != CURLE_OK) {
    return res;
  }
#endif /* CURL_DOES_CONVERSIONS */

#if defined(HAVE_KRB4) || defined(HAVE_GSSAPI)
  conn->data_prot = PROT_CMD;
#endif
  res = Curl_write(conn, conn->sock[FIRSTSOCKET], sptr, write_len,
                   &bytes_written);
#if defined(HAVE_KRB4) || defined(HAVE_GSSAPI)
  DEBUGASSERT(data_sec > PROT_NONE && data_sec < PROT_LAST);
  conn->data_prot = data_sec;
#endif

  if(CURLE_OK != res)
    return res;

  if(conn->data->set.verbose)
    Curl_debug(conn->data, CURLINFO_HEADER_OUT,
               sptr, (size_t)bytes_written, conn);

  if(bytes_written != (ssize_t)write_len) {
    /* the whole chunk was not sent, store the rest of the data */
    write_len -= bytes_written;
    sptr += bytes_written;
    pp->sendthis = malloc(write_len);
    if(pp->sendthis) {
      memcpy(pp->sendthis, sptr, write_len);
      pp->sendsize = pp->sendleft = write_len;
    }
    else {
      failf(data, "out of memory");
      res = CURLE_OUT_OF_MEMORY;
    }
  }
  else
    pp->response = Curl_tvnow();

  return res;
}


/***********************************************************************
 *
 * Curl_pp_sendf()
 *
 * Send the formated string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * NOTE: we build the command in a fixed-length buffer, which sets length
 * restrictions on the command!
 *
 * made to never block
 */
CURLcode Curl_pp_sendf(struct pingpong *pp,
                       const char *fmt, ...)
{
  CURLcode res;
  va_list ap;
  va_start(ap, fmt);

  res = Curl_pp_vsendf(pp, fmt, ap);

  va_end(ap);

  return res;
}

/*
 * Curl_pp_readresp()
 *
 * Reads a piece of a server response.
 */
CURLcode Curl_pp_readresp(curl_socket_t sockfd,
                          struct pingpong *pp,
                          int *code, /* return the server code if done */
                          size_t *size) /* size of the response */
{
  ssize_t perline; /* count bytes per line */
  bool keepon=TRUE;
  ssize_t gotbytes;
  char *ptr;
  struct connectdata *conn = pp->conn;
  struct SessionHandle *data = conn->data;
  char * const buf = data->state.buffer;
  CURLcode result = CURLE_OK;

  *code = 0; /* 0 for errors or not done */
  *size = 0;

  ptr=buf + pp->nread_resp;

  /* number of bytes in the current line, so far */
  perline = (ssize_t)(ptr-pp->linestart_resp);

  keepon=TRUE;

  while((pp->nread_resp<BUFSIZE) && (keepon && !result)) {

    if(pp->cache) {
      /* we had data in the "cache", copy that instead of doing an actual
       * read
       *
       * ftp->cache_size is cast to int here.  This should be safe,
       * because it would have been populated with something of size
       * int to begin with, even though its datatype may be larger
       * than an int.
       */
      DEBUGASSERT((ptr+pp->cache_size) <= (buf+BUFSIZE+1));
      memcpy(ptr, pp->cache, pp->cache_size);
      gotbytes = (ssize_t)pp->cache_size;
      free(pp->cache);    /* free the cache */
      pp->cache = NULL;   /* clear the pointer */
      pp->cache_size = 0; /* zero the size just in case */
    }
    else {
      int res;
#if defined(HAVE_KRB4) || defined(HAVE_GSSAPI)
      enum protection_level prot = conn->data_prot;
      conn->data_prot = PROT_CLEAR;
#endif
      DEBUGASSERT((ptr+BUFSIZE-pp->nread_resp) <= (buf+BUFSIZE+1));
      res = Curl_read(conn, sockfd, ptr, BUFSIZE-pp->nread_resp,
                      &gotbytes);
#if defined(HAVE_KRB4) || defined(HAVE_GSSAPI)
      DEBUGASSERT(prot  > PROT_NONE && prot < PROT_LAST);
      conn->data_prot = prot;
#endif
      if(res == CURLE_AGAIN)
        return CURLE_OK; /* return */

#ifdef CURL_DOES_CONVERSIONS
      if((res == CURLE_OK) && (gotbytes > 0)) {
        /* convert from the network encoding */
        res = Curl_convert_from_network(data, ptr, gotbytes);
        /* Curl_convert_from_network calls failf if unsuccessful */
      }
#endif /* CURL_DOES_CONVERSIONS */

      if(CURLE_OK != res) {
        result = (CURLcode)res; /* Set outer result variable to this error. */
        keepon = FALSE;
      }
    }

    if(!keepon)
      ;
    else if(gotbytes <= 0) {
      keepon = FALSE;
      result = CURLE_RECV_ERROR;
      failf(data, "response reading failed");
    }
    else {
      /* we got a whole chunk of data, which can be anything from one
       * byte to a set of lines and possible just a piece of the last
       * line */
      ssize_t i;
      ssize_t clipamount = 0;
      bool restart = FALSE;

      data->req.headerbytecount += (long)gotbytes;

      pp->nread_resp += gotbytes;
      for(i = 0; i < gotbytes; ptr++, i++) {
        perline++;
        if(*ptr=='\n') {
          /* a newline is CRLF in ftp-talk, so the CR is ignored as
             the line isn't really terminated until the LF comes */

          /* output debug output if that is requested */
#if defined(HAVE_KRB4) || defined(HAVE_GSSAPI)
          if(!conn->sec_complete)
#endif
            if(data->set.verbose)
              Curl_debug(data, CURLINFO_HEADER_IN,
                         pp->linestart_resp, (size_t)perline, conn);

          /*
           * We pass all response-lines to the callback function registered
           * for "headers". The response lines can be seen as a kind of
           * headers.
           */
          result = Curl_client_write(conn, CLIENTWRITE_HEADER,
                                     pp->linestart_resp, perline);
          if(result)
            return result;

          if(pp->endofresp(pp, code)) {
            /* This is the end of the last line, copy the last line to the
               start of the buffer and zero terminate, for old times sake (and
               krb4)! */
            char *meow;
            int n;
            for(meow=pp->linestart_resp, n=0; meow<ptr; meow++, n++)
              buf[n] = *meow;
            *meow=0; /* zero terminate */
            keepon=FALSE;
            pp->linestart_resp = ptr+1; /* advance pointer */
            i++; /* skip this before getting out */

            *size = pp->nread_resp; /* size of the response */
            pp->nread_resp = 0; /* restart */
            break;
          }
          perline=0; /* line starts over here */
          pp->linestart_resp = ptr+1;
        }
      }

      if(!keepon && (i != gotbytes)) {
        /* We found the end of the response lines, but we didn't parse the
           full chunk of data we have read from the server. We therefore need
           to store the rest of the data to be checked on the next invoke as
           it may actually contain another end of response already! */
        clipamount = gotbytes - i;
        restart = TRUE;
      }
      else if(keepon) {

        if((perline == gotbytes) && (gotbytes > BUFSIZE/2)) {
          /* We got an excessive line without newlines and we need to deal
             with it. We keep the first bytes of the line then we throw
             away the rest. */
          infof(data, "Excessive server response line length received, %zd bytes."
                " Stripping\n", gotbytes);
          restart = TRUE;

          /* we keep 40 bytes since all our pingpong protocols are only
             interested in the first piece */
          clipamount = 40;
        }
        else if(pp->nread_resp > BUFSIZE/2) {
          /* We got a large chunk of data and there's potentially still trailing
             data to take care of, so we put any such part in the "cache", clear
             the buffer to make space and restart. */
          clipamount = perline;
          restart = TRUE;
        }
      }
      else if(i == gotbytes)
        restart = TRUE;

      if(clipamount) {
        pp->cache_size = clipamount;
        pp->cache = malloc(pp->cache_size);
        if(pp->cache)
          memcpy(pp->cache, pp->linestart_resp, pp->cache_size);
        else
          return CURLE_OUT_OF_MEMORY;
      }
      if(restart) {
        /* now reset a few variables to start over nicely from the start of
           the big buffer */
        pp->nread_resp = 0; /* start over from scratch in the buffer */
        ptr = pp->linestart_resp = buf;
        perline = 0;
      }

    } /* there was data */

  } /* while there's buffer left and loop is requested */

  pp->pending_resp = FALSE;

  return result;
}

int Curl_pp_getsock(struct pingpong *pp,
                    curl_socket_t *socks,
                    int numsocks)
{
  struct connectdata *conn = pp->conn;

  if(!numsocks)
    return GETSOCK_BLANK;

  socks[0] = conn->sock[FIRSTSOCKET];

  if(pp->sendleft) {
    /* write mode */
    return GETSOCK_WRITESOCK(0);
  }

  /* read mode */
  return GETSOCK_READSOCK(0);
}

CURLcode Curl_pp_flushsend(struct pingpong *pp)
{
  /* we have a piece of a command still left to send */
  struct connectdata *conn = pp->conn;
  ssize_t written;
  CURLcode result = CURLE_OK;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];

  result = Curl_write(conn, sock, pp->sendthis + pp->sendsize -
                      pp->sendleft, pp->sendleft, &written);
  if(result)
    return result;

  if(written != (ssize_t)pp->sendleft) {
    /* only a fraction was sent */
    pp->sendleft -= written;
  }
  else {
    free(pp->sendthis);
    pp->sendthis=NULL;
    pp->sendleft = pp->sendsize = 0;
    pp->response = Curl_tvnow();
  }
  return CURLE_OK;
}

CURLcode Curl_pp_disconnect(struct pingpong *pp)
{
  if(pp->cache) {
    free(pp->cache);
    pp->cache = NULL;
  }
  return CURLE_OK;
}



#endif
