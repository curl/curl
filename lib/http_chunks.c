/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifndef CURL_DISABLE_HTTP

#include "urldata.h" /* it includes http_chunks.h */
#include "sendf.h"   /* for the client write stuff */

#include "content_encoding.h"
#include "http.h"
#include "curl_memory.h"
#include "non-ascii.h" /* for Curl_convert_to_network prototype */
#include "strtoofft.h"
#include "warnless.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/*
 * Chunk format (simplified):
 *
 * <HEX SIZE>[ chunk extension ] CRLF
 * <DATA> CRLF
 *
 * Highlights from RFC2616 section 3.6 say:

   The chunked encoding modifies the body of a message in order to
   transfer it as a series of chunks, each with its own size indicator,
   followed by an OPTIONAL trailer containing entity-header fields. This
   allows dynamically produced content to be transferred along with the
   information necessary for the recipient to verify that it has
   received the full message.

       Chunked-Body   = *chunk
                        last-chunk
                        trailer
                        CRLF

       chunk          = chunk-size [ chunk-extension ] CRLF
                        chunk-data CRLF
       chunk-size     = 1*HEX
       last-chunk     = 1*("0") [ chunk-extension ] CRLF

       chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
       chunk-ext-name = token
       chunk-ext-val  = token | quoted-string
       chunk-data     = chunk-size(OCTET)
       trailer        = *(entity-header CRLF)

   The chunk-size field is a string of hex digits indicating the size of
   the chunk. The chunked encoding is ended by any chunk whose size is
   zero, followed by the trailer, which is terminated by an empty line.

 */

/* Check for an ASCII hex digit.
 We avoid the use of isxdigit to accommodate non-ASCII hosts. */
static bool Curl_isxdigit(char digit)
{
  return ( (digit >= 0x30 && digit <= 0x39) /* 0-9 */
        || (digit >= 0x41 && digit <= 0x46) /* A-F */
        || (digit >= 0x61 && digit <= 0x66) /* a-f */ ) ? TRUE : FALSE;
}

void Curl_httpchunk_init(struct connectdata *conn)
{
  struct Curl_chunker *chunk = &conn->chunk;
  chunk->hexindex=0;        /* start at 0 */
  chunk->dataleft=0;        /* no data left yet! */
  chunk->state = CHUNK_HEX; /* we get hex first! */
}

/*
 * chunk_read() returns a OK for normal operations, or a positive return code
 * for errors. STOP means this sequence of chunks is complete.  The 'wrote'
 * argument is set to tell the caller how many bytes we actually passed to the
 * client (for byte-counting and whatever).
 *
 * The states and the state-machine is further explained in the header file.
 *
 * This function always uses ASCII hex values to accommodate non-ASCII hosts.
 * For example, 0x0d and 0x0a are used instead of '\r' and '\n'.
 */
CHUNKcode Curl_httpchunk_read(struct connectdata *conn,
                              char *datap,
                              ssize_t datalen,
                              ssize_t *wrotep)
{
  CURLcode result=CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct Curl_chunker *ch = &conn->chunk;
  struct SingleRequest *k = &data->req;
  size_t piece;
  curl_off_t length = (curl_off_t)datalen;
  size_t *wrote = (size_t *)wrotep;

  *wrote = 0; /* nothing's written yet */

  /* the original data is written to the client, but we go on with the
     chunk read process, to properly calculate the content length*/
  if(data->set.http_te_skip && !k->ignorebody) {
    result = Curl_client_write(conn, CLIENTWRITE_BODY, datap, datalen);
    if(result)
      return CHUNKE_WRITE_ERROR;
  }

  while(length) {
    switch(ch->state) {
    case CHUNK_HEX:
      if(Curl_isxdigit(*datap)) {
        if(ch->hexindex < MAXNUM_SIZE) {
          ch->hexbuffer[ch->hexindex] = *datap;
          datap++;
          length--;
          ch->hexindex++;
        }
        else {
          return CHUNKE_TOO_LONG_HEX; /* longer hex than we support */
        }
      }
      else {
        char *endptr;
        if(0 == ch->hexindex)
          /* This is illegal data, we received junk where we expected
             a hexadecimal digit. */
          return CHUNKE_ILLEGAL_HEX;

        /* length and datap are unmodified */
        ch->hexbuffer[ch->hexindex]=0;

        /* convert to host encoding before calling strtoul */
        result = Curl_convert_from_network(conn->data, ch->hexbuffer,
                                           ch->hexindex);
        if(result) {
          /* Curl_convert_from_network calls failf if unsuccessful */
          /* Treat it as a bad hex character */
          return CHUNKE_ILLEGAL_HEX ;
        }

        ch->datasize=curlx_strtoofft(ch->hexbuffer, &endptr, 16);
        if((ch->datasize == CURL_OFF_T_MAX) && (errno == ERANGE))
          /* overflow is an error */
          return CHUNKE_ILLEGAL_HEX;
        ch->state = CHUNK_LF; /* now wait for the CRLF */
      }
      break;

    case CHUNK_LF:
      /* waiting for the LF after a chunk size */
      if(*datap == 0x0a) {
        /* we're now expecting data to come, unless size was zero! */
        if(0 == ch->datasize) {
          ch->state = CHUNK_TRAILER; /* now check for trailers */
          conn->trlPos=0;
        }
        else
          ch->state = CHUNK_DATA;
      }

      datap++;
      length--;
      break;

    case CHUNK_DATA:
      /* We expect 'datasize' of data. We have 'length' right now, it can be
         more or less than 'datasize'. Get the smallest piece.
      */
      piece = curlx_sotouz((ch->datasize >= length)?length:ch->datasize);

      /* Write the data portion available */
#ifdef HAVE_LIBZ
      switch (conn->data->set.http_ce_skip?
              IDENTITY : data->req.auto_decoding) {
      case IDENTITY:
#endif
        if(!k->ignorebody) {
          if(!data->set.http_te_skip)
            result = Curl_client_write(conn, CLIENTWRITE_BODY, datap,
                                       piece);
          else
            result = CURLE_OK;
        }
#ifdef HAVE_LIBZ
        break;

      case DEFLATE:
        /* update data->req.keep.str to point to the chunk data. */
        data->req.str = datap;
        result = Curl_unencode_deflate_write(conn, &data->req,
                                             (ssize_t)piece);
        break;

      case GZIP:
        /* update data->req.keep.str to point to the chunk data. */
        data->req.str = datap;
        result = Curl_unencode_gzip_write(conn, &data->req,
                                          (ssize_t)piece);
        break;

      case COMPRESS:
      default:
        failf (conn->data,
               "Unrecognized content encoding type. "
               "libcurl understands `identity', `deflate' and `gzip' "
               "content encodings.");
        return CHUNKE_BAD_ENCODING;
      }
#endif

      if(result)
        return CHUNKE_WRITE_ERROR;

      *wrote += piece;

      ch->datasize -= piece; /* decrease amount left to expect */
      datap += piece;    /* move read pointer forward */
      length -= piece;   /* decrease space left in this round */

      if(0 == ch->datasize)
        /* end of data this round, we now expect a trailing CRLF */
        ch->state = CHUNK_POSTLF;
      break;

    case CHUNK_POSTLF:
      if(*datap == 0x0a) {
        /* The last one before we go back to hex state and start all over. */
        Curl_httpchunk_init(conn); /* sets state back to CHUNK_HEX */
      }
      else if(*datap != 0x0d)
        return CHUNKE_BAD_CHUNK;
      datap++;
      length--;
      break;

    case CHUNK_TRAILER:
      if((*datap == 0x0d) || (*datap == 0x0a)) {
        /* this is the end of a trailer, but if the trailer was zero bytes
           there was no trailer and we move on */

        if(conn->trlPos) {
          /* we allocate trailer with 3 bytes extra room to fit this */
          conn->trailer[conn->trlPos++]=0x0d;
          conn->trailer[conn->trlPos++]=0x0a;
          conn->trailer[conn->trlPos]=0;

          /* Convert to host encoding before calling Curl_client_write */
          result = Curl_convert_from_network(conn->data, conn->trailer,
                                             conn->trlPos);
          if(result)
            /* Curl_convert_from_network calls failf if unsuccessful */
            /* Treat it as a bad chunk */
            return CHUNKE_BAD_CHUNK;

          if(!data->set.http_te_skip) {
            result = Curl_client_write(conn, CLIENTWRITE_HEADER,
                                       conn->trailer, conn->trlPos);
            if(result)
              return CHUNKE_WRITE_ERROR;
          }
          conn->trlPos=0;
          ch->state = CHUNK_TRAILER_CR;
          if(*datap == 0x0a)
            /* already on the LF */
            break;
        }
        else {
          /* no trailer, we're on the final CRLF pair */
          ch->state = CHUNK_TRAILER_POSTCR;
          break; /* don't advance the pointer */
        }
      }
      else {
        /* conn->trailer is assumed to be freed in url.c on a
           connection basis */
        if(conn->trlPos >= conn->trlMax) {
          /* we always allocate three extra bytes, just because when the full
             header has been received we append CRLF\0 */
          char *ptr;
          if(conn->trlMax) {
            conn->trlMax *= 2;
            ptr = realloc(conn->trailer, conn->trlMax + 3);
          }
          else {
            conn->trlMax=128;
            ptr = malloc(conn->trlMax + 3);
          }
          if(!ptr)
            return CHUNKE_OUT_OF_MEMORY;
          conn->trailer = ptr;
        }
        conn->trailer[conn->trlPos++]=*datap;
      }
      datap++;
      length--;
      break;

    case CHUNK_TRAILER_CR:
      if(*datap == 0x0a) {
        ch->state = CHUNK_TRAILER_POSTCR;
        datap++;
        length--;
      }
      else
        return CHUNKE_BAD_CHUNK;
      break;

    case CHUNK_TRAILER_POSTCR:
      /* We enter this state when a CR should arrive so we expect to
         have to first pass a CR before we wait for LF */
      if((*datap != 0x0d) && (*datap != 0x0a)) {
        /* not a CR then it must be another header in the trailer */
        ch->state = CHUNK_TRAILER;
        break;
      }
      if(*datap == 0x0d) {
        /* skip if CR */
        datap++;
        length--;
      }
      /* now wait for the final LF */
      ch->state = CHUNK_STOP;
      break;

    case CHUNK_STOP:
      if(*datap == 0x0a) {
        length--;

        /* Record the length of any data left in the end of the buffer
           even if there's no more chunks to read */
        ch->dataleft = curlx_sotouz(length);

        return CHUNKE_STOP; /* return stop */
      }
      else
        return CHUNKE_BAD_CHUNK;
    }
  }
  return CHUNKE_OK;
}

const char *Curl_chunked_strerror(CHUNKcode code)
{
  switch (code) {
  default:
    return "OK";
  case CHUNKE_TOO_LONG_HEX:
    return "Too long hexadecimal number";
  case CHUNKE_ILLEGAL_HEX:
    return "Illegal or missing hexadecimal sequence";
  case CHUNKE_BAD_CHUNK:
    return "Malformed encoding found";
  case CHUNKE_WRITE_ERROR:
    return "Write error";
  case CHUNKE_BAD_ENCODING:
    return "Bad content-encoding found";
  case CHUNKE_OUT_OF_MEMORY:
    return "Out of memory";
  }
}

#endif /* CURL_DISABLE_HTTP */
