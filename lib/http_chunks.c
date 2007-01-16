/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifndef CURL_DISABLE_HTTP
/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "urldata.h" /* it includes http_chunks.h */
#include "sendf.h"   /* for the client write stuff */

#include "content_encoding.h"
#include "http.h"
#include "memory.h"
#include "easyif.h" /* for Curl_convert_to_network prototype */

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


void Curl_httpchunk_init(struct connectdata *conn)
{
  struct Curl_chunker *chunk = &conn->data->reqdata.proto.http->chunk;
  chunk->hexindex=0; /* start at 0 */
  chunk->dataleft=0; /* no data left yet! */
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
  struct Curl_chunker *ch = &data->reqdata.proto.http->chunk;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;
  size_t piece;
  size_t length = (size_t)datalen;
  size_t *wrote = (size_t *)wrotep;

  *wrote = 0; /* nothing's written yet */

  while(length) {
    switch(ch->state) {
    case CHUNK_HEX:
       /* Check for an ASCII hex digit.
          We avoid the use of isxdigit to accommodate non-ASCII hosts. */
       if((*datap >= 0x30 && *datap <= 0x39)    /* 0-9 */
       || (*datap >= 0x41 && *datap <= 0x46)    /* A-F */
       || (*datap >= 0x61 && *datap <= 0x66)) { /* a-f */
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
        if(0 == ch->hexindex) {
          /* This is illegal data, we received junk where we expected
             a hexadecimal digit. */
          return CHUNKE_ILLEGAL_HEX;
        }
        /* length and datap are unmodified */
        ch->hexbuffer[ch->hexindex]=0;
#ifdef CURL_DOES_CONVERSIONS
        /* convert to host encoding before calling strtoul */
        result = Curl_convert_from_network(conn->data,
                                           ch->hexbuffer,
                                           ch->hexindex);
        if(result != CURLE_OK) {
          /* Curl_convert_from_network calls failf if unsuccessful */
          /* Treat it as a bad hex character */
          return(CHUNKE_ILLEGAL_HEX);
        }
#endif /* CURL_DOES_CONVERSIONS */
        ch->datasize=strtoul(ch->hexbuffer, NULL, 16);
        ch->state = CHUNK_POSTHEX;
      }
      break;

    case CHUNK_POSTHEX:
      /* In this state, we're waiting for CRLF to arrive. We support
         this to allow so called chunk-extensions to show up here
         before the CRLF comes. */
      if(*datap == 0x0d)
        ch->state = CHUNK_CR;
      length--;
      datap++;
      break;

    case CHUNK_CR:
      /* waiting for the LF */
      if(*datap == 0x0a) {
        /* we're now expecting data to come, unless size was zero! */
        if(0 == ch->datasize) {
          if (conn->bits.trailerHdrPresent!=TRUE) {
            /* No Trailer: header found - revert to original Curl processing */
            ch->state = CHUNK_STOP;
            if (1 == length) {
               /* This is the final byte, return right now */
               return CHUNKE_STOP;
            }
          }
          else {
            ch->state = CHUNK_TRAILER; /* attempt to read trailers */
            conn->trlPos=0;
          }
        }
        else
          ch->state = CHUNK_DATA;
      }
      else
        /* previously we got a fake CR, go back to CR waiting! */
        ch->state = CHUNK_CR;
      datap++;
      length--;
      break;

    case CHUNK_DATA:
      /* we get pure and fine data

         We expect another 'datasize' of data. We have 'length' right now,
         it can be more or less than 'datasize'. Get the smallest piece.
      */
      piece = (ch->datasize >= length)?length:ch->datasize;

      /* Write the data portion available */
#ifdef HAVE_LIBZ
      switch (data->reqdata.keep.content_encoding) {
        case IDENTITY:
#endif
          if(!k->ignorebody)
            result = Curl_client_write(conn, CLIENTWRITE_BODY, datap,
                                       piece);
#ifdef HAVE_LIBZ
          break;

        case DEFLATE:
          /* update data->reqdata.keep.str to point to the chunk data. */
          data->reqdata.keep.str = datap;
          result = Curl_unencode_deflate_write(conn, &data->reqdata.keep,
                                               (ssize_t)piece);
          break;

        case GZIP:
          /* update data->reqdata.keep.str to point to the chunk data. */
          data->reqdata.keep.str = datap;
          result = Curl_unencode_gzip_write(conn, &data->reqdata.keep,
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
        ch->state = CHUNK_POSTCR;
      break;

    case CHUNK_POSTCR:
      if(*datap == 0x0d) {
        ch->state = CHUNK_POSTLF;
        datap++;
        length--;
      }
      else
        return CHUNKE_BAD_CHUNK;
      break;

    case CHUNK_POSTLF:
      if(*datap == 0x0a) {
        /*
         * The last one before we go back to hex state and start all
         * over.
         */
        Curl_httpchunk_init(conn);
        datap++;
        length--;
      }
      else
        return CHUNKE_BAD_CHUNK;
      break;

    case CHUNK_TRAILER:
      /* conn->trailer is assumed to be freed in url.c on a
         connection basis */
      if (conn->trlPos >= conn->trlMax) {
        char *ptr;
        if(conn->trlMax) {
          conn->trlMax *= 2;
          ptr = (char*)realloc(conn->trailer,conn->trlMax);
        }
        else {
          conn->trlMax=128;
          ptr = (char*)malloc(conn->trlMax);
        }
        if(!ptr)
          return CHUNKE_OUT_OF_MEMORY;
        conn->trailer = ptr;
      }
      conn->trailer[conn->trlPos++]=*datap;

      if(*datap == 0x0d)
        ch->state = CHUNK_TRAILER_CR;
      else {
        datap++;
        length--;
     }
      break;

    case CHUNK_TRAILER_CR:
      if(*datap == 0x0d) {
        ch->state = CHUNK_TRAILER_POSTCR;
        datap++;
        length--;
      }
      else
        return CHUNKE_BAD_CHUNK;
      break;

    case CHUNK_TRAILER_POSTCR:
      if (*datap == 0x0a) {
        conn->trailer[conn->trlPos++]=0x0a;
        conn->trailer[conn->trlPos]=0;
        if (conn->trlPos==2) {
          ch->state = CHUNK_STOP;
          return CHUNKE_STOP;
        }
        else {
#ifdef CURL_DOES_CONVERSIONS
          /* Convert to host encoding before calling Curl_client_write */
          result = Curl_convert_from_network(conn->data,
                                             conn->trailer,
                                             conn->trlPos);
          if(result != CURLE_OK) {
            /* Curl_convert_from_network calls failf if unsuccessful */
            /* Treat it as a bad chunk */
            return(CHUNKE_BAD_CHUNK);
          }
#endif /* CURL_DOES_CONVERSIONS */
          Curl_client_write(conn, CLIENTWRITE_HEADER,
                            conn->trailer, conn->trlPos);
        }
        ch->state = CHUNK_TRAILER;
        conn->trlPos=0;
        datap++;
        length--;
      }
      else
        return CHUNKE_BAD_CHUNK;
      break;

    case CHUNK_STOP:
      /* If we arrive here, there is data left in the end of the buffer
         even if there's no more chunks to read */
      ch->dataleft = length;
      return CHUNKE_STOP; /* return stop */
    default:
      return CHUNKE_STATE_ERROR;
    }
  }
  return CHUNKE_OK;
}
#endif /* CURL_DISABLE_HTTP */
