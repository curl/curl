/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_HTTP

#include "urldata.h" /* it includes http_chunks.h */
#include "curl_printf.h"
#include "curl_trc.h"
#include "sendf.h"   /* for the client write stuff */
#include "dynbuf.h"
#include "content_encoding.h"
#include "http.h"
#include "multiif.h"
#include "strtoofft.h"
#include "warnless.h"

/* The last #include files should be: */
#include "curl_memory.h"
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

void Curl_httpchunk_init(struct Curl_easy *data, struct Curl_chunker *ch,
                         bool ignore_body)
{
  (void)data;
  ch->hexindex = 0;      /* start at 0 */
  ch->state = CHUNK_HEX; /* we get hex first! */
  ch->last_code = CHUNKE_OK;
  Curl_dyn_init(&ch->trailer, DYN_H1_TRAILER);
  ch->ignore_body = ignore_body;
}

void Curl_httpchunk_reset(struct Curl_easy *data, struct Curl_chunker *ch,
                          bool ignore_body)
{
  (void)data;
  ch->hexindex = 0;      /* start at 0 */
  ch->state = CHUNK_HEX; /* we get hex first! */
  ch->last_code = CHUNKE_OK;
  Curl_dyn_reset(&ch->trailer);
  ch->ignore_body = ignore_body;
}

void Curl_httpchunk_free(struct Curl_easy *data, struct Curl_chunker *ch)
{
  (void)data;
  Curl_dyn_free(&ch->trailer);
}

bool Curl_httpchunk_is_done(struct Curl_easy *data, struct Curl_chunker *ch)
{
  (void)data;
  return ch->state == CHUNK_DONE;
}

static CURLcode httpchunk_readwrite(struct Curl_easy *data,
                                    struct Curl_chunker *ch,
                                    struct Curl_cwriter *cw_next,
                                    const char *buf, size_t blen,
                                    size_t *pconsumed)
{
  CURLcode result = CURLE_OK;
  size_t piece;

  *pconsumed = 0; /* nothing's written yet */
  /* first check terminal states that will not progress anywhere */
  if(ch->state == CHUNK_DONE)
    return CURLE_OK;
  if(ch->state == CHUNK_FAILED)
    return CURLE_RECV_ERROR;

  /* the original data is written to the client, but we go on with the
     chunk read process, to properly calculate the content length */
  if(data->set.http_te_skip && !ch->ignore_body) {
    if(cw_next)
      result = Curl_cwriter_write(data, cw_next, CLIENTWRITE_BODY, buf, blen);
    else
      result = Curl_client_write(data, CLIENTWRITE_BODY, (char *)buf, blen);
    if(result) {
      ch->state = CHUNK_FAILED;
      ch->last_code = CHUNKE_PASSTHRU_ERROR;
      return result;
    }
  }

  while(blen) {
    switch(ch->state) {
    case CHUNK_HEX:
      if(ISXDIGIT(*buf)) {
        if(ch->hexindex >= CHUNK_MAXNUM_LEN) {
          failf(data, "chunk hex-length longer than %d", CHUNK_MAXNUM_LEN);
          ch->state = CHUNK_FAILED;
          ch->last_code = CHUNKE_TOO_LONG_HEX; /* longer than we support */
          return CURLE_RECV_ERROR;
        }
        ch->hexbuffer[ch->hexindex++] = *buf;
        buf++;
        blen--;
        (*pconsumed)++;
      }
      else {
        if(0 == ch->hexindex) {
          /* This is illegal data, we received junk where we expected
             a hexadecimal digit. */
          failf(data, "chunk hex-length char not a hex digit: 0x%x", *buf);
          ch->state = CHUNK_FAILED;
          ch->last_code = CHUNKE_ILLEGAL_HEX;
          return CURLE_RECV_ERROR;
        }

        /* blen and buf are unmodified */
        ch->hexbuffer[ch->hexindex] = 0;
        if(curlx_strtoofft(ch->hexbuffer, NULL, 16, &ch->datasize)) {
          failf(data, "chunk hex-length not valid: '%s'", ch->hexbuffer);
          ch->state = CHUNK_FAILED;
          ch->last_code = CHUNKE_ILLEGAL_HEX;
          return CURLE_RECV_ERROR;
        }
        ch->state = CHUNK_LF; /* now wait for the CRLF */
      }
      break;

    case CHUNK_LF:
      /* waiting for the LF after a chunk size */
      if(*buf == 0x0a) {
        /* we're now expecting data to come, unless size was zero! */
        if(0 == ch->datasize) {
          ch->state = CHUNK_TRAILER; /* now check for trailers */
        }
        else {
          ch->state = CHUNK_DATA;
          CURL_TRC_WRITE(data, "http_chunked, chunk start of %"
                         CURL_FORMAT_CURL_OFF_T " bytes", ch->datasize);
        }
      }

      buf++;
      blen--;
      (*pconsumed)++;
      break;

    case CHUNK_DATA:
      /* We expect 'datasize' of data. We have 'blen' right now, it can be
         more or less than 'datasize'. Get the smallest piece.
      */
      piece = blen;
      if(ch->datasize < (curl_off_t)blen)
        piece = curlx_sotouz(ch->datasize);

      /* Write the data portion available */
      if(!data->set.http_te_skip && !ch->ignore_body) {
        if(cw_next)
          result = Curl_cwriter_write(data, cw_next, CLIENTWRITE_BODY,
                                      buf, piece);
        else
          result = Curl_client_write(data, CLIENTWRITE_BODY,
                                    (char *)buf, piece);
        if(result) {
          ch->state = CHUNK_FAILED;
          ch->last_code = CHUNKE_PASSTHRU_ERROR;
          return result;
        }
      }

      *pconsumed += piece;
      ch->datasize -= piece; /* decrease amount left to expect */
      buf += piece;    /* move read pointer forward */
      blen -= piece;   /* decrease space left in this round */
      CURL_TRC_WRITE(data, "http_chunked, write %zu body bytes, %"
                     CURL_FORMAT_CURL_OFF_T " bytes in chunk remain",
                     piece, ch->datasize);

      if(0 == ch->datasize)
        /* end of data this round, we now expect a trailing CRLF */
        ch->state = CHUNK_POSTLF;
      break;

    case CHUNK_POSTLF:
      if(*buf == 0x0a) {
        /* The last one before we go back to hex state and start all over. */
        Curl_httpchunk_reset(data, ch, ch->ignore_body);
      }
      else if(*buf != 0x0d) {
        ch->state = CHUNK_FAILED;
        ch->last_code = CHUNKE_BAD_CHUNK;
        return CURLE_RECV_ERROR;
      }
      buf++;
      blen--;
      (*pconsumed)++;
      break;

    case CHUNK_TRAILER:
      if((*buf == 0x0d) || (*buf == 0x0a)) {
        char *tr = Curl_dyn_ptr(&ch->trailer);
        /* this is the end of a trailer, but if the trailer was zero bytes
           there was no trailer and we move on */

        if(tr) {
          size_t trlen;
          result = Curl_dyn_addn(&ch->trailer, (char *)STRCONST("\x0d\x0a"));
          if(result) {
            ch->state = CHUNK_FAILED;
            ch->last_code = CHUNKE_OUT_OF_MEMORY;
            return result;
          }
          tr = Curl_dyn_ptr(&ch->trailer);
          trlen = Curl_dyn_len(&ch->trailer);
          if(!data->set.http_te_skip) {
            if(cw_next)
              result = Curl_cwriter_write(data, cw_next,
                                          CLIENTWRITE_HEADER|
                                          CLIENTWRITE_TRAILER,
                                          tr, trlen);
            else
              result = Curl_client_write(data,
                                         CLIENTWRITE_HEADER|
                                         CLIENTWRITE_TRAILER,
                                         tr, trlen);
            if(result) {
              ch->state = CHUNK_FAILED;
              ch->last_code = CHUNKE_PASSTHRU_ERROR;
              return result;
            }
          }
          Curl_dyn_reset(&ch->trailer);
          ch->state = CHUNK_TRAILER_CR;
          if(*buf == 0x0a)
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
        result = Curl_dyn_addn(&ch->trailer, buf, 1);
        if(result) {
          ch->state = CHUNK_FAILED;
          ch->last_code = CHUNKE_OUT_OF_MEMORY;
          return result;
        }
      }
      buf++;
      blen--;
      (*pconsumed)++;
      break;

    case CHUNK_TRAILER_CR:
      if(*buf == 0x0a) {
        ch->state = CHUNK_TRAILER_POSTCR;
        buf++;
        blen--;
        (*pconsumed)++;
      }
      else {
        ch->state = CHUNK_FAILED;
        ch->last_code = CHUNKE_BAD_CHUNK;
        return CURLE_RECV_ERROR;
      }
      break;

    case CHUNK_TRAILER_POSTCR:
      /* We enter this state when a CR should arrive so we expect to
         have to first pass a CR before we wait for LF */
      if((*buf != 0x0d) && (*buf != 0x0a)) {
        /* not a CR then it must be another header in the trailer */
        ch->state = CHUNK_TRAILER;
        break;
      }
      if(*buf == 0x0d) {
        /* skip if CR */
        buf++;
        blen--;
        (*pconsumed)++;
      }
      /* now wait for the final LF */
      ch->state = CHUNK_STOP;
      break;

    case CHUNK_STOP:
      if(*buf == 0x0a) {
        blen--;
        (*pconsumed)++;
        /* Record the length of any data left in the end of the buffer
           even if there's no more chunks to read */
        ch->datasize = blen;
        ch->state = CHUNK_DONE;
        CURL_TRC_WRITE(data, "http_chunk, response complete");
        return CURLE_OK;
      }
      else {
        ch->state = CHUNK_FAILED;
        ch->last_code = CHUNKE_BAD_CHUNK;
        CURL_TRC_WRITE(data, "http_chunk error, expected 0x0a, seeing 0x%ux",
                       (unsigned int)*buf);
        return CURLE_RECV_ERROR;
      }
    case CHUNK_DONE:
      return CURLE_OK;

    case CHUNK_FAILED:
      return CURLE_RECV_ERROR;
    }

  }
  return CURLE_OK;
}

static const char *Curl_chunked_strerror(CHUNKcode code)
{
  switch(code) {
  default:
    return "OK";
  case CHUNKE_TOO_LONG_HEX:
    return "Too long hexadecimal number";
  case CHUNKE_ILLEGAL_HEX:
    return "Illegal or missing hexadecimal sequence";
  case CHUNKE_BAD_CHUNK:
    return "Malformed encoding found";
  case CHUNKE_PASSTHRU_ERROR:
    return "Error writing data to client";
  case CHUNKE_BAD_ENCODING:
    return "Bad content-encoding found";
  case CHUNKE_OUT_OF_MEMORY:
    return "Out of memory";
  }
}

CURLcode Curl_httpchunk_read(struct Curl_easy *data,
                             struct Curl_chunker *ch,
                             char *buf, size_t blen,
                             size_t *pconsumed)
{
  return httpchunk_readwrite(data, ch, NULL, buf, blen, pconsumed);
}

struct chunked_writer {
  struct Curl_cwriter super;
  struct Curl_chunker ch;
};

static CURLcode cw_chunked_init(struct Curl_easy *data,
                                struct Curl_cwriter *writer)
{
  struct chunked_writer *ctx = writer->ctx;

  data->req.chunk = TRUE;      /* chunks coming our way. */
  Curl_httpchunk_init(data, &ctx->ch, FALSE);
  return CURLE_OK;
}

static void cw_chunked_close(struct Curl_easy *data,
                             struct Curl_cwriter *writer)
{
  struct chunked_writer *ctx = writer->ctx;
  Curl_httpchunk_free(data, &ctx->ch);
}

static CURLcode cw_chunked_write(struct Curl_easy *data,
                                 struct Curl_cwriter *writer, int type,
                                 const char *buf, size_t blen)
{
  struct chunked_writer *ctx = writer->ctx;
  CURLcode result;
  size_t consumed;

  if(!(type & CLIENTWRITE_BODY))
    return Curl_cwriter_write(data, writer->next, type, buf, blen);

  consumed = 0;
  result = httpchunk_readwrite(data, &ctx->ch, writer->next, buf, blen,
                               &consumed);

  if(result) {
    if(CHUNKE_PASSTHRU_ERROR == ctx->ch.last_code) {
      failf(data, "Failed reading the chunked-encoded stream");
    }
    else {
      failf(data, "%s in chunked-encoding",
            Curl_chunked_strerror(ctx->ch.last_code));
    }
    return result;
  }

  blen -= consumed;
  if(CHUNK_DONE == ctx->ch.state) {
    /* chunks read successfully, download is complete */
    data->req.download_done = TRUE;
    if(blen) {
      infof(data, "Leftovers after chunking: %zu bytes", blen);
    }
  }
  else if((type & CLIENTWRITE_EOS) && !data->req.no_body) {
    failf(data, "transfer closed with outstanding read data remaining");
    return CURLE_PARTIAL_FILE;
  }

  return CURLE_OK;
}

/* HTTP chunked Transfer-Encoding decoder */
const struct Curl_cwtype Curl_httpchunk_unencoder = {
  "chunked",
  NULL,
  cw_chunked_init,
  cw_chunked_write,
  cw_chunked_close,
  sizeof(struct chunked_writer)
};

/* max length of a HTTP chunk that we want to generate */
#define CURL_CHUNKED_MINLEN   (1024)
#define CURL_CHUNKED_MAXLEN   (64 * 1024)

struct chunked_reader {
  struct Curl_creader super;
  struct bufq chunkbuf;
  BIT(read_eos);  /* we read an EOS from the next reader */
  BIT(eos);       /* we have returned an EOS */
};

static CURLcode cr_chunked_init(struct Curl_easy *data,
                                struct Curl_creader *reader)
{
  struct chunked_reader *ctx = reader->ctx;
  (void)data;
  Curl_bufq_init2(&ctx->chunkbuf, CURL_CHUNKED_MAXLEN, 2, BUFQ_OPT_SOFT_LIMIT);
  return CURLE_OK;
}

static void cr_chunked_close(struct Curl_easy *data,
                             struct Curl_creader *reader)
{
  struct chunked_reader *ctx = reader->ctx;
  (void)data;
  Curl_bufq_free(&ctx->chunkbuf);
}

static CURLcode add_last_chunk(struct Curl_easy *data,
                               struct Curl_creader *reader)
{
  struct chunked_reader *ctx = reader->ctx;
  struct curl_slist *trailers = NULL, *tr;
  CURLcode result;
  size_t n;
  int rc;

  if(!data->set.trailer_callback) {
    CURL_TRC_READ(data, "http_chunk, added last, empty chunk");
    return Curl_bufq_cwrite(&ctx->chunkbuf, STRCONST("0\r\n\r\n"), &n);
  }

  result = Curl_bufq_cwrite(&ctx->chunkbuf, STRCONST("0\r\n"), &n);
  if(result)
    goto out;

  Curl_set_in_callback(data, true);
  rc = data->set.trailer_callback(&trailers, data->set.trailer_data);
  Curl_set_in_callback(data, false);

  if(rc != CURL_TRAILERFUNC_OK) {
    failf(data, "operation aborted by trailing headers callback");
    result = CURLE_ABORTED_BY_CALLBACK;
    goto out;
  }

  for(tr = trailers; tr; tr = tr->next) {
    /* only add correctly formatted trailers */
    char *ptr = strchr(tr->data, ':');
    if(!ptr || *(ptr + 1) != ' ') {
      infof(data, "Malformatted trailing header, skipping trailer");
      continue;
    }

    result = Curl_bufq_cwrite(&ctx->chunkbuf, tr->data,
                              strlen(tr->data), &n);
    if(!result)
      result = Curl_bufq_cwrite(&ctx->chunkbuf, STRCONST("\r\n"), &n);
    if(result)
      goto out;
  }

  result = Curl_bufq_cwrite(&ctx->chunkbuf, STRCONST("\r\n"), &n);

out:
  curl_slist_free_all(trailers);
  CURL_TRC_READ(data, "http_chunk, added last chunk with trailers "
                "from client -> %d", result);
  return result;
}

static CURLcode add_chunk(struct Curl_easy *data,
                          struct Curl_creader *reader,
                          char *buf, size_t blen)
{
  struct chunked_reader *ctx = reader->ctx;
  CURLcode result;
  char tmp[CURL_CHUNKED_MINLEN];
  size_t nread;
  bool eos;

  DEBUGASSERT(!ctx->read_eos);
  blen = CURLMIN(blen, CURL_CHUNKED_MAXLEN); /* respect our buffer pref */
  if(blen < sizeof(tmp)) {
    /* small read, make a chunk of decent size */
    buf = tmp;
    blen = sizeof(tmp);
  }
  else {
    /* larger read, make a chunk that will fit when read back */
    blen -= (8 + 2 + 2); /* deduct max overhead, 8 hex + 2*crlf */
  }

  result = Curl_creader_read(data, reader->next, buf, blen, &nread, &eos);
  if(result)
    return result;
  if(eos)
    ctx->read_eos = TRUE;

  if(nread) {
    /* actually got bytes, wrap them into the chunkbuf */
    char hd[11] = "";
    int hdlen;
    size_t n;

    hdlen = msnprintf(hd, sizeof(hd), "%zx\r\n", nread);
    if(hdlen <= 0)
      return CURLE_READ_ERROR;
    /* On a soft-limited bufq, we do not need to check that all was written */
    result = Curl_bufq_cwrite(&ctx->chunkbuf, hd, hdlen, &n);
    if(!result)
      result = Curl_bufq_cwrite(&ctx->chunkbuf, buf, nread, &n);
    if(!result)
      result = Curl_bufq_cwrite(&ctx->chunkbuf, "\r\n", 2, &n);
    CURL_TRC_READ(data, "http_chunk, made chunk of %zu bytes -> %d",
                 nread, result);
    if(result)
      return result;
  }

  if(ctx->read_eos)
    return add_last_chunk(data, reader);
  return CURLE_OK;
}

static CURLcode cr_chunked_read(struct Curl_easy *data,
                                struct Curl_creader *reader,
                                char *buf, size_t blen,
                                size_t *pnread, bool *peos)
{
  struct chunked_reader *ctx = reader->ctx;
  CURLcode result = CURLE_READ_ERROR;

  *pnread = 0;
  *peos = ctx->eos;

  if(!ctx->eos) {
    if(!ctx->read_eos && Curl_bufq_is_empty(&ctx->chunkbuf)) {
      /* Still getting data form the next reader, buffer is empty */
      result = add_chunk(data, reader, buf, blen);
      if(result)
        return result;
    }

    if(!Curl_bufq_is_empty(&ctx->chunkbuf)) {
      result = Curl_bufq_cread(&ctx->chunkbuf, buf, blen, pnread);
      if(!result && ctx->read_eos && Curl_bufq_is_empty(&ctx->chunkbuf)) {
        /* no more data, read all, done. */
        ctx->eos = TRUE;
        *peos = TRUE;
      }
      return result;
    }
  }
  /* We may get here, because we are done or because callbacks paused */
  DEBUGASSERT(ctx->eos || !ctx->read_eos);
  return CURLE_OK;
}

static curl_off_t cr_chunked_total_length(struct Curl_easy *data,
                                          struct Curl_creader *reader)
{
  /* this reader changes length depending on input */
  (void)data;
  (void)reader;
  return -1;
}

/* HTTP chunked Transfer-Encoding encoder */
const struct Curl_crtype Curl_httpchunk_encoder = {
  "chunked",
  cr_chunked_init,
  cr_chunked_read,
  cr_chunked_close,
  Curl_creader_def_needs_rewind,
  cr_chunked_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_rewind,
  Curl_creader_def_unpause,
  Curl_creader_def_done,
  sizeof(struct chunked_reader)
};

CURLcode Curl_httpchunk_add_reader(struct Curl_easy *data)
{
  struct Curl_creader *reader = NULL;
  CURLcode result;

  result = Curl_creader_create(&reader, data, &Curl_httpchunk_encoder,
                               CURL_CR_TRANSFER_ENCODE);
  if(!result)
    result = Curl_creader_add(data, reader);

  if(result && reader)
    Curl_creader_free(data, reader);
  return result;
}

#endif /* CURL_DISABLE_HTTP */
