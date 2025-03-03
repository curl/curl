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

#include "urldata.h"
#include <curl/curl.h>
#include <stddef.h>

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#ifdef HAVE_BROTLI
#if defined(__GNUC__) || defined(__clang__)
/* Ignore -Wvla warnings in brotli headers */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
#endif
#include <brotli/decode.h>
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#include "sendf.h"
#include "http.h"
#include "content_encoding.h"
#include "strdup.h"
#include "strcase.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define CONTENT_ENCODING_DEFAULT  "identity"

#ifndef CURL_DISABLE_HTTP

/* allow no more than 5 "chained" compression steps */
#define MAX_ENCODE_STACK 5

#if defined(HAVE_LIBZ) || defined(HAVE_BROTLI) || defined(HAVE_ZSTD)
#define DECOMPRESS_BUFFER_SIZE 16384 /* buffer size for decompressed data */
#endif

#ifdef HAVE_LIBZ

#if !defined(ZLIB_VERNUM) || (ZLIB_VERNUM < 0x1204)
#error "requires zlib 1.2.0.4 or newer"
#endif

typedef enum {
  ZLIB_UNINIT,               /* uninitialized */
  ZLIB_INIT,                 /* initialized */
  ZLIB_INFLATING,            /* inflating started. */
  ZLIB_EXTERNAL_TRAILER,     /* reading external trailer */
  ZLIB_INIT_GZIP             /* initialized in transparent gzip mode */
} zlibInitState;

/* Deflate and gzip writer. */
struct zlib_writer {
  struct Curl_cwriter super;
  zlibInitState zlib_init;   /* zlib init state */
  char buffer[DECOMPRESS_BUFFER_SIZE]; /* Put the decompressed data here. */
  uInt trailerlen;           /* Remaining trailer byte count. */
  z_stream z;                /* State structure for zlib. */
};


static voidpf
zalloc_cb(voidpf opaque, unsigned int items, unsigned int size)
{
  (void) opaque;
  /* not a typo, keep it calloc() */
  return (voidpf) calloc(items, size);
}

static void
zfree_cb(voidpf opaque, voidpf ptr)
{
  (void) opaque;
  free(ptr);
}

static CURLcode
process_zlib_error(struct Curl_easy *data, z_stream *z)
{
  if(z->msg)
    failf(data, "Error while processing content unencoding: %s",
          z->msg);
  else
    failf(data, "Error while processing content unencoding: "
          "Unknown failure within decompression software.");

  return CURLE_BAD_CONTENT_ENCODING;
}

static CURLcode
exit_zlib(struct Curl_easy *data,
          z_stream *z, zlibInitState *zlib_init, CURLcode result)
{
  if(*zlib_init != ZLIB_UNINIT) {
    if(inflateEnd(z) != Z_OK && result == CURLE_OK)
      result = process_zlib_error(data, z);
    *zlib_init = ZLIB_UNINIT;
  }

  return result;
}

static CURLcode process_trailer(struct Curl_easy *data,
                                struct zlib_writer *zp)
{
  z_stream *z = &zp->z;
  CURLcode result = CURLE_OK;
  uInt len = z->avail_in < zp->trailerlen ? z->avail_in : zp->trailerlen;

  /* Consume expected trailer bytes. Terminate stream if exhausted.
     Issue an error if unexpected bytes follow. */

  zp->trailerlen -= len;
  z->avail_in -= len;
  z->next_in += len;
  if(z->avail_in)
    result = CURLE_WRITE_ERROR;
  if(result || !zp->trailerlen)
    result = exit_zlib(data, z, &zp->zlib_init, result);
  else {
    /* Only occurs for gzip with zlib < 1.2.0.4 or raw deflate. */
    zp->zlib_init = ZLIB_EXTERNAL_TRAILER;
  }
  return result;
}

static CURLcode inflate_stream(struct Curl_easy *data,
                               struct Curl_cwriter *writer, int type,
                               zlibInitState started)
{
  struct zlib_writer *zp = (struct zlib_writer *) writer;
  z_stream *z = &zp->z;         /* zlib state structure */
  uInt nread = z->avail_in;
  Bytef *orig_in = z->next_in;
  bool done = FALSE;
  CURLcode result = CURLE_OK;   /* Curl_client_write status */

  /* Check state. */
  if(zp->zlib_init != ZLIB_INIT &&
     zp->zlib_init != ZLIB_INFLATING &&
     zp->zlib_init != ZLIB_INIT_GZIP)
    return exit_zlib(data, z, &zp->zlib_init, CURLE_WRITE_ERROR);

  /* because the buffer size is fixed, iteratively decompress and transfer to
     the client via next_write function. */
  while(!done) {
    int status;                   /* zlib status */
    done = TRUE;

    /* (re)set buffer for decompressed output for every iteration */
    z->next_out = (Bytef *) zp->buffer;
    z->avail_out = DECOMPRESS_BUFFER_SIZE;

#ifdef Z_BLOCK
    /* Z_BLOCK is only available in zlib ver. >= 1.2.0.5 */
    status = inflate(z, Z_BLOCK);
#else
    /* fallback for zlib ver. < 1.2.0.5 */
    status = inflate(z, Z_SYNC_FLUSH);
#endif

    /* Flush output data if some. */
    if(z->avail_out != DECOMPRESS_BUFFER_SIZE) {
      if(status == Z_OK || status == Z_STREAM_END) {
        zp->zlib_init = started;      /* Data started. */
        result = Curl_cwriter_write(data, writer->next, type, zp->buffer,
                                    DECOMPRESS_BUFFER_SIZE - z->avail_out);
        if(result) {
          exit_zlib(data, z, &zp->zlib_init, result);
          break;
        }
      }
    }

    /* Dispatch by inflate() status. */
    switch(status) {
    case Z_OK:
      /* Always loop: there may be unflushed latched data in zlib state. */
      done = FALSE;
      break;
    case Z_BUF_ERROR:
      /* No more data to flush: just exit loop. */
      break;
    case Z_STREAM_END:
      result = process_trailer(data, zp);
      break;
    case Z_DATA_ERROR:
      /* some servers seem to not generate zlib headers, so this is an attempt
         to fix and continue anyway */
      if(zp->zlib_init == ZLIB_INIT) {
        /* Do not use inflateReset2(): only available since zlib 1.2.3.4. */
        (void) inflateEnd(z);     /* do not care about the return code */
        if(inflateInit2(z, -MAX_WBITS) == Z_OK) {
          z->next_in = orig_in;
          z->avail_in = nread;
          zp->zlib_init = ZLIB_INFLATING;
          zp->trailerlen = 4; /* Tolerate up to 4 unknown trailer bytes. */
          done = FALSE;
          break;
        }
        zp->zlib_init = ZLIB_UNINIT;    /* inflateEnd() already called. */
      }
      result = exit_zlib(data, z, &zp->zlib_init, process_zlib_error(data, z));
      break;
    default:
      result = exit_zlib(data, z, &zp->zlib_init, process_zlib_error(data, z));
      break;
    }
  }

  /* We are about to leave this call so the `nread' data bytes will not be seen
     again. If we are in a state that would wrongly allow restart in raw mode
     at the next call, assume output has already started. */
  if(nread && zp->zlib_init == ZLIB_INIT)
    zp->zlib_init = started;      /* Cannot restart anymore. */

  return result;
}


/* Deflate handler. */
static CURLcode deflate_do_init(struct Curl_easy *data,
                                struct Curl_cwriter *writer)
{
  struct zlib_writer *zp = (struct zlib_writer *) writer;
  z_stream *z = &zp->z;     /* zlib state structure */

  /* Initialize zlib */
  z->zalloc = (alloc_func) zalloc_cb;
  z->zfree = (free_func) zfree_cb;

  if(inflateInit(z) != Z_OK)
    return process_zlib_error(data, z);
  zp->zlib_init = ZLIB_INIT;
  return CURLE_OK;
}

static CURLcode deflate_do_write(struct Curl_easy *data,
                                 struct Curl_cwriter *writer, int type,
                                 const char *buf, size_t nbytes)
{
  struct zlib_writer *zp = (struct zlib_writer *) writer;
  z_stream *z = &zp->z;     /* zlib state structure */

  if(!(type & CLIENTWRITE_BODY) || !nbytes)
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  /* Set the compressed input when this function is called */
  z->next_in = (Bytef *) buf;
  z->avail_in = (uInt) nbytes;

  if(zp->zlib_init == ZLIB_EXTERNAL_TRAILER)
    return process_trailer(data, zp);

  /* Now uncompress the data */
  return inflate_stream(data, writer, type, ZLIB_INFLATING);
}

static void deflate_do_close(struct Curl_easy *data,
                             struct Curl_cwriter *writer)
{
  struct zlib_writer *zp = (struct zlib_writer *) writer;
  z_stream *z = &zp->z;     /* zlib state structure */

  exit_zlib(data, z, &zp->zlib_init, CURLE_OK);
}

static const struct Curl_cwtype deflate_encoding = {
  "deflate",
  NULL,
  deflate_do_init,
  deflate_do_write,
  deflate_do_close,
  sizeof(struct zlib_writer)
};


/* Gzip handler. */
static CURLcode gzip_do_init(struct Curl_easy *data,
                             struct Curl_cwriter *writer)
{
  struct zlib_writer *zp = (struct zlib_writer *) writer;
  z_stream *z = &zp->z;     /* zlib state structure */

  /* Initialize zlib */
  z->zalloc = (alloc_func) zalloc_cb;
  z->zfree = (free_func) zfree_cb;

  if(inflateInit2(z, MAX_WBITS + 32) != Z_OK)
    return process_zlib_error(data, z);

  zp->zlib_init = ZLIB_INIT_GZIP; /* Transparent gzip decompress state */
  return CURLE_OK;
}

static CURLcode gzip_do_write(struct Curl_easy *data,
                              struct Curl_cwriter *writer, int type,
                              const char *buf, size_t nbytes)
{
  struct zlib_writer *zp = (struct zlib_writer *) writer;
  z_stream *z = &zp->z;     /* zlib state structure */

  if(!(type & CLIENTWRITE_BODY) || !nbytes)
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  if(zp->zlib_init == ZLIB_INIT_GZIP) {
    /* Let zlib handle the gzip decompression entirely */
    z->next_in = (Bytef *) buf;
    z->avail_in = (uInt) nbytes;
    /* Now uncompress the data */
    return inflate_stream(data, writer, type, ZLIB_INIT_GZIP);
  }

  /* We are running with an old version: return error. */
  return exit_zlib(data, z, &zp->zlib_init, CURLE_WRITE_ERROR);
}

static void gzip_do_close(struct Curl_easy *data,
                              struct Curl_cwriter *writer)
{
  struct zlib_writer *zp = (struct zlib_writer *) writer;
  z_stream *z = &zp->z;     /* zlib state structure */

  exit_zlib(data, z, &zp->zlib_init, CURLE_OK);
}

static const struct Curl_cwtype gzip_encoding = {
  "gzip",
  "x-gzip",
  gzip_do_init,
  gzip_do_write,
  gzip_do_close,
  sizeof(struct zlib_writer)
};

#endif /* HAVE_LIBZ */

#ifdef HAVE_BROTLI
/* Brotli writer. */
struct brotli_writer {
  struct Curl_cwriter super;
  char buffer[DECOMPRESS_BUFFER_SIZE];
  BrotliDecoderState *br;    /* State structure for brotli. */
};

static CURLcode brotli_map_error(BrotliDecoderErrorCode be)
{
  switch(be) {
  case BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_NIBBLE:
  case BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_META_NIBBLE:
  case BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET:
  case BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_SAME:
  case BROTLI_DECODER_ERROR_FORMAT_CL_SPACE:
  case BROTLI_DECODER_ERROR_FORMAT_HUFFMAN_SPACE:
  case BROTLI_DECODER_ERROR_FORMAT_CONTEXT_MAP_REPEAT:
  case BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_1:
  case BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_2:
  case BROTLI_DECODER_ERROR_FORMAT_TRANSFORM:
  case BROTLI_DECODER_ERROR_FORMAT_DICTIONARY:
  case BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS:
  case BROTLI_DECODER_ERROR_FORMAT_PADDING_1:
  case BROTLI_DECODER_ERROR_FORMAT_PADDING_2:
#ifdef BROTLI_DECODER_ERROR_COMPOUND_DICTIONARY
  case BROTLI_DECODER_ERROR_COMPOUND_DICTIONARY:
#endif
#ifdef BROTLI_DECODER_ERROR_DICTIONARY_NOT_SET
  case BROTLI_DECODER_ERROR_DICTIONARY_NOT_SET:
#endif
  case BROTLI_DECODER_ERROR_INVALID_ARGUMENTS:
    return CURLE_BAD_CONTENT_ENCODING;
  case BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES:
  case BROTLI_DECODER_ERROR_ALLOC_TREE_GROUPS:
  case BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MAP:
  case BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_1:
  case BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_2:
  case BROTLI_DECODER_ERROR_ALLOC_BLOCK_TYPE_TREES:
    return CURLE_OUT_OF_MEMORY;
  default:
    break;
  }
  return CURLE_WRITE_ERROR;
}

static CURLcode brotli_do_init(struct Curl_easy *data,
                               struct Curl_cwriter *writer)
{
  struct brotli_writer *bp = (struct brotli_writer *) writer;
  (void) data;

  bp->br = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  return bp->br ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

static CURLcode brotli_do_write(struct Curl_easy *data,
                                struct Curl_cwriter *writer, int type,
                                const char *buf, size_t nbytes)
{
  struct brotli_writer *bp = (struct brotli_writer *) writer;
  const uint8_t *src = (const uint8_t *) buf;
  uint8_t *dst;
  size_t dstleft;
  CURLcode result = CURLE_OK;
  BrotliDecoderResult r = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;

  if(!(type & CLIENTWRITE_BODY) || !nbytes)
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  if(!bp->br)
    return CURLE_WRITE_ERROR;  /* Stream already ended. */

  while((nbytes || r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) &&
        result == CURLE_OK) {
    dst = (uint8_t *) bp->buffer;
    dstleft = DECOMPRESS_BUFFER_SIZE;
    r = BrotliDecoderDecompressStream(bp->br,
                                      &nbytes, &src, &dstleft, &dst, NULL);
    result = Curl_cwriter_write(data, writer->next, type,
                                bp->buffer, DECOMPRESS_BUFFER_SIZE - dstleft);
    if(result)
      break;
    switch(r) {
    case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
    case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
      break;
    case BROTLI_DECODER_RESULT_SUCCESS:
      BrotliDecoderDestroyInstance(bp->br);
      bp->br = NULL;
      if(nbytes)
        result = CURLE_WRITE_ERROR;
      break;
    default:
      result = brotli_map_error(BrotliDecoderGetErrorCode(bp->br));
      break;
    }
  }
  return result;
}

static void brotli_do_close(struct Curl_easy *data,
                                struct Curl_cwriter *writer)
{
  struct brotli_writer *bp = (struct brotli_writer *) writer;
  (void) data;

  if(bp->br) {
    BrotliDecoderDestroyInstance(bp->br);
    bp->br = NULL;
  }
}

static const struct Curl_cwtype brotli_encoding = {
  "br",
  NULL,
  brotli_do_init,
  brotli_do_write,
  brotli_do_close,
  sizeof(struct brotli_writer)
};
#endif

#ifdef HAVE_ZSTD
/* Zstd writer. */
struct zstd_writer {
  struct Curl_cwriter super;
  ZSTD_DStream *zds;    /* State structure for zstd. */
  char buffer[DECOMPRESS_BUFFER_SIZE];
};

#ifdef ZSTD_STATIC_LINKING_ONLY
static void *Curl_zstd_alloc(void *opaque, size_t size)
{
  (void)opaque;
  return Curl_cmalloc(size);
}

static void Curl_zstd_free(void *opaque, void *address)
{
  (void)opaque;
  Curl_cfree(address);
}
#endif

static CURLcode zstd_do_init(struct Curl_easy *data,
                             struct Curl_cwriter *writer)
{
  struct zstd_writer *zp = (struct zstd_writer *) writer;

  (void)data;

#ifdef ZSTD_STATIC_LINKING_ONLY
  zp->zds = ZSTD_createDStream_advanced((ZSTD_customMem) {
    .customAlloc = Curl_zstd_alloc,
    .customFree  = Curl_zstd_free,
    .opaque      = NULL
  });
#else
  zp->zds = ZSTD_createDStream();
#endif

  return zp->zds ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

static CURLcode zstd_do_write(struct Curl_easy *data,
                              struct Curl_cwriter *writer, int type,
                              const char *buf, size_t nbytes)
{
  CURLcode result = CURLE_OK;
  struct zstd_writer *zp = (struct zstd_writer *) writer;
  ZSTD_inBuffer in;
  ZSTD_outBuffer out;
  size_t errorCode;

  if(!(type & CLIENTWRITE_BODY) || !nbytes)
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  in.pos = 0;
  in.src = buf;
  in.size = nbytes;

  for(;;) {
    out.pos = 0;
    out.dst = zp->buffer;
    out.size = DECOMPRESS_BUFFER_SIZE;

    errorCode = ZSTD_decompressStream(zp->zds, &out, &in);
    if(ZSTD_isError(errorCode)) {
      return CURLE_BAD_CONTENT_ENCODING;
    }
    if(out.pos > 0) {
      result = Curl_cwriter_write(data, writer->next, type,
                                  zp->buffer, out.pos);
      if(result)
        break;
    }
    if((in.pos == nbytes) && (out.pos < out.size))
      break;
  }

  return result;
}

static void zstd_do_close(struct Curl_easy *data,
                              struct Curl_cwriter *writer)
{
  struct zstd_writer *zp = (struct zstd_writer *) writer;
  (void)data;

  if(zp->zds) {
    ZSTD_freeDStream(zp->zds);
    zp->zds = NULL;
  }
}

static const struct Curl_cwtype zstd_encoding = {
  "zstd",
  NULL,
  zstd_do_init,
  zstd_do_write,
  zstd_do_close,
  sizeof(struct zstd_writer)
};
#endif

/* Identity handler. */
static const struct Curl_cwtype identity_encoding = {
  "identity",
  "none",
  Curl_cwriter_def_init,
  Curl_cwriter_def_write,
  Curl_cwriter_def_close,
  sizeof(struct Curl_cwriter)
};

/* supported general content decoders. */
static const struct Curl_cwtype * const general_unencoders[] = {
  &identity_encoding,
#ifdef HAVE_LIBZ
  &deflate_encoding,
  &gzip_encoding,
#endif
#ifdef HAVE_BROTLI
  &brotli_encoding,
#endif
#ifdef HAVE_ZSTD
  &zstd_encoding,
#endif
  NULL
};

/* supported content decoders only for transfer encodings */
static const struct Curl_cwtype * const transfer_unencoders[] = {
#ifndef CURL_DISABLE_HTTP
  &Curl_httpchunk_unencoder,
#endif
  NULL
};

/* Provide a list of comma-separated names of supported encodings.
*/
void Curl_all_content_encodings(char *buf, size_t blen)
{
  size_t len = 0;
  const struct Curl_cwtype * const *cep;
  const struct Curl_cwtype *ce;

  DEBUGASSERT(buf);
  DEBUGASSERT(blen);
  buf[0] = 0;

  for(cep = general_unencoders; *cep; cep++) {
    ce = *cep;
    if(!strcasecompare(ce->name, CONTENT_ENCODING_DEFAULT))
      len += strlen(ce->name) + 2;
  }

  if(!len) {
    if(blen >= sizeof(CONTENT_ENCODING_DEFAULT))
      strcpy(buf, CONTENT_ENCODING_DEFAULT);
  }
  else if(blen > len) {
    char *p = buf;
    for(cep = general_unencoders; *cep; cep++) {
      ce = *cep;
      if(!strcasecompare(ce->name, CONTENT_ENCODING_DEFAULT)) {
        strcpy(p, ce->name);
        p += strlen(p);
        *p++ = ',';
        *p++ = ' ';
      }
    }
    p[-2] = '\0';
  }
}

/* Deferred error dummy writer. */
static CURLcode error_do_init(struct Curl_easy *data,
                              struct Curl_cwriter *writer)
{
  (void)data;
  (void)writer;
  return CURLE_OK;
}

static CURLcode error_do_write(struct Curl_easy *data,
                               struct Curl_cwriter *writer, int type,
                               const char *buf, size_t nbytes)
{
  (void) writer;
  (void) buf;
  (void) nbytes;

  if(!(type & CLIENTWRITE_BODY) || !nbytes)
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);
  else {
    char all[256];
    (void)Curl_all_content_encodings(all, sizeof(all));
    failf(data, "Unrecognized content encoding type. "
          "libcurl understands %s content encodings.", all);
  }
  return CURLE_BAD_CONTENT_ENCODING;
}

static void error_do_close(struct Curl_easy *data,
                               struct Curl_cwriter *writer)
{
  (void) data;
  (void) writer;
}

static const struct Curl_cwtype error_writer = {
  "ce-error",
  NULL,
  error_do_init,
  error_do_write,
  error_do_close,
  sizeof(struct Curl_cwriter)
};

/* Find the content encoding by name. */
static const struct Curl_cwtype *find_unencode_writer(const char *name,
                                                      size_t len,
                                                      Curl_cwriter_phase phase)
{
  const struct Curl_cwtype * const *cep;

  if(phase == CURL_CW_TRANSFER_DECODE) {
    for(cep = transfer_unencoders; *cep; cep++) {
      const struct Curl_cwtype *ce = *cep;
      if((strncasecompare(name, ce->name, len) && !ce->name[len]) ||
         (ce->alias && strncasecompare(name, ce->alias, len)
                    && !ce->alias[len]))
        return ce;
    }
  }
  /* look among the general decoders */
  for(cep = general_unencoders; *cep; cep++) {
    const struct Curl_cwtype *ce = *cep;
    if((strncasecompare(name, ce->name, len) && !ce->name[len]) ||
       (ce->alias && strncasecompare(name, ce->alias, len) && !ce->alias[len]))
      return ce;
  }
  return NULL;
}

/* Setup the unencoding stack from the Content-Encoding header value.
 * See RFC 7231 section 3.1.2.2. */
CURLcode Curl_build_unencoding_stack(struct Curl_easy *data,
                                     const char *enclist, int is_transfer)
{
  Curl_cwriter_phase phase = is_transfer ?
    CURL_CW_TRANSFER_DECODE : CURL_CW_CONTENT_DECODE;
  CURLcode result;

  do {
    const char *name;
    size_t namelen;
    bool is_chunked = FALSE;

    /* Parse a single encoding name. */
    while(ISBLANK(*enclist) || *enclist == ',')
      enclist++;

    name = enclist;

    for(namelen = 0; *enclist && *enclist != ','; enclist++)
      if(*enclist > ' ')
        namelen = enclist - name + 1;

    if(namelen) {
      const struct Curl_cwtype *cwt;
      struct Curl_cwriter *writer;

      CURL_TRC_WRITE(data, "looking for %s decoder: %.*s",
                     is_transfer ? "transfer" : "content", (int)namelen, name);
      is_chunked = (is_transfer && (namelen == 7) &&
                    strncasecompare(name, "chunked", 7));
      /* if we skip the decoding in this phase, do not look further.
       * Exception is "chunked" transfer-encoding which always must happen */
      if((is_transfer && !data->set.http_transfer_encoding && !is_chunked) ||
         (!is_transfer && data->set.http_ce_skip)) {
        /* not requested, ignore */
        CURL_TRC_WRITE(data, "decoder not requested, ignored: %.*s",
                       (int)namelen, name);
        return CURLE_OK;
      }

      if(Curl_cwriter_count(data, phase) + 1 >= MAX_ENCODE_STACK) {
        failf(data, "Reject response due to more than %u content encodings",
              MAX_ENCODE_STACK);
        return CURLE_BAD_CONTENT_ENCODING;
      }

      cwt = find_unencode_writer(name, namelen, phase);
      if(cwt && is_chunked && Curl_cwriter_get_by_type(data, cwt)) {
        /* A 'chunked' transfer encoding has already been added.
         * Ignore duplicates. See #13451.
         * Also RFC 9112, ch. 6.1:
         * "A sender MUST NOT apply the chunked transfer coding more than
         *  once to a message body."
         */
        CURL_TRC_WRITE(data, "ignoring duplicate 'chunked' decoder");
        return CURLE_OK;
      }

      if(is_transfer && !is_chunked &&
         Curl_cwriter_get_by_name(data, "chunked")) {
        /* RFC 9112, ch. 6.1:
         * "If any transfer coding other than chunked is applied to a
         *  response's content, the sender MUST either apply chunked as the
         *  final transfer coding or terminate the message by closing the
         *  connection."
         * "chunked" must be the last added to be the first in its phase,
         *  reject this.
         */
        failf(data, "Reject response due to 'chunked' not being the last "
              "Transfer-Encoding");
        return CURLE_BAD_CONTENT_ENCODING;
      }

      if(!cwt)
        cwt = &error_writer;  /* Defer error at use. */

      result = Curl_cwriter_create(&writer, data, cwt, phase);
      CURL_TRC_WRITE(data, "added %s decoder %s -> %d",
                     is_transfer ? "transfer" : "content", cwt->name, result);
      if(result)
        return result;

      result = Curl_cwriter_add(data, writer);
      if(result) {
        Curl_cwriter_free(data, writer);
        return result;
      }
    }
  } while(*enclist);

  return CURLE_OK;
}

#else
/* Stubs for builds without HTTP. */
CURLcode Curl_build_unencoding_stack(struct Curl_easy *data,
                                     const char *enclist, int is_transfer)
{
  (void) data;
  (void) enclist;
  (void) is_transfer;
  return CURLE_NOT_BUILT_IN;
}

void Curl_all_content_encodings(char *buf, size_t blen)
{
  DEBUGASSERT(buf);
  DEBUGASSERT(blen);
  if(blen < sizeof(CONTENT_ENCODING_DEFAULT))
    buf[0] = 0;
  else
    strcpy(buf, CONTENT_ENCODING_DEFAULT);
}

#endif /* CURL_DISABLE_HTTP */
