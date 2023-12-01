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
#if defined(__GNUC__)
/* Ignore -Wvla warnings in brotli headers */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
#endif
#include <brotli/decode.h>
#if defined(__GNUC__)
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

#define DSIZ CURL_MAX_WRITE_SIZE /* buffer size for decompressed data */


#ifdef HAVE_LIBZ

/* Comment this out if zlib is always going to be at least ver. 1.2.0.4
   (doing so will reduce code size slightly). */
#define OLD_ZLIB_SUPPORT 1

#define GZIP_MAGIC_0 0x1f
#define GZIP_MAGIC_1 0x8b

/* gzip flag byte */
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */

typedef enum {
  ZLIB_UNINIT,               /* uninitialized */
  ZLIB_INIT,                 /* initialized */
  ZLIB_INFLATING,            /* inflating started. */
  ZLIB_EXTERNAL_TRAILER,     /* reading external trailer */
  ZLIB_GZIP_HEADER,          /* reading gzip header */
  ZLIB_GZIP_INFLATING,       /* inflating gzip stream */
  ZLIB_INIT_GZIP             /* initialized in transparent gzip mode */
} zlibInitState;

/* Deflate and gzip writer. */
struct zlib_writer {
  struct Curl_cwriter super;
  zlibInitState zlib_init;   /* zlib init state */
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
  if(*zlib_init == ZLIB_GZIP_HEADER)
    Curl_safefree(z->next_in);

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
  uInt len = z->avail_in < zp->trailerlen? z->avail_in: zp->trailerlen;

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
  char *decomp;                 /* Put the decompressed data here. */

  /* Check state. */
  if(zp->zlib_init != ZLIB_INIT &&
     zp->zlib_init != ZLIB_INFLATING &&
     zp->zlib_init != ZLIB_INIT_GZIP &&
     zp->zlib_init != ZLIB_GZIP_INFLATING)
    return exit_zlib(data, z, &zp->zlib_init, CURLE_WRITE_ERROR);

  /* Dynamically allocate a buffer for decompression because it's uncommonly
     large to hold on the stack */
  decomp = malloc(DSIZ);
  if(!decomp)
    return exit_zlib(data, z, &zp->zlib_init, CURLE_OUT_OF_MEMORY);

  /* because the buffer size is fixed, iteratively decompress and transfer to
     the client via next_write function. */
  while(!done) {
    int status;                   /* zlib status */
    done = TRUE;

    /* (re)set buffer for decompressed output for every iteration */
    z->next_out = (Bytef *) decomp;
    z->avail_out = DSIZ;

#ifdef Z_BLOCK
    /* Z_BLOCK is only available in zlib ver. >= 1.2.0.5 */
    status = inflate(z, Z_BLOCK);
#else
    /* fallback for zlib ver. < 1.2.0.5 */
    status = inflate(z, Z_SYNC_FLUSH);
#endif

    /* Flush output data if some. */
    if(z->avail_out != DSIZ) {
      if(status == Z_OK || status == Z_STREAM_END) {
        zp->zlib_init = started;      /* Data started. */
        result = Curl_cwriter_write(data, writer->next, type, decomp,
                                     DSIZ - z->avail_out);
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
        (void) inflateEnd(z);     /* don't care about the return code */
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
  free(decomp);

  /* We're about to leave this call so the `nread' data bytes won't be seen
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

  if(!(type & CLIENTWRITE_BODY))
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

  if(strcmp(zlibVersion(), "1.2.0.4") >= 0) {
    /* zlib ver. >= 1.2.0.4 supports transparent gzip decompressing */
    if(inflateInit2(z, MAX_WBITS + 32) != Z_OK) {
      return process_zlib_error(data, z);
    }
    zp->zlib_init = ZLIB_INIT_GZIP; /* Transparent gzip decompress state */
  }
  else {
    /* we must parse the gzip header and trailer ourselves */
    if(inflateInit2(z, -MAX_WBITS) != Z_OK) {
      return process_zlib_error(data, z);
    }
    zp->trailerlen = 8; /* A CRC-32 and a 32-bit input size (RFC 1952, 2.2) */
    zp->zlib_init = ZLIB_INIT; /* Initial call state */
  }

  return CURLE_OK;
}

#ifdef OLD_ZLIB_SUPPORT
/* Skip over the gzip header */
typedef enum {
  GZIP_OK,
  GZIP_BAD,
  GZIP_UNDERFLOW
} gzip_status;

static gzip_status check_gzip_header(unsigned char const *data, ssize_t len,
                                     ssize_t *headerlen)
{
  int method, flags;
  const ssize_t totallen = len;

  /* The shortest header is 10 bytes */
  if(len < 10)
    return GZIP_UNDERFLOW;

  if((data[0] != GZIP_MAGIC_0) || (data[1] != GZIP_MAGIC_1))
    return GZIP_BAD;

  method = data[2];
  flags = data[3];

  if(method != Z_DEFLATED || (flags & RESERVED) != 0) {
    /* Can't handle this compression method or unknown flag */
    return GZIP_BAD;
  }

  /* Skip over time, xflags, OS code and all previous bytes */
  len -= 10;
  data += 10;

  if(flags & EXTRA_FIELD) {
    ssize_t extra_len;

    if(len < 2)
      return GZIP_UNDERFLOW;

    extra_len = (data[1] << 8) | data[0];

    if(len < (extra_len + 2))
      return GZIP_UNDERFLOW;

    len -= (extra_len + 2);
    data += (extra_len + 2);
  }

  if(flags & ORIG_NAME) {
    /* Skip over NUL-terminated file name */
    while(len && *data) {
      --len;
      ++data;
    }
    if(!len || *data)
      return GZIP_UNDERFLOW;

    /* Skip over the NUL */
    --len;
    ++data;
  }

  if(flags & COMMENT) {
    /* Skip over NUL-terminated comment */
    while(len && *data) {
      --len;
      ++data;
    }
    if(!len || *data)
      return GZIP_UNDERFLOW;

    /* Skip over the NUL */
    --len;
  }

  if(flags & HEAD_CRC) {
    if(len < 2)
      return GZIP_UNDERFLOW;

    len -= 2;
  }

  *headerlen = totallen - len;
  return GZIP_OK;
}
#endif

static CURLcode gzip_do_write(struct Curl_easy *data,
                                    struct Curl_cwriter *writer, int type,
                                    const char *buf, size_t nbytes)
{
  struct zlib_writer *zp = (struct zlib_writer *) writer;
  z_stream *z = &zp->z;     /* zlib state structure */

  if(!(type & CLIENTWRITE_BODY))
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  if(zp->zlib_init == ZLIB_INIT_GZIP) {
    /* Let zlib handle the gzip decompression entirely */
    z->next_in = (Bytef *) buf;
    z->avail_in = (uInt) nbytes;
    /* Now uncompress the data */
    return inflate_stream(data, writer, type, ZLIB_INIT_GZIP);
  }

#ifndef OLD_ZLIB_SUPPORT
  /* Support for old zlib versions is compiled away and we are running with
     an old version, so return an error. */
  return exit_zlib(data, z, &zp->zlib_init, CURLE_WRITE_ERROR);

#else
  /* This next mess is to get around the potential case where there isn't
   * enough data passed in to skip over the gzip header.  If that happens, we
   * malloc a block and copy what we have then wait for the next call.  If
   * there still isn't enough (this is definitely a worst-case scenario), we
   * make the block bigger, copy the next part in and keep waiting.
   *
   * This is only required with zlib versions < 1.2.0.4 as newer versions
   * can handle the gzip header themselves.
   */

  switch(zp->zlib_init) {
  /* Skip over gzip header? */
  case ZLIB_INIT:
  {
    /* Initial call state */
    ssize_t hlen;

    switch(check_gzip_header((unsigned char *) buf, nbytes, &hlen)) {
    case GZIP_OK:
      z->next_in = (Bytef *) buf + hlen;
      z->avail_in = (uInt) (nbytes - hlen);
      zp->zlib_init = ZLIB_GZIP_INFLATING; /* Inflating stream state */
      break;

    case GZIP_UNDERFLOW:
      /* We need more data so we can find the end of the gzip header.  It's
       * possible that the memory block we malloc here will never be freed if
       * the transfer abruptly aborts after this point.  Since it's unlikely
       * that circumstances will be right for this code path to be followed in
       * the first place, and it's even more unlikely for a transfer to fail
       * immediately afterwards, it should seldom be a problem.
       */
      z->avail_in = (uInt) nbytes;
      z->next_in = malloc(z->avail_in);
      if(!z->next_in) {
        return exit_zlib(data, z, &zp->zlib_init, CURLE_OUT_OF_MEMORY);
      }
      memcpy(z->next_in, buf, z->avail_in);
      zp->zlib_init = ZLIB_GZIP_HEADER;  /* Need more gzip header data state */
      /* We don't have any data to inflate yet */
      return CURLE_OK;

    case GZIP_BAD:
    default:
      return exit_zlib(data, z, &zp->zlib_init, process_zlib_error(data, z));
    }

  }
  break;

  case ZLIB_GZIP_HEADER:
  {
    /* Need more gzip header data state */
    ssize_t hlen;
    z->avail_in += (uInt) nbytes;
    z->next_in = Curl_saferealloc(z->next_in, z->avail_in);
    if(!z->next_in) {
      return exit_zlib(data, z, &zp->zlib_init, CURLE_OUT_OF_MEMORY);
    }
    /* Append the new block of data to the previous one */
    memcpy(z->next_in + z->avail_in - nbytes, buf, nbytes);

    switch(check_gzip_header(z->next_in, z->avail_in, &hlen)) {
    case GZIP_OK:
      /* This is the zlib stream data */
      free(z->next_in);
      /* Don't point into the malloced block since we just freed it */
      z->next_in = (Bytef *) buf + hlen + nbytes - z->avail_in;
      z->avail_in = (uInt) (z->avail_in - hlen);
      zp->zlib_init = ZLIB_GZIP_INFLATING;   /* Inflating stream state */
      break;

    case GZIP_UNDERFLOW:
      /* We still don't have any data to inflate! */
      return CURLE_OK;

    case GZIP_BAD:
    default:
      return exit_zlib(data, z, &zp->zlib_init, process_zlib_error(data, z));
    }

  }
  break;

  case ZLIB_EXTERNAL_TRAILER:
    z->next_in = (Bytef *) buf;
    z->avail_in = (uInt) nbytes;
    return process_trailer(data, zp);

  case ZLIB_GZIP_INFLATING:
  default:
    /* Inflating stream state */
    z->next_in = (Bytef *) buf;
    z->avail_in = (uInt) nbytes;
    break;
  }

  if(z->avail_in == 0) {
    /* We don't have any data to inflate; wait until next time */
    return CURLE_OK;
  }

  /* We've parsed the header, now uncompress the data */
  return inflate_stream(data, writer, type, ZLIB_GZIP_INFLATING);
#endif
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
  return bp->br? CURLE_OK: CURLE_OUT_OF_MEMORY;
}

static CURLcode brotli_do_write(struct Curl_easy *data,
                                      struct Curl_cwriter *writer, int type,
                                      const char *buf, size_t nbytes)
{
  struct brotli_writer *bp = (struct brotli_writer *) writer;
  const uint8_t *src = (const uint8_t *) buf;
  char *decomp;
  uint8_t *dst;
  size_t dstleft;
  CURLcode result = CURLE_OK;
  BrotliDecoderResult r = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;

  if(!(type & CLIENTWRITE_BODY))
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  if(!bp->br)
    return CURLE_WRITE_ERROR;  /* Stream already ended. */

  decomp = malloc(DSIZ);
  if(!decomp)
    return CURLE_OUT_OF_MEMORY;

  while((nbytes || r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) &&
        result == CURLE_OK) {
    dst = (uint8_t *) decomp;
    dstleft = DSIZ;
    r = BrotliDecoderDecompressStream(bp->br,
                                      &nbytes, &src, &dstleft, &dst, NULL);
    result = Curl_cwriter_write(data, writer->next, type,
                                 decomp, DSIZ - dstleft);
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
  free(decomp);
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
  void *decomp;
};

static CURLcode zstd_do_init(struct Curl_easy *data,
                                 struct Curl_cwriter *writer)
{
  struct zstd_writer *zp = (struct zstd_writer *) writer;

  (void)data;

  zp->zds = ZSTD_createDStream();
  zp->decomp = NULL;
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

  if(!(type & CLIENTWRITE_BODY))
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  if(!zp->decomp) {
    zp->decomp = malloc(DSIZ);
    if(!zp->decomp)
      return CURLE_OUT_OF_MEMORY;
  }
  in.pos = 0;
  in.src = buf;
  in.size = nbytes;

  for(;;) {
    out.pos = 0;
    out.dst = zp->decomp;
    out.size = DSIZ;

    errorCode = ZSTD_decompressStream(zp->zds, &out, &in);
    if(ZSTD_isError(errorCode)) {
      return CURLE_BAD_CONTENT_ENCODING;
    }
    if(out.pos > 0) {
      result = Curl_cwriter_write(data, writer->next, type,
                                   zp->decomp, out.pos);
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

  if(zp->decomp) {
    free(zp->decomp);
    zp->decomp = NULL;
  }
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
  char all[256];
  (void)Curl_all_content_encodings(all, sizeof(all));

  (void) writer;
  (void) buf;
  (void) nbytes;

  if(!(type & CLIENTWRITE_BODY))
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  failf(data, "Unrecognized content encoding type. "
        "libcurl understands %s content encodings.", all);
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

/* Set-up the unencoding stack from the Content-Encoding header value.
 * See RFC 7231 section 3.1.2.2. */
CURLcode Curl_build_unencoding_stack(struct Curl_easy *data,
                                     const char *enclist, int is_transfer)
{
  Curl_cwriter_phase phase = is_transfer?
                             CURL_CW_TRANSFER_DECODE:CURL_CW_CONTENT_DECODE;
  CURLcode result;

  do {
    const char *name;
    size_t namelen;

    /* Parse a single encoding name. */
    while(ISBLANK(*enclist) || *enclist == ',')
      enclist++;

    name = enclist;

    for(namelen = 0; *enclist && *enclist != ','; enclist++)
      if(!ISSPACE(*enclist))
        namelen = enclist - name + 1;

    if(namelen) {
      const struct Curl_cwtype *cwt;
      struct Curl_cwriter *writer;

      /* if we skip the decoding in this phase, do not look further.
       * Exception is "chunked" transfer-encoding which always must happen */
      if((is_transfer && !data->set.http_transfer_encoding &&
          (namelen != 7 || !strncasecompare(name, "chunked", 7))) ||
         (!is_transfer && data->set.http_ce_skip)) {
        /* not requested, ignore */
        return CURLE_OK;
      }

      if(Curl_cwriter_count(data, phase) + 1 >= MAX_ENCODE_STACK) {
        failf(data, "Reject response due to more than %u content encodings",
              MAX_ENCODE_STACK);
        return CURLE_BAD_CONTENT_ENCODING;
      }

      cwt = find_unencode_writer(name, namelen, phase);
      if(!cwt)
        cwt = &error_writer;  /* Defer error at use. */

      result = Curl_cwriter_create(&writer, data, cwt, phase);
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
