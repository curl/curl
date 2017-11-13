/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "urldata.h"
#include <curl/curl.h>
#include <stddef.h>

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#ifdef __SYMBIAN32__
/* zlib pollutes the namespace with this definition */
#undef WIN32
#endif
#endif

#ifdef HAVE_BROTLI
#include <brotli/decode.h>
#endif

#include "sendf.h"
#include "http.h"
#include "content_encoding.h"
#include "strdup.h"
#include "strcase.h"
#include "curl_memory.h"
#include "memdebug.h"

#define CONTENT_ENCODING_DEFAULT  "identity"

#ifndef CURL_DISABLE_HTTP

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
  ZLIB_UNINIT,          /* uninitialized */
  ZLIB_INIT,            /* initialized */
  ZLIB_GZIP_HEADER,     /* reading gzip header */
  ZLIB_GZIP_INFLATING,  /* inflating gzip stream */
  ZLIB_INIT_GZIP        /* initialized in transparent gzip mode */
} zlibInitState;

/* Writer parameters. */
typedef struct {
  zlibInitState zlib_init;    /* zlib init state */
  z_stream z;                /* State structure for zlib. */
}  zlib_params;


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
process_zlib_error(struct connectdata *conn, z_stream *z)
{
  struct Curl_easy *data = conn->data;
  if(z->msg)
    failf(data, "Error while processing content unencoding: %s",
          z->msg);
  else
    failf(data, "Error while processing content unencoding: "
          "Unknown failure within decompression software.");

  return CURLE_BAD_CONTENT_ENCODING;
}

static CURLcode
exit_zlib(struct connectdata *conn,
          z_stream *z, zlibInitState *zlib_init, CURLcode result)
{
  if(*zlib_init == ZLIB_GZIP_HEADER)
    Curl_safefree(z->next_in);

  if(*zlib_init != ZLIB_UNINIT) {
    if(inflateEnd(z) != Z_OK && result == CURLE_OK)
      result = process_zlib_error(conn, z);
    *zlib_init = ZLIB_UNINIT;
  }

  return result;
}

static CURLcode
inflate_stream(struct connectdata *conn, contenc_writer *writer)
{
  zlib_params *zp = (zlib_params *) &writer->params;
  int allow_restart = 1;
  z_stream *z = &zp->z;         /* zlib state structure */
  uInt nread = z->avail_in;
  Bytef *orig_in = z->next_in;
  int status;                   /* zlib status */
  CURLcode result = CURLE_OK;   /* Curl_client_write status */
  char *decomp;                 /* Put the decompressed data here. */

  /* Dynamically allocate a buffer for decompression because it's uncommonly
     large to hold on the stack */
  decomp = malloc(DSIZ);
  if(decomp == NULL) {
    return exit_zlib(conn, z, &zp->zlib_init, CURLE_OUT_OF_MEMORY);
  }

  /* because the buffer size is fixed, iteratively decompress and transfer to
     the client via client_write. */
  for(;;) {
    if(z->avail_in == 0) {
      free(decomp);
      return result;
    }

    /* (re)set buffer for decompressed output for every iteration */
    z->next_out = (Bytef *) decomp;
    z->avail_out = DSIZ;

    status = inflate(z, Z_SYNC_FLUSH);
    if(status == Z_OK || status == Z_STREAM_END) {
      allow_restart = 0;
      result = Curl_unencode_write(conn, writer->downstream, decomp,
                                   DSIZ - z->avail_out);
      /* if !CURLE_OK, clean up, return */
      if(result) {
        free(decomp);
        return exit_zlib(conn, z, &zp->zlib_init, result);
      }

      /* Done? clean up, return */
      if(status == Z_STREAM_END) {
        free(decomp);
        return exit_zlib(conn, z, &zp->zlib_init, result);
      }

      /* Done with these bytes, exit */

      /* status is always Z_OK at this point! */
      continue;
    }
    else if(allow_restart && status == Z_DATA_ERROR) {
      /* some servers seem to not generate zlib headers, so this is an attempt
         to fix and continue anyway */

      (void) inflateEnd(z);     /* don't care about the return code */
      if(inflateInit2(z, -MAX_WBITS) != Z_OK) {
        free(decomp);
        zp->zlib_init = ZLIB_UNINIT;  /* inflateEnd() already called. */
        return exit_zlib(conn, z, &zp->zlib_init, process_zlib_error(conn, z));
      }
      z->next_in = orig_in;
      z->avail_in = nread;
      allow_restart = 0;
      continue;
    }
    else {                      /* Error; exit loop, handle below */
      free(decomp);
      return exit_zlib(conn, z, &zp->zlib_init, process_zlib_error(conn, z));
    }
  }
  /* UNREACHED */
}


/* Deflate handler. */
static CURLcode deflate_init_writer(struct connectdata *conn,
                                    contenc_writer *writer)
{
  zlib_params *zp = (zlib_params *) &writer->params;
  z_stream *z = &zp->z;     /* zlib state structure */

  if(!writer->downstream)
    return CURLE_WRITE_ERROR;

  /* Initialize zlib */
  z->zalloc = (alloc_func) zalloc_cb;
  z->zfree = (free_func) zfree_cb;

  if(inflateInit(z) != Z_OK)
    return process_zlib_error(conn, z);
  zp->zlib_init = ZLIB_INIT;
  return CURLE_OK;
}

static CURLcode deflate_unencode_write(struct connectdata *conn,
                                       contenc_writer *writer,
                                       const char *buf, size_t nbytes)
{
  zlib_params *zp = (zlib_params *) &writer->params;
  z_stream *z = &zp->z;     /* zlib state structure */

  /* Set the compressed input when this function is called */
  z->next_in = (Bytef *) buf;
  z->avail_in = (uInt) nbytes;

  /* Now uncompress the data */
  return inflate_stream(conn, writer);
}

static void deflate_close_writer(struct connectdata *conn,
                                 contenc_writer *writer)
{
  zlib_params *zp = (zlib_params *) &writer->params;
  z_stream *z = &zp->z;     /* zlib state structure */

  exit_zlib(conn, z, &zp->zlib_init, CURLE_OK);
}

static const content_encoding deflate_encoding = {
  "deflate",
  NULL,
  deflate_init_writer,
  deflate_unencode_write,
  deflate_close_writer,
  sizeof(zlib_params)
};


/* Gzip handler. */
static CURLcode gzip_init_writer(struct connectdata *conn,
                                 contenc_writer *writer)
{
  zlib_params *zp = (zlib_params *) &writer->params;
  z_stream *z = &zp->z;     /* zlib state structure */

  if(!writer->downstream)
    return CURLE_WRITE_ERROR;

  /* Initialize zlib */
  z->zalloc = (alloc_func) zalloc_cb;
  z->zfree = (free_func) zfree_cb;

  if(strcmp(zlibVersion(), "1.2.0.4") >= 0) {
    /* zlib ver. >= 1.2.0.4 supports transparent gzip decompressing */
    if(inflateInit2(z, MAX_WBITS + 32) != Z_OK) {
      return process_zlib_error(conn, z);
    }
    zp->zlib_init = ZLIB_INIT_GZIP; /* Transparent gzip decompress state */
  }
  else {
    /* we must parse the gzip header ourselves */
    if(inflateInit2(z, -MAX_WBITS) != Z_OK) {
      return process_zlib_error(conn, z);
    }
    zp->zlib_init = ZLIB_INIT;   /* Initial call state */
  }

  return CURLE_OK;
}

#ifdef OLD_ZLIB_SUPPORT
/* Skip over the gzip header */
static enum {
  GZIP_OK,
  GZIP_BAD,
  GZIP_UNDERFLOW
} check_gzip_header(unsigned char const *data, ssize_t len, ssize_t *headerlen)
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

static CURLcode gzip_unencode_write(struct connectdata *conn,
                                    contenc_writer *writer,
                                    const char *buf, size_t nbytes)
{
  zlib_params *zp = (zlib_params *) &writer->params;
  z_stream *z = &zp->z;     /* zlib state structure */

  if(zp->zlib_init == ZLIB_INIT_GZIP) {
    /* Let zlib handle the gzip decompression entirely */
    z->next_in = (Bytef *) buf;
    z->avail_in = (uInt) nbytes;
    /* Now uncompress the data */
    return inflate_stream(conn, writer);
  }

#ifndef OLD_ZLIB_SUPPORT
  /* Support for old zlib versions is compiled away and we are running with
     an old version, so return an error. */
  return exit_zlib(conn, z, &zp->zlib_init, CURLE_WRITE_ERROR);

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
      if(z->next_in == NULL) {
        return exit_zlib(conn, z, &zp->zlib_init, CURLE_OUT_OF_MEMORY);
      }
      memcpy(z->next_in, buf, z->avail_in);
      zp->zlib_init = ZLIB_GZIP_HEADER;  /* Need more gzip header data state */
      /* We don't have any data to inflate yet */
      return CURLE_OK;

    case GZIP_BAD:
    default:
      return exit_zlib(conn, z, &zp->zlib_init, process_zlib_error(conn, z));
    }

  }
  break;

  case ZLIB_GZIP_HEADER:
  {
    /* Need more gzip header data state */
    ssize_t hlen;
    z->avail_in += (uInt) nbytes;
    z->next_in = Curl_saferealloc(z->next_in, z->avail_in);
    if(z->next_in == NULL) {
      return exit_zlib(conn, z, &zp->zlib_init, CURLE_OUT_OF_MEMORY);
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
      return exit_zlib(conn, z, &zp->zlib_init, process_zlib_error(conn, z));
    }

  }
  break;

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
  return inflate_stream(conn, writer);
#endif
}

static void gzip_close_writer(struct connectdata *conn,
                              contenc_writer *writer)
{
  zlib_params *zp = (zlib_params *) &writer->params;
  z_stream *z = &zp->z;     /* zlib state structure */

  exit_zlib(conn, z, &zp->zlib_init, CURLE_OK);
}

static const content_encoding gzip_encoding = {
  "gzip",
  "x-gzip",
  gzip_init_writer,
  gzip_unencode_write,
  gzip_close_writer,
  sizeof(zlib_params)
};

#endif /* HAVE_LIBZ */


#ifdef HAVE_BROTLI

/* Writer parameters. */
typedef struct {
  BrotliDecoderState *br;    /* State structure for brotli. */
}  brotli_params;


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
  case BROTLI_DECODER_ERROR_COMPOUND_DICTIONARY:
  case BROTLI_DECODER_ERROR_DICTIONARY_NOT_SET:
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

static CURLcode brotli_init_writer(struct connectdata *conn,
                                   contenc_writer *writer)
{
  brotli_params *bp = (brotli_params *) &writer->params;

  (void) conn;

  if(!writer->downstream)
    return CURLE_WRITE_ERROR;

  bp->br = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  return bp->br? CURLE_OK: CURLE_OUT_OF_MEMORY;
}

static CURLcode brotli_unencode_write(struct connectdata *conn,
                                      contenc_writer *writer,
                                      const char *buf, size_t nbytes)
{
  brotli_params *bp = (brotli_params *) &writer->params;
  const uint8_t *src = (const uint8_t *) buf;
  char *decomp;
  uint8_t *dst;
  size_t dstleft;
  CURLcode result = CURLE_OK;

  if(!bp->br)
    return CURLE_WRITE_ERROR;  /* Stream already ended. */

  decomp = malloc(DSIZ);
  if(!decomp)
    return CURLE_OUT_OF_MEMORY;

  while(nbytes && result == CURLE_OK) {
    BrotliDecoderResult r;

    dst = (uint8_t *) decomp;
    dstleft = DSIZ;
    r = BrotliDecoderDecompressStream(bp->br,
                                      &nbytes, &src, &dstleft, &dst, NULL);
    result = Curl_unencode_write(conn, writer->downstream,
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

static void brotli_close_writer(struct connectdata *conn,
                                contenc_writer *writer)
{
  brotli_params *bp = (brotli_params *) &writer->params;

  (void) conn;

  if(bp->br) {
    BrotliDecoderDestroyInstance(bp->br);
    bp->br = NULL;
  }
}

static const content_encoding brotli_encoding = {
  "br",
  NULL,
  brotli_init_writer,
  brotli_unencode_write,
  brotli_close_writer,
  sizeof(brotli_params)
};
#endif


/* Identity handler. */
static CURLcode identity_init_writer(struct connectdata *conn,
                                     contenc_writer *writer)
{
  (void) conn;
  return writer->downstream? CURLE_OK: CURLE_WRITE_ERROR;
}

static CURLcode identity_unencode_write(struct connectdata *conn,
                                        contenc_writer *writer,
                                        const char *buf, size_t nbytes)
{
  return Curl_unencode_write(conn, writer->downstream, buf, nbytes);
}

static void identity_close_writer(struct connectdata *conn,
                                  contenc_writer *writer)
{
  (void) conn;
  (void) writer;
}

static const content_encoding identity_encoding = {
  "identity",
  NULL,
  identity_init_writer,
  identity_unencode_write,
  identity_close_writer,
  0
};


/* supported content encodings table. */
static const content_encoding * const encodings[] = {
  &identity_encoding,
#ifdef HAVE_LIBZ
  &deflate_encoding,
  &gzip_encoding,
#endif
#ifdef HAVE_BROTLI
  &brotli_encoding,
#endif
  NULL
};


/* Return a list of comma-separated names of supported encodings. */
char *Curl_all_content_encodings(void)
{
  size_t len = 0;
  const content_encoding * const *cep;
  const content_encoding *ce;
  char *ace;
  char *p;

  for(cep = encodings; *cep; cep++) {
    ce = *cep;
    if(!strcasecompare(ce->name, CONTENT_ENCODING_DEFAULT))
      len += strlen(ce->name) + 2;
  }

  if(!len)
    return strdup(CONTENT_ENCODING_DEFAULT);

  ace = malloc(len);
  if(ace) {
    p = ace;
    for(cep = encodings; *cep; cep++) {
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

  return ace;
}


/* Real client writer: no downstream. */
static CURLcode client_init_writer(struct connectdata *conn,
                                   contenc_writer *writer)
{
  (void) conn;
  return writer->downstream? CURLE_WRITE_ERROR: CURLE_OK;
}

static CURLcode client_unencode_write(struct connectdata *conn,
                                      contenc_writer *writer,
                                      const char *buf, size_t nbytes)
{
  struct Curl_easy *data = conn->data;
  struct SingleRequest *k = &data->req;

  (void) writer;

  if(!nbytes || k->ignorebody)
    return CURLE_OK;

  return Curl_client_write(conn, CLIENTWRITE_BODY, (char *) buf, nbytes);
}

static void client_close_writer(struct connectdata *conn,
                                contenc_writer *writer)
{
  (void) conn;
  (void) writer;
}

static const content_encoding client_encoding = {
  NULL,
  NULL,
  client_init_writer,
  client_unencode_write,
  client_close_writer,
  0
};


/* Deferred error dummy writer. */
static CURLcode error_init_writer(struct connectdata *conn,
                                  contenc_writer *writer)
{
  (void) conn;
  return writer->downstream? CURLE_OK: CURLE_WRITE_ERROR;
}

static CURLcode error_unencode_write(struct connectdata *conn,
                                     contenc_writer *writer,
                                     const char *buf, size_t nbytes)
{
  char *all = Curl_all_content_encodings();

  (void) writer;
  (void) buf;
  (void) nbytes;

  if(!all)
    return CURLE_OUT_OF_MEMORY;
  failf(conn->data, "Unrecognized content encoding type. "
                    "libcurl understands %s content encodings.", all);
  free(all);
  return CURLE_BAD_CONTENT_ENCODING;
}

static void error_close_writer(struct connectdata *conn,
                               contenc_writer *writer)
{
  (void) conn;
  (void) writer;
}

static const content_encoding error_encoding = {
  NULL,
  NULL,
  error_init_writer,
  error_unencode_write,
  error_close_writer,
  0
};

/* Create an unencoding writer stage using the given handler. */
static contenc_writer *new_unencoding_writer(struct connectdata *conn,
                                             const content_encoding *handler,
                                             contenc_writer *downstream)
{
  size_t sz = offsetof(contenc_writer, params) + handler->paramsize;
  contenc_writer *writer = (contenc_writer *) malloc(sz);

  if(writer) {
    memset(writer, 0, sz);
    writer->handler = handler;
    writer->downstream = downstream;
    if(handler->init_writer(conn, writer)) {
      free(writer);
      writer = NULL;
    }
  }

  return writer;
}

/* Write data using an unencoding writer stack. */
CURLcode Curl_unencode_write(struct connectdata *conn, contenc_writer *writer,
                             const char *buf, size_t nbytes)
{
  if(!nbytes)
    return CURLE_OK;
  return writer->handler->unencode_write(conn, writer, buf, nbytes);
}

/* Close and clean-up the connection's writer stack. */
void Curl_unencode_cleanup(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  struct SingleRequest *k = &data->req;
  contenc_writer *writer = k->writer_stack;

  while(writer) {
    k->writer_stack = writer->downstream;
    writer->handler->close_writer(conn, writer);
    free(writer);
    writer = k->writer_stack;
  }
}

/* Find the content encoding by name. */
static const content_encoding *find_encoding(const char *name, size_t len)
{
  const content_encoding * const *cep;
  const content_encoding *ce;

  for(cep = encodings; *cep; cep++) {
    ce = *cep;
    if((strncasecompare(name, ce->name, len) && !ce->name[len]) ||
       (ce->alias && strncasecompare(name, ce->alias, len) && !ce->alias[len]))
      return ce;
  }
  return NULL;
}

/* Set-up the unencoding stack from the Content-Encoding header value.
 * See RFC 7231 section 3.1.2.2. */
CURLcode Curl_build_unencoding_stack(struct connectdata *conn,
                                     const char *enclist, int maybechunked)
{
  struct Curl_easy *data = conn->data;
  struct SingleRequest *k = &data->req;

  do {
    const char *name;
    size_t namelen;

    /* Parse a single encoding name. */
    while(ISSPACE(*enclist) || *enclist == ',')
      enclist++;

    name = enclist;

    for(namelen = 0; *enclist && *enclist != ','; enclist++)
      if(!ISSPACE(*enclist))
        namelen = enclist - name + 1;

    /* Special case: chunked encoding is handled at the reader level. */
    if(maybechunked && namelen == 7 && strncasecompare(name, "chunked", 7)) {
      k->chunk = TRUE;             /* chunks coming our way. */
      Curl_httpchunk_init(conn);   /* init our chunky engine. */
    }
    else if(namelen) {
      const content_encoding *encoding = find_encoding(name, namelen);
      contenc_writer *writer;

      if(!k->writer_stack) {
        k->writer_stack = new_unencoding_writer(conn, &client_encoding, NULL);

        if(!k->writer_stack)
          return CURLE_OUT_OF_MEMORY;
      }

      if(!encoding)
        encoding = &error_encoding;  /* Defer error at stack use. */

      /* Stack the unencoding stage. */
      writer = new_unencoding_writer(conn, encoding, k->writer_stack);
      if(!writer)
        return CURLE_OUT_OF_MEMORY;
      k->writer_stack = writer;
    }
  } while(*enclist);

  return CURLE_OK;
}

#else
/* Stubs for builds without HTTP. */
CURLcode Curl_build_unencoding_stack(struct connectdata *conn,
                                     const char *enclist, int maybechunked)
{
  (void) conn;
  (void) enclist;
  (void) maybechunked;
  return CURLE_NOT_BUILT_IN;
}

CURLcode Curl_unencode_write(struct connectdata *conn, contenc_writer *writer,
                             const char *buf, size_t nbytes)
{
  (void) conn;
  (void) writer;
  (void) buf;
  (void) nbytes;
  return CURLE_NOT_BUILT_IN;
}

void Curl_unencode_cleanup(struct connectdata *conn)
{
  (void) conn;
}

char *Curl_all_content_encodings(void)
{
  return strdup(CONTENT_ENCODING_DEFAULT);  /* Satisfy caller. */
}

#endif /* CURL_DISABLE_HTTP */
