/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_LIBZ

#include <stdlib.h>
#include <string.h>

#include "urldata.h"
#include <curl/curl.h>
#include "sendf.h"
#include "content_encoding.h"
#include "memory.h"

#include "memdebug.h"

#define DSIZ 0x10000             /* buffer size for decompressed data */

#define GZIP_MAGIC_0 0x1f
#define GZIP_MAGIC_1 0x8b

/* gzip flag byte */
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */

static CURLcode
process_zlib_error(struct SessionHandle *data, z_stream *z)
{
  if (z->msg)
    failf (data, "Error while processing content unencoding.\n%s",
           z->msg);
  else
    failf (data, "Error while processing content unencoding.\n"
           "Unknown failure within decompression software.");

  return CURLE_BAD_CONTENT_ENCODING;
}

static CURLcode
exit_zlib(z_stream *z, bool *zlib_init, CURLcode result)
{
  inflateEnd(z);
  *zlib_init = 0;
  return result;
}

CURLcode
Curl_unencode_deflate_write(struct SessionHandle *data,
                            struct Curl_transfer_keeper *k,
                            ssize_t nread)
{
  int status;                   /* zlib status */
  CURLcode result = CURLE_OK;   /* Curl_client_write status */
  char decomp[DSIZ];            /* Put the decompressed data here. */
  z_stream *z = &k->z;          /* zlib state structure */

  /* Initialize zlib? */
  if (!k->zlib_init) {
    z->zalloc = (alloc_func)Z_NULL;
    z->zfree = (free_func)Z_NULL;
    z->opaque = 0;
    z->next_in = NULL;
    z->avail_in = 0;
    if (inflateInit(z) != Z_OK)
      return process_zlib_error(data, z);
    k->zlib_init = 1;
  }

  /* Set the compressed input when this function is called */
  z->next_in = (Bytef *)k->str;
  z->avail_in = (uInt)nread;

  /* because the buffer size is fixed, iteratively decompress
     and transfer to the client via client_write. */
  for (;;) {
    /* (re)set buffer for decompressed output for every iteration */
    z->next_out = (Bytef *)&decomp[0];
    z->avail_out = DSIZ;

    status = inflate(z, Z_SYNC_FLUSH);
    if (status == Z_OK || status == Z_STREAM_END) {
      if (DSIZ - z->avail_out) {
        result = Curl_client_write(data, CLIENTWRITE_BODY, decomp,
                                   DSIZ - z->avail_out);
        /* if !CURLE_OK, clean up, return */
        if (result)
          return exit_zlib(z, &k->zlib_init, result);
      }

      /* Done?; clean up, return */
      if (status == Z_STREAM_END) {
        if (inflateEnd(z) == Z_OK)
          return exit_zlib(z, &k->zlib_init, result);
        else
          return exit_zlib(z, &k->zlib_init, process_zlib_error(data, z));
      }

      /* Done with these bytes, exit */
      if (status == Z_OK && z->avail_in == 0 && z->avail_out > 0)
        return result;
    }
    else {                      /* Error; exit loop, handle below */
      return exit_zlib(z, &k->zlib_init, process_zlib_error(data, z));
    }
  }
}

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
  if (len < 10)
    return GZIP_UNDERFLOW;

  if ((data[0] != GZIP_MAGIC_0) || (data[1] != GZIP_MAGIC_1))
    return GZIP_BAD;

  method = data[2];
  flags = data[3];

  if (method != Z_DEFLATED || (flags & RESERVED) != 0) {
    /* Can't handle this compression method or unknown flag */
    return GZIP_BAD;
  }

  /* Skip over time, xflags, OS code and all previous bytes */
  len -= 10;
  data += 10;

  if (flags & EXTRA_FIELD) {
    ssize_t extra_len;

    if (len < 2)
      return GZIP_UNDERFLOW;

    extra_len = (data[1] << 8) | data[0];

    if (len < (extra_len+2))
      return GZIP_UNDERFLOW;

    len -= (extra_len + 2);
  }

  if (flags & ORIG_NAME) {
    /* Skip over NUL-terminated file name */
    while (len && *data) {
      --len;
      ++data;
    }
    if (!len || *data)
      return GZIP_UNDERFLOW;

    /* Skip over the NUL */
    --len;
    ++data;
  }

  if (flags & COMMENT) {
    /* Skip over NUL-terminated comment */
    while (len && *data) {
      --len;
      ++data;
    }
    if (!len || *data)
      return GZIP_UNDERFLOW;

    /* Skip over the NUL */
    --len;
    ++data;
  }

  if (flags & HEAD_CRC) {
    if (len < 2)
      return GZIP_UNDERFLOW;

    len -= 2;
    data += 2;
  }

  *headerlen = totallen - len;
  return GZIP_OK;
}

CURLcode
Curl_unencode_gzip_write(struct SessionHandle *data,
                         struct Curl_transfer_keeper *k,
                         ssize_t nread)
{
  int status;                   /* zlib status */
  CURLcode result = CURLE_OK;   /* Curl_client_write status */
  char decomp[DSIZ];            /* Put the decompressed data here. */
  z_stream *z = &k->z;          /* zlib state structure */

  /* Initialize zlib? */
  if (!k->zlib_init) {
    z->zalloc = (alloc_func)Z_NULL;
    z->zfree = (free_func)Z_NULL;
    z->opaque = 0;
    z->next_in = NULL;
    z->avail_in = 0;
    if (inflateInit2(z, -MAX_WBITS) != Z_OK)
      return process_zlib_error(data, z);
    k->zlib_init = 1;   /* Initial call state */
  }

  /* This next mess is to get around the potential case where there isn't
   * enough data passed in to skip over the gzip header.  If that happens, we
   * malloc a block and copy what we have then wait for the next call.  If
   * there still isn't enough (this is definitely a worst-case scenario), we
   * make the block bigger, copy the next part in and keep waiting.
   */

  /* Skip over gzip header? */
  if (k->zlib_init == 1) {
    /* Initial call state */
    ssize_t hlen;

    switch (check_gzip_header((unsigned char *)k->str, nread, &hlen)) {
    case GZIP_OK:
      z->next_in = (Bytef *)k->str + hlen;
      z->avail_in = (uInt)(nread - hlen);
      k->zlib_init = 3; /* Inflating stream state */
      break;

    case GZIP_UNDERFLOW:
      /* We need more data so we can find the end of the gzip header.  It's
       * possible that the memory block we malloc here will never be freed if
       * the transfer abruptly aborts after this point.  Since it's unlikely
       * that circumstances will be right for this code path to be followed in
       * the first place, and it's even more unlikely for a transfer to fail
       * immediately afterwards, it should seldom be a problem.
       */
      z->avail_in = (uInt)nread;
      z->next_in = malloc(z->avail_in);
      if (z->next_in == NULL) {
        return exit_zlib(z, &k->zlib_init, CURLE_OUT_OF_MEMORY);
      }
      memcpy(z->next_in, k->str, z->avail_in);
      k->zlib_init = 2;   /* Need more gzip header data state */
      /* We don't have any data to inflate yet */
      return CURLE_OK;

    case GZIP_BAD:
    default:
      return exit_zlib(z, &k->zlib_init, process_zlib_error(data, z));
    }

  }
  else if (k->zlib_init == 2) {
    /* Need more gzip header data state */
    ssize_t hlen;
    unsigned char *oldblock = z->next_in;

    z->avail_in += nread;
    z->next_in = realloc(z->next_in, z->avail_in);
    if (z->next_in == NULL) {
      free(oldblock);
      return exit_zlib(z, &k->zlib_init, CURLE_OUT_OF_MEMORY);
    }
    /* Append the new block of data to the previous one */
    memcpy(z->next_in + z->avail_in - nread, k->str, nread);

    switch (check_gzip_header(z->next_in, z->avail_in, &hlen)) {
    case GZIP_OK:
      /* This is the zlib stream data */
      free(z->next_in);
      /* Don't point into the malloced block since we just freed it */
      z->next_in = (Bytef *)k->str + hlen + nread - z->avail_in;
      z->avail_in = (uInt)(z->avail_in - hlen);
      k->zlib_init = 3;   /* Inflating stream state */
      break;

    case GZIP_UNDERFLOW:
      /* We still don't have any data to inflate! */
      return CURLE_OK;

    case GZIP_BAD:
    default:
      free(z->next_in);
      return exit_zlib(z, &k->zlib_init, process_zlib_error(data, z));
    }

  }
  else {
    /* Inflating stream state */
    z->next_in = (Bytef *)k->str;
    z->avail_in = (uInt)nread;
  }

  if (z->avail_in == 0) {
    /* We don't have any data to inflate; wait until next time */
    return CURLE_OK;
  }

  /* because the buffer size is fixed, iteratively decompress and transfer to
     the client via client_write. */
  for (;;) {
    /* (re)set buffer for decompressed output for every iteration */
    z->next_out = (Bytef *)&decomp[0];
    z->avail_out = DSIZ;

    status = inflate(z, Z_SYNC_FLUSH);
    if (status == Z_OK || status == Z_STREAM_END) {
      if(DSIZ - z->avail_out) {
        result = Curl_client_write(data, CLIENTWRITE_BODY, decomp,
                                   DSIZ - z->avail_out);
        /* if !CURLE_OK, clean up, return */
        if (result)
          return exit_zlib(z, &k->zlib_init, result);
      }

      /* Done?; clean up, return */
      /* We should really check the gzip CRC here */
      if (status == Z_STREAM_END) {
        if (inflateEnd(z) == Z_OK)
          return exit_zlib(z, &k->zlib_init, result);
        else
          return exit_zlib(z, &k->zlib_init, process_zlib_error(data, z));
      }

      /* Done with these bytes, exit */
      if (status == Z_OK && z->avail_in == 0 && z->avail_out > 0)
        return result;
    }
    else {                      /* Error; exit loop, handle below */
      return exit_zlib(z, &k->zlib_init, process_zlib_error(data, z));
    }
  }
}
#endif /* HAVE_LIBZ */
