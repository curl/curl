/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "urldata.h"
#include <curl/curl.h>
#include <curl/types.h>
#include "sendf.h"

#define DSIZ 4096               /* buffer size for decompressed data */


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
  int result;                   /* Curl_client_write status */
  char decomp[DSIZ];            /* Put the decompressed data here. */
  z_stream *z = &k->z;          /* zlib state structure */
              
  /* Initialize zlib? */
  if (!k->zlib_init) {
    z->zalloc = (alloc_func)Z_NULL;
    z->zfree = (free_func)Z_NULL;
    z->opaque = 0;              /* of dubious use 08/27/02 jhrg */
    if (inflateInit(z) != Z_OK)
      return process_zlib_error(data, z);
    k->zlib_init = 1;
  }

  /* Set the compressed input when this fucntion is called */
  z->next_in = (Bytef *)k->str;
  z->avail_in = nread;

  /* because the buffer size is fixed, iteratively decompress
     and transfer to the client via client_write. */
  for (;;) {
    /* (re)set buffer for decompressed output for every iteration */
    z->next_out = (Bytef *)&decomp[0];
    z->avail_out = DSIZ;

    status = inflate(z, Z_SYNC_FLUSH);
    if (status == Z_OK || status == Z_STREAM_END) {
      result = Curl_client_write(data, CLIENTWRITE_BODY, decomp, 
                                 DSIZ - z->avail_out);
      /* if !CURLE_OK, clean up, return */
      if (result) {              
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
#endif /* HAVE_LIBZ */

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
