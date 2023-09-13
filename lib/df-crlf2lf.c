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

#include "curl_trc.h"
#include "cfilters.h"
#include "dfilters.h"
#include "df-crlf2lf.h"
#include "strdup.h"
#include "strcase.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#if defined(CURL_DO_LINEEND_CONV) && !defined(CURL_DISABLE_FTP)

struct df_crlf2lf_ctx {
  struct Curl_df_writer super;
  /* for FTP downloads: track CRLF sequences that span blocks */
  BIT(prev_block_had_trailing_cr);
};

/*
 * change CRLF (\r\n) end-of-line markers to a single LF (\n),
 * with special processing for CRLF sequences that are split between two
 * blocks of data.  Remaining, bare CRs are changed to LFs.  The possibly new
 * size of the data is returned.
 */
static size_t df_out_convert_crlf(struct Curl_df_writer *writer,
                                  struct Curl_easy *data,
                                  char *startPtr, size_t size)
{
  struct df_crlf2lf_ctx *ctx = (struct df_crlf2lf_ctx *)writer;
  char *inPtr, *outPtr;

  /* sanity check */
  if(!startPtr || (size < 1)) {
    return size;
  }

  if(ctx->prev_block_had_trailing_cr) {
    /* The previous block of incoming data
       had a trailing CR, which was turned into a LF. */
    if(*startPtr == '\n') {
      /* This block of incoming data starts with the
         previous block's LF so get rid of it */
      memmove(startPtr, startPtr + 1, size-1);
      size--;
      /* and it wasn't a bare CR but a CRLF conversion instead */
      data->state.crlf_conversions++;
    }
    ctx->prev_block_had_trailing_cr = FALSE; /* reset the flag */
  }

  /* find 1st CR, if any */
  inPtr = outPtr = memchr(startPtr, '\r', size);
  if(inPtr) {
    /* at least one CR, now look for CRLF */
    while(inPtr < (startPtr + size-1)) {
      /* note that it's size-1, so we'll never look past the last byte */
      if(memcmp(inPtr, "\r\n", 2) == 0) {
        /* CRLF found, bump past the CR and copy the NL */
        inPtr++;
        *outPtr = *inPtr;
        /* keep track of how many CRLFs we converted */
        data->state.crlf_conversions++;
      }
      else {
        if(*inPtr == '\r') {
          /* lone CR, move LF instead */
          *outPtr = '\n';
        }
        else {
          /* not a CRLF nor a CR, just copy whatever it is */
          *outPtr = *inPtr;
        }
      }
      outPtr++;
      inPtr++;
    } /* end of while loop */

    if(inPtr < startPtr + size) {
      /* handle last byte */
      if(*inPtr == '\r') {
        /* deal with a CR at the end of the buffer */
        *outPtr = '\n'; /* copy a NL instead */
        /* note that a CRLF might be split across two blocks */
        ctx->prev_block_had_trailing_cr = TRUE;
      }
      else {
        /* copy last byte */
        *outPtr = *inPtr;
      }
      outPtr++;
    }
    if(outPtr < startPtr + size)
      /* tidy up by null terminating the now shorter data */
      *outPtr = '\0';

    return (outPtr - startPtr);
  }
  return size;
}

static CURLcode df_crlf2lf_init(struct Curl_df_writer *writer,
                                struct Curl_easy *data)
{
  (void)writer;
  (void)data;
  return CURLE_OK;
}

static bool is_active(struct Curl_easy *data, int meta_type)
{
  return (meta_type & DF_WRITE_BODY &&
          (data->conn->handler->protocol & PROTO_FAMILY_FTP) &&
          data->conn->proto.ftpc.transfertype == 'A');
}

static CURLcode df_crlf2lf_do_meta(struct Curl_df_writer *writer,
                                   struct Curl_easy *data, int meta_type,
                                   const char *buf, size_t blen)
{
  if(is_active(data, meta_type)) {
    blen = df_out_convert_crlf(writer, data, (char *)buf, blen);
  }
  return Curl_df_write_meta(writer->next, data, meta_type, buf, blen);
}

static CURLcode df_crlf2lf_do_body(struct Curl_df_writer *writer,
                                   struct Curl_easy *data,
                                   const char *buf, size_t blen)
{
  if(is_active(data, DF_WRITE_BODY)) {
    blen = df_out_convert_crlf(writer, data, (char *)buf, blen);
  }
  return Curl_df_write_body(writer->next, data, buf, blen);
}

static void df_crlf2lf_close(struct Curl_df_writer *writer,
                         struct Curl_easy *data)
{
  (void)writer;
  (void)data;
}

const struct Curl_df_write_type df_crlf2lf = {
  "crlf2lf",
  NULL,
  df_crlf2lf_init,
  df_crlf2lf_do_meta,
  df_crlf2lf_do_body,
  df_crlf2lf_close,
  sizeof(struct df_crlf2lf_ctx)
};

#endif /* CURL_DO_LINEEND_CONV) && !CURL_DISABLE_FTP */
