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

#include "cfilters.h"
#include "dfilters.h"
#include "df-out.h"
#include "sendf.h"
#include "strdup.h"
#include "strcase.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

/* allow no more than 5 "chained" TRANSCODE+CONTENT phase writers */
#define MAX_ENCODE_STACK 5

CURLcode Curl_df_write_meta(struct Curl_df_writer *writer,
                            struct Curl_easy *data, int meta_type,
                            const char *buf, size_t nbytes)
{
  if(!writer)
    return CURLE_WRITE_ERROR;
  if(!nbytes)
    return CURLE_OK;
  return writer->dft->do_meta(writer, data, meta_type, buf, nbytes);
}

CURLcode Curl_df_write_body(struct Curl_df_writer *writer,
                            struct Curl_easy *data,
                            const char *buf, size_t nbytes)
{
  if(!writer)
    return CURLE_WRITE_ERROR;
  if(!nbytes)
    return CURLE_OK;
  return writer->dft->do_body(writer, data, buf, nbytes);
}

bool Curl_df_is_paused(struct Curl_df_writer *writer,
                       struct Curl_easy *data)
{
  if(!writer)
    return FALSE;
  return writer->dft->is_paused(writer, data);
}

CURLcode Curl_df_unpause(struct Curl_df_writer *writer,
                             struct Curl_easy *data)
{
  if(!writer)
    return CURLE_OK;
  return writer->dft->unpause(writer, data);
}

CURLcode Curl_df_def_do_meta(struct Curl_df_writer *writer,
                             struct Curl_easy *data,
                             int meta_type, const char *buf, size_t blen)
{
  return Curl_df_write_meta(writer->next, data, meta_type, buf, blen);
}

CURLcode Curl_df_def_do_body(struct Curl_df_writer *writer,
                             struct Curl_easy *data,
                             const char *buf, size_t blen)
{
  return Curl_df_write_body(writer->next, data, buf, blen);
}

bool Curl_df_def_is_paused(struct Curl_df_writer *writer,
                           struct Curl_easy *data)
{
  return Curl_df_is_paused(writer->next, data);
}

CURLcode Curl_df_def_unpause(struct Curl_df_writer *writer,
                             struct Curl_easy *data)
{
  return Curl_df_unpause(writer->next, data);
}

/* Create an unencoding writer stage using the given handler. */
static struct Curl_df_writer *
Curl_df_writer_create(struct Curl_easy *data,
                      const struct Curl_df_write_type *handler,
                      curl_df_phase phase)
{
  struct Curl_df_writer *writer;

  DEBUGASSERT(handler->writersize >= sizeof(struct Curl_df_writer));
  writer = calloc(1, handler->writersize);
  if(writer) {
    writer->dft = handler;
    writer->phase = phase;
    if(handler->do_init(writer, data)) {
      free(writer);
      writer = NULL;
    }
  }
  return writer;
}

/* Close and clean-up the connection's writer stack. */
void Curl_df_writers_cleanup(struct Curl_easy *data)
{
  struct Curl_df_writer *writer;

  while(data->req.df_client_writers) {
    writer = data->req.df_client_writers;
    data->req.df_client_writers = writer->next;
    writer->dft->do_close(writer, data);
    free(writer);
  }
}

static CURLcode init_writer_chain(struct Curl_easy *data)
{
  DEBUGASSERT(!data->req.df_client_writers);
  data->req.df_client_writers = Curl_df_writer_create(data, &df_writer_out,
                                                      CURL_DF_PHASE_APP);
  if(!data->req.df_client_writers)
    return CURLE_OUT_OF_MEMORY;
  return CURLE_OK;
}

CURLcode Curl_df_add_writer(struct Curl_easy *data,
                            const struct Curl_df_write_type *wtype,
                            curl_df_phase phase,
                            struct Curl_df_writer **pdf)
{
  struct Curl_df_writer *writer = NULL;
  CURLcode result = CURLE_OK;

  if(phase == CURL_DF_PHASE_TRANSCODE ||
     phase == CURL_DF_PHASE_DECODE) {
    /* Do we exceed the max number of decoders for these phases? */
    size_t ndecoders = 1; /* we are about to add 1 */
    for(writer = data->req.df_client_writers; writer; writer = writer->next) {
      if(writer->phase == CURL_DF_PHASE_TRANSCODE ||
         writer->phase == CURL_DF_PHASE_DECODE)
         ++ndecoders;
    }
    if(ndecoders >= MAX_ENCODE_STACK) {
      failf(data, "Reject response due to more than %u content encodings",
            MAX_ENCODE_STACK);
      result = CURLE_BAD_CONTENT_ENCODING;
      goto out;
    }
  }

  writer = Curl_df_writer_create(data, wtype, phase);
  if(!writer) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  /* Make sure we have a last writer that passes data to the client.
   * Additionally added writers in CURL_DF_PHASE_APP will come before
   * it and may override it intentionally. */
  if(!data->req.df_client_writers) {
    result = init_writer_chain(data);
    if(result)
      goto out;
  }

  /* Insert the writer into the stack as the first of its phase.
   * writers are ordered in increasing phase value */
  if(data->req.df_client_writers->phase >= phase) {
    /* first installed writer has higher or same phase, insert at head */
    writer->next = data->req.df_client_writers;
    data->req.df_client_writers = writer;
  }
  else {
    struct Curl_df_writer *w = data->req.df_client_writers;
    while(w->next && w->next->phase < phase)
      w = w->next;
    /* w is now the last writer in the chain with a phase lower
     * than what we need to insert */
    writer->next = w->next;
    w->next = writer;
  }

out:
  if(result && writer)
    Curl_safefree(writer);
  if(pdf)
    *pdf = writer;
  return result;
}

CURLcode Curl_client_write_body(struct Curl_easy *data, char *buf, size_t blen)
{
  if(!blen || data->req.ignorebody)
    return CURLE_OK;

  if(!data->req.df_client_writers) {
    CURLcode result = init_writer_chain(data);
    if(result)
      return result;
  }
  return Curl_df_write_body(data->req.df_client_writers, data, buf, blen);
}

CURLcode Curl_client_write_meta(struct Curl_easy *data, int meta_type,
                                char *buf, size_t blen)
{
  if(!data->req.df_client_writers) {
    CURLcode result = init_writer_chain(data);
    if(result)
      return result;
  }
  return Curl_df_write_meta(data->req.df_client_writers, data,
                            meta_type, buf, blen);
}

bool Curl_client_is_paused(struct Curl_easy *data)
{
  return Curl_df_is_paused(data->req.df_client_writers, data);
}

CURLcode Curl_client_unpause(struct Curl_easy *data)
{
  return Curl_df_unpause(data->req.df_client_writers, data);
}

