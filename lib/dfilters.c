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

#include "dfilters.h"
#include "sendf.h"
#include "http.h"
#include "strdup.h"
#include "strcase.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

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


/* Real client writer: no downstream. */
static CURLcode df_app_init(struct Curl_df_writer *writer,
                            struct Curl_easy *data)
{
  (void)data;
  (void)writer;
  return CURLE_OK;
}

static CURLcode df_app_do_meta(struct Curl_df_writer *writer,
                               struct Curl_easy *data, int meta_type,
                               const char *buf, size_t blen)
{
  (void)writer;
  return Curl_client_write(data, meta_type, (char *) buf, blen);
}

static CURLcode df_app_do_body(struct Curl_df_writer *writer,
                               struct Curl_easy *data,
                               const char *buf, size_t nbytes)
{
  struct SingleRequest *k = &data->req;
  (void)writer;

  if(!nbytes || k->ignorebody)
    return CURLE_OK;

  return Curl_client_write(data, CLIENTWRITE_BODY, (char *) buf, nbytes);
}

static void df_app_close(struct Curl_df_writer *writer,
                         struct Curl_easy *data)
{
  (void)data;
  (void)writer;
}

static const struct Curl_df_write_type df_writer_app = {
  "app",
  NULL,
  df_app_init,
  df_app_do_meta,
  df_app_do_body,
  df_app_close,
  sizeof(struct Curl_df_writer)
};

/* Create an unencoding writer stage using the given handler. */
static struct Curl_df_writer *
Curl_df_writer_create(struct Curl_easy *data,
                      const struct Curl_df_write_type *handler,
                      curl_df_phase phase)
{
  struct Curl_df_writer *writer;

  DEBUGASSERT(handler->writersize >= sizeof(struct Curl_df_writer));
  writer = (struct Curl_df_writer *) calloc(1, handler->writersize);

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
  struct SingleRequest *k = &data->req;
  struct Curl_df_writer *writer;

  while(k->writer_stack) {
    writer = k->writer_stack;
    k->writer_stack = writer->next;
    writer->dft->do_close(writer, data);
    free(writer);
  }
}

CURLcode Curl_df_add_writer(struct Curl_easy *data,
                            const struct Curl_df_write_type *wtype,
                            curl_df_phase phase)
{
  struct Curl_df_writer *writer;

  if(phase == CURL_DF_PHASE_TRANSCODE ||
     phase == CURL_DF_PHASE_CONTENT) {
    /* Do we exceed the max number of decoders for these phases? */
    size_t ndecoders = 1; /* we are about to add 1 */
    for(writer = data->req.writer_stack; writer; writer = writer->next) {
      if(writer->phase == CURL_DF_PHASE_TRANSCODE ||
         writer->phase == CURL_DF_PHASE_CONTENT)
         ++ndecoders;
    }
    if(ndecoders >= MAX_ENCODE_STACK) {
      failf(data, "Reject response due to more than %u content encodings",
            MAX_ENCODE_STACK);
      return CURLE_BAD_CONTENT_ENCODING;
    }
  }

  writer = Curl_df_writer_create(data, wtype, phase);
  if(!writer)
    return CURLE_OUT_OF_MEMORY;

  /* Make sure we have a last writer that passes data to the client.
   * Additionally added writers in CURL_DF_PHASE_APP will come before
   * it and may override it intentionally. */
  if(!data->req.writer_stack) {
    data->req.writer_stack = Curl_df_writer_create(data, &df_writer_app,
                                            CURL_DF_PHASE_APP);
    if(!data->req.writer_stack)
      return CURLE_OUT_OF_MEMORY;
  }

  /* Insert the writer into the stack as the first of its phase.
   * writers are ordered in increasing phase value */
  if(data->req.writer_stack->phase >= phase) {
    /* first installed writer has higher or same phase, insert at head */
    writer->next = data->req.writer_stack;
    data->req.writer_stack = writer;
  }
  else {
    struct Curl_df_writer *w = data->req.writer_stack;
    while(w->next && w->next->phase < phase)
      w = w->next;
    /* w is now the last writer in the chain with a phase lower
     * than what we need to insert */
    writer->next = w->next;
    w->next = writer;
  }

  return CURLE_OK;
}

CURLcode Curl_client_write_body(struct Curl_easy *data, char *buf, size_t blen)
{
  if(data->req.writer_stack)
    return Curl_df_write_body(data->req.writer_stack, data, buf, blen);
  else
    return Curl_client_write(data, CLIENTWRITE_BODY, buf, blen);
}

CURLcode Curl_client_write_meta(struct Curl_easy *data, int meta_type,
                                char *buf, size_t blen)
{
  if(data->req.writer_stack)
    return Curl_df_write_meta(data->req.writer_stack, data,
                              meta_type, buf, blen);
  else
    return Curl_client_write(data, meta_type, buf, blen);
}
