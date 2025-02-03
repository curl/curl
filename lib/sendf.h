#ifndef HEADER_FETCH_SENDF_H
#define HEADER_FETCH_SENDF_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#include "fetch_trc.h"

/**
 * Type of data that is being written to the client (application)
 * - data written can be either BODY or META data
 * - META data is either INFO or HEADER
 * - INFO is meta information, e.g. not BODY, that cannot be interpreted
 *   as headers of a response. Example FTP/IMAP pingpong answers.
 * - HEADER can have additional bits set (more than one)
 *   - STATUS special "header", e.g. response status line in HTTP
 *   - CONNECT header was received during proxying the connection
 *   - 1XX header is part of an intermediate response, e.g. HTTP 1xx code
 *   - TRAILER header is trailing response data, e.g. HTTP trailers
 * BODY, INFO and HEADER should not be mixed, as this would lead to
 * confusion on how to interpret/format/convert the data.
 */
#define CLIENTWRITE_BODY (1 << 0)    /* non-meta information, BODY */
#define CLIENTWRITE_INFO (1 << 1)    /* meta information, not a HEADER */
#define CLIENTWRITE_HEADER (1 << 2)  /* meta information, HEADER */
#define CLIENTWRITE_STATUS (1 << 3)  /* a special status HEADER */
#define CLIENTWRITE_CONNECT (1 << 4) /* a CONNECT related HEADER */
#define CLIENTWRITE_1XX (1 << 5)     /* a 1xx response related HEADER */
#define CLIENTWRITE_TRAILER (1 << 6) /* a trailer HEADER */
#define CLIENTWRITE_EOS (1 << 7)     /* End Of transfer download Stream */

/**
 * Write `len` bytes at `prt` to the client. `type` indicates what
 * kind of data is being written.
 */
FETCHcode Fetch_client_write(struct Fetch_easy *data, int type, const char *ptr,
                            size_t len) WARN_UNUSED_RESULT;

/**
 * Free all resources related to client writing.
 */
void Fetch_client_cleanup(struct Fetch_easy *data);

/**
 * Reset readers and writer chains, keep rewind information
 * when necessary.
 */
void Fetch_client_reset(struct Fetch_easy *data);

/**
 * A new request is starting, perform any ops like rewinding
 * previous readers when needed.
 */
FETCHcode Fetch_client_start(struct Fetch_easy *data);

/**
 * Client Writers - a chain passing transfer BODY data to the client.
 * Main application: HTTP and related protocols
 * Other uses: monitoring of download progress
 *
 * Writers in the chain are order by their `phase`. First come all
 * writers in FETCH_CW_RAW, followed by any in FETCH_CW_TRANSFER_DECODE,
 * followed by any in FETCH_CW_PROTOCOL, etc.
 *
 * When adding a writer, it is inserted as first in its phase. This means
 * the order of adding writers of the same phase matters, but writers for
 * different phases may be added in any order.
 *
 * Writers which do modify the BODY data written are expected to be of
 * phases TRANSFER_DECODE or CONTENT_DECODE. The other phases are intended
 * for monitoring writers. Which do *not* modify the data but gather
 * statistics or update progress reporting.
 */

/* Phase a writer operates at. */
typedef enum
{
  FETCH_CW_RAW,             /* raw data written, before any decoding */
  FETCH_CW_TRANSFER_DECODE, /* remove transfer-encodings */
  FETCH_CW_PROTOCOL,        /* after transfer, but before content decoding */
  FETCH_CW_CONTENT_DECODE,  /* remove content-encodings */
  FETCH_CW_CLIENT           /* data written to client */
} Fetch_cwriter_phase;

/* Client Writer Type, provides the implementation */
struct Fetch_cwtype
{
  const char *name;  /* writer name. */
  const char *alias; /* writer name alias, maybe NULL. */
  FETCHcode (*do_init)(struct Fetch_easy *data,
                       struct Fetch_cwriter *writer);
  FETCHcode (*do_write)(struct Fetch_easy *data,
                        struct Fetch_cwriter *writer, int type,
                        const char *buf, size_t nbytes);
  void (*do_close)(struct Fetch_easy *data,
                   struct Fetch_cwriter *writer);
  size_t cwriter_size; /* sizeof() allocated struct Fetch_cwriter */
};

/* Client writer instance, allocated on creation.
 * `void *ctx` is the pointer from the allocation of
 * the `struct Fetch_cwriter` itself. This is suitable for "downcasting"
 * by the writers implementation. See https://github.com/fetch/fetch/pull/13054
 * for the alignment problems that arise otherwise.
 */
struct Fetch_cwriter
{
  const struct Fetch_cwtype *cwt; /* type implementation */
  struct Fetch_cwriter *next;     /* Downstream writer. */
  void *ctx;                     /* allocated instance pointer */
  Fetch_cwriter_phase phase;      /* phase at which it operates */
};

/**
 * Create a new cwriter instance with given type and phase. Is not
 * inserted into the writer chain by this call.
 * Invokes `writer->do_init()`.
 */
FETCHcode Fetch_cwriter_create(struct Fetch_cwriter **pwriter,
                              struct Fetch_easy *data,
                              const struct Fetch_cwtype *ce_handler,
                              Fetch_cwriter_phase phase);

/**
 * Free a cwriter instance.
 * Invokes `writer->do_close()`.
 */
void Fetch_cwriter_free(struct Fetch_easy *data,
                       struct Fetch_cwriter *writer);

/**
 * Count the number of writers installed of the given phase.
 */
size_t Fetch_cwriter_count(struct Fetch_easy *data, Fetch_cwriter_phase phase);

/**
 * Adds a writer to the transfer's writer chain.
 * The writers `phase` determines where in the chain it is inserted.
 */
FETCHcode Fetch_cwriter_add(struct Fetch_easy *data,
                           struct Fetch_cwriter *writer);

/**
 * Look up an installed client writer on `data` by its type.
 * @return first writer with that type or NULL
 */
struct Fetch_cwriter *Fetch_cwriter_get_by_type(struct Fetch_easy *data,
                                              const struct Fetch_cwtype *cwt);

struct Fetch_cwriter *Fetch_cwriter_get_by_name(struct Fetch_easy *data,
                                              const char *name);

/**
 * Convenience method for calling `writer->do_write()` that
 * checks for NULL writer.
 */
FETCHcode Fetch_cwriter_write(struct Fetch_easy *data,
                             struct Fetch_cwriter *writer, int type,
                             const char *buf, size_t nbytes);

/**
 * Return TRUE iff client writer is paused.
 */
bool Fetch_cwriter_is_paused(struct Fetch_easy *data);

/**
 * Unpause client writer and flush any buffered date to the client.
 */
FETCHcode Fetch_cwriter_unpause(struct Fetch_easy *data);

/**
 * Default implementations for do_init, do_write, do_close that
 * do nothing and pass the data through.
 */
FETCHcode Fetch_cwriter_def_init(struct Fetch_easy *data,
                                struct Fetch_cwriter *writer);
FETCHcode Fetch_cwriter_def_write(struct Fetch_easy *data,
                                 struct Fetch_cwriter *writer, int type,
                                 const char *buf, size_t nbytes);
void Fetch_cwriter_def_close(struct Fetch_easy *data,
                            struct Fetch_cwriter *writer);

/* Client Reader Type, provides the implementation */
struct Fetch_crtype
{
  const char *name; /* writer name. */
  FETCHcode (*do_init)(struct Fetch_easy *data, struct Fetch_creader *reader);
  FETCHcode (*do_read)(struct Fetch_easy *data, struct Fetch_creader *reader,
                       char *buf, size_t blen, size_t *nread, bool *eos);
  void (*do_close)(struct Fetch_easy *data, struct Fetch_creader *reader);
  bool (*needs_rewind)(struct Fetch_easy *data, struct Fetch_creader *reader);
  fetch_off_t (*total_length)(struct Fetch_easy *data,
                              struct Fetch_creader *reader);
  FETCHcode (*resume_from)(struct Fetch_easy *data,
                           struct Fetch_creader *reader, fetch_off_t offset);
  FETCHcode (*rewind)(struct Fetch_easy *data, struct Fetch_creader *reader);
  FETCHcode (*unpause)(struct Fetch_easy *data, struct Fetch_creader *reader);
  bool (*is_paused)(struct Fetch_easy *data, struct Fetch_creader *reader);
  void (*done)(struct Fetch_easy *data,
               struct Fetch_creader *reader, int premature);
  size_t creader_size; /* sizeof() allocated struct Fetch_creader */
};

/* Phase a reader operates at. */
typedef enum
{
  FETCH_CR_NET,             /* data send to the network (connection filters) */
  FETCH_CR_TRANSFER_ENCODE, /* add transfer-encodings */
  FETCH_CR_PROTOCOL,        /* before transfer, but after content decoding */
  FETCH_CR_CONTENT_ENCODE,  /* add content-encodings */
  FETCH_CR_CLIENT           /* data read from client */
} Fetch_creader_phase;

/* Client reader instance, allocated on creation.
 * `void *ctx` is the pointer from the allocation of
 * the `struct Fetch_cwriter` itself. This is suitable for "downcasting"
 * by the writers implementation. See https://github.com/fetch/fetch/pull/13054
 * for the alignment problems that arise otherwise.
 */
struct Fetch_creader
{
  const struct Fetch_crtype *crt; /* type implementation */
  struct Fetch_creader *next;     /* Downstream reader. */
  void *ctx;
  Fetch_creader_phase phase; /* phase at which it operates */
};

/**
 * Default implementations for do_init, do_write, do_close that
 * do nothing and pass the data through.
 */
FETCHcode Fetch_creader_def_init(struct Fetch_easy *data,
                                struct Fetch_creader *reader);
void Fetch_creader_def_close(struct Fetch_easy *data,
                            struct Fetch_creader *reader);
FETCHcode Fetch_creader_def_read(struct Fetch_easy *data,
                                struct Fetch_creader *reader,
                                char *buf, size_t blen,
                                size_t *nread, bool *eos);
bool Fetch_creader_def_needs_rewind(struct Fetch_easy *data,
                                   struct Fetch_creader *reader);
fetch_off_t Fetch_creader_def_total_length(struct Fetch_easy *data,
                                          struct Fetch_creader *reader);
FETCHcode Fetch_creader_def_resume_from(struct Fetch_easy *data,
                                       struct Fetch_creader *reader,
                                       fetch_off_t offset);
FETCHcode Fetch_creader_def_rewind(struct Fetch_easy *data,
                                  struct Fetch_creader *reader);
FETCHcode Fetch_creader_def_unpause(struct Fetch_easy *data,
                                   struct Fetch_creader *reader);
bool Fetch_creader_def_is_paused(struct Fetch_easy *data,
                                struct Fetch_creader *reader);
void Fetch_creader_def_done(struct Fetch_easy *data,
                           struct Fetch_creader *reader, int premature);

/**
 * Convenience method for calling `reader->do_read()` that
 * checks for NULL reader.
 */
FETCHcode Fetch_creader_read(struct Fetch_easy *data,
                            struct Fetch_creader *reader,
                            char *buf, size_t blen, size_t *nread, bool *eos);

/**
 * Create a new creader instance with given type and phase. Is not
 * inserted into the writer chain by this call.
 * Invokes `reader->do_init()`.
 */
FETCHcode Fetch_creader_create(struct Fetch_creader **preader,
                              struct Fetch_easy *data,
                              const struct Fetch_crtype *cr_handler,
                              Fetch_creader_phase phase);

/**
 * Free a creader instance.
 * Invokes `reader->do_close()`.
 */
void Fetch_creader_free(struct Fetch_easy *data, struct Fetch_creader *reader);

/**
 * Adds a reader to the transfer's reader chain.
 * The readers `phase` determines where in the chain it is inserted.
 */
FETCHcode Fetch_creader_add(struct Fetch_easy *data,
                           struct Fetch_creader *reader);

/**
 * Set the given reader, which needs to be of type FETCH_CR_CLIENT,
 * as the new first reader. Discard any installed readers and init
 * the reader chain anew.
 * The function takes ownership of `r`.
 */
FETCHcode Fetch_creader_set(struct Fetch_easy *data, struct Fetch_creader *r);

/**
 * Read at most `blen` bytes at `buf` from the client.
 * @param data    the transfer to read client bytes for
 * @param buf     the memory location to read to
 * @param blen    the amount of memory at `buf`
 * @param nread   on return the number of bytes read into `buf`
 * @param eos     TRUE iff bytes are the end of data from client
 * @return FETCHE_OK on successful read (even 0 length) or error
 */
FETCHcode Fetch_client_read(struct Fetch_easy *data, char *buf, size_t blen,
                           size_t *nread, bool *eos) WARN_UNUSED_RESULT;

/**
 * TRUE iff client reader needs rewing before it can be used for
 * a retry request.
 */
bool Fetch_creader_needs_rewind(struct Fetch_easy *data);

/**
 * TRUE iff client reader will rewind at next start
 */
bool Fetch_creader_will_rewind(struct Fetch_easy *data);

/**
 * En-/disable rewind of client reader at next start.
 */
void Fetch_creader_set_rewind(struct Fetch_easy *data, bool enable);

/**
 * Get the total length of bytes provided by the installed readers.
 * This is independent of the amount already delivered and is calculated
 * by all readers in the stack. If a reader like "chunked" or
 * "crlf conversion" is installed, the returned length will be -1.
 * @return -1 if length is indeterminate
 */
fetch_off_t Fetch_creader_total_length(struct Fetch_easy *data);

/**
 * Get the total length of bytes provided by the reader at phase
 * FETCH_CR_CLIENT. This may not match the amount of bytes read
 * for a request, depending if other, encoding readers are also installed.
 * However it allows for rough estimation of the overall length.
 * @return -1 if length is indeterminate
 */
fetch_off_t Fetch_creader_client_length(struct Fetch_easy *data);

/**
 * Ask the installed reader at phase FETCH_CR_CLIENT to start
 * reading from the given offset. On success, this will reduce
 * the `total_length()` by the amount.
 * @param data    the transfer to read client bytes for
 * @param offset  the offset where to start reads from, negative
 *                values will be ignored.
 * @return FETCHE_OK if offset could be set
 *         FETCHE_READ_ERROR if not supported by reader or seek/read failed
 *                          of offset larger then total length
 *         FETCHE_PARTIAL_FILE if offset led to 0 total length
 */
FETCHcode Fetch_creader_resume_from(struct Fetch_easy *data, fetch_off_t offset);

/**
 * Unpause all installed readers.
 */
FETCHcode Fetch_creader_unpause(struct Fetch_easy *data);

/**
 * Return TRUE iff any of the installed readers is paused.
 */
bool Fetch_creader_is_paused(struct Fetch_easy *data);

/**
 * Tell all client readers that they are done.
 */
void Fetch_creader_done(struct Fetch_easy *data, int premature);

/**
 * Look up an installed client reader on `data` by its type.
 * @return first reader with that type or NULL
 */
struct Fetch_creader *Fetch_creader_get_by_type(struct Fetch_easy *data,
                                              const struct Fetch_crtype *crt);

/**
 * Set the client reader to provide 0 bytes, immediate EOS.
 */
FETCHcode Fetch_creader_set_null(struct Fetch_easy *data);

/**
 * Set the client reader the reads from fread callback.
 */
FETCHcode Fetch_creader_set_fread(struct Fetch_easy *data, fetch_off_t len);

/**
 * Set the client reader the reads from the supplied buf (NOT COPIED).
 */
FETCHcode Fetch_creader_set_buf(struct Fetch_easy *data,
                               const char *buf, size_t blen);

#endif /* HEADER_FETCH_SENDF_H */
