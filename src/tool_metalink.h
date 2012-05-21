#ifndef HEADER_CURL_TOOL_METALINK_H
#define HEADER_CURL_TOOL_METALINK_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "tool_setup.h"

#include <metalink/metalink_parser.h>

#include "tool_cfgable.h"

struct metalinkfile {
  struct metalinkfile *next;
  metalink_file_t *file;
};

struct metalink {
  struct metalink *next;
  metalink_t* metalink;
};

struct metalinkfile *new_metalinkfile(metalink_file_t *metalinkfile);

struct metalink *new_metalink(metalink_t *metalink);

/*
 * Counts the resource in the metalinkfile.
 */
int count_next_metalink_resource(struct metalinkfile *mlfile);

void clean_metalink(struct Configurable *config);

int parse_metalink(struct Configurable *config, const char *infile);

/*
 * Returns nonzero if content_type includes "application/metalink+xml"
 * media-type. The check is done in case-insensitive manner.
 */
int check_metalink_content_type(const char *content_type);

typedef void (* Curl_digest_init_func)(void *context);
typedef void (* Curl_digest_update_func)(void *context,
                                         const unsigned char *data,
                                         unsigned int len);
typedef void (* Curl_digest_final_func)(unsigned char *result, void *context);

typedef struct {
  Curl_digest_init_func     digest_init;   /* Initialize context procedure */
  Curl_digest_update_func   digest_update; /* Update context with data */
  Curl_digest_final_func    digest_final;  /* Get final result procedure */
  unsigned int           digest_ctxtsize;  /* Context structure size */
  unsigned int           digest_resultlen; /* Result length (bytes) */
} digest_params;

typedef struct {
  const digest_params   *digest_hash;      /* Hash function definition */
  void                  *digest_hashctx;   /* Hash function context */
} digest_context;

extern const digest_params MD5_DIGEST_PARAMS[1];
extern const digest_params SHA1_DIGEST_PARAMS[1];
extern const digest_params SHA256_DIGEST_PARAMS[1];

digest_context * Curl_digest_init(const digest_params *dparams);
int Curl_digest_update(digest_context *context,
                       const unsigned char *data,
                       unsigned int len);
int Curl_digest_final(digest_context *context, unsigned char *result);

typedef struct {
  const char *hash_name;
  const digest_params *dparams;
} metalink_digest_def;

typedef struct {
  const char *alias_name;
  const metalink_digest_def *digest_def;
} metalink_digest_alias;

/*
 * Check checksum of file denoted by filename.
 *
 * This function returns 1 if the checksum matches or one of the
 * following integers:
 *
 * 0:
 *   Checksum didn't match.
 * -1:
 *   Could not open file; or could not read data from file.
 * -2:
 *   No checksum in Metalink supported; or Metalink does not contain
 *   checksum.
 */
int metalink_check_hash(struct Configurable *config,
                        struct metalinkfile *mlfile,
                        const char *filename);

#endif /* HEADER_CURL_TOOL_METALINK_H */
