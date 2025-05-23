#ifndef HEADER_CURL_TOOL_SDECLS_H
#define HEADER_CURL_TOOL_SDECLS_H
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
#include "tool_setup.h"

/*
 * OutStruct variables keep track of information relative to curl's
 * output writing, which may take place to a standard stream or a file.
 *
 * 'filename' member is either a pointer to a filename string or NULL
 * when dealing with a standard stream.
 *
 * 'alloc_filename' member is TRUE when string pointed by 'filename' has been
 * dynamically allocated and 'belongs' to this OutStruct, otherwise FALSE.
 *
 * 'is_cd_filename' member is TRUE when string pointed by 'filename' has been
 * set using a server-specified Content-Disposition filename, otherwise FALSE.
 *
 * 's_isreg' member is TRUE when output goes to a regular file, this also
 * implies that output is 'seekable' and 'appendable' and also that member
 * 'filename' points to filename's string. For any standard stream member
 * 's_isreg' will be FALSE.
 *
 * 'fopened' member is TRUE when output goes to a regular file and it
 * has been fopen'ed, requiring it to be closed later on. In any other
 * case this is FALSE.
 *
 * 'stream' member is a pointer to a stream controlling object as returned
 * from a 'fopen' call or a standard stream.
 *
 * 'config' member is a pointer to associated 'OperationConfig' struct.
 *
 * 'bytes' member represents amount written so far.
 *
 * 'init' member holds original file size or offset at which truncation is
 * taking place. Always zero unless appending to a non-empty regular file.
 *
 * [Windows]
 * 'utf8seq' member holds an incomplete UTF-8 sequence destined for the console
 * until it can be completed (1-4 bytes) + NUL.
 */

struct OutStruct {
  char *filename;
  FILE *stream;
  curl_off_t bytes;
  curl_off_t init;
#ifdef _WIN32
  unsigned char utf8seq[5];
#endif
  BIT(alloc_filename);
  BIT(is_cd_filename);
  BIT(s_isreg);
  BIT(fopened);
};

/*
 * A linked list of these 'getout' nodes contain URL's to fetch,
 * as well as information relative to where URL contents should
 * be stored or which file should be uploaded.
 */

struct getout {
  struct getout *next;      /* next one */
  char          *url;       /* the URL we deal with */
  char          *outfile;   /* where to store the output */
  char          *infile;    /* file to upload, if GETOUT_UPLOAD is set */
  int            num;       /* which URL number in an invocation */

  BIT(outset);    /* when outfile is set */
  BIT(urlset);    /* when URL is set */
  BIT(uploadset); /* when -T is set */
  BIT(useremote); /* use remote filename locally */
  BIT(noupload);  /* if set, -T "" has been used */
  BIT(noglob);    /* disable globbing for this URL */
};
/*
 * 'trace' enumeration represents curl's output look'n feel possibilities.
 */

typedef enum {
  TRACE_NONE,  /* no trace/verbose output at all */
  TRACE_BIN,   /* tcpdump inspired look */
  TRACE_ASCII, /* like *BIN but without the hex output */
  TRACE_PLAIN  /* -v/--verbose type */
} trace;


/*
 * 'HttpReq' enumeration represents HTTP request types.
 */

typedef enum {
  TOOL_HTTPREQ_UNSPEC,  /* first in list */
  TOOL_HTTPREQ_GET,
  TOOL_HTTPREQ_HEAD,
  TOOL_HTTPREQ_MIMEPOST,
  TOOL_HTTPREQ_SIMPLEPOST,
  TOOL_HTTPREQ_PUT
} HttpReq;


/*
 * Complete struct declarations which have OperationConfig struct members,
 * just in case this header is directly included in some source file.
 */

#include "tool_cfgable.h"

#endif /* HEADER_CURL_TOOL_SDECLS_H */
