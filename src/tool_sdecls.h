#ifndef HEADER_CURL_TOOL_SDECLS_H
#define HEADER_CURL_TOOL_SDECLS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "setup.h"


/*
 * OutStruct variables keep track of information relative to curl's
 * output writing, which may take place to stdout or to some file.
 *
 * 'filename' member is a pointer to either a file name string or to
 * string "-" to indicate that output is written to stdout.
 *
 * 'alloc_filename' member is TRUE when string pointed by 'filename' has been
 * dynamically allocated and 'belongs' to this OutStruct, otherwise FALSE.
 *
 * 'stream' member is a pointer to a stream controlling object as returned
 * from a 'fopen' call or stdout. When 'stdout' this shall not be closed.
 *
 * 'bytes' member represents amount written, and 'init' initial file size.
 */

struct OutStruct {
  char *filename;               /* pointer to file name or "-" string */
  bool alloc_filename;          /* allocated filename belongs to this */
  FILE *stream;                 /* stdout or stream controlling object */
  struct Configurable *config;  /* pointer back to Configurable struct */
  curl_off_t bytes;             /* amount written so far */
  curl_off_t init;              /* original size (non-zero when appending) */
};


/*
 * InStruct variables keep track of information relative to curl's
 * input reading, which may take place from stdin or from some file.
 *
 * 'fd' member is either 'stdin' file descriptor number STDIN_FILENO
 * or a file descriptor as returned from an 'open' call for some file.
 *
 * 'config' member is a pointer to associated 'Configurable' struct.
 *
 * TODO: evaluate if an additional struct member should be added to
 * allow easier handling of 'stdin' vs other 'file' descriptors.
 */

struct InStruct {
  int fd;
  struct Configurable *config;
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
  int            flags;     /* options - composed of GETOUT_* bits */
};

#define GETOUT_OUTFILE    (1<<0)  /* set when outfile is deemed done */
#define GETOUT_URL        (1<<1)  /* set when URL is deemed done */
#define GETOUT_USEREMOTE  (1<<2)  /* use remote file name locally */
#define GETOUT_UPLOAD     (1<<3)  /* if set, -T has been used */
#define GETOUT_NOUPLOAD   (1<<4)  /* if set, -T "" has been used */


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
  HTTPREQ_UNSPEC,  /* first in list */
  HTTPREQ_GET,
  HTTPREQ_HEAD,
  HTTPREQ_POST,
  HTTPREQ_SIMPLEPOST,
  HTTPREQ_CUSTOM,
  HTTPREQ_LAST     /* last in list */
} HttpReq;


/*
 * Complete struct declarations which have Configurable struct members,
 * just in case this header is directly included in some source file.
 */

#include "tool_cfgable.h"

#endif /* HEADER_CURL_TOOL_SDECLS_H */

