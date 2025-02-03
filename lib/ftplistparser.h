#ifndef HEADER_FETCH_FTPLISTPARSER_H
#define HEADER_FETCH_FTPLISTPARSER_H
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

#ifndef FETCH_DISABLE_FTP

/* WRITEFUNCTION callback for parsing LIST responses */
size_t Fetch_ftp_parselist(char *buffer, size_t size, size_t nmemb,
                          void *connptr);

struct ftp_parselist_data; /* defined inside ftplibparser.c */

FETCHcode Fetch_ftp_parselist_geterror(struct ftp_parselist_data *pl_data);

struct ftp_parselist_data *Fetch_ftp_parselist_data_alloc(void);

void Fetch_ftp_parselist_data_free(struct ftp_parselist_data **pl_data);

/* list of wildcard process states */
typedef enum
{
  FETCHWC_CLEAR = 0,
  FETCHWC_INIT = 1,
  FETCHWC_MATCHING, /* library is trying to get list of addresses for
                      downloading */
  FETCHWC_DOWNLOADING,
  FETCHWC_CLEAN, /* deallocate resources and reset settings */
  FETCHWC_SKIP,  /* skip over concrete file */
  FETCHWC_ERROR, /* error cases */
  FETCHWC_DONE   /* if is wildcard->state == FETCHWC_DONE wildcard loop
                   will end */
} wildcard_states;

typedef void (*wildcard_dtor)(void *ptr);

/* struct keeping information about wildcard download process */
struct WildcardData
{
  char *path;                 /* path to the directory, where we trying wildcard-match */
  char *pattern;              /* wildcard pattern */
  struct Fetch_llist filelist; /* llist with struct Fetch_fileinfo */
  struct ftp_wc *ftpwc;       /* pointer to FTP wildcard data */
  wildcard_dtor dtor;
  unsigned char state; /* wildcard_states */
};

FETCHcode Fetch_wildcard_init(struct WildcardData *wc);
void Fetch_wildcard_dtor(struct WildcardData **wcp);

struct Fetch_easy;

#else
/* FTP is disabled */
#define Fetch_wildcard_dtor(x)
#endif /* FETCH_DISABLE_FTP */
#endif /* HEADER_FETCH_FTPLISTPARSER_H */
