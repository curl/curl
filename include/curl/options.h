#ifndef FETCHINC_OPTIONS_H
#define FETCHINC_OPTIONS_H
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

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
  FETCHOT_LONG,    /* long (a range of values) */
  FETCHOT_VALUES,  /*      (a defined set or bitmask) */
  FETCHOT_OFF_T,   /* fetch_off_t (a range of values) */
  FETCHOT_OBJECT,  /* pointer (void *) */
  FETCHOT_STRING,  /*         (char * to null-terminated buffer) */
  FETCHOT_SLIST,   /*         (struct fetch_slist *) */
  FETCHOT_CBPTR,   /*         (void * passed as-is to a callback) */
  FETCHOT_BLOB,    /* blob (struct fetch_blob *) */
  FETCHOT_FUNCTION /* function pointer */
} fetch_easytype;

/* Flag bits */

/* "alias" means it is provided for old programs to remain functional,
   we prefer another name */
#define FETCHOT_FLAG_ALIAS (1<<0)

/* The FETCHOPTTYPE_* id ranges can still be used to figure out what type/size
   to use for fetch_easy_setopt() for the given id */
struct fetch_easyoption {
  const char *name;
  FETCHoption id;
  fetch_easytype type;
  unsigned int flags;
};

FETCH_EXTERN const struct fetch_easyoption *
fetch_easy_option_by_name(const char *name);

FETCH_EXTERN const struct fetch_easyoption *
fetch_easy_option_by_id(FETCHoption id);

FETCH_EXTERN const struct fetch_easyoption *
fetch_easy_option_next(const struct fetch_easyoption *prev);

#ifdef __cplusplus
} /* end of extern "C" */
#endif
#endif /* FETCHINC_OPTIONS_H */
