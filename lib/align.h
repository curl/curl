#ifndef HEADER_CURL_ALIGN_H
#define HEADER_CURL_ALIGN_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* Universal type alignment macros. */

#include "curl_setup.h"
#include <stddef.h>

/* Alignment for type.*/
#define ALIGN(type)     offsetof(struct { char c; type t; }, t)

/* Union of all scalar types for universal alignment computation. */
union all_scalar_types {
  char          c;
  short         s;
  int           i;
  long          l;
#ifdef HAVE_LONGLONG
  long long     ll;
#endif
  float         f;
  double        d;
#ifdef HAVE_LONGDOUBLE
  long double   ld;
#endif
  void *        p;
  void         (*pf)(void); /* May have a different alignment than void *. */
};

/* Universal alignment constant. */
#define UALIGN  ALIGN(union all_scalar_types)

/* Align a size downwards.*/
#define DNALIGNSIZE(s, a)   ((s) - ((s) % (a)))

/* Align a size upwards.*/
#define UPALIGNSIZE(s, a)   DNALIGNSIZE((s) + (a) - 1, (a))

/* Align a pointer downwards.*/
#define DNALIGNPTR(p, a)    ((void *) ((char *) (p) - ((size_t) (p) % (a))))

/* Align a pointer upwards.*/
#define UPALIGNPTR(p, a)    DNALIGNPTR((char *) (p) + (a) - 1, (a))

#endif /* HEADER_CURL_ALIGN_H */
