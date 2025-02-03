#ifndef HEADER_FETCH_TOOL_EASYSRC_H
#define HEADER_FETCH_TOOL_EASYSRC_H
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
#include "tool_setup.h"
#ifndef FETCH_DISABLE_LIBFETCH_OPTION

/* global variable declarations, for easy-interface source code generation */

extern struct slist_wc *easysrc_decl;    /* Variable declarations */
extern struct slist_wc *easysrc_data;    /* Build slists, forms etc. */
extern struct slist_wc *easysrc_code;    /* Setopt calls etc. */
extern struct slist_wc *easysrc_toohard; /* Unconvertible setopt */
extern struct slist_wc *easysrc_clean;   /* Clean up (reverse order) */

extern int easysrc_mime_count;  /* Number of fetch_mime variables */
extern int easysrc_slist_count; /* Number of fetch_slist variables */

extern FETCHcode easysrc_init(void);
extern FETCHcode easysrc_add(struct slist_wc **plist, const char *bupf);
extern FETCHcode easysrc_addf(struct slist_wc **plist,
                              const char *fmt, ...) FETCH_PRINTF(2, 3);
extern FETCHcode easysrc_perform(void);
extern FETCHcode easysrc_cleanup(void);

void dumpeasysrc(struct GlobalConfig *config);

#else /* FETCH_DISABLE_LIBFETCH_OPTION is defined */

#define easysrc_init() FETCHE_OK
#define easysrc_cleanup()
#define dumpeasysrc(x)
#define easysrc_perform() FETCHE_OK

#endif /* FETCH_DISABLE_LIBFETCH_OPTION */

#endif /* HEADER_FETCH_TOOL_EASYSRC_H */
