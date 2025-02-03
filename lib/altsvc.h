#ifndef HEADER_FETCH_ALTSVC_H
#define HEADER_FETCH_ALTSVC_H
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

#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_ALTSVC)
#include <fetch/fetch.h>
#include "llist.h"

struct althost
{
  char *host;
  unsigned short port;
  enum alpnid alpnid;
};

struct altsvc
{
  struct althost src;
  struct althost dst;
  time_t expires;
  bool persist;
  unsigned int prio;
  struct Fetch_llist_node node;
};

struct altsvcinfo
{
  char *filename;
  struct Fetch_llist list; /* list of entries */
  long flags;             /* the publicly set bitmask */
};

const char *Fetch_alpnid2str(enum alpnid id);
struct altsvcinfo *Fetch_altsvc_init(void);
FETCHcode Fetch_altsvc_load(struct altsvcinfo *asi, const char *file);
FETCHcode Fetch_altsvc_save(struct Fetch_easy *data,
                           struct altsvcinfo *asi, const char *file);
FETCHcode Fetch_altsvc_ctrl(struct altsvcinfo *asi, const long ctrl);
void Fetch_altsvc_cleanup(struct altsvcinfo **altsvc);
FETCHcode Fetch_altsvc_parse(struct Fetch_easy *data,
                            struct altsvcinfo *altsvc, const char *value,
                            enum alpnid srcalpn, const char *srchost,
                            unsigned short srcport);
bool Fetch_altsvc_lookup(struct altsvcinfo *asi,
                        enum alpnid srcalpnid, const char *srchost,
                        int srcport,
                        struct altsvc **dstentry,
                        const int versions); /* FETCHALTSVC_H* bits */
#else
/* disabled */
#define Fetch_altsvc_save(a, b, c)
#define Fetch_altsvc_cleanup(x)
#endif /* !FETCH_DISABLE_HTTP && !FETCH_DISABLE_ALTSVC */
#endif /* HEADER_FETCH_ALTSVC_H */
