#ifndef HEADER_CURL_SPLAY_H
#define HEADER_CURL_SPLAY_H
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

#include "curlx/timeval.h"

struct Curl_easy;

/* only use function calls to access this struct */
struct Curl_tree {
  struct Curl_tree *smaller; /* smaller node */
  struct Curl_tree *larger;  /* larger node */
  struct Curl_tree *same;    /* points to the next node with identical key */
  timediff_t key;            /* this node's "sort" key */
  uint32_t id;               /* provided id for this node */
  BIT(registered);           /* node is registered in splay tree */
};

struct Curl_timeouts {
  struct Curl_tree *tree;
  struct curltime time_base;
};

void Curl_timeouts_init(struct Curl_timeouts *timeouts,
                        const struct curltime *ptime_base);

bool Curl_timeouts_has(struct Curl_easy *data);

timediff_t Curl_timeouts_offset_us(struct Curl_timeouts *timeouts,
                                   const struct curltime *pts);

int Curl_timeouts_next_ms(struct Curl_timeouts *timeouts,
                          const struct curltime *pnow,
                          timediff_t *pexpire_offset_us,
                          uint32_t *pmid);

bool Curl_timeouts_remove_expired(struct Curl_timeouts *timeouts,
                                  const struct curltime *ts,
                                  uint32_t *pmid);

void Curl_timeouts_add(struct Curl_timeouts *timeouts,
                       struct Curl_easy *data,
                       timediff_t offset_us);

/* Returns TRUE if data was registered in timeouts before */
bool Curl_timeouts_remove(struct Curl_timeouts *timeouts,
                          struct Curl_easy *data);

struct Curl_tree *Curl_splay(timediff_t key,
                             struct Curl_tree *root);

struct Curl_tree *Curl_splayinsert(timediff_t key,
                                   struct Curl_tree *root,
                                   struct Curl_tree *node,
                                   uint32_t id);

struct Curl_tree *Curl_splaygetbest(timediff_t key,
                                    struct Curl_tree *root,
                                    struct Curl_tree **removed);

int Curl_splayremove(struct Curl_tree *root,
                     struct Curl_tree *removenode,
                     struct Curl_tree **newroot);

/* set and get the custom payload for this tree node */
void Curl_splayset(struct Curl_tree *node, uint32_t id);
uint32_t Curl_splayget(struct Curl_tree *node);

#endif /* HEADER_CURL_SPLAY_H */
