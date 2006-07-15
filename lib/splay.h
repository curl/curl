#ifndef __SPLAY_H
#define __SPLAY_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1997 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

struct Curl_tree {
  struct Curl_tree *smaller; /* smaller node */
  struct Curl_tree *larger;  /* larger node */
  struct Curl_tree *same;    /* points to a node with identical key */
  int key;                   /* the "sort" key */
  void *payload;             /* data the splay code doesn't care about */
};

struct Curl_tree *Curl_splay(int i, struct Curl_tree *t);
struct Curl_tree *Curl_splayinsert(int key, struct Curl_tree *t,
                                   struct Curl_tree *newnode);
#if 0
struct Curl_tree *Curl_splayremove(int key, struct Curl_tree *t,
                                   struct Curl_tree **removed);
#endif

struct Curl_tree *Curl_splaygetbest(int key, struct Curl_tree *t,
                                    struct Curl_tree **removed);
int Curl_splayremovebyaddr(struct Curl_tree *t,
                           struct Curl_tree *remove,
                           struct Curl_tree **newroot);

#ifdef CURLDEBUG
void Curl_splayprint(struct Curl_tree * t, int d, char output);
#else
#define Curl_splayprint(x,y,z)
#endif

#endif
