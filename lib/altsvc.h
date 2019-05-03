#ifndef HEADER_CURL_ALTSVC_H
#define HEADER_CURL_ALTSVC_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_ALTSVC)
#include <curl/curl.h>
#include "llist.h"

enum alpnid {
  ALPN_none,
  ALPN_h1,
  ALPN_h2,
  ALPN_h2c,
  ALPN_h3
};

struct altsvc {
  char *srchost;
  char *dsthost;
  unsigned short srcport;
  unsigned short dstport;
  enum alpnid srcalpnid;
  enum alpnid dstalpnid;
  time_t expires;
  bool persist;
  int prio;
  struct curl_llist_element node;
};

struct altsvcinfo {
  char *filename;
  struct curl_llist list; /* list of entries */
  size_t num; /* number of alt-svc entries */
  long flags; /* the publicly set bitmask */
};

const char *Curl_alpnid2str(enum alpnid id);
struct altsvcinfo *Curl_altsvc_init(void);
CURLcode Curl_altsvc_load(struct altsvcinfo *asi, const char *file);
CURLcode Curl_altsvc_save(struct altsvcinfo *asi, const char *file);
CURLcode Curl_altsvc_ctrl(struct altsvcinfo *asi, const long ctrl);
void Curl_altsvc_cleanup(struct altsvcinfo *altsvc);
CURLcode Curl_altsvc_parse(struct Curl_easy *data,
                           struct altsvcinfo *altsvc, const char *value,
                           enum alpnid srcalpn, const char *srchost,
                           unsigned short srcport);
bool Curl_altsvc_lookup(struct altsvcinfo *asi,
                        enum alpnid srcalpnid, const char *srchost,
                        int srcport,
                        enum alpnid *dstalpnid, const char **dsthost,
                        int *dstport);
#else
/* disabled */
#define Curl_altsvc_save(a,b)
#endif /* CURL_DISABLE_HTTP || USE_ALTSVC */
#endif /* HEADER_CURL_ALTSVC_H */
