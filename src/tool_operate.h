#ifndef HEADER_CURL_TOOL_OPERATE_H
#define HEADER_CURL_TOOL_OPERATE_H
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
#include "tool_cb_hdr.h"
#include "tool_cb_prg.h"
#include "tool_sdecls.h"

struct per_transfer {
  /* double linked */
  struct per_transfer *next;
  struct per_transfer *prev;
  struct OperationConfig *config; /* for this transfer */
  struct curl_certinfo *certinfo;
  CURL *curl;
  long retry_remaining;
  long retry_sleep_default;
  long retry_sleep;
  long num_retries; /* counts the performed retries */
  struct timeval start; /* start of this transfer */
  struct timeval retrystart;
  char *url;
  unsigned int urlnum; /* the index of the given URL */
  char *outfile;
  int infd;
  struct ProgressData progressbar;
  struct OutStruct outs;
  struct OutStruct heads;
  struct OutStruct etag_save;
  struct HdrCbData hdrcbdata;
  long num_headers;
  time_t startat; /* when doing parallel transfers, this is a retry transfer
                     that has been set to sleep until this time before it
                     should get started (again) */
  /* for parallel progress bar */
  curl_off_t dltotal;
  curl_off_t dlnow;
  curl_off_t ultotal;
  curl_off_t ulnow;
  curl_off_t uploadfilesize; /* expected total amount */
  curl_off_t uploadedsofar; /* amount delivered from the callback */
  BIT(dltotal_added); /* if the total has been added from this */
  BIT(ultotal_added);

  /* NULL or malloced */
  char *uploadfile;
  char *errorbuffer; /* allocated and assigned while this is used for a
                        transfer */
  BIT(infdopen); /* TRUE if infd needs closing */
  BIT(noprogress);
  BIT(was_last_header_empty);

  BIT(added); /* set TRUE when added to the multi handle */
  BIT(abort); /* when doing parallel transfers and this is TRUE then a critical
                 error (eg --fail-early) has occurred in another transfer and
                 this transfer will be aborted in the progress callback */
  BIT(skip);  /* considered already done */
};

CURLcode operate(struct GlobalConfig *config, int argc, argv_item_t argv[]);
void single_transfer_cleanup(struct OperationConfig *config);

extern struct per_transfer *transfers; /* first node */

#endif /* HEADER_CURL_TOOL_OPERATE_H */
