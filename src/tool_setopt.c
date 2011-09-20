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

#include <curl/curl.h>

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_easysrc.h"
#include "tool_setopt.h"

#include "memdebug.h" /* keep this as LAST include */

CURLcode tool_setopt(CURL *curl, bool str, struct Configurable *config,
                     const char *name, CURLoption tag, ...)
{
  va_list arg;
  char *bufp;
  char value[256];
  bool remark = FALSE;
  bool skip = FALSE;
  CURLcode ret = CURLE_OK;

  va_start(arg, tag);

  if(tag < CURLOPTTYPE_OBJECTPOINT) {
    long lval = va_arg(arg, long);
    snprintf(value, sizeof(value), "%ldL", lval);
    ret = curl_easy_setopt(curl, tag, lval);
    if(!lval)
      skip = TRUE;
  }
  else if(tag < CURLOPTTYPE_OFF_T) {
    void *pval = va_arg(arg, void *);
    unsigned char *ptr = (unsigned char *)pval;

    /* function pointers are never printable */
    if(tag >= CURLOPTTYPE_FUNCTIONPOINT) {
      if(pval) {
        strcpy(value, "functionpointer"); /* 'value' fits 256 bytes */
        remark = TRUE;
      }
      else
        skip = TRUE;
    }

    else if(pval && str)
      snprintf(value, sizeof(value), "\"%s\"", (char *)ptr);
    else if(pval) {
      strcpy(value, "objectpointer"); /* 'value' fits 256 bytes */
      remark = TRUE;
    }
    else
      skip = TRUE;

    ret = curl_easy_setopt(curl, tag, pval);

  }
  else {
    curl_off_t oval = va_arg(arg, curl_off_t);
    snprintf(value, sizeof(value),
             "(curl_off_t)%" CURL_FORMAT_CURL_OFF_T, oval);
    ret = curl_easy_setopt(curl, tag, oval);

    if(!oval)
      skip = TRUE;
  }

  va_end(arg);

  if(config->libcurl && !skip && !ret) {
    /* we only use this for real if --libcurl was used */

    if(remark)
      bufp = curlx_maprintf("%s set to a %s", name, value);
    else
      bufp = curlx_maprintf("curl_easy_setopt(hnd, %s, %s);", name, value);

    if(!bufp)
      ret = CURLE_OUT_OF_MEMORY;
    else {
      struct curl_slist *list =
        curl_slist_append(remark?easysrc_remarks:easysrc, bufp);

      curl_free(bufp);

      if(!list) {
        curl_slist_free_all(easysrc_remarks);
        curl_slist_free_all(easysrc);
        easysrc_remarks = NULL;
        easysrc = NULL;
        ret = CURLE_OUT_OF_MEMORY;
      }
      else if(remark)
        easysrc_remarks = list;
      else
        easysrc = list;
    }
  }

  return ret;
}

