/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2011 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifdef ENABLE_LIBPROXY

#include "urldata.h"

#include <proxy.h>
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static pxProxyFactory *factory;

CURLcode Curl_libproxy_global_init(void)
{
  factory = px_proxy_factory_new();
  if(!factory)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

void Curl_libproxy_global_cleanup(void)
{
  if(factory)
    px_proxy_factory_free(factory);

  factory = NULL;
}

char *Curl_libproxy_detect_proxy(const char *url)
{
  char *result = NULL;

  if(factory) {
    char **libproxy_results = px_proxy_factory_get_proxies(factory, url);

    if(libproxy_results) {
      int i;

      /* We only cope with one; can't fall back on failure */
      result = libproxy_results[0];
      for(i=1; libproxy_results[i]; i++)
        free(libproxy_results[i]);
      free(libproxy_results);
    }
  }

  return result;
}

#endif /* ENABLE_LIBPROXY */
