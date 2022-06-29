/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Jan-Michael Brummer <jan-michael.brummer1@volkswagen.de>.
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

#ifndef CURL_DISABLE_LIBPROXY

#include "urldata.h"

#include <proxy.h>
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

void Curl_libproxy_cleanup(pxProxyFactory *proxy_factory)
{
  if(proxy_factory)
    px_proxy_factory_free(proxy_factory);
}

char *Curl_libproxy_detect_proxy(struct Curl_easy *data, const char *url)
{
  char *result = NULL;

  /* Initialization of libproxy is done here, as otherwise libproxy and curl
   * will have a cycle issue
   */
  if(!data->proxy_factory)
    data->proxy_factory = px_proxy_factory_new();

  if(data->proxy_factory) {
    char **libproxy_results =
        px_proxy_factory_get_proxies(data->proxy_factory, url);

    if(libproxy_results) {
      /*
       * - We only cope with one; can't fall back on failure
       * - direct:// access is returned as NULL
       */
      if(strcmp(libproxy_results[0], "direct://") != 0)
        result = strdup(libproxy_results[0]);

      px_proxy_factory_free_proxies(libproxy_results);
    }
  }

  return result;
}

#endif /* CURL_DISABLE_LIBPROXY */
