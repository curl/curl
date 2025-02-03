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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "tool_setup.h"

#ifndef FETCH_DISABLE_IPFS
#include "fetchx.h"
#include "dynbuf.h"

#include "tool_cfgable.h"
#include "tool_msgs.h"
#include "tool_ipfs.h"

#include "memdebug.h" /* keep this as LAST include */

/* ensure input ends in slash */
static FETCHcode ensure_trailing_slash(char **input)
{
  if (*input && **input)
  {
    size_t len = strlen(*input);
    if (((*input)[len - 1] != '/'))
    {
      struct fetchx_dynbuf dyn;
      fetchx_dyn_init(&dyn, len + 2);

      if (fetchx_dyn_addn(&dyn, *input, len))
      {
        Curl_safefree(*input);
        return FETCHE_OUT_OF_MEMORY;
      }

      Curl_safefree(*input);

      if (fetchx_dyn_addn(&dyn, "/", 1))
        return FETCHE_OUT_OF_MEMORY;

      *input = fetchx_dyn_ptr(&dyn);
    }
  }

  return FETCHE_OK;
}

static char *ipfs_gateway(void)
{
  char *ipfs_path = NULL;
  char *gateway_composed_file_path = NULL;
  FILE *gateway_file = NULL;
  char *gateway = fetch_getenv("IPFS_GATEWAY");

  /* Gateway is found from environment variable. */
  if (gateway)
  {
    if (ensure_trailing_slash(&gateway))
      goto fail;
    return gateway;
  }

  /* Try to find the gateway in the IPFS data folder. */
  ipfs_path = fetch_getenv("IPFS_PATH");

  if (!ipfs_path)
  {
    char *home = getenv("HOME");
    if (home && *home)
      ipfs_path = aprintf("%s/.ipfs/", home);
    /* fallback to "~/.ipfs", as that is the default location. */
  }

  if (!ipfs_path || ensure_trailing_slash(&ipfs_path))
    goto fail;

  gateway_composed_file_path = aprintf("%sgateway", ipfs_path);

  if (!gateway_composed_file_path)
    goto fail;

  gateway_file = fopen(gateway_composed_file_path, FOPEN_READTEXT);
  Curl_safefree(gateway_composed_file_path);

  if (gateway_file)
  {
    int c;
    struct fetchx_dynbuf dyn;
    fetchx_dyn_init(&dyn, MAX_GATEWAY_URL_LEN);

    /* get the first line of the gateway file, ignore the rest */
    while ((c = getc(gateway_file)) != EOF && c != '\n' && c != '\r')
    {
      char c_char = (char)c;
      if (fetchx_dyn_addn(&dyn, &c_char, 1))
        goto fail;
    }

    fclose(gateway_file);
    gateway_file = NULL;

    if (fetchx_dyn_len(&dyn))
      gateway = fetchx_dyn_ptr(&dyn);

    if (gateway)
      ensure_trailing_slash(&gateway);

    if (!gateway)
      goto fail;

    Curl_safefree(ipfs_path);

    return gateway;
  }
fail:
  if (gateway_file)
    fclose(gateway_file);
  Curl_safefree(gateway);
  Curl_safefree(ipfs_path);
  return NULL;
}

/*
 * Rewrite ipfs://<cid> and ipns://<cid> to an HTTP(S)
 * URL that can be handled by an IPFS gateway.
 */
FETCHcode ipfs_url_rewrite(FETCHU *uh, const char *protocol, char **url,
                           struct OperationConfig *config)
{
  FETCHcode result = FETCHE_URL_MALFORMAT;
  FETCHUcode getResult;
  char *gateway = NULL;
  char *gwhost = NULL;
  char *gwpath = NULL;
  char *gwquery = NULL;
  char *gwscheme = NULL;
  char *gwport = NULL;
  char *inputpath = NULL;
  char *cid = NULL;
  char *pathbuffer = NULL;
  char *cloneurl;
  FETCHU *gatewayurl = fetch_url();

  if (!gatewayurl)
  {
    result = FETCHE_FAILED_INIT;
    goto clean;
  }

  getResult = fetch_url_get(uh, FETCHUPART_HOST, &cid, FETCHU_URLDECODE);
  if (getResult || !cid)
    goto clean;

  /* We might have a --ipfs-gateway argument. Check it first and use it. Error
   * if we do have something but if it is an invalid url.
   */
  if (config->ipfs_gateway)
  {
    /* ensure the gateway ends in a trailing / */
    if (ensure_trailing_slash(&config->ipfs_gateway) != FETCHE_OK)
    {
      result = FETCHE_OUT_OF_MEMORY;
      goto clean;
    }

    if (!fetch_url_set(gatewayurl, FETCHUPART_URL, config->ipfs_gateway,
                       FETCHU_GUESS_SCHEME))
    {
      gateway = strdup(config->ipfs_gateway);
      if (!gateway)
      {
        result = FETCHE_URL_MALFORMAT;
        goto clean;
      }
    }
    else
    {
      result = FETCHE_BAD_FUNCTION_ARGUMENT;
      goto clean;
    }
  }
  else
  {
    /* this is ensured to end in a trailing / within ipfs_gateway() */
    gateway = ipfs_gateway();
    if (!gateway)
    {
      result = FETCHE_FILE_COULDNT_READ_FILE;
      goto clean;
    }

    if (fetch_url_set(gatewayurl, FETCHUPART_URL, gateway, 0))
    {
      result = FETCHE_URL_MALFORMAT;
      goto clean;
    }
  }

  /* check for unsupported gateway parts */
  if (fetch_url_get(gatewayurl, FETCHUPART_QUERY, &gwquery, 0) != FETCHUE_NO_QUERY)
  {
    result = FETCHE_URL_MALFORMAT;
    goto clean;
  }

  /* get gateway parts */
  if (fetch_url_get(gatewayurl, FETCHUPART_HOST,
                    &gwhost, FETCHU_URLDECODE))
  {
    goto clean;
  }

  if (fetch_url_get(gatewayurl, FETCHUPART_SCHEME,
                    &gwscheme, FETCHU_URLDECODE))
  {
    goto clean;
  }

  fetch_url_get(gatewayurl, FETCHUPART_PORT, &gwport, FETCHU_URLDECODE);
  fetch_url_get(gatewayurl, FETCHUPART_PATH, &gwpath, FETCHU_URLDECODE);

  /* get the path from user input */
  fetch_url_get(uh, FETCHUPART_PATH, &inputpath, FETCHU_URLDECODE);
  /* inputpath might be NULL or a valid pointer now */

  /* set gateway parts in input url */
  if (fetch_url_set(uh, FETCHUPART_SCHEME, gwscheme, FETCHU_URLENCODE) ||
      fetch_url_set(uh, FETCHUPART_HOST, gwhost, FETCHU_URLENCODE) ||
      fetch_url_set(uh, FETCHUPART_PORT, gwport, FETCHU_URLENCODE))
    goto clean;

  /* if the input path is just a slash, clear it */
  if (inputpath && (inputpath[0] == '/') && !inputpath[1])
    *inputpath = '\0';

  /* ensure the gateway path ends with a trailing slash */
  ensure_trailing_slash(&gwpath);

  pathbuffer = aprintf("%s%s/%s%s", gwpath, protocol, cid,
                       inputpath ? inputpath : "");
  if (!pathbuffer)
  {
    goto clean;
  }

  if (fetch_url_set(uh, FETCHUPART_PATH, pathbuffer, FETCHU_URLENCODE))
  {
    goto clean;
  }

  /* Free whatever it has now, rewriting is next */
  Curl_safefree(*url);

  if (fetch_url_get(uh, FETCHUPART_URL, &cloneurl, FETCHU_URLENCODE))
  {
    goto clean;
  }
  /* we need to strdup the URL so that we can call free() on it later */
  *url = strdup(cloneurl);
  fetch_free(cloneurl);
  if (!*url)
    goto clean;

  result = FETCHE_OK;

clean:
  free(gateway);
  fetch_free(gwhost);
  fetch_free(gwpath);
  fetch_free(gwquery);
  fetch_free(inputpath);
  fetch_free(gwscheme);
  fetch_free(gwport);
  fetch_free(cid);
  fetch_free(pathbuffer);
  fetch_url_cleanup(gatewayurl);
  {
    switch (result)
    {
    case FETCHE_URL_MALFORMAT:
      helpf(tool_stderr, "malformed target URL");
      break;
    case FETCHE_FILE_COULDNT_READ_FILE:
      helpf(tool_stderr, "IPFS automatic gateway detection failed");
      break;
    case FETCHE_BAD_FUNCTION_ARGUMENT:
      helpf(tool_stderr, "--ipfs-gateway was given a malformed URL");
      break;
    default:
      break;
    }
  }
  return result;
}
#endif /* !FETCH_DISABLE_IPFS */
