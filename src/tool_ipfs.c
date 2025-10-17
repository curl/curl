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

#ifndef CURL_DISABLE_IPFS

#include "tool_cfgable.h"
#include "tool_msgs.h"
#include "tool_ipfs.h"
#include "memdebug.h" /* keep this as LAST include */

/* input string ends in slash? */
static bool has_trailing_slash(const char *input)
{
  size_t len = strlen(input);
  return (len && input[len - 1] == '/');
}

static char *ipfs_gateway(void)
{
  char *ipfs_path_c = NULL;
  char *gateway_composed_c = NULL;
  FILE *gfile = NULL;
  char *gateway_env = getenv("IPFS_GATEWAY");

  if(gateway_env)
    return strdup(gateway_env);

  /* Try to find the gateway in the IPFS data folder. */
  ipfs_path_c = curl_getenv("IPFS_PATH");

  if(!ipfs_path_c) {
    char *home = getenv("HOME");
    /* fallback to "~/.ipfs", as that is the default location. */
    if(home && *home)
      ipfs_path_c = curl_maprintf("%s/.ipfs/", home);
    if(!ipfs_path_c)
      goto fail;
  }

  gateway_composed_c =
    curl_maprintf("%s%sgateway", ipfs_path_c,
                  has_trailing_slash(ipfs_path_c) ? "" : "/");

  if(!gateway_composed_c)
    goto fail;

  gfile = curlx_fopen(gateway_composed_c, FOPEN_READTEXT);
  curl_free(gateway_composed_c);

  if(gfile) {
    int c;
    struct dynbuf dyn;
    char *gateway = NULL;
    curlx_dyn_init(&dyn, MAX_GATEWAY_URL_LEN);

    /* get the first line of the gateway file, ignore the rest */
    while((c = getc(gfile)) != EOF && c != '\n' && c != '\r') {
      char c_char = (char)c;
      if(curlx_dyn_addn(&dyn, &c_char, 1))
        goto fail;
    }

    if(curlx_dyn_len(&dyn))
      gateway = curlx_dyn_ptr(&dyn);

    curl_free(ipfs_path_c);
    curlx_fclose(gfile);

    return gateway;
  }
fail:
  if(gfile)
    curlx_fclose(gfile);
  curl_free(ipfs_path_c);
  return NULL;
}

/*
 * Rewrite ipfs://<cid> and ipns://<cid> to an HTTP(S)
 * URL that can be handled by an IPFS gateway.
 */
CURLcode ipfs_url_rewrite(CURLU *uh, const char *protocol, char **url,
                          struct OperationConfig *config)
{
  CURLcode result = CURLE_URL_MALFORMAT;
  CURLUcode getResult;
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
  CURLU *gatewayurl = curl_url();

  if(!gatewayurl) {
    result = CURLE_FAILED_INIT;
    goto clean;
  }

  getResult = curl_url_get(uh, CURLUPART_HOST, &cid, CURLU_URLDECODE);
  if(getResult || !cid)
    goto clean;

  /* We might have a --ipfs-gateway argument. Check it first and use it. Error
   * if we do have something but if it is an invalid url.
   */
  if(config->ipfs_gateway) {
    if(!curl_url_set(gatewayurl, CURLUPART_URL, config->ipfs_gateway,
                     CURLU_GUESS_SCHEME)) {
      gateway = strdup(config->ipfs_gateway);
      if(!gateway) {
        result = CURLE_URL_MALFORMAT;
        goto clean;
      }
    }
    else {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto clean;
    }
  }
  else {
    gateway = ipfs_gateway();
    if(!gateway) {
      result = CURLE_FILE_COULDNT_READ_FILE;
      goto clean;
    }

    if(curl_url_set(gatewayurl, CURLUPART_URL, gateway, 0)) {
      result = CURLE_URL_MALFORMAT;
      goto clean;
    }
  }

  /* check for unsupported gateway parts */
  if(curl_url_get(gatewayurl, CURLUPART_QUERY, &gwquery, 0)
                  != CURLUE_NO_QUERY) {
    result = CURLE_URL_MALFORMAT;
    goto clean;
  }

  /* get gateway parts */
  if(curl_url_get(gatewayurl, CURLUPART_HOST,
                  &gwhost, CURLU_URLDECODE)) {
    goto clean;
  }

  if(curl_url_get(gatewayurl, CURLUPART_SCHEME,
                  &gwscheme, CURLU_URLDECODE)) {
    goto clean;
  }

  curl_url_get(gatewayurl, CURLUPART_PORT, &gwport, CURLU_URLDECODE);
  curl_url_get(gatewayurl, CURLUPART_PATH, &gwpath, CURLU_URLDECODE);

  /* get the path from user input */
  curl_url_get(uh, CURLUPART_PATH, &inputpath, CURLU_URLDECODE);
  /* inputpath might be NULL or a valid pointer now */

  /* set gateway parts in input url */
  if(curl_url_set(uh, CURLUPART_SCHEME, gwscheme, CURLU_URLENCODE) ||
     curl_url_set(uh, CURLUPART_HOST, gwhost, CURLU_URLENCODE) ||
     curl_url_set(uh, CURLUPART_PORT, gwport, CURLU_URLENCODE))
    goto clean;

  /* if the input path is just a slash, clear it */
  if(inputpath && (inputpath[0] == '/') && !inputpath[1])
    *inputpath = '\0';


  pathbuffer = curl_maprintf("%s%s%s/%s%s", gwpath,
                             has_trailing_slash(gwpath) ? "" : "/",
                             protocol, cid,
                             inputpath ? inputpath : "");
  if(!pathbuffer) {
    goto clean;
  }

  if(curl_url_set(uh, CURLUPART_PATH, pathbuffer, CURLU_URLENCODE)) {
    goto clean;
  }

  /* Free whatever it has now, rewriting is next */
  tool_safefree(*url);

  if(curl_url_get(uh, CURLUPART_URL, &cloneurl, CURLU_URLENCODE)) {
    goto clean;
  }
  /* we need to strdup the URL so that we can call free() on it later */
  *url = strdup(cloneurl);
  curl_free(cloneurl);
  if(!*url)
    goto clean;

  result = CURLE_OK;

clean:
  free(gateway);
  curl_free(gwhost);
  curl_free(gwpath);
  curl_free(gwquery);
  curl_free(inputpath);
  curl_free(gwscheme);
  curl_free(gwport);
  curl_free(cid);
  curl_free(pathbuffer);
  curl_url_cleanup(gatewayurl);
  {
    switch(result) {
    case CURLE_URL_MALFORMAT:
      helpf("malformed target URL");
      break;
    case CURLE_FILE_COULDNT_READ_FILE:
      helpf("IPFS automatic gateway detection failed");
      break;
    case CURLE_BAD_FUNCTION_ARGUMENT:
      helpf("--ipfs-gateway was given a malformed URL");
      break;
    default:
      break;
    }
  }
  return result;
}
#endif /* !CURL_DISABLE_IPFS */
