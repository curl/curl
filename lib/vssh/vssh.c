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
 * SPDX-License-Identifier: curl AND ISC
 *
 ***************************************************************************/
#include "../curl_setup.h"

#ifdef USE_SSH

#include "vssh.h"
#include "../curlx/strparse.h"
#include "../curl_trc.h"
#include "../escape.h"

#define MAX_SSHPATH_LEN 100000 /* arbitrary */

/* figure out the path to work with in this particular request */
CURLcode Curl_getworkingpath(struct Curl_easy *data,
                             char *homedir,  /* when SFTP is used */
                             char **path) /* returns the  allocated
                                             real path to work with */
{
  char *working_path;
  size_t working_path_len;
  struct dynbuf npath;
  CURLcode result =
    Curl_urldecode(data->state.up.path, 0, &working_path,
                   &working_path_len, REJECT_ZERO);
  if(result)
    return result;

  /* new path to switch to in case we need to */
  curlx_dyn_init(&npath, MAX_SSHPATH_LEN);

  /* Check for /~/, indicating relative to the user's home directory */
  if((data->conn->handler->protocol & CURLPROTO_SCP) &&
     (working_path_len > 3) && (!memcmp(working_path, "/~/", 3))) {
    /* It is referenced to the home directory, so strip the leading '/~/' */
    if(curlx_dyn_addn(&npath, &working_path[3], working_path_len - 3)) {
      curlx_free(working_path);
      return CURLE_OUT_OF_MEMORY;
    }
  }
  else if((data->conn->handler->protocol & CURLPROTO_SFTP) &&
          (!strcmp("/~", working_path) ||
           ((working_path_len > 2) && !memcmp(working_path, "/~/", 3)))) {
    if(curlx_dyn_add(&npath, homedir)) {
      curlx_free(working_path);
      return CURLE_OUT_OF_MEMORY;
    }
    if(working_path_len > 2) {
      size_t len;
      const char *p;
      int copyfrom = 3;
      /* Copy a separating '/' if homedir does not end with one */
      len = curlx_dyn_len(&npath);
      p = curlx_dyn_ptr(&npath);
      if(len && (p[len - 1] != '/'))
        copyfrom = 2;

      if(curlx_dyn_addn(&npath, &working_path[copyfrom],
                        working_path_len - copyfrom)) {
        curlx_free(working_path);
        return CURLE_OUT_OF_MEMORY;
      }
    }
    else {
      if(curlx_dyn_add(&npath, "/")) {
        curlx_free(working_path);
        return CURLE_OUT_OF_MEMORY;
      }
    }
  }

  if(curlx_dyn_len(&npath)) {
    curlx_free(working_path);

    /* store the pointer for the caller to receive */
    *path = curlx_dyn_ptr(&npath);
  }
  else
    *path = working_path;
  DEBUGASSERT(*path && (*path)[0]);

  return CURLE_OK;
}

#define MAX_PATHLENGTH 65535 /* arbitrary long */

CURLcode Curl_get_pathname(const char **cpp, char **path, const char *homedir)
{
  const char *cp = *cpp;
  struct dynbuf out;
  CURLcode result;

  DEBUGASSERT(homedir);
  *path = NULL;
  *cpp = NULL;
  if(!*cp || !homedir)
    return CURLE_QUOTE_ERROR;

  curlx_dyn_init(&out, MAX_PATHLENGTH);

  /* Ignore leading whitespace */
  curlx_str_passblanks(&cp);

  /* Check for quoted filenames */
  if(*cp == '\"' || *cp == '\'') {
    char quot = *cp++;

    /* Search for terminating quote, unescape some chars */
    while(*cp != quot) {
      if(!*cp) /* End of string */
        goto fail;

      if(*cp == '\\') { /* Escaped characters */
        cp++;
        if(*cp != '\'' && *cp != '\"' && *cp != '\\')
          goto fail;
      }
      result = curlx_dyn_addn(&out, cp, 1);
      if(result)
        return result;
      cp++;
    }
    cp++; /* pass the end quote */

    if(!curlx_dyn_len(&out))
      goto fail;
  }
  else {
    struct Curl_str word;
    bool content = FALSE;
    int rc;
    /* Handling for relative path - prepend home directory */
    if(cp[0] == '/' && cp[1] == '~' && cp[2] == '/') {
      result = curlx_dyn_add(&out, homedir);
      if(!result)
        result = curlx_dyn_addn(&out, "/", 1);
      if(result)
        return result;
      cp += 3;
      content = TRUE;
    }
    /* Read to end of filename - either to whitespace or terminator */
    rc = curlx_str_word(&cp, &word, MAX_PATHLENGTH);
    if(rc) {
      if(rc == STRE_BIG) {
        curlx_dyn_free(&out);
        return CURLE_TOO_LARGE;
      }
      else if(!content)
        /* no path, no word, this is incorrect */
        goto fail;
    }
    else {
      /* append the word */
      result = curlx_dyn_addn(&out, curlx_str(&word), curlx_strlen(&word));
      if(result)
        return result;
    }
  }
  /* skip whitespace */
  curlx_str_passblanks(&cp);

  /* return pointer to second parameter if it exists */
  *cpp = cp;

  *path = curlx_dyn_ptr(&out);
  return CURLE_OK;

fail:
  curlx_dyn_free(&out);
  return CURLE_QUOTE_ERROR;
}

CURLcode Curl_ssh_range(struct Curl_easy *data,
                        const char *p, curl_off_t filesize,
                        curl_off_t *startp, curl_off_t *sizep)
{
  curl_off_t from, to;
  int to_t;
  int from_t = curlx_str_number(&p, &from, CURL_OFF_T_MAX);
  if(from_t == STRE_OVERFLOW)
    return CURLE_RANGE_ERROR;
  curlx_str_passblanks(&p);
  (void)curlx_str_single(&p, '-');

  to_t = curlx_str_numblanks(&p, &to);
  if((to_t == STRE_OVERFLOW) || (to_t && from_t) || *p)
    return CURLE_RANGE_ERROR;

  if(from_t) {
    /* no start point given, set from relative to end of file */
    if(!to)
      /* "-0" is not a fine range */
      return CURLE_RANGE_ERROR;
    else if(to > filesize)
      to = filesize;
    from = filesize - to;
    to = filesize - 1;
  }
  else if(from > filesize) {
    failf(data, "Offset (%" FMT_OFF_T ") was beyond file size (%"
          FMT_OFF_T ")", from, filesize);
    return CURLE_RANGE_ERROR;
  }
  else if((to_t == STRE_NO_NUM) || (to >= filesize))
    to = filesize - 1;

  if(from > to) {
    failf(data, "Bad range: start offset larger than end offset");
    return CURLE_RANGE_ERROR;
  }
  if((to - from) == CURL_OFF_T_MAX)
    return CURLE_RANGE_ERROR;

  *startp = from;
  *sizep = to - from + 1;
  return CURLE_OK;
}

#endif /* USE_SSH */
