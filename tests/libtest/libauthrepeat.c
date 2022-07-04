/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/* argv1 = URL
 * argv2 = auth types in form auth1[-auth2[-auth3[-user4]]]
 * argv3 = auth users in form [user1[-user2[-user3[-user4]]]]
 * argv4 = auth passwords in form [pwd1[-pwd2[-pwd3[-pwd4]]]]
 */
/*
   This tool issue requests with specified auth types and user names in order:
   * one request with auth1 and user1:pwd1
   * one request with auth2 and user2:pwd2
   * two requests with auth3 and user3:pwd3
   * two requests with auth4 and user4:pwd4

   Auth types 2, 3, and 4 are optional, if missing then first values
   will be repeated. The same applies for user names and passwords.
   If no username is specified then default value 'testuser' is used.
   If no password is specified then default value 'testpass' is used.
 */

#include "test.h"
#include "memdebug.h"

static const char *auth_scheme_name(long auth_scheme)
{
  switch(auth_scheme) {
  case CURLAUTH_NONE:
    return "none";
  case CURLAUTH_BASIC:
    return "Basic";
  case CURLAUTH_DIGEST:
    return "Digest";
  case CURLAUTH_NTLM:
    return "NTLM";
  default:
    break;
  }
  return "UNKNOWN";
}

static CURLcode send_request(CURL *curl, const char *url, int seq,
                             long auth_scheme, const char *user,
                             const char *pwd)
{
  CURLcode res;
  size_t len = strlen(url) + 4 + 1;
  char *full_url = malloc(len);
  if(!full_url) {
    fprintf(stderr, "Not enough memory for full url\n");
    return CURLE_OUT_OF_MEMORY;
  }

  msnprintf(full_url, len, "%s%04d", url, seq);
  fprintf(stderr, "Sending new request %d to %s with credential %s:%s "
          "(auth %s)\n", seq, full_url, user, pwd,
          auth_scheme_name(auth_scheme));
  test_setopt(curl, CURLOPT_URL, full_url);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_HTTPGET, 1L);
  test_setopt(curl, CURLOPT_USERNAME, user);
  test_setopt(curl, CURLOPT_PASSWORD, pwd);
  test_setopt(curl, CURLOPT_HTTPAUTH, auth_scheme);
  test_setopt(curl, CURLOPT_FAILONERROR, 1L);

  res = curl_easy_perform(curl);

test_cleanup:
  free(full_url);
  return res;
}

#ifndef HAVE_STRDUP
static char *local_strdup(const char *str)
{
  char *ptr;
  size_t len = strlen(str);
  ptr = malloc(len + 1);
  if(!ptr)
    return ptr;
  memcpy(ptr, str, len + 1);
  return ptr;
}

#ifdef strdup
#undef strdup
#endif
#define strdup local_strdup
#endif

static int parse_auth_types(const char *arg, long auth_types[4])
{
  char *arg_copy;
  const char *token;
  char *sep;
  unsigned int i;
  unsigned int j;

  if(!arg) {
    fprintf(stderr, "no auth scheme on commandline\n");
    return TEST_ERR_MAJOR_BAD;
  }
  arg_copy = strdup(arg);
  if(!arg_copy) {
    fprintf(stderr, "out of memory error\n");
    return TEST_ERR_MAJOR_BAD;
  }

  i = 0;
  token = arg_copy;
  while(!0) {
    if(i >= 4) {
      fprintf(stderr, "too many auth schemes on commandline\n");
      free(arg_copy);
      return TEST_ERR_MAJOR_BAD;
    }
    sep = strchr(token, '-');
    if(sep)
      *sep = 0;
    if(curl_strequal(token, "none"))
      auth_types[i++] = CURLAUTH_NONE;
    else if(curl_strequal(token, "basic"))
      auth_types[i++] = CURLAUTH_BASIC;
    else if(curl_strequal(token, "digest"))
      auth_types[i++] = CURLAUTH_DIGEST;
    else if(curl_strequal(token, "ntlm"))
      auth_types[i++] = CURLAUTH_NTLM;
    else {
      fprintf(stderr, "unknown auth scheme on commandline\n");
      free(arg_copy);
      return TEST_ERR_MAJOR_BAD;
    }
    if(!sep)
      break;
    token = sep + 1;
  }
  free(arg_copy);
  for(j = i; j < 4; j++) {
    auth_types[j] = auth_types[j % i];
  }
  return 0;
}


static int parse_cred_strings(const char *arg, char creds[4][32],
                              const char *def_str)
{
  unsigned int i;
  unsigned int j;

  i = 0;
  if(!arg)
    strcpy(creds[i++], def_str);
  else {
    const char *sep;
    const char *token;
    size_t len;

    token = arg;
    while(!0) {
      if(i >= 4) {
        fprintf(stderr, "too many usernames or passwords on commandline\n");
        return TEST_ERR_MAJOR_BAD;
      }
      sep = strchr(token, '-');
      if(sep)
        len = (size_t) (sep - token);
      else
        len = strlen(token);
      if(len > 31) {
        fprintf(stderr, "too long username or password\n");
        return TEST_ERR_MAJOR_BAD;
      }
      memcpy(creds[i], token, len);
      creds[i][len] = 0;
      i++;
      if(!sep)
        break;
      token = sep + 1;
    }
  }

  for(j = i; j < 4; j++) {
    strcpy(creds[j], creds[j % i]);
  }
  return 0;
}

int test(char *url)
{
  CURLcode res;
  CURL *curl = NULL;
  long auth_types[4];
  char usernames[4][32];
  char passwords[4][32];
  int i;

  if(parse_auth_types(libtest_arg2, auth_types) ||
     parse_cred_strings(libtest_arg3, usernames, "testuser") ||
     parse_cred_strings(libtest_arg4, passwords, "testpass"))
    return TEST_ERR_MAJOR_BAD;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  for(i = 0; i < 4; i++) {
    res = send_request(curl, url, 100 * (i + 1), auth_types[i],
                       usernames[i], passwords[i]);
    if(res != CURLE_OK)
      break;
    if(i >= 2) {
      /* Send the same request twice */
      res = send_request(curl, url, 100 * (i + 1) + 10, auth_types[i],
                         usernames[i], passwords[i]);
      if(res != CURLE_OK)
        break;
    }
  }

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
