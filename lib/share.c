/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"
#include <stdlib.h>
#include <curl/curl.h>
#include "share.h"
#include "urldata.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

#define CURL_SHARE_SET_LOCKED(__share, __type) ((__share)->locked += (__type))
#define CURL_SHARE_SET_UNLOCKED(__share, __type) ((__share)->locked -= (__type))

#define CURL_SHARE_SET_USED(__share, __type) ((__share)->specifier += (__type))
#define CURL_SHARE_SET_UNUSED(__share, __type) ((__share)->specifier -= (__type))
#define CURL_SHARE_IS_USED(__share, __type) ((__share)->specifier & (__type))
#define CURL_SHARE_IS_LOCKED(__share, __type) ((__share)->locked & (__type))

#define CURL_SHARE_IS_DIRTY(__share) ((__share)->dirty)

#define CURL_SHARE_GET(__handle) (((struct SessionHandle *) (__handle))->share)

curl_share *
curl_share_init (void)
{
  curl_share *share = (curl_share *) malloc (sizeof (curl_share));
  if (share) {
    memset (share, 0, sizeof (curl_share));
  }

  return share;
}

CURLcode 
curl_share_setopt (curl_share *share, curl_lock_type option, int enable)
{
  if (CURL_SHARE_IS_DIRTY(share)) {
    return CURLE_SHARE_IN_USE;
  }

  if (enable) {
    CURL_SHARE_SET_USED (share, option);
  }
  else {
    CURL_SHARE_SET_UNUSED (share, option);
  }

  return CURLE_OK;
}

CURLcode
curl_share_set_lock_function (curl_share *share, curl_lock_function lock)
{
  if (CURL_SHARE_IS_DIRTY(share)) {
    return CURLE_SHARE_IN_USE;
  }

  share->lockfunc = lock;
  return CURLE_OK;
}

CURLcode
curl_share_set_unlock_function (curl_share *share, curl_unlock_function unlock)
{
  if (CURL_SHARE_IS_DIRTY(share)) {
    return CURLE_SHARE_IN_USE;
  }

  share->unlockfunc = unlock;
  return CURLE_OK;
}

CURLcode
curl_share_set_lock_data (curl_share *share, void *data) 
{
  if (CURL_SHARE_IS_DIRTY(share)) {
    return CURLE_SHARE_IN_USE;
  }

  share->clientdata = data;
  return CURLE_OK;
}

Curl_share_error 
Curl_share_acquire_lock (CURL *handle, curl_lock_type type)
{
  curl_share *share = CURL_SHARE_GET (handle);
  if (share == NULL) {
    return SHARE_ERROR_INVALID;
  }

  if (! (share->specifier & type)) {
    return SHARE_ERROR_NOT_REGISTERED;
  }

  if (CURL_SHARE_IS_LOCKED (share, type)) {
    return SHARE_ERROR_OK;
  }

  share->lockfunc (handle, type, share->clientdata);
  CURL_SHARE_SET_LOCKED (share, type);

  return SHARE_ERROR_OK;
}

Curl_share_error 
Curl_share_release_lock (CURL *handle, curl_lock_type type)
{
  curl_share *share = CURL_SHARE_GET(handle);
  if (share == NULL) {
    return SHARE_ERROR_INVALID;
  }

  if (! (share->specifier & type)) {
    return SHARE_ERROR_NOT_REGISTERED;
  }

  if (!CURL_SHARE_IS_LOCKED (share, type)) {
    return SHARE_ERROR_OK;
  }

  share->unlockfunc (handle, type, share->clientdata);
  CURL_SHARE_SET_UNLOCKED (share, type);

  return SHARE_ERROR_OK;
}

CURLcode curl_share_destroy (curl_share *share)
{
  if (CURL_SHARE_IS_DIRTY(share)) {
    return CURLE_SHARE_IN_USE;
  }

  free (share);
  
  return CURLE_OK;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
