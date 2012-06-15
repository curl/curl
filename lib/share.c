/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "urldata.h"
#include "share.h"
#include "sslgen.h"
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

CURLSH *
curl_share_init(void)
{
  struct Curl_share *share = calloc(1, sizeof(struct Curl_share));
  if(share)
    share->specifier |= (1<<CURL_LOCK_DATA_SHARE);

  return share;
}

#undef curl_share_setopt
CURLSHcode
curl_share_setopt(CURLSH *sh, CURLSHoption option, ...)
{
  struct Curl_share *share = (struct Curl_share *)sh;
  va_list param;
  int type;
  curl_lock_function lockfunc;
  curl_unlock_function unlockfunc;
  void *ptr;
  CURLSHcode res = CURLSHE_OK;

  if(share->dirty)
    /* don't allow setting options while one or more handles are already
       using this share */
    return CURLSHE_IN_USE;

  va_start(param, option);

  switch(option) {
  case CURLSHOPT_SHARE:
    /* this is a type this share will share */
    type = va_arg(param, int);
    share->specifier |= (1<<type);
    switch( type ) {
    case CURL_LOCK_DATA_DNS:
      if(!share->hostcache) {
        share->hostcache = Curl_mk_dnscache();
        if(!share->hostcache)
          res = CURLSHE_NOMEM;
      }
      break;

    case CURL_LOCK_DATA_COOKIE:
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(!share->cookies) {
        share->cookies = Curl_cookie_init(NULL, NULL, NULL, TRUE );
        if(!share->cookies)
          res = CURLSHE_NOMEM;
      }
#else   /* CURL_DISABLE_HTTP */
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    case CURL_LOCK_DATA_SSL_SESSION:
#ifdef USE_SSL
      if(!share->sslsession) {
        share->max_ssl_sessions = 8;
        share->sslsession = calloc(share->max_ssl_sessions,
                                   sizeof(struct curl_ssl_session));
        share->sessionage = 0;
        if(!share->sslsession)
          res = CURLSHE_NOMEM;
      }
#else
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    case CURL_LOCK_DATA_CONNECT:     /* not supported (yet) */
      break;

    default:
      res = CURLSHE_BAD_OPTION;
    }
    break;

  case CURLSHOPT_UNSHARE:
    /* this is a type this share will no longer share */
    type = va_arg(param, int);
    share->specifier &= ~(1<<type);
    switch( type ) {
    case CURL_LOCK_DATA_DNS:
      if(share->hostcache) {
        Curl_hash_destroy(share->hostcache);
        share->hostcache = NULL;
      }
      break;

    case CURL_LOCK_DATA_COOKIE:
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(share->cookies) {
        Curl_cookie_cleanup(share->cookies);
        share->cookies = NULL;
      }
#else   /* CURL_DISABLE_HTTP */
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    case CURL_LOCK_DATA_SSL_SESSION:
#ifdef USE_SSL
      Curl_safefree(share->sslsession);
#else
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    case CURL_LOCK_DATA_CONNECT:
      break;

    default:
      res = CURLSHE_BAD_OPTION;
      break;
    }
    break;

  case CURLSHOPT_LOCKFUNC:
    lockfunc = va_arg(param, curl_lock_function);
    share->lockfunc = lockfunc;
    break;

  case CURLSHOPT_UNLOCKFUNC:
    unlockfunc = va_arg(param, curl_unlock_function);
    share->unlockfunc = unlockfunc;
    break;

  case CURLSHOPT_USERDATA:
    ptr = va_arg(param, void *);
    share->clientdata = ptr;
    break;

  default:
    res = CURLSHE_BAD_OPTION;
    break;
  }

  va_end(param);

  return res;
}

CURLSHcode
curl_share_cleanup(CURLSH *sh)
{
  struct Curl_share *share = (struct Curl_share *)sh;

  if(share == NULL)
    return CURLSHE_INVALID;

  if(share->lockfunc)
    share->lockfunc(NULL, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE,
                    share->clientdata);

  if(share->dirty) {
    if(share->unlockfunc)
      share->unlockfunc(NULL, CURL_LOCK_DATA_SHARE, share->clientdata);
    return CURLSHE_IN_USE;
  }

  if(share->hostcache) {
    Curl_hash_destroy(share->hostcache);
    share->hostcache = NULL;
  }

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
  if(share->cookies)
    Curl_cookie_cleanup(share->cookies);
#endif

#ifdef USE_SSL
  if(share->sslsession) {
    size_t i;
    for(i = 0; i < share->max_ssl_sessions; i++)
      Curl_ssl_kill_session(&(share->sslsession[i]));
    free(share->sslsession);
  }
#endif

  if(share->unlockfunc)
    share->unlockfunc(NULL, CURL_LOCK_DATA_SHARE, share->clientdata);
  free(share);

  return CURLSHE_OK;
}


CURLSHcode
Curl_share_lock(struct SessionHandle *data, curl_lock_data type,
                curl_lock_access accesstype)
{
  struct Curl_share *share = data->share;

  if(share == NULL)
    return CURLSHE_INVALID;

  if(share->specifier & (1<<type)) {
    if(share->lockfunc) /* only call this if set! */
      share->lockfunc(data, type, accesstype, share->clientdata);
  }
  /* else if we don't share this, pretend successful lock */

  return CURLSHE_OK;
}

CURLSHcode
Curl_share_unlock(struct SessionHandle *data, curl_lock_data type)
{
  struct Curl_share *share = data->share;

  if(share == NULL)
    return CURLSHE_INVALID;

  if(share->specifier & (1<<type)) {
    if(share->unlockfunc) /* only call this if set! */
      share->unlockfunc (data, type, share->clientdata);
  }

  return CURLSHE_OK;
}
