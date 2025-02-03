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
 * are also available at https://fetch.se/docs/copyright.html.
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

#include "fetch_setup.h"

#include <fetch/fetch.h>
#include "urldata.h"
#include "connect.h"
#include "share.h"
#include "psl.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "hsts.h"
#include "url.h"

/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

FETCHSH *
fetch_share_init(void)
{
  struct Curl_share *share = calloc(1, sizeof(struct Curl_share));
  if(share) {
    share->magic = FETCH_GOOD_SHARE;
    share->specifier |= (1 << FETCH_LOCK_DATA_SHARE);
    Curl_init_dnscache(&share->hostcache, 23);
  }

  return share;
}

#undef fetch_share_setopt
FETCHSHcode
fetch_share_setopt(FETCHSH *sh, FETCHSHoption option, ...)
{
  va_list param;
  int type;
  fetch_lock_function lockfunc;
  fetch_unlock_function unlockfunc;
  void *ptr;
  FETCHSHcode res = FETCHSHE_OK;
  struct Curl_share *share = sh;

  if(!GOOD_SHARE_HANDLE(share))
    return FETCHSHE_INVALID;

  if(share->dirty)
    /* do not allow setting options while one or more handles are already
       using this share */
    return FETCHSHE_IN_USE;

  va_start(param, option);

  switch(option) {
  case FETCHSHOPT_SHARE:
    /* this is a type this share will share */
    type = va_arg(param, int);

    switch(type) {
    case FETCH_LOCK_DATA_DNS:
      break;

    case FETCH_LOCK_DATA_COOKIE:
#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_COOKIES)
      if(!share->cookies) {
        share->cookies = Curl_cookie_init(NULL, NULL, NULL, TRUE);
        if(!share->cookies)
          res = FETCHSHE_NOMEM;
      }
#else   /* FETCH_DISABLE_HTTP */
      res = FETCHSHE_NOT_BUILT_IN;
#endif
      break;

    case FETCH_LOCK_DATA_HSTS:
#ifndef FETCH_DISABLE_HSTS
      if(!share->hsts) {
        share->hsts = Curl_hsts_init();
        if(!share->hsts)
          res = FETCHSHE_NOMEM;
      }
#else   /* FETCH_DISABLE_HSTS */
      res = FETCHSHE_NOT_BUILT_IN;
#endif
      break;

    case FETCH_LOCK_DATA_SSL_SESSION:
#ifdef USE_SSL
      if(!share->ssl_scache) {
        /* There is no way (yet) for the application to configure the
         * session cache size, shared between many transfers. As for fetch
         * itself, a high session count will impact startup time. Also, the
         * scache is not optimized for several hundreds of peers. So,
         * keep it at a reasonable level. */
        if(Curl_ssl_scache_create(25, 2, &share->ssl_scache))
          res = FETCHSHE_NOMEM;
      }
#else
      res = FETCHSHE_NOT_BUILT_IN;
#endif
      break;

    case FETCH_LOCK_DATA_CONNECT:
      /* It is safe to set this option several times on a share. */
      if(!share->cpool.idata) {
        if(Curl_cpool_init(&share->cpool, Curl_on_disconnect,
                           NULL, share, 103))
          res = FETCHSHE_NOMEM;
      }
      break;

    case FETCH_LOCK_DATA_PSL:
#ifndef USE_LIBPSL
      res = FETCHSHE_NOT_BUILT_IN;
#endif
      break;

    default:
      res = FETCHSHE_BAD_OPTION;
    }
    if(!res)
      share->specifier |= (unsigned int)(1 << type);
    break;

  case FETCHSHOPT_UNSHARE:
    /* this is a type this share will no longer share */
    type = va_arg(param, int);
    share->specifier &= ~(unsigned int)(1 << type);
    switch(type) {
    case FETCH_LOCK_DATA_DNS:
      break;

    case FETCH_LOCK_DATA_COOKIE:
#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_COOKIES)
      if(share->cookies) {
        Curl_cookie_cleanup(share->cookies);
        share->cookies = NULL;
      }
#else   /* FETCH_DISABLE_HTTP */
      res = FETCHSHE_NOT_BUILT_IN;
#endif
      break;

    case FETCH_LOCK_DATA_HSTS:
#ifndef FETCH_DISABLE_HSTS
      if(share->hsts) {
        Curl_hsts_cleanup(&share->hsts);
      }
#else   /* FETCH_DISABLE_HSTS */
      res = FETCHSHE_NOT_BUILT_IN;
#endif
      break;

    case FETCH_LOCK_DATA_SSL_SESSION:
#ifdef USE_SSL
      if(share->ssl_scache) {
        Curl_ssl_scache_destroy(share->ssl_scache);
        share->ssl_scache = NULL;
      }
#else
      res = FETCHSHE_NOT_BUILT_IN;
#endif
      break;

    case FETCH_LOCK_DATA_CONNECT:
      break;

    default:
      res = FETCHSHE_BAD_OPTION;
      break;
    }
    break;

  case FETCHSHOPT_LOCKFUNC:
    lockfunc = va_arg(param, fetch_lock_function);
    share->lockfunc = lockfunc;
    break;

  case FETCHSHOPT_UNLOCKFUNC:
    unlockfunc = va_arg(param, fetch_unlock_function);
    share->unlockfunc = unlockfunc;
    break;

  case FETCHSHOPT_USERDATA:
    ptr = va_arg(param, void *);
    share->clientdata = ptr;
    break;

  default:
    res = FETCHSHE_BAD_OPTION;
    break;
  }

  va_end(param);

  return res;
}

FETCHSHcode
fetch_share_cleanup(FETCHSH *sh)
{
  struct Curl_share *share = sh;
  if(!GOOD_SHARE_HANDLE(share))
    return FETCHSHE_INVALID;

  if(share->lockfunc)
    share->lockfunc(NULL, FETCH_LOCK_DATA_SHARE, FETCH_LOCK_ACCESS_SINGLE,
                    share->clientdata);

  if(share->dirty) {
    if(share->unlockfunc)
      share->unlockfunc(NULL, FETCH_LOCK_DATA_SHARE, share->clientdata);
    return FETCHSHE_IN_USE;
  }

  if(share->specifier & (1 << FETCH_LOCK_DATA_CONNECT)) {
    Curl_cpool_destroy(&share->cpool);
  }
  Curl_hash_destroy(&share->hostcache);

#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_COOKIES)
  Curl_cookie_cleanup(share->cookies);
#endif

#ifndef FETCH_DISABLE_HSTS
  Curl_hsts_cleanup(&share->hsts);
#endif

#ifdef USE_SSL
  if(share->ssl_scache) {
    Curl_ssl_scache_destroy(share->ssl_scache);
    share->ssl_scache = NULL;
  }
#endif

  Curl_psl_destroy(&share->psl);

  if(share->unlockfunc)
    share->unlockfunc(NULL, FETCH_LOCK_DATA_SHARE, share->clientdata);
  share->magic = 0;
  free(share);

  return FETCHSHE_OK;
}


FETCHSHcode
Curl_share_lock(struct Curl_easy *data, fetch_lock_data type,
                fetch_lock_access accesstype)
{
  struct Curl_share *share = data->share;

  if(!share)
    return FETCHSHE_INVALID;

  if(share->specifier & (unsigned int)(1 << type)) {
    if(share->lockfunc) /* only call this if set! */
      share->lockfunc(data, type, accesstype, share->clientdata);
  }
  /* else if we do not share this, pretend successful lock */

  return FETCHSHE_OK;
}

FETCHSHcode
Curl_share_unlock(struct Curl_easy *data, fetch_lock_data type)
{
  struct Curl_share *share = data->share;

  if(!share)
    return FETCHSHE_INVALID;

  if(share->specifier & (unsigned int)(1 << type)) {
    if(share->unlockfunc) /* only call this if set! */
      share->unlockfunc (data, type, share->clientdata);
  }

  return FETCHSHE_OK;
}
