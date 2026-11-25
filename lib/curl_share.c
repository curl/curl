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
#include "curl_setup.h"

#include "urldata.h"
#include "multiif.h"
#include "curl_threads.h"
#include "curl_share.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "hsts.h"
#include "url.h"

static void share_destroy(struct Curl_share *share)
{
  if(!share)
    return;

  /* make the share no longer usable in calls, in case the application
   * keeps pointer copies or tries to use the share in callbacks invoked
   * during its destruction. */
  share->magic = 0;

  if(share->specifier & (1 << CURL_LOCK_DATA_CONNECT)) {
    Curl_cpool_destroy(&share->cpool, share->admin);
  }

  Curl_dnscache_destroy(&share->dnscache);

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
  Curl_cookie_cleanup(share->cookies);
#endif

#ifndef CURL_DISABLE_HSTS
  Curl_hsts_cleanup(&share->hsts);
#endif

#ifdef USE_SSL
  if(share->ssl_scache) {
    Curl_ssl_scache_destroy(share->ssl_scache);
    share->ssl_scache = NULL;
  }
#endif

  Curl_psl_destroy(&share->psl);
  Curl_close(&share->admin);

#ifdef USE_MUTEX
  Curl_mutex_destroy(&share->lock);
#endif
  curlx_memzero(share, sizeof(*share));
  curlx_free(share);
}

CURLSH *curl_share_init(void)
{
  struct Curl_share *share = curlx_calloc(1, sizeof(struct Curl_share));
  if(share) {
    share->magic = CURL_GOOD_SHARE;
    share->specifier |= (1 << CURL_LOCK_DATA_SHARE);
#ifdef USE_MUTEX
    Curl_mutex_init(&share->lock);
#endif
    Curl_refcount_init(&share->ref_count, 1);
    Curl_dnscache_init(&share->dnscache, 23);
    share->admin = curl_easy_init();
    if(!share->admin) {
      share_destroy(share);
      return NULL;
    }
    /* admin handles have mid 0 */
    share->admin->mid = 0;
    share->admin->state.internal = TRUE;
#ifdef DEBUGBUILD
    if(getenv("CURL_DEBUG"))
      share->admin->set.verbose = TRUE;
#endif
  }
  return share;
}

static bool share_has_been_shared(struct Curl_share *share)
{
  bool was_shared;
#ifdef USE_MUTEX
  Curl_mutex_acquire(&share->lock);
  was_shared = share->has_been_shared;
  Curl_mutex_release(&share->lock);
#else
  was_shared = share->has_been_shared;
#endif
  return was_shared;
}

static bool share_lock_acquire(struct Curl_share *share,
                               struct Curl_easy *data)
{
  if(share->lockfunc && share->unlockfunc &&
     (data || share_has_been_shared(share))) {
    share->lockfunc(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE,
                    share->clientdata);
    return TRUE;
  }
  return FALSE;
}

static void share_lock_release(struct Curl_share *share,
                               struct Curl_easy *data,
                               bool locked)
{
  if(locked) {
    DEBUGASSERT(share->unlockfunc);
    if(share->unlockfunc)
      share->unlockfunc(data, CURL_LOCK_DATA_SHARE, share->clientdata);
  }
}

static uint32_t share_unlink(struct Curl_share **pshare)
{
  struct Curl_share *share = *pshare;
  uint32_t n;

  *pshare = NULL;
  n = Curl_refcount_decr(&share->ref_count);
  DEBUGASSERT(n != UINT32_MAX); /* no underflow */
  if(!n)  /* last reference gone */
    share_destroy(share);
  return n;
}

#undef curl_share_setopt
CURLSHcode curl_share_setopt(CURLSH *sh, CURLSHoption option, ...)
{
  va_list param;
  int type;
  curl_lock_function lockfunc;
  curl_unlock_function unlockfunc;
  void *ptr;
  CURLSHcode res = CURLSHE_OK;
  struct Curl_share *share = sh;
  uint32_t n;

  if(!GOOD_SHARE_HANDLE(share))
    return CURLSHE_INVALID;

  n = Curl_refcount_incr(&share->ref_count);
  if(n == 1) {  /* We got a share with 0 refcount? */
    res = CURLSHE_INVALID;
    goto out;
  }
  else if(n > 2) {
    /* do not allow setting options while one or more handles are already
       using this share */
    res = CURLSHE_IN_USE;
    goto out;
  }

  va_start(param, option);

  switch(option) {
  case CURLSHOPT_SHARE:
    /* this is a type this share will share */
    type = va_arg(param, int);

    switch(type) {
    case CURL_LOCK_DATA_DNS:
      break;

    case CURL_LOCK_DATA_COOKIE:
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(!share->cookies) {
        share->cookies = Curl_cookie_init();
        if(!share->cookies)
          res = CURLSHE_NOMEM;
      }
#else /* CURL_DISABLE_HTTP || CURL_DISABLE_COOKIES */
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    case CURL_LOCK_DATA_HSTS:
#ifndef CURL_DISABLE_HSTS
      if(!share->hsts) {
        share->hsts = Curl_hsts_init();
        if(!share->hsts)
          res = CURLSHE_NOMEM;
      }
#else /* CURL_DISABLE_HSTS */
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    case CURL_LOCK_DATA_SSL_SESSION:
#ifdef USE_SSL
      if(!share->ssl_scache) {
        /* There is no way (yet) for the application to configure the
         * session cache size, shared between many transfers. As for curl
         * itself, a high session count will impact startup time. Also, the
         * scache is not optimized for several hundreds of peers.
         * Keep it at a reasonable level. */
        if(Curl_ssl_scache_create(25, 2, &share->ssl_scache))
          res = CURLSHE_NOMEM;
      }
#else
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    case CURL_LOCK_DATA_CONNECT:
      /* It is safe to set this option several times on a share. */
      if(!share->cpool.initialized) {
        Curl_cpool_init(&share->cpool, share, 103);
      }
      break;

    case CURL_LOCK_DATA_PSL:
#ifndef USE_LIBPSL
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    default:
      res = CURLSHE_BAD_OPTION;
    }
    if(!res)
      share->specifier |= (unsigned int)(1 << type);
    break;

  case CURLSHOPT_UNSHARE:
    /* this is a type this share will no longer share */
    type = va_arg(param, int);
    switch(type) {
    case CURL_LOCK_DATA_DNS:
      break;

    case CURL_LOCK_DATA_COOKIE:
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(share->cookies) {
        Curl_cookie_cleanup(share->cookies);
        share->cookies = NULL;
      }
#else /* CURL_DISABLE_HTTP || CURL_DISABLE_COOKIES */
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    case CURL_LOCK_DATA_HSTS:
#ifndef CURL_DISABLE_HSTS
      if(share->hsts) {
        Curl_hsts_cleanup(&share->hsts);
      }
#else /* CURL_DISABLE_HSTS */
      res = CURLSHE_NOT_BUILT_IN;
#endif
      break;

    case CURL_LOCK_DATA_SSL_SESSION:
#ifdef USE_SSL
      if(share->ssl_scache) {
        Curl_ssl_scache_destroy(share->ssl_scache);
        share->ssl_scache = NULL;
      }
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
    if(!res)
      share->specifier &= ~(unsigned int)(1 << type);
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

out:
  va_end(param);
  Curl_refcount_decr(&share->ref_count);
  return res;
}

CURLSHcode curl_share_cleanup(CURLSH *sh)
{
  struct Curl_share *share = sh;
  uint32_t n;

  if(!GOOD_SHARE_HANDLE(share))
    return CURLSHE_INVALID;

  /* Check if we release the last reference here. This check is not
   * thread-safe, as the application might link the share after the
   * check again in another thread. */
  n = Curl_refcount_get(&share->ref_count);
  if(n > 1)
    return CURLSHE_IN_USE;
  else if(!n)
    return CURLSHE_INVALID;

  share_unlink(&share);
  return CURLSHE_OK;
}

CURLSHcode Curl_share_lock_share(struct Curl_share *share,
                                 struct Curl_easy *data,
                                 curl_lock_data type,
                                 curl_lock_access accesstype)
{
  if(!GOOD_SHARE_HANDLE(share))
    return CURLSHE_INVALID;

  if(share->specifier & (unsigned int)(1 << type) &&
     share->lockfunc) /* only call this if set! */
    share->lockfunc(data, type, accesstype, share->clientdata);
  /* else if we do not share this, pretend successful lock */

  return CURLSHE_OK;
}

CURLSHcode Curl_share_lock(struct Curl_easy *data, curl_lock_data type,
                           curl_lock_access accesstype)
{
  return Curl_share_lock_share(data->share, data, type, accesstype);
}

CURLSHcode Curl_share_unlock_share(struct Curl_share *share,
                                   struct Curl_easy *data,
                                   curl_lock_data type)
{
  if(!GOOD_SHARE_HANDLE(share))
    return CURLSHE_INVALID;

  if(share->specifier & (unsigned int)(1 << type) &&
     share->unlockfunc) /* only call this if set! */
    share->unlockfunc(data, type, share->clientdata);

  return CURLSHE_OK;
}

CURLSHcode Curl_share_unlock(struct Curl_easy *data, curl_lock_data type)
{
  return Curl_share_unlock_share(data->share, data, type);
}

CURLcode Curl_share_easy_unlink(struct Curl_easy *data)
{
  struct Curl_share *share = data->share;

  if(share) {
    bool locked;

    if(!GOOD_SHARE_HANDLE(share))
      return CURLE_BAD_FUNCTION_ARGUMENT;

    locked = share_lock_acquire(share, data);
    /* If share caches connections, detach any existing connection and
     * forget its identifier. */
    if((share->specifier & (1 << CURL_LOCK_DATA_CONNECT))) {
      if(data->conn)
        Curl_detach_connection(data);
      data->state.last_conn_id = -1;
      data->state.last_cpid = UINT32_MAX;
    }

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
    if(share->cookies == data->cookies)
      data->cookies = NULL;
#endif

#ifndef CURL_DISABLE_HSTS
    if(share->hsts == data->hsts)
      data->hsts = NULL;
#endif
#ifdef USE_LIBPSL
    if(&share->psl == data->psl)
      data->psl = data->multi ? &data->multi->psl : NULL;
#endif

    share_lock_release(data->share, data, locked);
    share_unlink(&data->share);
  }
  return CURLE_OK;
}

CURLcode Curl_share_easy_link(struct Curl_easy *data,
                              struct Curl_share *share)
{
  CURLcode result = CURLE_OK;
  bool locked = FALSE;
  uint32_t n;

  if(data->share) {
    DEBUGASSERT(0);
    return CURLE_FAILED_INIT;
  }

  if(!share)
    return CURLE_OK;
  else if(!GOOD_SHARE_HANDLE(share))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* increment ref count while we use this share */
  n = Curl_refcount_incr(&share->ref_count);
  if(n == 1) { /* someone is using a share with 0 refcount */
    DEBUGASSERT(0);
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }

  locked = share_lock_acquire(share, data);
  /* Forget identifiers from the previously used connection cache. */
  if((share->specifier & (1 << CURL_LOCK_DATA_CONNECT))) {
    data->state.last_conn_id = -1;
    data->state.last_cpid = UINT32_MAX;
  }

  /* increment again for the assignment into the easy */
  (void)Curl_refcount_incr(&share->ref_count);
  data->share = share;
  share->has_been_shared = TRUE;

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
  if(share->cookies) {
    /* use shared cookie list, first free own one if any */
    Curl_cookie_cleanup(data->cookies);
    /* enable cookies since we now use a share that uses cookies! */
    data->cookies = share->cookies;
  }
#endif /* CURL_DISABLE_HTTP */
#ifndef CURL_DISABLE_HSTS
  if(share->hsts) {
    /* first free the private one if any */
    Curl_hsts_cleanup(&data->hsts);
    data->hsts = share->hsts;
  }
#endif
#ifdef USE_LIBPSL
  if(share->specifier & (1 << CURL_LOCK_DATA_PSL))
    data->psl = &share->psl;
#endif

  /* check for host cache not needed,
   * it will be done by curl_easy_perform */
  share_lock_release(share, data, locked);

out:
  /* give up our use of the share */
  share_unlink(&share);
  return result;
}
