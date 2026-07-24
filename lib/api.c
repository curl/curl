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
#include "api.h"
#include "curl_threads.h"
#include "multiif.h"
#include "vtls/vtls_scache.h"

struct Curl_eapi_fn_props {
  Curl_eapi_fn fn;
  uint8_t data_is_killed; /* easy handle is killed in call */
  uint8_t recurse;        /* may be called when another call is in progress */
  uint8_t no_event_cb;    /* may not be called during a multi event callback */
  uint8_t no_scache_lock; /* may not be called with easy's vtls_scache
                             locked by current thread */
};

static const struct Curl_eapi_fn_props eapi_fn_props[CURL_EAPI_FN_LAST] = {
  /* function                   kill rec !ev !scach */
  { CURL_EAPI_FN_easy_cleanup,     1,  0,  0,  0 },
  { CURL_EAPI_FN_easy_duphandle,   0,  1,  0,  0 },
  { CURL_EAPI_FN_easy_getinfo,     0,  1,  0,  0 },
  { CURL_EAPI_FN_easy_pause,       0,  1,  1,  0 },
  { CURL_EAPI_FN_easy_perform_ev,  0,  0,  0,  1 },
  { CURL_EAPI_FN_easy_perform,     0,  0,  0,  1 },
  { CURL_EAPI_FN_easy_recv,        0,  0,  0,  1 },
  { CURL_EAPI_FN_easy_reset,       0,  0,  0,  0 },
  { CURL_EAPI_FN_easy_send,        0,  0,  0,  1 },
  { CURL_EAPI_FN_easy_setopt,      0,  1,  0,  0 },
  { CURL_EAPI_FN_easy_ssls_export, 0,  0,  0,  1 },
  { CURL_EAPI_FN_easy_ssls_import, 0,  0,  0,  1 },
  { CURL_EAPI_FN_easy_upkeep,      0,  0,  0,  1 },
  { CURL_EAPI_FN_ws_recv,          0,  1,  0,  1 },
  { CURL_EAPI_FN_ws_send,          0,  1,  0,  1 },
  { CURL_EAPI_FN_ws_start_frame,   0,  1,  0,  0 },
};

struct Curl_mapi_fn_props {
  Curl_mapi_fn fn;
  uint8_t multi_is_killed; /* multi handle is killed during call */
  uint8_t recurse;         /* may be called when another call is in progress */
  uint8_t allow_ntfy_cb;   /* may be called during a notify callback */
  uint8_t no_scache_lock;  /* may not be called with multi's vtls_scache
                              locked by current thread */
};

static const struct Curl_mapi_fn_props mapi_fn_props[CURL_MAPI_FN_LAST] = {
  /* function                       kill rec ntfy !scach */
  { CURL_MAPI_FN_multi_add_handle,     0,  0,   1,  0 },
  { CURL_MAPI_FN_multi_assign,         0,  1,   1,  0 },
  { CURL_MAPI_FN_multi_cleanup,        1,  0,   0,  1 },
  { CURL_MAPI_FN_multi_fdset,          0,  0,   1,  0 },
  { CURL_MAPI_FN_multi_get_handles,    0,  1,   1,  0 },
  { CURL_MAPI_FN_multi_get_offt,       0,  1,   1,  0 },
  { CURL_MAPI_FN_multi_info_read,      0,  1,   1,  0 },
  { CURL_MAPI_FN_multi_notify_disable, 0,  1,   1,  0 },
  { CURL_MAPI_FN_multi_notify_enable,  0,  1,   1,  0 },
  { CURL_MAPI_FN_multi_perform,        0,  0,   0,  1 },
  { CURL_MAPI_FN_multi_poll,           0,  0,   1,  0 },
  { CURL_MAPI_FN_multi_remove_handle,  0,  0,   1,  0 },
  { CURL_MAPI_FN_multi_setopt,         0,  0,   1,  0 },
  { CURL_MAPI_FN_multi_socket_action,  0,  0,   0,  1 },
  { CURL_MAPI_FN_multi_socket_all,     0,  0,   0,  1 },
  { CURL_MAPI_FN_multi_socket,         0,  0,   0,  1 },
  { CURL_MAPI_FN_multi_timeout,        0,  0,   1,  1 },
  { CURL_MAPI_FN_multi_wait,           0,  0,   1,  0 },
  { CURL_MAPI_FN_multi_waitfds,        0,  0,   1,  0 },
};

struct Curl_cbapi_fn_props {
  Curl_cbapi_fn fn;
  uint8_t is_event_cb;     /* is a multi event processing callback */
};

static const struct Curl_cbapi_fn_props
cbapi_fn_props[CURL_CBAPI_FN_LAST - CURL_CBAPI_FN_START] = {
  { CURL_CBAPI_FN_easy_chunk_bgn,             0 },
  { CURL_CBAPI_FN_easy_chunk_end,             0 },
  { CURL_CBAPI_FN_easy_closesocket,           0 },
  { CURL_CBAPI_FN_easy_cr_in_read,            0 },
  { CURL_CBAPI_FN_easy_cr_in_resume_from,     0 },
  { CURL_CBAPI_FN_easy_cw_out_cb,             0 },
  { CURL_CBAPI_FN_easy_fdebug,                0 },
  { CURL_CBAPI_FN_easy_fnmatch_data,          0 },
  { CURL_CBAPI_FN_easy_fopensocket,           0 },
  { CURL_CBAPI_FN_easy_fprereq,               0 },
  { CURL_CBAPI_FN_easy_fprogress,             0 },
  { CURL_CBAPI_FN_easy_fread_func,            0 },
  { CURL_CBAPI_FN_easy_fsockopt,              0 },
  { CURL_CBAPI_FN_easy_fsslctx,               0 },
  { CURL_CBAPI_FN_easy_fwrite_rtp,            0 },
  { CURL_CBAPI_FN_easy_fxferinfo,             0 },
  { CURL_CBAPI_FN_easy_ioctl_func,            0 },
  { CURL_CBAPI_FN_easy_resolver_start,        0 },
  { CURL_CBAPI_FN_easy_seek_func,             0 },
  { CURL_CBAPI_FN_easy_ssh_hostkeyfunc,       0 },
  { CURL_CBAPI_FN_easy_ssh_keyfunc,           0 },
  { CURL_CBAPI_FN_easy_trailer_callback,      0 },

  { CURL_CBAPI_FN_multi_ntfy_cb,              0 },
  { CURL_CBAPI_FN_multi_push_cb,              0 },
  { CURL_CBAPI_FN_multi_socket_cb,            1 },
  { CURL_CBAPI_FN_multi_timer_cb,             1 },
};

static bool eapi_in_event_cb(struct Curl_easy *data)
{
  struct Curl_multi *multi = data->multi;
  if(multi && multi->callstack.count) {
    size_t i;
    for(i = 0; i < multi->callstack.count; ++i) {
      if(multi->callstack.calls[i] >= CURL_CBAPI_FN_START) {
        uint16_t fn = multi->callstack.calls[i];
        if((fn < CURL_CBAPI_FN_LAST) &&
           cbapi_fn_props[fn - CURL_CBAPI_FN_START].is_event_cb)
          return TRUE;
      }
    }
  }
  return FALSE;
}

static bool mapi_in_ntfy_cb(struct Curl_multi *multi)
{
  if(multi && multi->callstack.count) {
    size_t i;
    for(i = 0; i < multi->callstack.count; ++i) {
      if(multi->callstack.calls[i] == CURL_CBAPI_FN_multi_ntfy_cb)
        return TRUE;
    }
  }
  return FALSE;
}

bool Curl_api_multi_is_in_callback(struct Curl_multi *multi)
{
  if(multi && multi->callstack.count) {
    size_t i;
    for(i = 0; i < multi->callstack.count; ++i) {
      if(multi->callstack.calls[i] >= CURL_CBAPI_FN_START)
        return TRUE;
    }
  }
  return FALSE;
}

bool Curl_api_is_in_callback(struct Curl_easy *data)
{
  if(data && data->multi) {
    return Curl_api_multi_is_in_callback(data->multi);
  }
  return FALSE;
}

bool Curl_eapi_enter(struct Curl_eapi_guard *guard,
                     CURL *curl,
                     Curl_eapi_fn fn,
                     CURLcode *presult)
{
  struct Curl_easy *data = curl;
  const struct Curl_eapi_fn_props *fn_props;
  CURLcode result = CURLE_OK;

  guard->depth = 0;

  /* Verify that we got an easy handle we can work with. */
  if(!GOOD_EASY_HANDLE(data)) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  /* verify that is either not added to a multi handle OR has a
   * GOOD multi handle that knows `data` for `data->mid`. */
  if(data->mid != UINT32_MAX) {
    if(GOOD_MULTI_HANDLE(data->multi)) {
      if(!Curl_multi_knows_easy(data->multi, data)) {
        /* But multi does not know it, something is fishy, better deny call */
        DEBUGASSERT(0);
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
    }
    else {
      DEBUGASSERT(0); /* data needs to have a GOOD multi handle */
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }
  }
  else if(data->multi) {
    DEBUGASSERT(0); /* data should not have a multi handle */
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  /* verify that the call `fn` we're about to enter is known
   * and check call properties to be admitting. */
  if(fn >= CURL_EAPI_FN_LAST) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  fn_props = &eapi_fn_props[fn];
  DEBUGASSERT(fn_props->fn == fn);
  if(!fn_props->recurse) {
    if(data->callstack.count) {
#ifdef CURLVERBOSE
      DEBUGF(curl_mfprintf(stderr,
        "EAPI guard: calling %u with call to %u ongoing\n", (uint16_t)fn,
        data->callstack.calls[data->callstack.count-1]));
#endif
      result = CURLE_RECURSIVE_API_CALL;
      goto out;
    }
    if(data->multi && data->multi->callstack.count) {
#ifdef CURLVERBOSE

      DEBUGF(curl_mfprintf(stderr,
        "EAPI guard: calling %u with multi call to %u ongoing\n", (uint16_t)fn,
        data->multi->callstack.calls[data->multi->callstack.count-1]));
#endif
      result = CURLE_RECURSIVE_API_CALL;
      goto out;
    }
  }

  if(fn_props->no_event_cb && eapi_in_event_cb(data)) {
    /* Not allowed to be invoked while an event cb is ongoing */
#ifdef CURLVERBOSE
      DEBUGF(curl_mfprintf(stderr,
        "EAPI guard: calling %u while event callback ongoing\n",
        (uint16_t)fn));
#endif
    result = CURLE_RECURSIVE_API_CALL;
    goto out;
  }

#if defined(USE_SSL) && defined(USE_MUTEX)
  if(fn_props->no_scache_lock &&
     Curl_ssl_scache_is_locked_by_current_thread(data)) {
#ifdef CURLVERBOSE
      DEBUGF(curl_mfprintf(stderr,
        "EAPI guard: calling %u while vtls_scache is locked by "
        "current thread\n", (uint16_t)fn));
#endif
    result = CURLE_RECURSIVE_API_CALL;
    goto out;
  }
#endif

  /* all fine, add to data's callstack */
  if(data->callstack.count >= CURL_EAPI_MAX_RECURSION) {
    result = CURLE_RECURSIVE_API_CALL;
    goto out;
  }
  data->callstack.calls[data->callstack.count] = (uint16_t)fn;
  ++data->callstack.count;
  guard->depth = data->callstack.count;
  guard->data = fn_props->data_is_killed ? NULL : data;

out:
  if(presult)
    *presult = result;
  return guard->depth > 0;
}

void Curl_eapi_leave(struct Curl_eapi_guard *guard)
{
  if(guard->depth) {
    /* guard->data is set when handle is supposed to stay alive during call */
    if(guard->data && GOOD_EASY_HANDLE(guard->data)) {
      if(guard->depth > guard->data->callstack.count) {
        DEBUGASSERT(0); /* something very wrong */
      }
      else {
        if(guard->depth < guard->data->callstack.count) {
          DEBUGASSERT(0); /* someone forgot to clean up */
        }
        /* reset to depth the guard was entered in */
        guard->data->callstack.count = (uint16_t)(guard->depth - 1);
      }
    }
  }
}

bool Curl_mapi_enter(struct Curl_mapi_guard *guard,
                     CURLM *m,
                     Curl_mapi_fn fn,
                     CURLMcode *pmresult)
{
  struct Curl_multi *multi = m;
  const struct Curl_mapi_fn_props *fn_props;
  CURLMcode mresult = CURLM_OK;

  guard->depth = 0;

  /* Verify that we got an easy handle we can work with. */
  if(!GOOD_MULTI_HANDLE(multi)) {
    mresult = CURLM_BAD_HANDLE;
    goto out;
  }
  if(fn >= CURL_MAPI_FN_LAST) {
    mresult = CURLM_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  fn_props = &mapi_fn_props[fn];
  DEBUGASSERT(fn_props->fn == fn);
  if(fn_props->allow_ntfy_cb && mapi_in_ntfy_cb(multi)) {
    /* explicitly allowed, even though normal recursion may not */
  }
  else if(!fn_props->recurse && multi->callstack.count) {
#ifdef CURLVERBOSE
      DEBUGF(curl_mfprintf(stderr,
        "MAPI guard: calling %u with call to %u ongoing\n", (uint16_t)fn,
        multi->callstack.calls[multi->callstack.count-1]));
#endif
    mresult = CURLM_RECURSIVE_API_CALL;
    goto out;
  }

#if defined(USE_SSL) && defined(USE_MUTEX)
  if(fn_props->no_scache_lock && multi->ssl_scache &&
     Curl_ssl_scache_is_locked_by_current_thread(multi->admin)) {
#ifdef CURLVERBOSE
      DEBUGF(curl_mfprintf(stderr,
        "MAPI guard: calling %u while its vtls_scache is locked by "
        "current thread\n", (uint16_t)fn));
#endif
    mresult = CURLM_RECURSIVE_API_CALL;
    goto out;
  }
#endif

  /* all fine, add to data's callstack */
  if(multi->callstack.count >= CURL_MAPI_MAX_RECURSION) {
    mresult = CURLM_RECURSIVE_API_CALL;
    goto out;
  }
  multi->callstack.calls[multi->callstack.count] = (uint16_t)fn;
  ++multi->callstack.count;
  guard->depth = multi->callstack.count;
  guard->multi = fn_props->multi_is_killed ? NULL : multi;

out:
  if(pmresult)
    *pmresult = mresult;
  return guard->depth > 0;
}

void Curl_mapi_leave(struct Curl_mapi_guard *guard)
{
  if(guard->depth) {
    /* guard->data is set when handle is supposed to stay alive during call */
    if(guard->multi && GOOD_MULTI_HANDLE(guard->multi)) {
      if(guard->depth > guard->multi->callstack.count) {
        DEBUGASSERT(0); /* something very wrong */
      }
      else {
        if(guard->depth < guard->multi->callstack.count) {
          DEBUGASSERT(0); /* someone forgot to clean up */
        }
        /* reset to depth the guard was entered in */
        guard->multi->callstack.count = (uint16_t)(guard->depth - 1);
      }
    }
  }
}

void Curl_cbapi_enter(struct Curl_mapi_guard *guard,
                      struct Curl_easy *data,
                      struct Curl_multi *multi,
                      Curl_cbapi_fn fn)
{
  guard->depth = 0;

  if(!multi)
    multi = data ? data->multi : NULL;
  /* if not multi is involved here, just leave */
  if(!multi)
    return;
  /* invalid callback specifier? */
  if((fn >= CURL_CBAPI_FN_LAST) || (fn < CURL_CBAPI_FN_START)) {
    DEBUGASSERT(0);
    return;
  }
  DEBUGASSERT(cbapi_fn_props[fn - CURL_CBAPI_FN_START].fn == fn);
  if(multi->callstack.count) {
    size_t i;
    for(i = multi->callstack.count; i; --i) {
      if(multi->callstack.calls[i - 1] == fn) {
        /* recursive invocation of the same callback */
        DEBUGASSERT(0);
        return;
      }
    }
  }

  /* all fine, add to data's callstack */
  /* if multi callstack already at max depth, leave */
  if(multi->callstack.count >= CURL_MAPI_MAX_RECURSION)
    return;
  multi->callstack.calls[multi->callstack.count] = (uint16_t)fn;
  ++multi->callstack.count;
  guard->depth = multi->callstack.count;
  guard->multi = multi;
}

void Curl_cbapi_leave(struct Curl_mapi_guard *guard)
{
  Curl_mapi_leave(guard);
}
