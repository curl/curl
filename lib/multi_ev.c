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

#include <curl/curl.h>

#include "urldata.h"
#include "url.h"
#include "cfilters.h"
#include "curl_trc.h"
#include "multiif.h"
#include "curlx/timeval.h"
#include "multi_ev.h"
#include "select.h"
#include "uint-bset.h"
#include "uint-spbset.h"
#include "uint-table.h"
#include "curlx/warnless.h"
#include "multihandle.h"
#include "socks.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


static void mev_in_callback(struct Curl_multi *multi, bool value)
{
  multi->in_callback = value;
}

/* Information about a socket for which we inform the libcurl application
 * what to supervise (CURL_POLL_IN/CURL_POLL_OUT/CURL_POLL_REMOVE)
 */
struct mev_sh_entry {
  struct uint_spbset xfers; /* bitset of transfers `mid`s on this socket */
  struct connectdata *conn; /* connection using this socket or NULL */
  void *user_data;      /* libcurl app data via curl_multi_assign() */
  unsigned int action;  /* CURL_POLL_IN/CURL_POLL_OUT we last told the
                         * libcurl application to watch out for */
  unsigned int readers; /* this many transfers want to read */
  unsigned int writers; /* this many transfers want to write */
  BIT(announced);       /* this socket has been passed to the socket
                           callback at least once */
};

static size_t mev_sh_entry_hash(void *key, size_t key_length, size_t slots_num)
{
  curl_socket_t fd = *((curl_socket_t *) key);
  (void)key_length;
  return (fd % (curl_socket_t)slots_num);
}

static size_t mev_sh_entry_compare(void *k1, size_t k1_len,
                                   void *k2, size_t k2_len)
{
  (void)k1_len; (void)k2_len;
  return (*((curl_socket_t *) k1)) == (*((curl_socket_t *) k2));
}

/* sockhash entry destructor callback */
static void mev_sh_entry_dtor(void *freethis)
{
  struct mev_sh_entry *entry = (struct mev_sh_entry *)freethis;
  Curl_uint_spbset_destroy(&entry->xfers);
  free(entry);
}

/* look up a given socket in the socket hash, skip invalid sockets */
static struct mev_sh_entry *
mev_sh_entry_get(struct Curl_hash *sh, curl_socket_t s)
{
  if(s != CURL_SOCKET_BAD) {
    /* only look for proper sockets */
    return Curl_hash_pick(sh, (char *)&s, sizeof(curl_socket_t));
  }
  return NULL;
}

/* make sure this socket is present in the hash for this handle */
static struct mev_sh_entry *
mev_sh_entry_add(struct Curl_hash *sh, curl_socket_t s)
{
  struct mev_sh_entry *there = mev_sh_entry_get(sh, s);
  struct mev_sh_entry *check;

  if(there) {
    /* it is present, return fine */
    return there;
  }

  /* not present, add it */
  check = calloc(1, sizeof(struct mev_sh_entry));
  if(!check)
    return NULL; /* major failure */

  Curl_uint_spbset_init(&check->xfers);

  /* make/add new hash entry */
  if(!Curl_hash_add(sh, (char *)&s, sizeof(curl_socket_t), check)) {
    mev_sh_entry_dtor(check);
    return NULL; /* major failure */
  }

  return check; /* things are good in sockhash land */
}

/* delete the given socket entry from the hash */
static void mev_sh_entry_kill(struct Curl_multi *multi, curl_socket_t s)
{
  Curl_hash_delete(&multi->ev.sh_entries, (char *)&s, sizeof(curl_socket_t));
}

static size_t mev_sh_entry_user_count(struct mev_sh_entry *e)
{
  return Curl_uint_spbset_count(&e->xfers) + (e->conn ? 1 : 0);
}

static bool mev_sh_entry_xfer_known(struct mev_sh_entry *e,
                                    struct Curl_easy *data)
{
  return Curl_uint_spbset_contains(&e->xfers, data->mid);
}

static bool mev_sh_entry_conn_known(struct mev_sh_entry *e,
                                    struct connectdata *conn)
{
  return (e->conn == conn);
}

static bool mev_sh_entry_xfer_add(struct mev_sh_entry *e,
                                  struct Curl_easy *data)
{
   /* detect weird values */
  DEBUGASSERT(mev_sh_entry_user_count(e) < 100000);
  return Curl_uint_spbset_add(&e->xfers, data->mid);
}

static bool mev_sh_entry_conn_add(struct mev_sh_entry *e,
                                  struct connectdata *conn)
{
   /* detect weird values */
  DEBUGASSERT(mev_sh_entry_user_count(e) < 100000);
  DEBUGASSERT(!e->conn);
  if(e->conn)
    return FALSE;
  e->conn = conn;
  return TRUE;
}


static bool mev_sh_entry_xfer_remove(struct mev_sh_entry *e,
                                     struct Curl_easy *data)
{
  bool present = Curl_uint_spbset_contains(&e->xfers, data->mid);
  if(present)
    Curl_uint_spbset_remove(&e->xfers, data->mid);
  return present;
}

static bool mev_sh_entry_conn_remove(struct mev_sh_entry *e,
                                     struct connectdata *conn)
{
  DEBUGASSERT(e->conn == conn);
  if(e->conn == conn) {
    e->conn = NULL;
    return TRUE;
  }
  return FALSE;
}

/* Purge any information about socket `s`.
 * Let the socket callback know as well when necessary */
static CURLMcode mev_forget_socket(struct Curl_multi *multi,
                                   struct Curl_easy *data,
                                   curl_socket_t s,
                                   const char *cause)
{
  struct mev_sh_entry *entry = mev_sh_entry_get(&multi->ev.sh_entries, s);
  int rc = 0;

  if(!entry) /* we never knew or already forgot about this socket */
    return CURLM_OK;

  /* We managed this socket before, tell the socket callback to forget it. */
  if(entry->announced && multi->socket_cb) {
    CURL_TRC_M(data, "ev %s, call(fd=%" FMT_SOCKET_T ", ev=REMOVE)",
               cause, s);
    mev_in_callback(multi, TRUE);
    rc = multi->socket_cb(data, s, CURL_POLL_REMOVE,
                          multi->socket_userp, entry->user_data);
    mev_in_callback(multi, FALSE);
    entry->announced = FALSE;
  }

  mev_sh_entry_kill(multi, s);
  if(rc == -1) {
    multi->dead = TRUE;
    return CURLM_ABORTED_BY_CALLBACK;
  }
  return CURLM_OK;
}

static CURLMcode mev_sh_entry_update(struct Curl_multi *multi,
                                     struct Curl_easy *data,
                                     struct mev_sh_entry *entry,
                                     curl_socket_t s,
                                     unsigned char last_action,
                                     unsigned char cur_action)
{
  int rc, comboaction;

  /* we should only be called when the callback exists */
  DEBUGASSERT(multi->socket_cb);
  if(!multi->socket_cb)
    return CURLM_OK;

  /* Transfer `data` goes from `last_action` to `cur_action` on socket `s`
   * with `multi->ev.sh_entries` entry `entry`. Update `entry` and trigger
   * `multi->socket_cb` on change, if the callback is set. */
  if(last_action == cur_action)  /* nothing from `data` changed */
    return CURLM_OK;

  if(last_action & CURL_POLL_IN) {
    DEBUGASSERT(entry->readers);
    if(!(cur_action & CURL_POLL_IN))
      entry->readers--;
  }
  else if(cur_action & CURL_POLL_IN)
    entry->readers++;

  if(last_action & CURL_POLL_OUT) {
    DEBUGASSERT(entry->writers);
    if(!(cur_action & CURL_POLL_OUT))
      entry->writers--;
  }
  else if(cur_action & CURL_POLL_OUT)
    entry->writers++;

  DEBUGASSERT(entry->readers <= mev_sh_entry_user_count(entry));
  DEBUGASSERT(entry->writers <= mev_sh_entry_user_count(entry));
  DEBUGASSERT(entry->writers + entry->readers);

  CURL_TRC_M(data, "ev update fd=%" FMT_SOCKET_T ", action '%s%s' -> '%s%s'"
             " (%d/%d r/w)", s,
             (last_action & CURL_POLL_IN) ? "IN" : "",
             (last_action & CURL_POLL_OUT) ? "OUT" : "",
             (cur_action & CURL_POLL_IN) ? "IN" : "",
             (cur_action & CURL_POLL_OUT) ? "OUT" : "",
             entry->readers, entry->writers);

  comboaction = (entry->writers ? CURL_POLL_OUT : 0) |
                (entry->readers ? CURL_POLL_IN : 0);
  if(((int)entry->action == comboaction)) /* nothing for socket changed */
    return CURLM_OK;

  CURL_TRC_M(data, "ev update call(fd=%" FMT_SOCKET_T ", ev=%s%s)",
             s, (comboaction & CURL_POLL_IN) ? "IN" : "",
             (comboaction & CURL_POLL_OUT) ? "OUT" : "");
  mev_in_callback(multi, TRUE);
  rc = multi->socket_cb(data, s, comboaction, multi->socket_userp,
                        entry->user_data);
  mev_in_callback(multi, FALSE);
  entry->announced = TRUE;
  if(rc == -1) {
    multi->dead = TRUE;
    return CURLM_ABORTED_BY_CALLBACK;
  }
  entry->action = (unsigned int)comboaction;
  return CURLM_OK;
}

static CURLMcode mev_pollset_diff(struct Curl_multi *multi,
                                  struct Curl_easy *data,
                                  struct connectdata *conn,
                                  struct easy_pollset *ps,
                                  struct easy_pollset *prev_ps)
{
  struct mev_sh_entry *entry;
  curl_socket_t s;
  unsigned int i, j;
  CURLMcode mresult;

  /* The transfer `data` reports in `ps` the sockets it is interested
   * in and which combination of CURL_POLL_IN/CURL_POLL_OUT it wants
   * to have monitored for events.
   * There can be more than 1 transfer interested in the same socket
   * and 1 transfer might be interested in more than 1 socket.
   * `prev_ps` is the pollset copy from the previous call here. On
   * the 1st call it will be empty.
   */
  DEBUGASSERT(ps);
  DEBUGASSERT(prev_ps);

  /* Handle changes to sockets the transfer is interested in. */
  for(i = 0; i < ps->n; i++) {
    unsigned char last_action;
    bool first_time = FALSE; /* data/conn appears first time on socket */

    s = ps->sockets[i];
    /* Have we handled this socket before? */
    entry = mev_sh_entry_get(&multi->ev.sh_entries, s);
    if(!entry) {
      /* new socket, add new entry */
      first_time = TRUE;
      entry = mev_sh_entry_add(&multi->ev.sh_entries, s);
      if(!entry) /* fatal */
        return CURLM_OUT_OF_MEMORY;
      CURL_TRC_M(data, "ev new entry fd=%" FMT_SOCKET_T, s);
    }
    else if(conn) {
      first_time = !mev_sh_entry_conn_known(entry, conn);
    }
    else {
      first_time = !mev_sh_entry_xfer_known(entry, data);
    }

    /* What was the previous action the transfer had regarding this socket?
     * If the transfer is new to the socket, disregard the information
     * in `last_poll`, because the socket might have been destroyed and
     * reopened. We'd have cleared the sh_entry for that, but the socket
     * might still be mentioned in the hashed pollsets. */
    last_action = 0;
    if(first_time) {
      if(conn) {
        if(!mev_sh_entry_conn_add(entry, conn))
          return CURLM_OUT_OF_MEMORY;
      }
      else {
        if(!mev_sh_entry_xfer_add(entry, data))
          return CURLM_OUT_OF_MEMORY;
      }
      CURL_TRC_M(data, "ev entry fd=%" FMT_SOCKET_T ", added %s #%" FMT_OFF_T
                 ", total=%u/%d (xfer/conn)", s,
                 conn ? "connection" : "transfer",
                 conn ? conn->connection_id : data->mid,
                 Curl_uint_spbset_count(&entry->xfers),
                 entry->conn ? 1 : 0);
    }
    else {
      for(j = 0; j < prev_ps->n; j++) {
        if(s == prev_ps->sockets[j]) {
          last_action = prev_ps->actions[j];
          break;
        }
      }
    }
    /* track readers/writers changes and report to socket callback */
    mresult = mev_sh_entry_update(multi, data, entry, s,
                                  last_action, ps->actions[i]);
    if(mresult)
      return mresult;
  }

  /* Handle changes to sockets the transfer is NO LONGER interested in. */
  for(i = 0; i < prev_ps->n; i++) {
    bool stillused = FALSE;

    s = prev_ps->sockets[i];
    for(j = 0; j < ps->n; j++) {
      if(s == ps->sockets[j]) {
        /* socket is still supervised */
        stillused = TRUE;
        break;
      }
    }
    if(stillused)
      continue;

    entry = mev_sh_entry_get(&multi->ev.sh_entries, s);
    /* if entry does not exist, we were either never told about it or
     * have already cleaned up this socket via Curl_multi_ev_socket_done().
     * In other words: this is perfectly normal */
    if(!entry)
      continue;

    if(conn && !mev_sh_entry_conn_remove(entry, conn)) {
      /* `conn` says in `prev_ps` that it had been using a socket,
       * but `conn` has not been registered for it.
       * This should not happen if our book-keeping is correct? */
      CURL_TRC_M(data, "ev entry fd=%" FMT_SOCKET_T ", conn lost "
                 "interest but is not registered", s);
      DEBUGASSERT(NULL);
      continue;
    }

    if(!conn && !mev_sh_entry_xfer_remove(entry, data)) {
      /* `data` says in `prev_ps` that it had been using a socket,
       * but `data` has not been registered for it.
       * This should not happen if our book-keeping is correct? */
      CURL_TRC_M(data, "ev entry fd=%" FMT_SOCKET_T ", transfer lost "
                 "interest but is not registered", s);
      DEBUGASSERT(NULL);
      continue;
    }

    if(mev_sh_entry_user_count(entry)) {
      /* track readers/writers changes and report to socket callback */
      mresult = mev_sh_entry_update(multi, data, entry, s,
                                    prev_ps->actions[i], 0);
      if(mresult)
        return mresult;
      CURL_TRC_M(data, "ev entry fd=%" FMT_SOCKET_T ", removed transfer, "
                 "total=%u/%d (xfer/conn)", s,
                 Curl_uint_spbset_count(&entry->xfers),
                 entry->conn ? 1 : 0);
    }
    else {
      mresult = mev_forget_socket(multi, data, s, "last user gone");
      if(mresult)
        return mresult;
    }
  } /* for loop over num */

  /* Remember for next time */
  Curl_pollset_move(prev_ps, ps);
  return CURLM_OK;
}

static void mev_pollset_dtor(void *key, size_t klen, void *entry)
{
  struct easy_pollset *ps = entry;
  (void)key;
  (void)klen;
  if(ps) {
    Curl_pollset_cleanup(ps);
    free(ps);
  }
}

static struct easy_pollset*
mev_add_new_conn_pollset(struct connectdata *conn)
{
  struct easy_pollset *ps;

  ps = Curl_pollset_create();
  if(!ps)
    return NULL;
  if(Curl_conn_meta_set(conn, CURL_META_MEV_POLLSET, ps, mev_pollset_dtor))
    return NULL;
  return ps;
}

static struct easy_pollset*
mev_add_new_xfer_pollset(struct Curl_easy *data)
{
  struct easy_pollset *ps;

  ps = Curl_pollset_create();
  if(!ps)
    return NULL;
  if(Curl_meta_set(data, CURL_META_MEV_POLLSET, ps, mev_pollset_dtor))
    return NULL;
  return ps;
}

static struct easy_pollset *
mev_get_last_pollset(struct Curl_easy *data,
                     struct connectdata *conn)
{
  if(data) {
    if(conn)
      return Curl_conn_meta_get(conn, CURL_META_MEV_POLLSET);
    return Curl_meta_get(data, CURL_META_MEV_POLLSET);
  }
  return NULL;
}

static CURLMcode mev_assess(struct Curl_multi *multi,
                            struct Curl_easy *data,
                            struct connectdata *conn)
{
  struct easy_pollset ps, *last_ps;
  CURLMcode res = CURLM_OK;

  if(!multi || !multi->socket_cb)
    return CURLM_OK;

  Curl_pollset_init(&ps);
  if(conn) {
    CURLcode r = Curl_conn_adjust_pollset(data, conn, &ps);
    if(r) {
      res = (r == CURLE_OUT_OF_MEMORY) ?
            CURLM_OUT_OF_MEMORY : CURLM_INTERNAL_ERROR;
      goto out;
    }
  }
  else if(data)
    Curl_multi_pollset(data, &ps, "ev assess");
  last_ps = mev_get_last_pollset(data, conn);

  if(!last_ps && ps.n) {
    if(conn)
      last_ps = mev_add_new_conn_pollset(conn);
    else
      last_ps = mev_add_new_xfer_pollset(data);
    if(!last_ps) {
      res = CURLM_OUT_OF_MEMORY;
      goto out;
    }
  }

  if(last_ps)
    res = mev_pollset_diff(multi, data, conn, &ps, last_ps);
  else
    DEBUGASSERT(!ps.n);
out:
  Curl_pollset_cleanup(&ps);
  return res;
}

CURLMcode Curl_multi_ev_assess_xfer(struct Curl_multi *multi,
                                    struct Curl_easy *data)
{
  return mev_assess(multi, data, NULL);
}

CURLMcode Curl_multi_ev_assess_conn(struct Curl_multi *multi,
                                    struct Curl_easy *data,
                                    struct connectdata *conn)
{
  return mev_assess(multi, data, conn);
}

CURLMcode Curl_multi_ev_assess_xfer_bset(struct Curl_multi *multi,
                                         struct uint_bset *set)
{
  unsigned int mid;
  CURLMcode result = CURLM_OK;

  if(multi && multi->socket_cb && Curl_uint_bset_first(set, &mid)) {
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(data)
        result = Curl_multi_ev_assess_xfer(multi, data);
    }
    while(!result && Curl_uint_bset_next(set, mid, &mid));
  }
  return result;
}


CURLMcode Curl_multi_ev_assign(struct Curl_multi *multi,
                               curl_socket_t s,
                               void *user_data)
{
  struct mev_sh_entry *e = mev_sh_entry_get(&multi->ev.sh_entries, s);
  if(!e)
    return CURLM_BAD_SOCKET;
  e->user_data = user_data;
  return CURLM_OK;
}

void Curl_multi_ev_dirty_xfers(struct Curl_multi *multi,
                               curl_socket_t s,
                               bool *run_cpool)
{
  struct mev_sh_entry *entry;

  DEBUGASSERT(s != CURL_SOCKET_TIMEOUT);
  entry = mev_sh_entry_get(&multi->ev.sh_entries, s);

  /* Unmatched socket, we cannot act on it but we ignore this fact. In
     real-world tests it has been proved that libevent can in fact give
     the application actions even though the socket was just previously
     asked to get removed, so thus we better survive stray socket actions
     and just move on. */
  if(entry) {
    struct Curl_easy *data;
    unsigned int mid;

    if(Curl_uint_spbset_first(&entry->xfers, &mid)) {
      do {
        data = Curl_multi_get_easy(multi, mid);
        if(data) {
          Curl_multi_mark_dirty(data);
        }
        else {
          CURL_TRC_M(multi->admin, "socket transfer %u no longer found", mid);
          Curl_uint_spbset_remove(&entry->xfers, mid);
        }
      }
      while(Curl_uint_spbset_next(&entry->xfers, mid, &mid));
    }

    if(entry->conn)
      *run_cpool = TRUE;
  }
}

void Curl_multi_ev_socket_done(struct Curl_multi *multi,
                               struct Curl_easy *data, curl_socket_t s)
{
  mev_forget_socket(multi, data, s, "socket done");
}

void Curl_multi_ev_xfer_done(struct Curl_multi *multi,
                             struct Curl_easy *data)
{
  DEBUGASSERT(!data->conn); /* transfer should have been detached */
  if(data != multi->admin) {
    (void)mev_assess(multi, data, NULL);
    Curl_meta_remove(data, CURL_META_MEV_POLLSET);
  }
}

void Curl_multi_ev_conn_done(struct Curl_multi *multi,
                             struct Curl_easy *data,
                             struct connectdata *conn)
{
  (void)mev_assess(multi, data, conn);
  Curl_conn_meta_remove(conn, CURL_META_MEV_POLLSET);
}

void Curl_multi_ev_init(struct Curl_multi *multi, size_t hashsize)
{
  Curl_hash_init(&multi->ev.sh_entries, hashsize, mev_sh_entry_hash,
                 mev_sh_entry_compare, mev_sh_entry_dtor);
}

void Curl_multi_ev_cleanup(struct Curl_multi *multi)
{
  Curl_hash_destroy(&multi->ev.sh_entries);
}
