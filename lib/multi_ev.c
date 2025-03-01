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
#include "cfilters.h"
#include "curl_trc.h"
#include "multiif.h"
#include "timeval.h"
#include "multi_ev.h"
#include "select.h"
#include "warnless.h"
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

#define CURL_MEV_XFER_HASH_SIZE 13
#define CURL_MEV_CONN_HASH_SIZE 3

/* Information about a socket for which we inform the libcurl application
 * what to supervise (CURL_POLL_IN/CURL_POLL_OUT/CURL_POLL_REMOVE)
 */
struct mev_sh_entry {
  struct Curl_hash_offt xfers; /* hash of transfers using this socket */
  struct Curl_hash_offt conns; /* hash of connections using this socket */
  void *user_data;      /* libcurl app data via curl_multi_assign() */
  unsigned int action;  /* CURL_POLL_IN/CURL_POLL_OUT we last told the
                         * libcurl application to watch out for */
  unsigned int readers; /* this many transfers want to read */
  unsigned int writers; /* this many transfers want to write */
};

static size_t mev_sh_entry_hash(void *key, size_t key_length, size_t slots_num)
{
  curl_socket_t fd = *((curl_socket_t *) key);
  (void) key_length;
  return (fd % (curl_socket_t)slots_num);
}

static size_t mev_sh_entry_compare(void *k1, size_t k1_len,
                                   void *k2, size_t k2_len)
{
  (void) k1_len; (void) k2_len;
  return (*((curl_socket_t *) k1)) == (*((curl_socket_t *) k2));
}

/* sockhash entry destructor callback */
static void mev_sh_entry_dtor(void *freethis)
{
  struct mev_sh_entry *entry = (struct mev_sh_entry *)freethis;
  Curl_hash_offt_destroy(&entry->xfers);
  Curl_hash_offt_destroy(&entry->conns);
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

  Curl_hash_offt_init(&check->xfers, CURL_MEV_XFER_HASH_SIZE, NULL);
  Curl_hash_offt_init(&check->conns, CURL_MEV_CONN_HASH_SIZE, NULL);

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
  return Curl_hash_offt_count(&e->xfers) + Curl_hash_offt_count(&e->conns);
}

static bool mev_sh_entry_xfer_known(struct mev_sh_entry *e,
                                    struct Curl_easy *data)
{
  return !!Curl_hash_offt_get(&e->xfers, data->id);
}

static bool mev_sh_entry_conn_known(struct mev_sh_entry *e,
                                    struct connectdata *conn)
{
  return !!Curl_hash_offt_get(&e->conns, conn->connection_id);
}

static bool mev_sh_entry_xfer_add(struct mev_sh_entry *e,
                                  struct Curl_easy *data)
{
   /* detect weird values */
  DEBUGASSERT(mev_sh_entry_user_count(e) < 100000);
  return !!Curl_hash_offt_set(&e->xfers, data->id, data);
}

static bool mev_sh_entry_conn_add(struct mev_sh_entry *e,
                                  struct connectdata *conn)
{
   /* detect weird values */
  DEBUGASSERT(mev_sh_entry_user_count(e) < 100000);
  return !!Curl_hash_offt_set(&e->conns, conn->connection_id, conn);
}


static bool mev_sh_entry_xfer_remove(struct mev_sh_entry *e,
                                     struct Curl_easy *data)
{
  return Curl_hash_offt_remove(&e->xfers, data->id);
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
  if(multi->socket_cb) {
    CURL_TRC_M(data, "ev %s, call(fd=%" FMT_SOCKET_T ", ev=REMOVE)",
               cause, s);
    mev_in_callback(multi, TRUE);
    rc = multi->socket_cb(data, s, CURL_POLL_REMOVE,
                          multi->socket_userp, entry->user_data);
    mev_in_callback(multi, FALSE);
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
   * in and which combinatino of CURL_POLL_IN/CURL_POLL_OUT it wants
   * to have monitored for events.
   * There can be more than 1 transfer interested in the same socket
   * and 1 transfer might be interested in more than 1 socket.
   * `prev_ps` is the pollset copy from the previous call here. On
   * the 1st call it will be empty.
   */
  DEBUGASSERT(ps);
  DEBUGASSERT(prev_ps);

  /* Handle changes to sockets the transfer is interested in. */
  for(i = 0; i < ps->num; i++) {
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
      first_time = !mev_sh_entry_conn_known(entry, data->conn);
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
        if(!mev_sh_entry_conn_add(entry, data->conn))
          return CURLM_OUT_OF_MEMORY;
      }
      else {
        if(!mev_sh_entry_xfer_add(entry, data))
          return CURLM_OUT_OF_MEMORY;
      }
      CURL_TRC_M(data, "ev entry fd=%" FMT_SOCKET_T ", added %s #%" FMT_OFF_T
                 ", total=%zu/%zu (xfer/conn)", s,
                 conn ? "connection" : "transfer",
                 conn ? conn->connection_id : data->id,
                 Curl_hash_offt_count(&entry->xfers),
                 Curl_hash_offt_count(&entry->conns));
    }
    else {
      for(j = 0; j < prev_ps->num; j++) {
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
  for(i = 0; i < prev_ps->num; i++) {
    bool stillused = FALSE;

    s = prev_ps->sockets[i];
    for(j = 0; j < ps->num; j++) {
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

    if(!mev_sh_entry_xfer_remove(entry, data)) {
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
                 "total=%zu/%zu (xfer/conn)", s,
                 Curl_hash_offt_count(&entry->xfers),
                 Curl_hash_offt_count(&entry->conns));
    }
    else {
      mresult = mev_forget_socket(multi, data, s, "last user gone");
      if(mresult)
        return mresult;
    }
  } /* for loop over num */

  /* Remember for next time */
  memcpy(prev_ps, ps, sizeof(*prev_ps));
  return CURLM_OK;
}

static struct easy_pollset*
mev_add_new_pollset(struct Curl_hash_offt *h, curl_off_t id)
{
  struct easy_pollset *ps;

  ps = calloc(1, sizeof(*ps));
  if(!ps)
    return NULL;
  if(!Curl_hash_offt_set(h, id, ps)) {
    free(ps);
    return NULL;
  }
  return ps;
}

static struct easy_pollset *
mev_get_last_pollset(struct Curl_multi *multi,
                     struct Curl_easy *data,
                     struct connectdata *conn)
{
  if(data) {
    if(conn)
      return Curl_hash_offt_get(&multi->ev.conn_pollsets,
                                conn->connection_id);
    else if(data)
      return Curl_hash_offt_get(&multi->ev.xfer_pollsets, data->id);
  }
  return NULL;
}

static void mev_init_cur_pollset(struct easy_pollset *ps,
                                 struct Curl_easy *data,
                                 struct connectdata *conn)
{
  memset(ps, 0, sizeof(*ps));
  if(conn)
    Curl_conn_adjust_pollset(data, conn, ps);
  else if(data)
    Curl_multi_getsock(data, ps, "ev assess");
}

static CURLMcode mev_assess(struct Curl_multi *multi,
                            struct Curl_easy *data,
                            struct connectdata *conn)
{
  if(multi && multi->socket_cb) {
    struct easy_pollset ps, *last_ps;

    mev_init_cur_pollset(&ps, data, conn);
    last_ps = mev_get_last_pollset(multi, data, conn);

    if(!last_ps && ps.num) {
      if(conn)
        last_ps = mev_add_new_pollset(&multi->ev.conn_pollsets,
                                      data->conn->connection_id);
      else
        last_ps = mev_add_new_pollset(&multi->ev.xfer_pollsets, data->id);
      if(!last_ps)
        return CURLM_OUT_OF_MEMORY;
    }

    if(last_ps)
      return mev_pollset_diff(multi, data, conn, &ps, last_ps);
    else
      DEBUGASSERT(!ps.num);
  }
  return CURLM_OK;
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

CURLMcode Curl_multi_ev_assess_xfer_list(struct Curl_multi *multi,
                                         struct Curl_llist *list)
{
  struct Curl_llist_node *e;
  CURLMcode result = CURLM_OK;

  if(multi && multi->socket_cb) {
    for(e = Curl_llist_head(list); e && !result; e = Curl_node_next(e)) {
      result = Curl_multi_ev_assess_xfer(multi, Curl_node_elem(e));
    }
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

static bool mev_xfer_expire_cb(curl_off_t id, void *value, void *user_data)
{
  const struct curltime *nowp = user_data;
  struct Curl_easy *data = value;

  DEBUGASSERT(data);
  DEBUGASSERT(data->magic == CURLEASY_MAGIC_NUMBER);
  if(data && id >= 0) {
    /* Expire with out current now, so we will get it below when
     * asking the splaytree for expired transfers. */
    Curl_expire_ex(data, nowp, 0, EXPIRE_RUN_NOW);
  }
  return TRUE;
}

void Curl_multi_ev_expire_xfers(struct Curl_multi *multi,
                                curl_socket_t s,
                                const struct curltime *nowp,
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
    Curl_hash_offt_visit(&entry->xfers, mev_xfer_expire_cb, (void *)nowp);

    if(Curl_hash_offt_count(&entry->conns))
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
  if(data->id >= 0) {
    (void)mev_assess(multi, data, NULL);
    Curl_hash_offt_remove(&multi->ev.xfer_pollsets, data->id);
  }
}

void Curl_multi_ev_conn_done(struct Curl_multi *multi,
                             struct Curl_easy *data,
                             struct connectdata *conn)
{
  (void)mev_assess(multi, data, conn);
  Curl_hash_offt_remove(&multi->ev.conn_pollsets, conn->connection_id);
}

#define CURL_MEV_PS_HASH_SLOTS   (991)  /* nice prime */

static void mev_hash_pollset_free(curl_off_t id, void *entry)
{
  (void)id;
  free(entry);
}

void Curl_multi_ev_init(struct Curl_multi *multi, size_t hashsize)
{
  Curl_hash_init(&multi->ev.sh_entries, hashsize, mev_sh_entry_hash,
                 mev_sh_entry_compare, mev_sh_entry_dtor);
  Curl_hash_offt_init(&multi->ev.xfer_pollsets,
                      CURL_MEV_PS_HASH_SLOTS, mev_hash_pollset_free);
  Curl_hash_offt_init(&multi->ev.conn_pollsets,
                      CURL_MEV_PS_HASH_SLOTS, mev_hash_pollset_free);
}

void Curl_multi_ev_cleanup(struct Curl_multi *multi)
{
  Curl_hash_destroy(&multi->ev.sh_entries);
  Curl_hash_offt_destroy(&multi->ev.xfer_pollsets);
  Curl_hash_offt_destroy(&multi->ev.conn_pollsets);
}
