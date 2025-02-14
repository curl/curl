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

/*
 * We add one of these structs to the sockhash for each socket
 */

#define CURL_MEV_TRHASH_SIZE 13

/* the given key here is a struct Curl_easy pointer */
static size_t mev_tr_entry_hash(void *key, size_t key_length, size_t slots_num)
{
  unsigned char bytes = ((unsigned char *)key)[key_length - 1] ^
    ((unsigned char *)key)[0];
  return (bytes % slots_num);
}

static size_t mev_tr_entry_compare(void *k1, size_t k1_len,
                                   void *k2, size_t k2_len)
{
  (void)k2_len;
  return !memcmp(k1, k2, k1_len);
}

static void mev_tr_entry_dtor(void *nada)
{
  (void)nada;
}

/* Information about a socket for which we inform the libcurl application
 * what to supervise (CURL_POLL_IN/CURL_POLL_OUT/CURL_POLL_REMOVE)
 */
struct mev_sh_entry {
  struct Curl_hash transfers; /* hash of transfers using this socket */
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
  Curl_hash_destroy(&entry->transfers);
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

  Curl_hash_init(&check->transfers, CURL_MEV_TRHASH_SIZE, mev_tr_entry_hash,
                 mev_tr_entry_compare, mev_tr_entry_dtor);

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

static size_t mev_sh_entry_xfer_count(struct mev_sh_entry *e)
{
  return Curl_hash_count(&e->transfers);
}

static bool mev_sh_entry_xfer_known(struct mev_sh_entry *e,
                                    struct Curl_easy *data)
{
  return !!Curl_hash_pick(&e->transfers, (char *)&data,
                          sizeof(struct Curl_easy *));
}

static bool mev_sh_entry_xfer_add(struct mev_sh_entry *e,
                                  struct Curl_easy *data)
{
   /* detect weird values */
  DEBUGASSERT(mev_sh_entry_xfer_count(e) < 100000);
  return !!Curl_hash_add(&e->transfers, (char *)&data, /* hash key */
                         sizeof(struct Curl_easy *), data);
}

static bool mev_sh_entry_xfer_remove(struct mev_sh_entry *e,
                                     struct Curl_easy *data)
{
  return !Curl_hash_delete(&e->transfers, (char *)&data,
                           sizeof(struct Curl_easy *));
}

/* Purge any information about socket `s`.
 * Let the socket callback know as well when necessary */
static CURLMcode mev_forget_socket(struct Curl_multi *multi,
                                   struct Curl_easy *data,
                                   curl_socket_t s)
{
  struct mev_sh_entry *entry = mev_sh_entry_get(&multi->ev.sh_entries, s);
  int rc = 0;

  if(!entry) /* we never knew or already forgot about this socket */
    return CURLM_OK;

  /* We managed this socket before, tell the socket callback to forget it. */
  CURL_TRC_M(data, "ev, forget about fd=%" FMT_SOCKET_T, s);
  if(multi->socket_cb) {
    CURL_TRC_M(data, "ev, socket_callback(fd=%" FMT_SOCKET_T ", REMOVE)", s);
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

  DEBUGASSERT(entry->readers <= mev_sh_entry_xfer_count(entry));
  DEBUGASSERT(entry->writers <= mev_sh_entry_xfer_count(entry));
  DEBUGASSERT(entry->writers + entry->readers);

  CURL_TRC_M(data, "sockhash fd=%" FMT_SOCKET_T ", action=0x%x, "
             "previously=0x%d, transfers=%zu, readers=%d, writers=%d",
             s, cur_action, last_action,
             mev_sh_entry_xfer_count(entry),
             entry->readers, entry->writers);

  /* If no one is interested, do not compute and update the
   * entry->action. If a callback is installed later, we need to
   * report any action, not just the diff to an unreported one. */
  if(!multi->socket_cb)
    return CURLM_OK;

  comboaction = (entry->writers ? CURL_POLL_OUT : 0) |
                (entry->readers ? CURL_POLL_IN : 0);
  if(((int)entry->action == comboaction)) /* nothing for socket changed */
    return CURLM_OK;

  CURL_TRC_M(data, "socket_callback(fd=%" FMT_SOCKET_T ", %s%s%s)",
             s, (comboaction & CURL_POLL_IN) ? "POLLIN" : "",
             (comboaction == (CURL_POLL_IN|CURL_POLL_OUT)) ? "|" : "",
             (comboaction & CURL_POLL_OUT) ? "POLLOUT" : "");
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

CURLMcode Curl_multi_ev_pollset(struct Curl_multi *multi,
                                struct Curl_easy *data,
                                struct easy_pollset *ps)
{
  struct easy_pollset *last_ps;
  struct mev_sh_entry *entry;
  curl_socket_t s;
  unsigned int i, j;
  CURLMcode mresult;

  /* The transfer `data` reports in `ps` the sockets it is interested
   * in and which combinatino of CURL_POLL_IN/CURL_POLL_OUT it wants
   * to have monitored for events.
   * There can be more than 1 transfer interested in the same socket
   * and 1 transfer might be interested in more than 1 socket.
   * `last_ps` is the pollset copy from the previous call here. On
   * the 1st call it will be empty.
   */
  /* For user transfers (id >= 0), we keep the last pollset at the transfer,
   * for internal transfers, we keep it at the connection */
  last_ps = (data && (data->id >= 0)) ? &data->last_poll :
             (data->conn ? &data->conn->shutdown_poll : NULL);
  if(!last_ps)
    return CURLM_BAD_FUNCTION_ARGUMENT;

  /* Handle changes to sockets the transfer is interested in. */
  for(i = 0; i < ps->num; i++) {
    unsigned char last_action;
    bool first_time_data = FALSE; /* data appears first time on socket */

    s = ps->sockets[i];
    /* Have we handled this socket before? */
    entry = mev_sh_entry_get(&multi->ev.sh_entries, s);
    if(!entry) {
      /* new socket, add new entry */
      first_time_data = TRUE;
      entry = mev_sh_entry_add(&multi->ev.sh_entries, s);
      if(!entry) /* fatal */
        return CURLM_OUT_OF_MEMORY;
      CURL_TRC_M(data, "sockhash, add fd=%" FMT_SOCKET_T, s);
    }
    else {
      first_time_data = !mev_sh_entry_xfer_known(entry, data);
    }

    last_action = 0;
    if(first_time_data) {
      if(!mev_sh_entry_xfer_add(entry, data)) {
        return CURLM_OUT_OF_MEMORY;
      }
      CURL_TRC_M(data, "sockhash fd=%" FMT_SOCKET_T ", add transfer", s);
    }
    else {
      /* if `data` was registered, its previous POLL_IN/OUT is relevant */
      for(j = 0; j < last_ps->num; j++) {
        if(s == last_ps->sockets[j]) {
          last_action = last_ps->actions[j];
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
  for(i = 0; i < last_ps->num; i++) {
    bool stillused = FALSE;

    s = last_ps->sockets[i];
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
     * have already cleaned up this socket via Curl_multi_ev_will_close().
     * In other words: this is perfectly normal */
    if(!entry)
      continue;

    if(!mev_sh_entry_xfer_remove(entry, data)) {
      /* `data` says in `last_ps` that it had been using a socket,
       * but `data` has not been registered for it.
       * This should not happen if our book-keeping is correct? */
      CURL_TRC_M(data, "sockhash, transfer no longer uses fd=%" FMT_SOCKET_T
                 " but is not registered", s);
      DEBUGASSERT(NULL);
      continue;
    }

    if(mev_sh_entry_xfer_count(entry)) {
      /* track readers/writers changes and report to socket callback */
      mresult = mev_sh_entry_update(multi, data, entry, s,
                                    last_ps->actions[i], 0);
      if(mresult)
        return mresult;
    }
    else {
      mresult = mev_forget_socket(multi, data, s);
      if(mresult)
        return mresult;
    }
  } /* for loop over num */

  /* Remember for next time */
  memcpy(last_ps, ps, sizeof(*last_ps));
  return CURLM_OK;
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

void Curl_multi_ev_expire_transfers(struct Curl_multi *multi,
                                    curl_socket_t s,
                                    int ev_bitmask,
                                    const struct curltime *nowp,
                                    bool *run_cpool)
{
  struct mev_sh_entry *entry;

  if(s == CURL_SOCKET_TIMEOUT)
    return;

  entry = mev_sh_entry_get(&multi->ev.sh_entries, s);

  if(!entry) {
    /* Unmatched socket, we cannot act on it but we ignore this fact. In
       real-world tests it has been proved that libevent can in fact give
       the application actions even though the socket was just previously
       asked to get removed, so thus we better survive stray socket actions
       and just move on. */
    /* The socket might come from a connection that is being shut down
     * by the multi's connection pool. */
    Curl_cpool_multi_socket(multi, s, ev_bitmask);
  }
  else {
    struct Curl_hash_iterator iter;
    struct Curl_hash_element *he;

    /* the socket can be shared by many transfers, iterate */
    Curl_hash_start_iterate(&entry->transfers, &iter);
    for(he = Curl_hash_next_element(&iter); he;
        he = Curl_hash_next_element(&iter)) {
      struct Curl_easy *data = (struct Curl_easy *)he->ptr;
      DEBUGASSERT(data);
      DEBUGASSERT(data->magic == CURLEASY_MAGIC_NUMBER);

      if(data == multi->cpool.idata)
        *run_cpool = TRUE;
      else {
        /* Expire with out current now, so we will get it below when
         * asking the splaytree for expired transfers. */
        Curl_expire_ex(data, nowp, 0, EXPIRE_RUN_NOW);
      }
    }
  }
}

void Curl_multi_ev_will_close(struct Curl_multi *multi,
                              struct Curl_easy *data, curl_socket_t s)
{
  mev_forget_socket(multi, data, s);
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
