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


static void multi_ev_in_callback(struct Curl_multi *multi, bool value)
{
  multi->in_callback = value;
}

/*
 * We add one of these structs to the sockhash for each socket
 */

#define TRHASH_SIZE 13

/* the given key here is a struct Curl_easy pointer */
static size_t trhash(void *key, size_t key_length, size_t slots_num)
{
  unsigned char bytes = ((unsigned char *)key)[key_length - 1] ^
    ((unsigned char *)key)[0];
  return (bytes % slots_num);
}

static size_t trhash_compare(void *k1, size_t k1_len, void *k2, size_t k2_len)
{
  (void)k2_len;
  return !memcmp(k1, k2, k1_len);
}

static void trhash_dtor(void *nada)
{
  (void)nada;
}

/*
 * free a sockhash entry
 */
static void sh_freeentry(void *freethis)
{
  struct Curl_sh_entry *p = (struct Curl_sh_entry *) freethis;

  free(p);
}

struct Curl_sh_entry {
  struct Curl_hash transfers; /* hash of transfers using this socket */
  unsigned int action;  /* what combined action READ/WRITE this socket waits
                           for */
  void *socketp; /* settable by users with curl_multi_assign() */
  unsigned int readers; /* this many transfers want to read */
  unsigned int writers; /* this many transfers want to write */
};

static size_t fd_key_compare(void *k1, size_t k1_len, void *k2, size_t k2_len)
{
  (void) k1_len; (void) k2_len;

  return (*((curl_socket_t *) k1)) == (*((curl_socket_t *) k2));
}

static size_t hash_fd(void *key, size_t key_length, size_t slots_num)
{
  curl_socket_t fd = *((curl_socket_t *) key);
  (void) key_length;

  return (fd % (curl_socket_t)slots_num);
}

/*
 * sh_init() creates a new socket hash and returns the handle for it.
 *
 * Quote from README.multi_socket:
 *
 * "Some tests at 7000 and 9000 connections showed that the socket hash lookup
 * is somewhat of a bottle neck. Its current implementation may be a bit too
 * limiting. It simply has a fixed-size array, and on each entry in the array
 * it has a linked list with entries. The hash only checks which list to scan
 * through. The code I had used so for used a list with merely 7 slots (as
 * that is what the DNS hash uses) but with 7000 connections that would make
 * an average of 1000 nodes in each list to run through. I upped that to 97
 * slots (I believe a prime is suitable) and noticed a significant speed
 * increase. I need to reconsider the hash implementation or use a rather
 * large default value like this. At 9000 connections I was still below 10us
 * per call."
 *
 */
static void sh_init(struct Curl_hash *hash, size_t hashsize)
{
  Curl_hash_init(hash, hashsize, hash_fd, fd_key_compare,
                 sh_freeentry);
}

/*
 * The sockhash has its own separate subhash in each entry that need to be
 * safely destroyed first.
 */
static void sockhash_destroy(struct Curl_hash *h)
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;

  DEBUGASSERT(h);
  Curl_hash_start_iterate(h, &iter);
  he = Curl_hash_next_element(&iter);
  while(he) {
    struct Curl_sh_entry *sh = (struct Curl_sh_entry *)he->ptr;
    Curl_hash_destroy(&sh->transfers);
    he = Curl_hash_next_element(&iter);
  }
  Curl_hash_destroy(h);
}

/* look up a given socket in the socket hash, skip invalid sockets */
static struct Curl_sh_entry *sh_getentry(struct Curl_hash *sh,
                                         curl_socket_t s)
{
  if(s != CURL_SOCKET_BAD) {
    /* only look for proper sockets */
    return Curl_hash_pick(sh, (char *)&s, sizeof(curl_socket_t));
  }
  return NULL;
}

/* make sure this socket is present in the hash for this handle */
static struct Curl_sh_entry *sh_addentry(struct Curl_hash *sh,
                                         curl_socket_t s)
{
  struct Curl_sh_entry *there = sh_getentry(sh, s);
  struct Curl_sh_entry *check;

  if(there) {
    /* it is present, return fine */
    return there;
  }

  /* not present, add it */
  check = calloc(1, sizeof(struct Curl_sh_entry));
  if(!check)
    return NULL; /* major failure */

  Curl_hash_init(&check->transfers, TRHASH_SIZE, trhash, trhash_compare,
                 trhash_dtor);

  /* make/add new hash entry */
  if(!Curl_hash_add(sh, (char *)&s, sizeof(curl_socket_t), check)) {
    Curl_hash_destroy(&check->transfers);
    free(check);
    return NULL; /* major failure */
  }

  return check; /* things are good in sockhash land */
}

/* delete the given socket + handle from the hash */
static void sh_delentry(struct Curl_sh_entry *entry,
                        struct Curl_hash *sh, curl_socket_t s)
{
  Curl_hash_destroy(&entry->transfers);

  /* We remove the hash entry. This will end up in a call to
     sh_freeentry(). */
  Curl_hash_delete(sh, (char *)&s, sizeof(curl_socket_t));
}

static CURLMcode multi_sh_entry_closed(struct Curl_multi *multi,
                                       struct Curl_easy *data,
                                       struct Curl_sh_entry *entry,
                                       curl_socket_t s)
{
  int rc = 0;
  /* No one is interested in this socket any longer, report REMOVE
   * and destroy entry */

  DEBUGASSERT(entry->readers <= 1);
  DEBUGASSERT(entry->writers <= 1);
  CURL_TRC_M(data, "sockhash, closed fd=%" FMT_SOCKET_T, s);
  if(multi->socket_cb) {
    CURL_TRC_M(data, "socket_callback(fd=%" FMT_SOCKET_T ", REMOVE)", s);
    multi_ev_in_callback(multi, TRUE);
    rc = multi->socket_cb(data, s, CURL_POLL_REMOVE,
                          multi->socket_userp, entry->socketp);
    multi_ev_in_callback(multi, FALSE);
  }

  sh_delentry(entry, &multi->sockhash, s);
  if(rc == -1) {
    multi->dead = TRUE;
    return CURLM_ABORTED_BY_CALLBACK;
  }
  return CURLM_OK;
}

static CURLMcode multi_sh_entry_update(struct Curl_multi *multi,
                                       struct Curl_easy *data,
                                       struct Curl_sh_entry *entry,
                                       curl_socket_t s,
                                       unsigned char last_action,
                                       unsigned char cur_action)
{
  int rc, comboaction;

  /* Transfer `data` goes from `last_action` to `cur_action` on socket `s`
   * with `multi->sockhash` entry `entry`. Update `entry` and trigger
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

  DEBUGASSERT(entry->readers <= Curl_hash_count(&entry->transfers));
  DEBUGASSERT(entry->writers <= Curl_hash_count(&entry->transfers));
  DEBUGASSERT(entry->writers + entry->readers);

  CURL_TRC_M(data, "sockhash fd=%" FMT_SOCKET_T ", action=0x%x, "
             "previously=0x%d, transfers=%zu, readers=%d, writers=%d",
             s, cur_action, last_action,
             Curl_hash_count(&entry->transfers),
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
  multi_ev_in_callback(multi, TRUE);
  rc = multi->socket_cb(data, s, comboaction, multi->socket_userp,
                        entry->socketp);

  multi_ev_in_callback(multi, FALSE);
  if(rc == -1) {
    multi->dead = TRUE;
    return CURLM_ABORTED_BY_CALLBACK;
  }
  entry->action = (unsigned int)comboaction;
  return CURLM_OK;
}

CURLMcode Curl_multi_ev_pollset(struct Curl_multi *multi,
                                struct Curl_easy *data,
                                struct easy_pollset *ps,
                                struct easy_pollset *last_ps)
{
  unsigned int i, j;
  struct Curl_sh_entry *entry;
  curl_socket_t s;
  CURLMcode mresult;

  /* The transfer `data` reports in `ps` the sockets it is interested
   * in and which combinatino of CURL_POLL_IN/CURL_POLL_OUT it wants
   * to have monitored for events.
   * There can be more than 1 transfer interested in the same socket
   * and 1 transfer might be interested in more than 1 socket.
   * `last_ps` is the pollset copy from the previous call here. On
   * the 1st call it will be empty.
   */

  /* Handle changes to sockets the transfer is interested in. */
  for(i = 0; i < ps->num; i++) {
    unsigned char last_action;
    bool first_time_data = FALSE; /* data appears first time on socket */

    s = ps->sockets[i];
    /* Have we handled this socket before? */
    entry = sh_getentry(&multi->sockhash, s);
    if(!entry) {
      /* new socket, add new entry */
      first_time_data = TRUE;
      entry = sh_addentry(&multi->sockhash, s);
      if(!entry) /* fatal */
        return CURLM_OUT_OF_MEMORY;
      CURL_TRC_M(data, "sockhash, add fd=%" FMT_SOCKET_T, s);
    }
    else {
      first_time_data = !Curl_hash_pick(&entry->transfers, (char *)&data,
                                        sizeof(struct Curl_easy *));
    }

    last_action = 0;
    if(first_time_data) {
      /* register 'data' as user of entry */
      if(!Curl_hash_add(&entry->transfers, (char *)&data, /* hash key */
                        sizeof(struct Curl_easy *), data)) {
        Curl_hash_destroy(&entry->transfers); /* really??? */
        return CURLM_OUT_OF_MEMORY;
      }
      CURL_TRC_M(data, "sockhash fd=%" FMT_SOCKET_T ", add transfer", s);
       /* detect weird values */
      DEBUGASSERT(Curl_hash_count(&entry->transfers) < 100000);
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
    mresult = multi_sh_entry_update(multi, data, entry, s,
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

    entry = sh_getentry(&multi->sockhash, s);
    /* if this is NULL here, the socket has been closed and notified so
       already by Curl_multi_closed() */
    if(!entry)
      continue;

    if(Curl_hash_delete(&entry->transfers, (char *)&data,
                        sizeof(struct Curl_easy *))) {
      /* `data` says in `last_ps` that it had been using a socket,
       * but `data` has not been registered for it.
       * This should not happen if our book-keeping is correct? */
      CURL_TRC_M(data, "sockhash, transfer no longer uses fd=%" FMT_SOCKET_T
                 " but is not registered", s);
      DEBUGASSERT(NULL);
      continue;
    }

    if(Curl_hash_count(&entry->transfers)) {
      /* track readers/writers changes and report to socket callback */
      mresult = multi_sh_entry_update(multi, data, entry, s,
                                      last_ps->actions[i], 0);
      if(mresult)
        return mresult;
    }
    else {
      mresult = multi_sh_entry_closed(multi, data, entry, s);
      if(mresult)
        return mresult;
    }
  } /* for loop over num */

  return CURLM_OK;
}

CURLMcode Curl_multi_ev_assign(struct Curl_multi *multi,
                               curl_socket_t s,
                               void *user_data)
{
  struct Curl_sh_entry *there;

  there = sh_getentry(&multi->sockhash, s);
  if(!there)
    return CURLM_BAD_SOCKET;

  there->socketp = user_data;
  return CURLM_OK;
}

void Curl_multi_ev_expire_transfers(struct Curl_multi *multi,
                                    curl_socket_t s,
                                    int ev_bitmask,
                                    const struct curltime *nowp,
                                    bool *run_cpool)
{
  struct Curl_sh_entry *entry;

  if(s == CURL_SOCKET_TIMEOUT)
    return;

  entry = sh_getentry(&multi->sockhash, s);

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

/*
 * Curl_multi_closed()
 *
 * Used by the connect code to tell the multi_socket code that one of the
 * sockets we were using is about to be closed. This function will then
 * remove it from the sockethash for this handle to make the multi_socket API
 * behave properly, especially for the case when libcurl will create another
 * socket again and it gets the same file descriptor number.
 */
void Curl_multi_closed(struct Curl_easy *data, curl_socket_t s)
{
  if(data) {
    /* if there is still an easy handle associated with this connection */
    struct Curl_multi *multi = data->multi;
    CURL_TRC_M(data, "Curl_multi_closed, fd=%" FMT_SOCKET_T
               " multi is %p", s, (void *)multi);
    if(multi) {
      /* this is set if this connection is part of a handle that is added to
         a multi handle, and only then this is necessary */
      struct Curl_sh_entry *entry = sh_getentry(&multi->sockhash, s);
      if(entry)
        multi_sh_entry_closed(multi, data, entry, s);
    }
  }
}

void Curl_multi_ev_init(struct Curl_multi *multi, size_t hashsize)
{
  sh_init(&multi->sockhash, hashsize);
}

void Curl_multi_ev_cleanup(struct Curl_multi *multi)
{
  sockhash_destroy(&multi->sockhash);
}
