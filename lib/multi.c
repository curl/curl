/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>

#include "urldata.h"
#include "transfer.h"
#include "url.h"
#include "connect.h"
#include "progress.h"
#include "easyif.h"
#include "share.h"
#include "multiif.h"
#include "sendf.h"
#include "timeval.h"
#include "http.h"
#include "select.h"
#include "warnless.h"
#include "speedcheck.h"
#include "conncache.h"
#include "multihandle.h"
#include "pipeline.h"
#include "sigpipe.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
  CURL_SOCKET_HASH_TABLE_SIZE should be a prime number. Increasing it from 97
  to 911 takes on a 32-bit machine 4 x 804 = 3211 more bytes.  Still, every
  CURL handle takes 45-50 K memory, therefore this 3K are not significant.
*/
#ifndef CURL_SOCKET_HASH_TABLE_SIZE
#define CURL_SOCKET_HASH_TABLE_SIZE 911
#endif

#define CURL_CONNECTION_HASH_SIZE 97

#define CURL_MULTI_HANDLE 0x000bab1e

#define GOOD_MULTI_HANDLE(x) \
  ((x) && (((struct Curl_multi *)(x))->type == CURL_MULTI_HANDLE))

static void singlesocket(struct Curl_multi *multi,
                         struct SessionHandle *data);
static int update_timer(struct Curl_multi *multi);

static CURLMcode add_next_timeout(struct timeval now,
                                  struct Curl_multi *multi,
                                  struct SessionHandle *d);
static CURLMcode multi_timeout(struct Curl_multi *multi,
                               long *timeout_ms);

#ifdef DEBUGBUILD
static const char * const statename[]={
  "INIT",
  "CONNECT_PEND",
  "CONNECT",
  "WAITRESOLVE",
  "WAITCONNECT",
  "WAITPROXYCONNECT",
  "SENDPROTOCONNECT",
  "PROTOCONNECT",
  "WAITDO",
  "DO",
  "DOING",
  "DO_MORE",
  "DO_DONE",
  "WAITPERFORM",
  "PERFORM",
  "TOOFAST",
  "DONE",
  "COMPLETED",
  "MSGSENT",
};
#endif

static void multi_freetimeout(void *a, void *b);

/* function pointer called once when switching TO a state */
typedef void (*init_multistate_func)(struct SessionHandle *data);

/* always use this function to change state, to make debugging easier */
static void mstate(struct SessionHandle *data, CURLMstate state
#ifdef DEBUGBUILD
                   , int lineno
#endif
)
{
  CURLMstate oldstate = data->mstate;
  static const init_multistate_func finit[CURLM_STATE_LAST] = {
    NULL,
    NULL,
    Curl_init_CONNECT, /* CONNECT */
    /* the rest is NULL too */
  };

#if defined(DEBUGBUILD) && defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void) lineno;
#endif

  if(oldstate == state)
    /* don't bother when the new state is the same as the old state */
    return;

  data->mstate = state;

#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  if(data->mstate >= CURLM_STATE_CONNECT_PEND &&
     data->mstate < CURLM_STATE_COMPLETED) {
    long connection_id = -5000;

    if(data->easy_conn)
      connection_id = data->easy_conn->connection_id;

    infof(data,
          "STATE: %s => %s handle %p; line %d (connection #%ld)\n",
          statename[oldstate], statename[data->mstate],
          (void *)data, lineno, connection_id);
  }
#endif

  if(state == CURLM_STATE_COMPLETED)
    /* changing to COMPLETED means there's one less easy handle 'alive' */
    data->multi->num_alive--;

  /* if this state has an init-function, run it */
  if(finit[state])
    finit[state](data);
}

#ifndef DEBUGBUILD
#define multistate(x,y) mstate(x,y)
#else
#define multistate(x,y) mstate(x,y, __LINE__)
#endif

/*
 * We add one of these structs to the sockhash for a particular socket
 */

struct Curl_sh_entry {
  struct SessionHandle *easy;
  int action;  /* what action READ/WRITE this socket waits for */
  curl_socket_t socket; /* mainly to ease debugging */
  void *socketp; /* settable by users with curl_multi_assign() */
};
/* bits for 'action' having no bits means this socket is not expecting any
   action */
#define SH_READ  1
#define SH_WRITE 2

/* look up a given socket in the socket hash, skip invalid sockets */
static struct Curl_sh_entry *sh_getentry(struct curl_hash *sh,
                                         curl_socket_t s)
{
  if(s != CURL_SOCKET_BAD)
    /* only look for proper sockets */
    return Curl_hash_pick(sh, (char *)&s, sizeof(curl_socket_t));
  return NULL;
}

/* make sure this socket is present in the hash for this handle */
static struct Curl_sh_entry *sh_addentry(struct curl_hash *sh,
                                         curl_socket_t s,
                                         struct SessionHandle *data)
{
  struct Curl_sh_entry *there = sh_getentry(sh, s);
  struct Curl_sh_entry *check;

  if(there)
    /* it is present, return fine */
    return there;

  /* not present, add it */
  check = calloc(1, sizeof(struct Curl_sh_entry));
  if(!check)
    return NULL; /* major failure */

  check->easy = data;
  check->socket = s;

  /* make/add new hash entry */
  if(!Curl_hash_add(sh, (char *)&s, sizeof(curl_socket_t), check)) {
    free(check);
    return NULL; /* major failure */
  }

  return check; /* things are good in sockhash land */
}


/* delete the given socket + handle from the hash */
static void sh_delentry(struct curl_hash *sh, curl_socket_t s)
{
  /* We remove the hash entry. This will end up in a call to
     sh_freeentry(). */
  Curl_hash_delete(sh, (char *)&s, sizeof(curl_socket_t));
}

/*
 * free a sockhash entry
 */
static void sh_freeentry(void *freethis)
{
  struct Curl_sh_entry *p = (struct Curl_sh_entry *) freethis;

  free(p);
}

static size_t fd_key_compare(void *k1, size_t k1_len, void *k2, size_t k2_len)
{
  (void) k1_len; (void) k2_len;

  return (*((curl_socket_t *) k1)) == (*((curl_socket_t *) k2));
}

static size_t hash_fd(void *key, size_t key_length, size_t slots_num)
{
  curl_socket_t fd = *((curl_socket_t *) key);
  (void) key_length;

  return (fd % slots_num);
}

/*
 * sh_init() creates a new socket hash and returns the handle for it.
 *
 * Quote from README.multi_socket:
 *
 * "Some tests at 7000 and 9000 connections showed that the socket hash lookup
 * is somewhat of a bottle neck. Its current implementation may be a bit too
 * limiting. It simply has a fixed-size array, and on each entry in the array
 * it has a linked list with entries. So the hash only checks which list to
 * scan through. The code I had used so for used a list with merely 7 slots
 * (as that is what the DNS hash uses) but with 7000 connections that would
 * make an average of 1000 nodes in each list to run through. I upped that to
 * 97 slots (I believe a prime is suitable) and noticed a significant speed
 * increase.  I need to reconsider the hash implementation or use a rather
 * large default value like this. At 9000 connections I was still below 10us
 * per call."
 *
 */
static int sh_init(struct curl_hash *hash, int hashsize)
{
  return Curl_hash_init(hash, hashsize, hash_fd, fd_key_compare,
                        sh_freeentry);
}

/*
 * multi_addmsg()
 *
 * Called when a transfer is completed. Adds the given msg pointer to
 * the list kept in the multi handle.
 */
static CURLMcode multi_addmsg(struct Curl_multi *multi,
                              struct Curl_message *msg)
{
  if(!Curl_llist_insert_next(multi->msglist, multi->msglist->tail, msg))
    return CURLM_OUT_OF_MEMORY;

  return CURLM_OK;
}

/*
 * multi_freeamsg()
 *
 * Callback used by the llist system when a single list entry is destroyed.
 */
static void multi_freeamsg(void *a, void *b)
{
  (void)a;
  (void)b;
}

struct Curl_multi *Curl_multi_handle(int hashsize, /* socket hash */
                                     int chashsize) /* connection hash */
{
  struct Curl_multi *multi = calloc(1, sizeof(struct Curl_multi));

  if(!multi)
    return NULL;

  multi->type = CURL_MULTI_HANDLE;

  if(Curl_mk_dnscache(&multi->hostcache))
    goto error;

  if(sh_init(&multi->sockhash, hashsize))
    goto error;

  if(Curl_conncache_init(&multi->conn_cache, chashsize))
    goto error;

  multi->msglist = Curl_llist_alloc(multi_freeamsg);
  if(!multi->msglist)
    goto error;

  multi->pending = Curl_llist_alloc(multi_freeamsg);
  if(!multi->pending)
    goto error;

  /* allocate a new easy handle to use when closing cached connections */
  multi->closure_handle = curl_easy_init();
  if(!multi->closure_handle)
    goto error;

  multi->closure_handle->multi = multi;
  multi->closure_handle->state.conn_cache = &multi->conn_cache;

  multi->max_pipeline_length = 5;

  /* -1 means it not set by user, use the default value */
  multi->maxconnects = -1;
  return (CURLM *) multi;

  error:

  Curl_hash_destroy(&multi->sockhash);
  Curl_hash_destroy(&multi->hostcache);
  Curl_conncache_destroy(&multi->conn_cache);
  Curl_close(multi->closure_handle);
  multi->closure_handle = NULL;
  Curl_llist_destroy(multi->msglist, NULL);
  Curl_llist_destroy(multi->pending, NULL);

  free(multi);
  return NULL;
}

CURLM *curl_multi_init(void)
{
  return Curl_multi_handle(CURL_SOCKET_HASH_TABLE_SIZE,
                           CURL_CONNECTION_HASH_SIZE);
}

CURLMcode curl_multi_add_handle(CURLM *multi_handle,
                                CURL *easy_handle)
{
  struct curl_llist *timeoutlist;
  struct Curl_multi *multi = (struct Curl_multi *)multi_handle;
  struct SessionHandle *data = (struct SessionHandle *)easy_handle;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  /* Verify that we got a somewhat good easy handle too */
  if(!GOOD_EASY_HANDLE(easy_handle))
    return CURLM_BAD_EASY_HANDLE;

  /* Prevent users from adding same easy handle more than once and prevent
     adding to more than one multi stack */
  if(data->multi)
    return CURLM_ADDED_ALREADY;

  /* Allocate and initialize timeout list for easy handle */
  timeoutlist = Curl_llist_alloc(multi_freetimeout);
  if(!timeoutlist)
    return CURLM_OUT_OF_MEMORY;

  /*
   * No failure allowed in this function beyond this point. And no
   * modification of easy nor multi handle allowed before this except for
   * potential multi's connection cache growing which won't be undone in this
   * function no matter what.
   */

  /* Make easy handle use timeout list initialized above */
  data->state.timeoutlist = timeoutlist;
  timeoutlist = NULL;

  /* set the easy handle */
  multistate(data, CURLM_STATE_INIT);

  if((data->set.global_dns_cache) &&
     (data->dns.hostcachetype != HCACHE_GLOBAL)) {
    /* global dns cache was requested but still isn't */
    struct curl_hash *global = Curl_global_host_cache_init();
    if(global) {
      /* only do this if the global cache init works */
      data->dns.hostcache = global;
      data->dns.hostcachetype = HCACHE_GLOBAL;
    }
  }
  /* for multi interface connections, we share DNS cache automatically if the
     easy handle's one is currently not set. */
  else if(!data->dns.hostcache ||
     (data->dns.hostcachetype == HCACHE_NONE)) {
    data->dns.hostcache = &multi->hostcache;
    data->dns.hostcachetype = HCACHE_MULTI;
  }

  /* Point to the multi's connection cache */
  data->state.conn_cache = &multi->conn_cache;

  /* This adds the new entry at the 'end' of the doubly-linked circular
     list of SessionHandle structs to try and maintain a FIFO queue so
     the pipelined requests are in order. */

  /* We add this new entry last in the list. */

  data->next = NULL; /* end of the line */
  if(multi->easyp) {
    struct SessionHandle *last = multi->easylp;
    last->next = data;
    data->prev = last;
    multi->easylp = data; /* the new last node */
  }
  else {
    /* first node, make prev NULL! */
    data->prev = NULL;
    multi->easylp = multi->easyp = data; /* both first and last */
  }

  /* make the SessionHandle refer back to this multi handle */
  data->multi = multi_handle;

  /* Set the timeout for this handle to expire really soon so that it will
     be taken care of even when this handle is added in the midst of operation
     when only the curl_multi_socket() API is used. During that flow, only
     sockets that time-out or have actions will be dealt with. Since this
     handle has no action yet, we make sure it times out to get things to
     happen. */
  Curl_expire(data, 1);

  /* increase the node-counter */
  multi->num_easy++;

  /* increase the alive-counter */
  multi->num_alive++;

  /* A somewhat crude work-around for a little glitch in update_timer() that
     happens if the lastcall time is set to the same time when the handle is
     removed as when the next handle is added, as then the check in
     update_timer() that prevents calling the application multiple times with
     the same timer infor will not trigger and then the new handle's timeout
     will not be notified to the app.

     The work-around is thus simply to clear the 'lastcall' variable to force
     update_timer() to always trigger a callback to the app when a new easy
     handle is added */
  memset(&multi->timer_lastcall, 0, sizeof(multi->timer_lastcall));

  update_timer(multi);
  return CURLM_OK;
}

#if 0
/* Debug-function, used like this:
 *
 * Curl_hash_print(multi->sockhash, debug_print_sock_hash);
 *
 * Enable the hash print function first by editing hash.c
 */
static void debug_print_sock_hash(void *p)
{
  struct Curl_sh_entry *sh = (struct Curl_sh_entry *)p;

  fprintf(stderr, " [easy %p/magic %x/socket %d]",
          (void *)sh->data, sh->data->magic, (int)sh->socket);
}
#endif

/* Mark the connection as 'idle', or close it if the cache is full.
   Returns TRUE if the connection is kept, or FALSE if it was closed. */
static bool
ConnectionDone(struct SessionHandle *data, struct connectdata *conn)
{
  /* data->multi->maxconnects can be negative, deal with it. */
  size_t maxconnects =
    (data->multi->maxconnects < 0) ? data->multi->num_easy * 4:
    data->multi->maxconnects;
  struct connectdata *conn_candidate = NULL;

  /* Mark the current connection as 'unused' */
  conn->inuse = FALSE;

  if(maxconnects > 0 &&
     data->state.conn_cache->num_connections > maxconnects) {
    infof(data, "Connection cache is full, closing the oldest one.\n");

    conn_candidate = Curl_oldest_idle_connection(data);

    if(conn_candidate) {
      /* Set the connection's owner correctly */
      conn_candidate->data = data;

      /* the winner gets the honour of being disconnected */
      (void)Curl_disconnect(conn_candidate, /* dead_connection */ FALSE);
    }
  }

  return (conn_candidate == conn) ? FALSE : TRUE;
}

static CURLcode multi_done(struct connectdata **connp,
                          CURLcode status,  /* an error if this is called
                                               after an error was detected */
                          bool premature)
{
  CURLcode result;
  struct connectdata *conn;
  struct SessionHandle *data;

  DEBUGASSERT(*connp);

  conn = *connp;
  data = conn->data;

  DEBUGF(infof(data, "multi_done\n"));

  if(data->state.done)
    /* Stop if multi_done() has already been called */
    return CURLE_OK;

  Curl_getoff_all_pipelines(data, conn);

  /* Cleanup possible redirect junk */
  free(data->req.newurl);
  data->req.newurl = NULL;
  free(data->req.location);
  data->req.location = NULL;

  switch(status) {
  case CURLE_ABORTED_BY_CALLBACK:
  case CURLE_READ_ERROR:
  case CURLE_WRITE_ERROR:
    /* When we're aborted due to a callback return code it basically have to
       be counted as premature as there is trouble ahead if we don't. We have
       many callbacks and protocols work differently, we could potentially do
       this more fine-grained in the future. */
    premature = TRUE;
  default:
    break;
  }

  /* this calls the protocol-specific function pointer previously set */
  if(conn->handler->done)
    result = conn->handler->done(conn, status, premature);
  else
    result = status;

  if(CURLE_ABORTED_BY_CALLBACK != result) {
    /* avoid this if we already aborted by callback to avoid this calling
       another callback */
    CURLcode rc = Curl_pgrsDone(conn);
    if(!result && rc)
      result = CURLE_ABORTED_BY_CALLBACK;
  }

  if((!premature &&
      conn->send_pipe->size + conn->recv_pipe->size != 0 &&
      !data->set.reuse_forbid &&
      !conn->bits.close)) {
    /* Stop if pipeline is not empty and we do not have to close
       connection. */
    DEBUGF(infof(data, "Connection still in use, no more multi_done now!\n"));
    return CURLE_OK;
  }

  data->state.done = TRUE; /* called just now! */
  Curl_resolver_cancel(conn);

  if(conn->dns_entry) {
    Curl_resolv_unlock(data, conn->dns_entry); /* done with this */
    conn->dns_entry = NULL;
  }

  /* if the transfer was completed in a paused state there can be buffered
     data left to write and then kill */
  free(data->state.tempwrite);
  data->state.tempwrite = NULL;

  /* if data->set.reuse_forbid is TRUE, it means the libcurl client has
     forced us to close this connection. This is ignored for requests taking
     place in a NTLM authentication handshake

     if conn->bits.close is TRUE, it means that the connection should be
     closed in spite of all our efforts to be nice, due to protocol
     restrictions in our or the server's end

     if premature is TRUE, it means this connection was said to be DONE before
     the entire request operation is complete and thus we can't know in what
     state it is for re-using, so we're forced to close it. In a perfect world
     we can add code that keep track of if we really must close it here or not,
     but currently we have no such detail knowledge.
  */

  if((data->set.reuse_forbid
#if defined(USE_NTLM)
      && !(conn->ntlm.state == NTLMSTATE_TYPE2 ||
           conn->proxyntlm.state == NTLMSTATE_TYPE2)
#endif
     ) || conn->bits.close || premature) {
    CURLcode res2 = Curl_disconnect(conn, premature); /* close connection */

    /* If we had an error already, make sure we return that one. But
       if we got a new error, return that. */
    if(!result && res2)
      result = res2;
  }
  else {
    /* the connection is no longer in use */
    if(ConnectionDone(data, conn)) {
      /* remember the most recently used connection */
      data->state.lastconnect = conn;

      infof(data, "Connection #%ld to host %s left intact\n",
            conn->connection_id,
            conn->bits.httpproxy?conn->proxy.dispname:conn->host.dispname);
    }
    else
      data->state.lastconnect = NULL;
  }

  *connp = NULL; /* to make the caller of this function better detect that
                    this was either closed or handed over to the connection
                    cache here, and therefore cannot be used from this point on
                 */
  Curl_free_request_state(data);

  return result;
}

CURLMcode curl_multi_remove_handle(CURLM *multi_handle,
                                   CURL *curl_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct SessionHandle *easy = curl_handle;
  struct SessionHandle *data = easy;
  bool premature;
  bool easy_owns_conn;
  struct curl_llist_element *e;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  /* Verify that we got a somewhat good easy handle too */
  if(!GOOD_EASY_HANDLE(curl_handle))
    return CURLM_BAD_EASY_HANDLE;

  /* Prevent users from trying to remove same easy handle more than once */
  if(!data->multi)
    return CURLM_OK; /* it is already removed so let's say it is fine! */

  premature = (data->mstate < CURLM_STATE_COMPLETED) ? TRUE : FALSE;
  easy_owns_conn = (data->easy_conn && (data->easy_conn->data == easy)) ?
    TRUE : FALSE;

  /* If the 'state' is not INIT or COMPLETED, we might need to do something
     nice to put the easy_handle in a good known state when this returns. */
  if(premature) {
    /* this handle is "alive" so we need to count down the total number of
       alive connections when this is removed */
    multi->num_alive--;

    /* When this handle gets removed, other handles may be able to get the
       connection */
    Curl_multi_process_pending_handles(multi);
  }

  if(data->easy_conn &&
     data->mstate > CURLM_STATE_DO &&
     data->mstate < CURLM_STATE_COMPLETED) {
    /* If the handle is in a pipeline and has started sending off its
       request but not received its response yet, we need to close
       connection. */
    connclose(data->easy_conn, "Removed with partial response");
    /* Set connection owner so that the DONE function closes it.  We can
       safely do this here since connection is killed. */
    data->easy_conn->data = easy;
    easy_owns_conn = TRUE;
  }

  /* The timer must be shut down before data->multi is set to NULL,
     else the timenode will remain in the splay tree after
     curl_easy_cleanup is called. */
  Curl_expire(data, 0);

  if(data->dns.hostcachetype == HCACHE_MULTI) {
    /* stop using the multi handle's DNS cache */
    data->dns.hostcache = NULL;
    data->dns.hostcachetype = HCACHE_NONE;
  }

  if(data->easy_conn) {

    /* we must call multi_done() here (if we still own the connection) so that
       we don't leave a half-baked one around */
    if(easy_owns_conn) {

      /* multi_done() clears the conn->data field to lose the association
         between the easy handle and the connection

         Note that this ignores the return code simply because there's
         nothing really useful to do with it anyway! */
      (void)multi_done(&data->easy_conn, data->result, premature);
    }
    else
      /* Clear connection pipelines, if multi_done above was not called */
      Curl_getoff_all_pipelines(data, data->easy_conn);
  }

  Curl_wildcard_dtor(&data->wildcard);

  /* destroy the timeout list that is held in the easy handle, do this *after*
     multi_done() as that may actually call Curl_expire that uses this */
  if(data->state.timeoutlist) {
    Curl_llist_destroy(data->state.timeoutlist, NULL);
    data->state.timeoutlist = NULL;
  }

  /* as this was using a shared connection cache we clear the pointer to that
     since we're not part of that multi handle anymore */
  data->state.conn_cache = NULL;

  /* change state without using multistate(), only to make singlesocket() do
     what we want */
  data->mstate = CURLM_STATE_COMPLETED;
  singlesocket(multi, easy); /* to let the application know what sockets that
                                vanish with this handle */

  /* Remove the association between the connection and the handle */
  if(data->easy_conn) {
    data->easy_conn->data = NULL;
    data->easy_conn = NULL;
  }

  data->multi = NULL; /* clear the association to this multi handle */

  /* make sure there's no pending message in the queue sent from this easy
     handle */

  for(e = multi->msglist->head; e; e = e->next) {
    struct Curl_message *msg = e->ptr;

    if(msg->extmsg.easy_handle == easy) {
      Curl_llist_remove(multi->msglist, e, NULL);
      /* there can only be one from this specific handle */
      break;
    }
  }

  /* make the previous node point to our next */
  if(data->prev)
    data->prev->next = data->next;
  else
    multi->easyp = data->next; /* point to first node */

  /* make our next point to our previous node */
  if(data->next)
    data->next->prev = data->prev;
  else
    multi->easylp = data->prev; /* point to last node */

  /* NOTE NOTE NOTE
     We do not touch the easy handle here! */
  multi->num_easy--; /* one less to care about now */

  update_timer(multi);
  return CURLM_OK;
}

/* Return TRUE if the application asked for a certain set of pipelining */
bool Curl_pipeline_wanted(const struct Curl_multi *multi, int bits)
{
  return (multi && (multi->pipelining & bits)) ? TRUE : FALSE;
}

void Curl_multi_handlePipeBreak(struct SessionHandle *data)
{
  data->easy_conn = NULL;
}

static int waitconnect_getsock(struct connectdata *conn,
                               curl_socket_t *sock,
                               int numsocks)
{
  int i;
  int s=0;
  int rc=0;

  if(!numsocks)
    return GETSOCK_BLANK;

  for(i=0; i<2; i++) {
    if(conn->tempsock[i] != CURL_SOCKET_BAD) {
      sock[s] = conn->tempsock[i];
      rc |= GETSOCK_WRITESOCK(s++);
    }
  }

  return rc;
}

static int waitproxyconnect_getsock(struct connectdata *conn,
                                    curl_socket_t *sock,
                                    int numsocks)
{
  if(!numsocks)
    return GETSOCK_BLANK;

  sock[0] = conn->sock[FIRSTSOCKET];

  /* when we've sent a CONNECT to a proxy, we should rather wait for the
     socket to become readable to be able to get the response headers */
  if(conn->tunnel_state[FIRSTSOCKET] == TUNNEL_CONNECT)
    return GETSOCK_READSOCK(0);

  return GETSOCK_WRITESOCK(0);
}

static int domore_getsock(struct connectdata *conn,
                          curl_socket_t *socks,
                          int numsocks)
{
  if(conn && conn->handler->domore_getsock)
    return conn->handler->domore_getsock(conn, socks, numsocks);
  return GETSOCK_BLANK;
}

/* returns bitmapped flags for this handle and its sockets */
static int multi_getsock(struct SessionHandle *data,
                         curl_socket_t *socks, /* points to numsocks number
                                                  of sockets */
                         int numsocks)
{
  /* If the pipe broke, or if there's no connection left for this easy handle,
     then we MUST bail out now with no bitmask set. The no connection case can
     happen when this is called from curl_multi_remove_handle() =>
     singlesocket() => multi_getsock().
  */
  if(data->state.pipe_broke || !data->easy_conn)
    return 0;

  if(data->mstate > CURLM_STATE_CONNECT &&
     data->mstate < CURLM_STATE_COMPLETED) {
    /* Set up ownership correctly */
    data->easy_conn->data = data;
  }

  switch(data->mstate) {
  default:
#if 0 /* switch back on these cases to get the compiler to check for all enums
         to be present */
  case CURLM_STATE_TOOFAST:  /* returns 0, so will not select. */
  case CURLM_STATE_COMPLETED:
  case CURLM_STATE_MSGSENT:
  case CURLM_STATE_INIT:
  case CURLM_STATE_CONNECT:
  case CURLM_STATE_WAITDO:
  case CURLM_STATE_DONE:
  case CURLM_STATE_LAST:
    /* this will get called with CURLM_STATE_COMPLETED when a handle is
       removed */
#endif
    return 0;

  case CURLM_STATE_WAITRESOLVE:
    return Curl_resolver_getsock(data->easy_conn, socks, numsocks);

  case CURLM_STATE_PROTOCONNECT:
  case CURLM_STATE_SENDPROTOCONNECT:
    return Curl_protocol_getsock(data->easy_conn, socks, numsocks);

  case CURLM_STATE_DO:
  case CURLM_STATE_DOING:
    return Curl_doing_getsock(data->easy_conn, socks, numsocks);

  case CURLM_STATE_WAITPROXYCONNECT:
    return waitproxyconnect_getsock(data->easy_conn, socks, numsocks);

  case CURLM_STATE_WAITCONNECT:
    return waitconnect_getsock(data->easy_conn, socks, numsocks);

  case CURLM_STATE_DO_MORE:
    return domore_getsock(data->easy_conn, socks, numsocks);

  case CURLM_STATE_DO_DONE: /* since is set after DO is completed, we switch
                               to waiting for the same as the *PERFORM
                               states */
  case CURLM_STATE_PERFORM:
  case CURLM_STATE_WAITPERFORM:
    return Curl_single_getsock(data->easy_conn, socks, numsocks);
  }

}

CURLMcode curl_multi_fdset(CURLM *multi_handle,
                           fd_set *read_fd_set, fd_set *write_fd_set,
                           fd_set *exc_fd_set, int *max_fd)
{
  /* Scan through all the easy handles to get the file descriptors set.
     Some easy handles may not have connected to the remote host yet,
     and then we must make sure that is done. */
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct SessionHandle *data;
  int this_max_fd=-1;
  curl_socket_t sockbunch[MAX_SOCKSPEREASYHANDLE];
  int bitmap;
  int i;
  (void)exc_fd_set; /* not used */

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  data=multi->easyp;
  while(data) {
    bitmap = multi_getsock(data, sockbunch, MAX_SOCKSPEREASYHANDLE);

    for(i=0; i< MAX_SOCKSPEREASYHANDLE; i++) {
      curl_socket_t s = CURL_SOCKET_BAD;

      if((bitmap & GETSOCK_READSOCK(i)) && VALID_SOCK((sockbunch[i]))) {
        FD_SET(sockbunch[i], read_fd_set);
        s = sockbunch[i];
      }
      if((bitmap & GETSOCK_WRITESOCK(i)) && VALID_SOCK((sockbunch[i]))) {
        FD_SET(sockbunch[i], write_fd_set);
        s = sockbunch[i];
      }
      if(s == CURL_SOCKET_BAD)
        /* this socket is unused, break out of loop */
        break;
      else {
        if((int)s > this_max_fd)
          this_max_fd = (int)s;
      }
    }

    data = data->next; /* check next handle */
  }

  *max_fd = this_max_fd;

  return CURLM_OK;
}

CURLMcode curl_multi_wait(CURLM *multi_handle,
                          struct curl_waitfd extra_fds[],
                          unsigned int extra_nfds,
                          int timeout_ms,
                          int *ret)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct SessionHandle *data;
  curl_socket_t sockbunch[MAX_SOCKSPEREASYHANDLE];
  int bitmap;
  unsigned int i;
  unsigned int nfds = 0;
  unsigned int curlfds;
  struct pollfd *ufds = NULL;
  long timeout_internal;
  int retcode = 0;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  /* If the internally desired timeout is actually shorter than requested from
     the outside, then use the shorter time! But only if the internal timer
     is actually larger than -1! */
  (void)multi_timeout(multi, &timeout_internal);
  if((timeout_internal >= 0) && (timeout_internal < (long)timeout_ms))
    timeout_ms = (int)timeout_internal;

  /* Count up how many fds we have from the multi handle */
  data=multi->easyp;
  while(data) {
    bitmap = multi_getsock(data, sockbunch, MAX_SOCKSPEREASYHANDLE);

    for(i=0; i< MAX_SOCKSPEREASYHANDLE; i++) {
      curl_socket_t s = CURL_SOCKET_BAD;

      if(bitmap & GETSOCK_READSOCK(i)) {
        ++nfds;
        s = sockbunch[i];
      }
      if(bitmap & GETSOCK_WRITESOCK(i)) {
        ++nfds;
        s = sockbunch[i];
      }
      if(s == CURL_SOCKET_BAD) {
        break;
      }
    }

    data = data->next; /* check next handle */
  }

  curlfds = nfds; /* number of internal file descriptors */
  nfds += extra_nfds; /* add the externally provided ones */

  if(nfds || extra_nfds) {
    ufds = malloc(nfds * sizeof(struct pollfd));
    if(!ufds)
      return CURLM_OUT_OF_MEMORY;
  }
  nfds = 0;

  /* only do the second loop if we found descriptors in the first stage run
     above */

  if(curlfds) {
    /* Add the curl handles to our pollfds first */
    data=multi->easyp;
    while(data) {
      bitmap = multi_getsock(data, sockbunch, MAX_SOCKSPEREASYHANDLE);

      for(i=0; i< MAX_SOCKSPEREASYHANDLE; i++) {
        curl_socket_t s = CURL_SOCKET_BAD;

        if(bitmap & GETSOCK_READSOCK(i)) {
          ufds[nfds].fd = sockbunch[i];
          ufds[nfds].events = POLLIN;
          ++nfds;
          s = sockbunch[i];
        }
        if(bitmap & GETSOCK_WRITESOCK(i)) {
          ufds[nfds].fd = sockbunch[i];
          ufds[nfds].events = POLLOUT;
          ++nfds;
          s = sockbunch[i];
        }
        if(s == CURL_SOCKET_BAD) {
          break;
        }
      }

      data = data->next; /* check next handle */
    }
  }

  /* Add external file descriptions from poll-like struct curl_waitfd */
  for(i = 0; i < extra_nfds; i++) {
    ufds[nfds].fd = extra_fds[i].fd;
    ufds[nfds].events = 0;
    if(extra_fds[i].events & CURL_WAIT_POLLIN)
      ufds[nfds].events |= POLLIN;
    if(extra_fds[i].events & CURL_WAIT_POLLPRI)
      ufds[nfds].events |= POLLPRI;
    if(extra_fds[i].events & CURL_WAIT_POLLOUT)
      ufds[nfds].events |= POLLOUT;
    ++nfds;
  }

  if(nfds) {
    int pollrc;
    /* wait... */
    pollrc = Curl_poll(ufds, nfds, timeout_ms);
    DEBUGF(infof(data, "Curl_poll(%d ds, %d ms) == %d\n",
                 nfds, timeout_ms, pollrc));

    if(pollrc > 0) {
      retcode = pollrc;
      /* copy revents results from the poll to the curl_multi_wait poll
         struct, the bit values of the actual underlying poll() implementation
         may not be the same as the ones in the public libcurl API! */
      for(i = 0; i < extra_nfds; i++) {
        unsigned short mask = 0;
        unsigned r = ufds[curlfds + i].revents;

        if(r & POLLIN)
          mask |= CURL_WAIT_POLLIN;
        if(r & POLLOUT)
          mask |= CURL_WAIT_POLLOUT;
        if(r & POLLPRI)
          mask |= CURL_WAIT_POLLPRI;

        extra_fds[i].revents = mask;
      }
    }
  }

  free(ufds);
  if(ret)
    *ret = retcode;
  return CURLM_OK;
}

/*
 * Curl_multi_connchanged() is called to tell that there is a connection in
 * this multi handle that has changed state (pipelining become possible, the
 * number of allowed streams changed or similar), and a subsequent use of this
 * multi handle should move CONNECT_PEND handles back to CONNECT to have them
 * retry.
 */
void Curl_multi_connchanged(struct Curl_multi *multi)
{
  multi->recheckstate = TRUE;
}

/*
 * multi_ischanged() is called
 *
 * Returns TRUE/FALSE whether the state is changed to trigger a CONNECT_PEND
 * => CONNECT action.
 *
 * Set 'clear' to TRUE to have it also clear the state variable.
 */
static bool multi_ischanged(struct Curl_multi *multi, bool clear)
{
  bool retval = multi->recheckstate;
  if(clear)
    multi->recheckstate = FALSE;
  return retval;
}

CURLMcode Curl_multi_add_perform(struct Curl_multi *multi,
                                 struct SessionHandle *data,
                                 struct connectdata *conn)
{
  CURLMcode rc;

  rc = curl_multi_add_handle(multi, data);
  if(!rc) {
    struct SingleRequest *k = &data->req;

    /* pass in NULL for 'conn' here since we don't want to init the
       connection, only this transfer */
    Curl_init_do(data, NULL);

    /* take this handle to the perform state right away */
    multistate(data, CURLM_STATE_PERFORM);
    data->easy_conn = conn;
    k->keepon |= KEEP_RECV; /* setup to receive! */
  }
  return rc;
}

static CURLcode multi_reconnect_request(struct connectdata **connp)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = *connp;
  struct SessionHandle *data = conn->data;

  /* This was a re-use of a connection and we got a write error in the
   * DO-phase. Then we DISCONNECT this connection and have another attempt to
   * CONNECT and then DO again! The retry cannot possibly find another
   * connection to re-use, since we only keep one possible connection for
   * each.  */

  infof(data, "Re-used connection seems dead, get a new one\n");

  connclose(conn, "Reconnect dead connection"); /* enforce close */
  result = multi_done(&conn, result, FALSE); /* we are so done with this */

  /* conn may no longer be a good pointer, clear it to avoid mistakes by
     parent functions */
  *connp = NULL;

  /*
   * We need to check for CURLE_SEND_ERROR here as well. This could happen
   * when the request failed on a FTP connection and thus multi_done() itself
   * tried to use the connection (again).
   */
  if(!result || (CURLE_SEND_ERROR == result)) {
    bool async;
    bool protocol_done = TRUE;

    /* Now, redo the connect and get a new connection */
    result = Curl_connect(data, connp, &async, &protocol_done);
    if(!result) {
      /* We have connected or sent away a name resolve query fine */

      conn = *connp; /* setup conn to again point to something nice */
      if(async) {
        /* Now, if async is TRUE here, we need to wait for the name
           to resolve */
        result = Curl_resolver_wait_resolv(conn, NULL);
        if(result)
          return result;

        /* Resolved, continue with the connection */
        result = Curl_async_resolved(conn, &protocol_done);
        if(result)
          return result;
      }
    }
  }

  return result;
}

/*
 * do_complete is called when the DO actions are complete.
 *
 * We init chunking and trailer bits to their default values here immediately
 * before receiving any header data for the current request in the pipeline.
 */
static void do_complete(struct connectdata *conn)
{
  conn->data->req.chunk=FALSE;
  conn->data->req.maxfd = (conn->sockfd>conn->writesockfd?
                           conn->sockfd:conn->writesockfd)+1;
  Curl_pgrsTime(conn->data, TIMER_PRETRANSFER);
}

static CURLcode multi_do(struct connectdata **connp, bool *done)
{
  CURLcode result=CURLE_OK;
  struct connectdata *conn = *connp;
  struct SessionHandle *data = conn->data;

  if(conn->handler->do_it) {
    /* generic protocol-specific function pointer set in curl_connect() */
    result = conn->handler->do_it(conn, done);

    /* This was formerly done in transfer.c, but we better do it here */
    if((CURLE_SEND_ERROR == result) && conn->bits.reuse) {
      /*
       * If the connection is using an easy handle, call reconnect
       * to re-establish the connection.  Otherwise, let the multi logic
       * figure out how to re-establish the connection.
       */
      if(!data->multi) {
        result = multi_reconnect_request(connp);

        if(!result) {
          /* ... finally back to actually retry the DO phase */
          conn = *connp; /* re-assign conn since multi_reconnect_request
                            creates a new connection */
          result = conn->handler->do_it(conn, done);
        }
      }
      else
        return result;
    }

    if(!result && *done)
      /* do_complete must be called after the protocol-specific DO function */
      do_complete(conn);
  }
  return result;
}

/*
 * multi_do_more() is called during the DO_MORE multi state. It is basically a
 * second stage DO state which (wrongly) was introduced to support FTP's
 * second connection.
 *
 * TODO: A future libcurl should be able to work away this state.
 *
 * 'complete' can return 0 for incomplete, 1 for done and -1 for go back to
 * DOING state there's more work to do!
 */

static CURLcode multi_do_more(struct connectdata *conn, int *complete)
{
  CURLcode result=CURLE_OK;

  *complete = 0;

  if(conn->handler->do_more)
    result = conn->handler->do_more(conn, complete);

  if(!result && (*complete == 1))
    /* do_complete must be called after the protocol-specific DO function */
    do_complete(conn);

  return result;
}

static CURLMcode multi_runsingle(struct Curl_multi *multi,
                                 struct timeval now,
                                 struct SessionHandle *data)
{
  struct Curl_message *msg = NULL;
  bool connected;
  bool async;
  bool protocol_connect = FALSE;
  bool dophase_done = FALSE;
  bool done = FALSE;
  CURLMcode rc;
  CURLcode result = CURLE_OK;
  struct SingleRequest *k;
  long timeout_ms;
  int control;

  if(!GOOD_EASY_HANDLE(data))
    return CURLM_BAD_EASY_HANDLE;

  do {
    bool disconnect_conn = FALSE;
    rc = CURLM_OK;

    /* Handle the case when the pipe breaks, i.e., the connection
       we're using gets cleaned up and we're left with nothing. */
    if(data->state.pipe_broke) {
      infof(data, "Pipe broke: handle %p, url = %s\n",
            (void *)data, data->state.path);

      if(data->mstate < CURLM_STATE_COMPLETED) {
        /* Head back to the CONNECT state */
        multistate(data, CURLM_STATE_CONNECT);
        rc = CURLM_CALL_MULTI_PERFORM;
        result = CURLE_OK;
      }

      data->state.pipe_broke = FALSE;
      data->easy_conn = NULL;
      continue;
    }

    if(!data->easy_conn &&
       data->mstate > CURLM_STATE_CONNECT &&
       data->mstate < CURLM_STATE_DONE) {
      /* In all these states, the code will blindly access 'data->easy_conn'
         so this is precaution that it isn't NULL. And it silences static
         analyzers. */
      failf(data, "In state %d with no easy_conn, bail out!\n", data->mstate);
      return CURLM_INTERNAL_ERROR;
    }

    if(multi_ischanged(multi, TRUE)) {
      DEBUGF(infof(data, "multi changed, check CONNECT_PEND queue!\n"));
      Curl_multi_process_pending_handles(multi);
    }

    if(data->easy_conn && data->mstate > CURLM_STATE_CONNECT &&
       data->mstate < CURLM_STATE_COMPLETED)
      /* Make sure we set the connection's current owner */
      data->easy_conn->data = data;

    if(data->easy_conn &&
       (data->mstate >= CURLM_STATE_CONNECT) &&
       (data->mstate < CURLM_STATE_COMPLETED)) {
      /* we need to wait for the connect state as only then is the start time
         stored, but we must not check already completed handles */

      timeout_ms = Curl_timeleft(data, &now,
                                 (data->mstate <= CURLM_STATE_WAITDO)?
                                 TRUE:FALSE);

      if(timeout_ms < 0) {
        /* Handle timed out */
        if(data->mstate == CURLM_STATE_WAITRESOLVE)
          failf(data, "Resolving timed out after %ld milliseconds",
                Curl_tvdiff(now, data->progress.t_startsingle));
        else if(data->mstate == CURLM_STATE_WAITCONNECT)
          failf(data, "Connection timed out after %ld milliseconds",
                Curl_tvdiff(now, data->progress.t_startsingle));
        else {
          k = &data->req;
          if(k->size != -1) {
            failf(data, "Operation timed out after %ld milliseconds with %"
                  CURL_FORMAT_CURL_OFF_T " out of %"
                  CURL_FORMAT_CURL_OFF_T " bytes received",
                  Curl_tvdiff(now, data->progress.t_startsingle),
                  k->bytecount, k->size);
          }
          else {
            failf(data, "Operation timed out after %ld milliseconds with %"
                  CURL_FORMAT_CURL_OFF_T " bytes received",
                  Curl_tvdiff(now, data->progress.t_startsingle),
                  k->bytecount);
          }
        }

        /* Force connection closed if the connection has indeed been used */
        if(data->mstate > CURLM_STATE_DO) {
          connclose(data->easy_conn, "Disconnected with pending data");
          disconnect_conn = TRUE;
        }
        result = CURLE_OPERATION_TIMEDOUT;
        (void)multi_done(&data->easy_conn, result, TRUE);
        /* Skip the statemachine and go directly to error handling section. */
        goto statemachine_end;
      }
    }

    switch(data->mstate) {
    case CURLM_STATE_INIT:
      /* init this transfer. */
      result=Curl_pretransfer(data);

      if(!result) {
        /* after init, go CONNECT */
        multistate(data, CURLM_STATE_CONNECT);
        Curl_pgrsTime(data, TIMER_STARTOP);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      break;

    case CURLM_STATE_CONNECT_PEND:
      /* We will stay here until there is a connection available. Then
         we try again in the CURLM_STATE_CONNECT state. */
      break;

    case CURLM_STATE_CONNECT:
      /* Connect. We want to get a connection identifier filled in. */
      Curl_pgrsTime(data, TIMER_STARTSINGLE);
      result = Curl_connect(data, &data->easy_conn,
                            &async, &protocol_connect);
      if(CURLE_NO_CONNECTION_AVAILABLE == result) {
        /* There was no connection available. We will go to the pending
           state and wait for an available connection. */
        multistate(data, CURLM_STATE_CONNECT_PEND);

        /* add this handle to the list of connect-pending handles */
        if(!Curl_llist_insert_next(multi->pending, multi->pending->tail, data))
          result = CURLE_OUT_OF_MEMORY;
        else
          result = CURLE_OK;
        break;
      }

      if(!result) {
        /* Add this handle to the send or pend pipeline */
        result = Curl_add_handle_to_pipeline(data, data->easy_conn);
        if(result)
          disconnect_conn = TRUE;
        else {
          if(async)
            /* We're now waiting for an asynchronous name lookup */
            multistate(data, CURLM_STATE_WAITRESOLVE);
          else {
            /* after the connect has been sent off, go WAITCONNECT unless the
               protocol connect is already done and we can go directly to
               WAITDO or DO! */
            rc = CURLM_CALL_MULTI_PERFORM;

            if(protocol_connect)
              multistate(data, Curl_pipeline_wanted(multi, CURLPIPE_HTTP1)?
                         CURLM_STATE_WAITDO:CURLM_STATE_DO);
            else {
#ifndef CURL_DISABLE_HTTP
              if(data->easy_conn->tunnel_state[FIRSTSOCKET] == TUNNEL_CONNECT)
                multistate(data, CURLM_STATE_WAITPROXYCONNECT);
              else
#endif
                multistate(data, CURLM_STATE_WAITCONNECT);
            }
          }
        }
      }
      break;

    case CURLM_STATE_WAITRESOLVE:
      /* awaiting an asynch name resolve to complete */
    {
      struct Curl_dns_entry *dns = NULL;
      struct connectdata *conn = data->easy_conn;
      const char *hostname;

      if(conn->bits.proxy)
        hostname = conn->proxy.name;
      else if(conn->bits.conn_to_host)
        hostname = conn->conn_to_host.name;
      else
        hostname = conn->host.name;

      /* check if we have the name resolved by now */
      dns = Curl_fetch_addr(conn, hostname, (int)conn->port);

      if(dns) {
#ifdef CURLRES_ASYNCH
        conn->async.dns = dns;
        conn->async.done = TRUE;
#endif
        result = CURLE_OK;
        infof(data, "Hostname '%s' was found in DNS cache\n", hostname);
      }

      if(!dns)
        result = Curl_resolver_is_resolved(data->easy_conn, &dns);

      /* Update sockets here, because the socket(s) may have been
         closed and the application thus needs to be told, even if it
         is likely that the same socket(s) will again be used further
         down.  If the name has not yet been resolved, it is likely
         that new sockets have been opened in an attempt to contact
         another resolver. */
      singlesocket(multi, data);

      if(dns) {
        /* Perform the next step in the connection phase, and then move on
           to the WAITCONNECT state */
        result = Curl_async_resolved(data->easy_conn, &protocol_connect);

        if(result)
          /* if Curl_async_resolved() returns failure, the connection struct
             is already freed and gone */
          data->easy_conn = NULL;           /* no more connection */
        else {
          /* call again please so that we get the next socket setup */
          rc = CURLM_CALL_MULTI_PERFORM;
          if(protocol_connect)
            multistate(data, Curl_pipeline_wanted(multi, CURLPIPE_HTTP1)?
                       CURLM_STATE_WAITDO:CURLM_STATE_DO);
          else {
#ifndef CURL_DISABLE_HTTP
            if(data->easy_conn->tunnel_state[FIRSTSOCKET] == TUNNEL_CONNECT)
              multistate(data, CURLM_STATE_WAITPROXYCONNECT);
            else
#endif
              multistate(data, CURLM_STATE_WAITCONNECT);
          }
        }
      }

      if(result) {
        /* failure detected */
        disconnect_conn = TRUE;
        break;
      }
    }
    break;

#ifndef CURL_DISABLE_HTTP
    case CURLM_STATE_WAITPROXYCONNECT:
      /* this is HTTP-specific, but sending CONNECT to a proxy is HTTP... */
      result = Curl_http_connect(data->easy_conn, &protocol_connect);

      if(data->easy_conn->bits.proxy_connect_closed) {
        rc = CURLM_CALL_MULTI_PERFORM;
        /* connect back to proxy again */
        result = CURLE_OK;
        multi_done(&data->easy_conn, CURLE_OK, FALSE);
        multistate(data, CURLM_STATE_CONNECT);
      }
      else if(!result) {
        if(data->easy_conn->tunnel_state[FIRSTSOCKET] == TUNNEL_COMPLETE) {
          rc = CURLM_CALL_MULTI_PERFORM;
          /* initiate protocol connect phase */
          multistate(data, CURLM_STATE_SENDPROTOCONNECT);
        }
      }
      break;
#endif

    case CURLM_STATE_WAITCONNECT:
      /* awaiting a completion of an asynch TCP connect */
      result = Curl_is_connected(data->easy_conn, FIRSTSOCKET, &connected);
      if(connected && !result) {
        rc = CURLM_CALL_MULTI_PERFORM;
        multistate(data, data->easy_conn->bits.tunnel_proxy?
                   CURLM_STATE_WAITPROXYCONNECT:
                   CURLM_STATE_SENDPROTOCONNECT);
      }
      else if(result) {
        /* failure detected */
        /* Just break, the cleaning up is handled all in one place */
        disconnect_conn = TRUE;
        break;
      }
      break;

    case CURLM_STATE_SENDPROTOCONNECT:
      result = Curl_protocol_connect(data->easy_conn, &protocol_connect);
      if(!protocol_connect)
        /* switch to waiting state */
        multistate(data, CURLM_STATE_PROTOCONNECT);
      else if(!result) {
        /* protocol connect has completed, go WAITDO or DO */
        multistate(data, Curl_pipeline_wanted(multi, CURLPIPE_HTTP1)?
                   CURLM_STATE_WAITDO:CURLM_STATE_DO);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else if(result) {
        /* failure detected */
        Curl_posttransfer(data);
        multi_done(&data->easy_conn, result, TRUE);
        disconnect_conn = TRUE;
      }
      break;

    case CURLM_STATE_PROTOCONNECT:
      /* protocol-specific connect phase */
      result = Curl_protocol_connecting(data->easy_conn, &protocol_connect);
      if(!result && protocol_connect) {
        /* after the connect has completed, go WAITDO or DO */
        multistate(data, Curl_pipeline_wanted(multi, CURLPIPE_HTTP1)?
                   CURLM_STATE_WAITDO:CURLM_STATE_DO);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else if(result) {
        /* failure detected */
        Curl_posttransfer(data);
        multi_done(&data->easy_conn, result, TRUE);
        disconnect_conn = TRUE;
      }
      break;

    case CURLM_STATE_WAITDO:
      /* Wait for our turn to DO when we're pipelining requests */
      if(Curl_pipeline_checkget_write(data, data->easy_conn)) {
        /* Grabbed the channel */
        multistate(data, CURLM_STATE_DO);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      break;

    case CURLM_STATE_DO:
      if(data->set.connect_only) {
        /* keep connection open for application to use the socket */
        connkeep(data->easy_conn, "CONNECT_ONLY");
        multistate(data, CURLM_STATE_DONE);
        result = CURLE_OK;
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else {
        /* Perform the protocol's DO action */
        result = multi_do(&data->easy_conn, &dophase_done);

        /* When multi_do() returns failure, data->easy_conn might be NULL! */

        if(!result) {
          if(!dophase_done) {
            /* some steps needed for wildcard matching */
            if(data->set.wildcardmatch) {
              struct WildcardData *wc = &data->wildcard;
              if(wc->state == CURLWC_DONE || wc->state == CURLWC_SKIP) {
                /* skip some states if it is important */
                multi_done(&data->easy_conn, CURLE_OK, FALSE);
                multistate(data, CURLM_STATE_DONE);
                rc = CURLM_CALL_MULTI_PERFORM;
                break;
              }
            }
            /* DO was not completed in one function call, we must continue
               DOING... */
            multistate(data, CURLM_STATE_DOING);
            rc = CURLM_OK;
          }

          /* after DO, go DO_DONE... or DO_MORE */
          else if(data->easy_conn->bits.do_more) {
            /* we're supposed to do more, but we need to sit down, relax
               and wait a little while first */
            multistate(data, CURLM_STATE_DO_MORE);
            rc = CURLM_OK;
          }
          else {
            /* we're done with the DO, now DO_DONE */
            multistate(data, CURLM_STATE_DO_DONE);
            rc = CURLM_CALL_MULTI_PERFORM;
          }
        }
        else if((CURLE_SEND_ERROR == result) &&
                data->easy_conn->bits.reuse) {
          /*
           * In this situation, a connection that we were trying to use
           * may have unexpectedly died.  If possible, send the connection
           * back to the CONNECT phase so we can try again.
           */
          char *newurl = NULL;
          followtype follow=FOLLOW_NONE;
          CURLcode drc;
          bool retry = FALSE;

          drc = Curl_retry_request(data->easy_conn, &newurl);
          if(drc) {
            /* a failure here pretty much implies an out of memory */
            result = drc;
            disconnect_conn = TRUE;
          }
          else
            retry = (newurl)?TRUE:FALSE;

          Curl_posttransfer(data);
          drc = multi_done(&data->easy_conn, result, FALSE);

          /* When set to retry the connection, we must to go back to
           * the CONNECT state */
          if(retry) {
            if(!drc || (drc == CURLE_SEND_ERROR)) {
              follow = FOLLOW_RETRY;
              drc = Curl_follow(data, newurl, follow);
              if(!drc) {
                multistate(data, CURLM_STATE_CONNECT);
                rc = CURLM_CALL_MULTI_PERFORM;
                result = CURLE_OK;
              }
              else {
                /* Follow failed */
                result = drc;
                free(newurl);
              }
            }
            else {
              /* done didn't return OK or SEND_ERROR */
              result = drc;
              free(newurl);
            }
          }
          else {
            /* Have error handler disconnect conn if we can't retry */
            disconnect_conn = TRUE;
            free(newurl);
          }
        }
        else {
          /* failure detected */
          Curl_posttransfer(data);
          if(data->easy_conn)
            multi_done(&data->easy_conn, result, FALSE);
          disconnect_conn = TRUE;
        }
      }
      break;

    case CURLM_STATE_DOING:
      /* we continue DOING until the DO phase is complete */
      result = Curl_protocol_doing(data->easy_conn,
                                   &dophase_done);
      if(!result) {
        if(dophase_done) {
          /* after DO, go DO_DONE or DO_MORE */
          multistate(data, data->easy_conn->bits.do_more?
                     CURLM_STATE_DO_MORE:
                     CURLM_STATE_DO_DONE);
          rc = CURLM_CALL_MULTI_PERFORM;
        } /* dophase_done */
      }
      else {
        /* failure detected */
        Curl_posttransfer(data);
        multi_done(&data->easy_conn, result, FALSE);
        disconnect_conn = TRUE;
      }
      break;

    case CURLM_STATE_DO_MORE:
      /*
       * When we are connected, DO MORE and then go DO_DONE
       */
      result = multi_do_more(data->easy_conn, &control);

      /* No need to remove this handle from the send pipeline here since that
         is done in multi_done() */
      if(!result) {
        if(control) {
          /* if positive, advance to DO_DONE
             if negative, go back to DOING */
          multistate(data, control==1?
                     CURLM_STATE_DO_DONE:
                     CURLM_STATE_DOING);
          rc = CURLM_CALL_MULTI_PERFORM;
        }
        else
          /* stay in DO_MORE */
          rc = CURLM_OK;
      }
      else {
        /* failure detected */
        Curl_posttransfer(data);
        multi_done(&data->easy_conn, result, FALSE);
        disconnect_conn = TRUE;
      }
      break;

    case CURLM_STATE_DO_DONE:
      /* Move ourselves from the send to recv pipeline */
      Curl_move_handle_from_send_to_recv_pipe(data, data->easy_conn);
      /* Check if we can move pending requests to send pipe */
      Curl_multi_process_pending_handles(multi);

      /* Only perform the transfer if there's a good socket to work with.
         Having both BAD is a signal to skip immediately to DONE */
      if((data->easy_conn->sockfd != CURL_SOCKET_BAD) ||
         (data->easy_conn->writesockfd != CURL_SOCKET_BAD))
        multistate(data, CURLM_STATE_WAITPERFORM);
      else
        multistate(data, CURLM_STATE_DONE);
      rc = CURLM_CALL_MULTI_PERFORM;
      break;

    case CURLM_STATE_WAITPERFORM:
      /* Wait for our turn to PERFORM */
      if(Curl_pipeline_checkget_read(data, data->easy_conn)) {
        /* Grabbed the channel */
        multistate(data, CURLM_STATE_PERFORM);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      break;

    case CURLM_STATE_TOOFAST: /* limit-rate exceeded in either direction */
      /* if both rates are within spec, resume transfer */
      if(Curl_pgrsUpdate(data->easy_conn))
        result = CURLE_ABORTED_BY_CALLBACK;
      else
        result = Curl_speedcheck(data, now);

      if(( (data->set.max_send_speed == 0) ||
           (data->progress.ulspeed < data->set.max_send_speed))  &&
         ( (data->set.max_recv_speed == 0) ||
           (data->progress.dlspeed < data->set.max_recv_speed)))
        multistate(data, CURLM_STATE_PERFORM);
      break;

    case CURLM_STATE_PERFORM:
    {
      char *newurl = NULL;
      bool retry = FALSE;

      /* check if over send speed */
      if((data->set.max_send_speed > 0) &&
         (data->progress.ulspeed > data->set.max_send_speed)) {
        int buffersize;

        multistate(data, CURLM_STATE_TOOFAST);

        /* calculate upload rate-limitation timeout. */
        buffersize = (int)(data->set.buffer_size ?
                           data->set.buffer_size : BUFSIZE);
        timeout_ms = Curl_sleep_time(data->set.max_send_speed,
                                     data->progress.ulspeed, buffersize);
        Curl_expire_latest(data, timeout_ms);
        break;
      }

      /* check if over recv speed */
      if((data->set.max_recv_speed > 0) &&
         (data->progress.dlspeed > data->set.max_recv_speed)) {
        int buffersize;

        multistate(data, CURLM_STATE_TOOFAST);

        /* Calculate download rate-limitation timeout. */
        buffersize = (int)(data->set.buffer_size ?
                           data->set.buffer_size : BUFSIZE);
        timeout_ms = Curl_sleep_time(data->set.max_recv_speed,
                                     data->progress.dlspeed, buffersize);
        Curl_expire_latest(data, timeout_ms);
        break;
      }

      /* read/write data if it is ready to do so */
      result = Curl_readwrite(data->easy_conn, data, &done);

      k = &data->req;

      if(!(k->keepon & KEEP_RECV))
        /* We're done receiving */
        Curl_pipeline_leave_read(data->easy_conn);

      if(!(k->keepon & KEEP_SEND))
        /* We're done sending */
        Curl_pipeline_leave_write(data->easy_conn);

      if(done || (result == CURLE_RECV_ERROR)) {
        /* If CURLE_RECV_ERROR happens early enough, we assume it was a race
         * condition and the server closed the re-used connection exactly when
         * we wanted to use it, so figure out if that is indeed the case.
         */
        CURLcode ret = Curl_retry_request(data->easy_conn, &newurl);
        if(!ret)
          retry = (newurl)?TRUE:FALSE;

        if(retry) {
          /* if we are to retry, set the result to OK and consider the
             request as done */
          result = CURLE_OK;
          done = TRUE;
        }
      }

      if(result) {
        /*
         * The transfer phase returned error, we mark the connection to get
         * closed to prevent being re-used. This is because we can't possibly
         * know if the connection is in a good shape or not now.  Unless it is
         * a protocol which uses two "channels" like FTP, as then the error
         * happened in the data connection.
         */

        if(!(data->easy_conn->handler->flags & PROTOPT_DUAL) &&
           result != CURLE_HTTP2_STREAM)
          connclose(data->easy_conn, "Transfer returned error");

        Curl_posttransfer(data);
        multi_done(&data->easy_conn, result, FALSE);
      }
      else if(done) {
        followtype follow=FOLLOW_NONE;

        /* call this even if the readwrite function returned error */
        Curl_posttransfer(data);

        /* we're no longer receiving */
        Curl_removeHandleFromPipeline(data, data->easy_conn->recv_pipe);

        /* expire the new receiving pipeline head */
        if(data->easy_conn->recv_pipe->head)
          Curl_expire_latest(data->easy_conn->recv_pipe->head->ptr, 1);

        /* Check if we can move pending requests to send pipe */
        Curl_multi_process_pending_handles(multi);

        /* When we follow redirects or is set to retry the connection, we must
           to go back to the CONNECT state */
        if(data->req.newurl || retry) {
          if(!retry) {
            /* if the URL is a follow-location and not just a retried request
               then figure out the URL here */
            free(newurl);
            newurl = data->req.newurl;
            data->req.newurl = NULL;
            follow = FOLLOW_REDIR;
          }
          else
            follow = FOLLOW_RETRY;
          result = multi_done(&data->easy_conn, CURLE_OK, FALSE);
          if(!result) {
            result = Curl_follow(data, newurl, follow);
            if(!result) {
              multistate(data, CURLM_STATE_CONNECT);
              rc = CURLM_CALL_MULTI_PERFORM;
              newurl = NULL; /* handed over the memory ownership to
                                Curl_follow(), make sure we don't free() it
                                here */
            }
          }
        }
        else {
          /* after the transfer is done, go DONE */

          /* but first check to see if we got a location info even though we're
             not following redirects */
          if(data->req.location) {
            free(newurl);
            newurl = data->req.location;
            data->req.location = NULL;
            result = Curl_follow(data, newurl, FOLLOW_FAKE);
            if(!result)
              newurl = NULL; /* allocation was handed over Curl_follow() */
            else
              disconnect_conn = TRUE;
          }

          multistate(data, CURLM_STATE_DONE);
          rc = CURLM_CALL_MULTI_PERFORM;
        }
      }

      free(newurl);
      break;
    }

    case CURLM_STATE_DONE:
      /* this state is highly transient, so run another loop after this */
      rc = CURLM_CALL_MULTI_PERFORM;

      if(data->easy_conn) {
        CURLcode res;

        /* Remove ourselves from the receive pipeline, if we are there. */
        Curl_removeHandleFromPipeline(data, data->easy_conn->recv_pipe);
        /* Check if we can move pending requests to send pipe */
        Curl_multi_process_pending_handles(multi);

        /* post-transfer command */
        res = multi_done(&data->easy_conn, result, FALSE);

        /* allow a previously set error code take precedence */
        if(!result)
          result = res;

        /*
         * If there are other handles on the pipeline, multi_done won't set
         * easy_conn to NULL.  In such a case, curl_multi_remove_handle() can
         * access free'd data, if the connection is free'd and the handle
         * removed before we perform the processing in CURLM_STATE_COMPLETED
         */
        if(data->easy_conn)
          data->easy_conn = NULL;
      }

      if(data->set.wildcardmatch) {
        if(data->wildcard.state != CURLWC_DONE) {
          /* if a wildcard is set and we are not ending -> lets start again
             with CURLM_STATE_INIT */
          multistate(data, CURLM_STATE_INIT);
          break;
        }
      }

      /* after we have DONE what we're supposed to do, go COMPLETED, and
         it doesn't matter what the multi_done() returned! */
      multistate(data, CURLM_STATE_COMPLETED);
      break;

    case CURLM_STATE_COMPLETED:
      /* this is a completed transfer, it is likely to still be connected */

      /* This node should be delinked from the list now and we should post
         an information message that we are complete. */

      /* Important: reset the conn pointer so that we don't point to memory
         that could be freed anytime */
      data->easy_conn = NULL;

      Curl_expire(data, 0); /* stop all timers */
      break;

    case CURLM_STATE_MSGSENT:
      data->result = result;
      return CURLM_OK; /* do nothing */

    default:
      return CURLM_INTERNAL_ERROR;
    }
    statemachine_end:

    if(data->mstate < CURLM_STATE_COMPLETED) {
      if(result) {
        /*
         * If an error was returned, and we aren't in completed state now,
         * then we go to completed and consider this transfer aborted.
         */

        /* NOTE: no attempt to disconnect connections must be made
           in the case blocks above - cleanup happens only here */

        data->state.pipe_broke = FALSE;

        /* Check if we can move pending requests to send pipe */
        Curl_multi_process_pending_handles(multi);

        if(data->easy_conn) {
          /* if this has a connection, unsubscribe from the pipelines */
          Curl_pipeline_leave_write(data->easy_conn);
          Curl_pipeline_leave_read(data->easy_conn);
          Curl_removeHandleFromPipeline(data, data->easy_conn->send_pipe);
          Curl_removeHandleFromPipeline(data, data->easy_conn->recv_pipe);

          if(disconnect_conn) {
            /* Don't attempt to send data over a connection that timed out */
            bool dead_connection = result == CURLE_OPERATION_TIMEDOUT;
            /* disconnect properly */
            Curl_disconnect(data->easy_conn, dead_connection);

            /* This is where we make sure that the easy_conn pointer is reset.
               We don't have to do this in every case block above where a
               failure is detected */
            data->easy_conn = NULL;
          }
        }
        else if(data->mstate == CURLM_STATE_CONNECT) {
          /* Curl_connect() failed */
          (void)Curl_posttransfer(data);
        }

        multistate(data, CURLM_STATE_COMPLETED);
      }
      /* if there's still a connection to use, call the progress function */
      else if(data->easy_conn && Curl_pgrsUpdate(data->easy_conn)) {
        /* aborted due to progress callback return code must close the
           connection */
        result = CURLE_ABORTED_BY_CALLBACK;
        connclose(data->easy_conn, "Aborted by callback");

        /* if not yet in DONE state, go there, otherwise COMPLETED */
        multistate(data, (data->mstate < CURLM_STATE_DONE)?
                   CURLM_STATE_DONE: CURLM_STATE_COMPLETED);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
    }

    if(CURLM_STATE_COMPLETED == data->mstate) {
      /* now fill in the Curl_message with this info */
      msg = &data->msg;

      msg->extmsg.msg = CURLMSG_DONE;
      msg->extmsg.easy_handle = data;
      msg->extmsg.data.result = result;

      rc = multi_addmsg(multi, msg);

      multistate(data, CURLM_STATE_MSGSENT);
    }
  } while((rc == CURLM_CALL_MULTI_PERFORM) || multi_ischanged(multi, FALSE));

  data->result = result;


  return rc;
}


CURLMcode curl_multi_perform(CURLM *multi_handle, int *running_handles)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct SessionHandle *data;
  CURLMcode returncode=CURLM_OK;
  struct Curl_tree *t;
  struct timeval now = Curl_tvnow();

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  data=multi->easyp;
  while(data) {
    CURLMcode result;
    SIGPIPE_VARIABLE(pipe_st);

    sigpipe_ignore(data, &pipe_st);
    result = multi_runsingle(multi, now, data);
    sigpipe_restore(&pipe_st);

    if(result)
      returncode = result;

    data = data->next; /* operate on next handle */
  }

  /*
   * Simply remove all expired timers from the splay since handles are dealt
   * with unconditionally by this function and curl_multi_timeout() requires
   * that already passed/handled expire times are removed from the splay.
   *
   * It is important that the 'now' value is set at the entry of this function
   * and not for the current time as it may have ticked a little while since
   * then and then we risk this loop to remove timers that actually have not
   * been handled!
   */
  do {
    multi->timetree = Curl_splaygetbest(now, multi->timetree, &t);
    if(t)
      /* the removed may have another timeout in queue */
      (void)add_next_timeout(now, multi, t->payload);

  } while(t);

  *running_handles = multi->num_alive;

  if(CURLM_OK >= returncode)
    update_timer(multi);

  return returncode;
}

static void close_all_connections(struct Curl_multi *multi)
{
  struct connectdata *conn;

  conn = Curl_conncache_find_first_connection(&multi->conn_cache);
  while(conn) {
    SIGPIPE_VARIABLE(pipe_st);
    conn->data = multi->closure_handle;

    sigpipe_ignore(conn->data, &pipe_st);
    /* This will remove the connection from the cache */
    (void)Curl_disconnect(conn, FALSE);
    sigpipe_restore(&pipe_st);

    conn = Curl_conncache_find_first_connection(&multi->conn_cache);
  }
}

CURLMcode curl_multi_cleanup(CURLM *multi_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct SessionHandle *data;
  struct SessionHandle *nextdata;

  if(GOOD_MULTI_HANDLE(multi)) {
    bool restore_pipe = FALSE;
    SIGPIPE_VARIABLE(pipe_st);

    multi->type = 0; /* not good anymore */

    /* Close all the connections in the connection cache */
    close_all_connections(multi);

    if(multi->closure_handle) {
      sigpipe_ignore(multi->closure_handle, &pipe_st);
      restore_pipe = TRUE;

      multi->closure_handle->dns.hostcache = &multi->hostcache;
      Curl_hostcache_clean(multi->closure_handle,
                           multi->closure_handle->dns.hostcache);

      Curl_close(multi->closure_handle);
    }

    Curl_hash_destroy(&multi->sockhash);
    Curl_conncache_destroy(&multi->conn_cache);
    Curl_llist_destroy(multi->msglist, NULL);
    Curl_llist_destroy(multi->pending, NULL);

    /* remove all easy handles */
    data = multi->easyp;
    while(data) {
      nextdata=data->next;
      if(data->dns.hostcachetype == HCACHE_MULTI) {
        /* clear out the usage of the shared DNS cache */
        Curl_hostcache_clean(data, data->dns.hostcache);
        data->dns.hostcache = NULL;
        data->dns.hostcachetype = HCACHE_NONE;
      }

      /* Clear the pointer to the connection cache */
      data->state.conn_cache = NULL;
      data->multi = NULL; /* clear the association */

      data = nextdata;
    }

    Curl_hash_destroy(&multi->hostcache);

    /* Free the blacklists by setting them to NULL */
    Curl_pipeline_set_site_blacklist(NULL, &multi->pipelining_site_bl);
    Curl_pipeline_set_server_blacklist(NULL, &multi->pipelining_server_bl);

    free(multi);
    if(restore_pipe)
      sigpipe_restore(&pipe_st);

    return CURLM_OK;
  }
  else
    return CURLM_BAD_HANDLE;
}

/*
 * curl_multi_info_read()
 *
 * This function is the primary way for a multi/multi_socket application to
 * figure out if a transfer has ended. We MUST make this function as fast as
 * possible as it will be polled frequently and we MUST NOT scan any lists in
 * here to figure out things. We must scale fine to thousands of handles and
 * beyond. The current design is fully O(1).
 */

CURLMsg *curl_multi_info_read(CURLM *multi_handle, int *msgs_in_queue)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_message *msg;

  *msgs_in_queue = 0; /* default to none */

  if(GOOD_MULTI_HANDLE(multi) && Curl_llist_count(multi->msglist)) {
    /* there is one or more messages in the list */
    struct curl_llist_element *e;

    /* extract the head of the list to return */
    e = multi->msglist->head;

    msg = e->ptr;

    /* remove the extracted entry */
    Curl_llist_remove(multi->msglist, e, NULL);

    *msgs_in_queue = curlx_uztosi(Curl_llist_count(multi->msglist));

    return &msg->extmsg;
  }
  else
    return NULL;
}

/*
 * singlesocket() checks what sockets we deal with and their "action state"
 * and if we have a different state in any of those sockets from last time we
 * call the callback accordingly.
 */
static void singlesocket(struct Curl_multi *multi,
                         struct SessionHandle *data)
{
  curl_socket_t socks[MAX_SOCKSPEREASYHANDLE];
  int i;
  struct Curl_sh_entry *entry;
  curl_socket_t s;
  int num;
  unsigned int curraction;

  for(i=0; i< MAX_SOCKSPEREASYHANDLE; i++)
    socks[i] = CURL_SOCKET_BAD;

  /* Fill in the 'current' struct with the state as it is now: what sockets to
     supervise and for what actions */
  curraction = multi_getsock(data, socks, MAX_SOCKSPEREASYHANDLE);

  /* We have 0 .. N sockets already and we get to know about the 0 .. M
     sockets we should have from now on. Detect the differences, remove no
     longer supervised ones and add new ones */

  /* walk over the sockets we got right now */
  for(i=0; (i< MAX_SOCKSPEREASYHANDLE) &&
        (curraction & (GETSOCK_READSOCK(i) | GETSOCK_WRITESOCK(i)));
      i++) {
    int action = CURL_POLL_NONE;

    s = socks[i];

    /* get it from the hash */
    entry = sh_getentry(&multi->sockhash, s);

    if(curraction & GETSOCK_READSOCK(i))
      action |= CURL_POLL_IN;
    if(curraction & GETSOCK_WRITESOCK(i))
      action |= CURL_POLL_OUT;

    if(entry) {
      /* yeps, already present so check if it has the same action set */
      if(entry->action == action)
        /* same, continue */
        continue;
    }
    else {
      /* this is a socket we didn't have before, add it! */
      entry = sh_addentry(&multi->sockhash, s, data);
      if(!entry)
        /* fatal */
        return;
    }

    /* we know (entry != NULL) at this point, see the logic above */
    if(multi->socket_cb)
      multi->socket_cb(data,
                       s,
                       action,
                       multi->socket_userp,
                       entry->socketp);

    entry->action = action; /* store the current action state */
  }

  num = i; /* number of sockets */

  /* when we've walked over all the sockets we should have right now, we must
     make sure to detect sockets that are removed */
  for(i=0; i< data->numsocks; i++) {
    int j;
    s = data->sockets[i];
    for(j=0; j<num; j++) {
      if(s == socks[j]) {
        /* this is still supervised */
        s = CURL_SOCKET_BAD;
        break;
      }
    }

    entry = sh_getentry(&multi->sockhash, s);
    if(entry) {
      /* this socket has been removed. Tell the app to remove it */
      bool remove_sock_from_hash = TRUE;

      /* check if the socket to be removed serves a connection which has
         other easy-s in a pipeline. In this case the socket should not be
         removed. */
      struct connectdata *easy_conn = data->easy_conn;
      if(easy_conn) {
        if(easy_conn->recv_pipe && easy_conn->recv_pipe->size > 1) {
          /* the handle should not be removed from the pipe yet */
          remove_sock_from_hash = FALSE;

          /* Update the sockhash entry to instead point to the next in line
             for the recv_pipe, or the first (in case this particular easy
             isn't already) */
          if(entry->easy == data) {
            if(Curl_recvpipe_head(data, easy_conn))
              entry->easy = easy_conn->recv_pipe->head->next->ptr;
            else
              entry->easy = easy_conn->recv_pipe->head->ptr;
          }
        }
        if(easy_conn->send_pipe  && easy_conn->send_pipe->size > 1) {
          /* the handle should not be removed from the pipe yet */
          remove_sock_from_hash = FALSE;

          /* Update the sockhash entry to instead point to the next in line
             for the send_pipe, or the first (in case this particular easy
             isn't already) */
          if(entry->easy == data) {
            if(Curl_sendpipe_head(data, easy_conn))
              entry->easy = easy_conn->send_pipe->head->next->ptr;
            else
              entry->easy = easy_conn->send_pipe->head->ptr;
          }
        }
        /* Don't worry about overwriting recv_pipe head with send_pipe_head,
           when action will be asked on the socket (see multi_socket()), the
           head of the correct pipe will be taken according to the
           action. */
      }

      if(remove_sock_from_hash) {
        /* in this case 'entry' is always non-NULL */
        if(multi->socket_cb)
          multi->socket_cb(data,
                           s,
                           CURL_POLL_REMOVE,
                           multi->socket_userp,
                           entry->socketp);
        sh_delentry(&multi->sockhash, s);
      }
    } /* if sockhash entry existed */
  } /* for loop over numsocks */

  memcpy(data->sockets, socks, num*sizeof(curl_socket_t));
  data->numsocks = num;
}

/*
 * Curl_multi_closed()
 *
 * Used by the connect code to tell the multi_socket code that one of the
 * sockets we were using is about to be closed.  This function will then
 * remove it from the sockethash for this handle to make the multi_socket API
 * behave properly, especially for the case when libcurl will create another
 * socket again and it gets the same file descriptor number.
 */

void Curl_multi_closed(struct connectdata *conn, curl_socket_t s)
{
  struct Curl_multi *multi = conn->data->multi;
  if(multi) {
    /* this is set if this connection is part of a handle that is added to
       a multi handle, and only then this is necessary */
    struct Curl_sh_entry *entry = sh_getentry(&multi->sockhash, s);

    if(entry) {
      if(multi->socket_cb)
        multi->socket_cb(conn->data, s, CURL_POLL_REMOVE,
                         multi->socket_userp,
                         entry->socketp);

      /* now remove it from the socket hash */
      sh_delentry(&multi->sockhash, s);
    }
  }
}



/*
 * add_next_timeout()
 *
 * Each SessionHandle has a list of timeouts. The add_next_timeout() is called
 * when it has just been removed from the splay tree because the timeout has
 * expired. This function is then to advance in the list to pick the next
 * timeout to use (skip the already expired ones) and add this node back to
 * the splay tree again.
 *
 * The splay tree only has each sessionhandle as a single node and the nearest
 * timeout is used to sort it on.
 */
static CURLMcode add_next_timeout(struct timeval now,
                                  struct Curl_multi *multi,
                                  struct SessionHandle *d)
{
  struct timeval *tv = &d->state.expiretime;
  struct curl_llist *list = d->state.timeoutlist;
  struct curl_llist_element *e;

  /* move over the timeout list for this specific handle and remove all
     timeouts that are now passed tense and store the next pending
     timeout in *tv */
  for(e = list->head; e;) {
    struct curl_llist_element *n = e->next;
    long diff = curlx_tvdiff(*(struct timeval *)e->ptr, now);
    if(diff <= 0)
      /* remove outdated entry */
      Curl_llist_remove(list, e, NULL);
    else
      /* the list is sorted so get out on the first mismatch */
      break;
    e = n;
  }
  e = list->head;
  if(!e) {
    /* clear the expire times within the handles that we remove from the
       splay tree */
    tv->tv_sec = 0;
    tv->tv_usec = 0;
  }
  else {
    /* copy the first entry to 'tv' */
    memcpy(tv, e->ptr, sizeof(*tv));

    /* remove first entry from list */
    Curl_llist_remove(list, e, NULL);

    /* insert this node again into the splay */
    multi->timetree = Curl_splayinsert(*tv, multi->timetree,
                                       &d->state.timenode);
  }
  return CURLM_OK;
}

static CURLMcode multi_socket(struct Curl_multi *multi,
                              bool checkall,
                              curl_socket_t s,
                              int ev_bitmask,
                              int *running_handles)
{
  CURLMcode result = CURLM_OK;
  struct SessionHandle *data = NULL;
  struct Curl_tree *t;
  struct timeval now = Curl_tvnow();

  if(checkall) {
    /* *perform() deals with running_handles on its own */
    result = curl_multi_perform(multi, running_handles);

    /* walk through each easy handle and do the socket state change magic
       and callbacks */
    if(result != CURLM_BAD_HANDLE) {
      data=multi->easyp;
      while(data) {
        singlesocket(multi, data);
        data = data->next;
      }
    }

    /* or should we fall-through and do the timer-based stuff? */
    return result;
  }
  else if(s != CURL_SOCKET_TIMEOUT) {

    struct Curl_sh_entry *entry = sh_getentry(&multi->sockhash, s);

    if(!entry)
      /* Unmatched socket, we can't act on it but we ignore this fact.  In
         real-world tests it has been proved that libevent can in fact give
         the application actions even though the socket was just previously
         asked to get removed, so thus we better survive stray socket actions
         and just move on. */
      ;
    else {
      SIGPIPE_VARIABLE(pipe_st);

      data = entry->easy;

      if(data->magic != CURLEASY_MAGIC_NUMBER)
        /* bad bad bad bad bad bad bad */
        return CURLM_INTERNAL_ERROR;

      /* If the pipeline is enabled, take the handle which is in the head of
         the pipeline. If we should write into the socket, take the send_pipe
         head.  If we should read from the socket, take the recv_pipe head. */
      if(data->easy_conn) {
        if((ev_bitmask & CURL_POLL_OUT) &&
           data->easy_conn->send_pipe &&
           data->easy_conn->send_pipe->head)
          data = data->easy_conn->send_pipe->head->ptr;
        else if((ev_bitmask & CURL_POLL_IN) &&
                data->easy_conn->recv_pipe &&
                data->easy_conn->recv_pipe->head)
          data = data->easy_conn->recv_pipe->head->ptr;
      }

      if(data->easy_conn &&
         !(data->easy_conn->handler->flags & PROTOPT_DIRLOCK))
        /* set socket event bitmask if they're not locked */
        data->easy_conn->cselect_bits = ev_bitmask;

      sigpipe_ignore(data, &pipe_st);
      result = multi_runsingle(multi, now, data);
      sigpipe_restore(&pipe_st);

      if(data->easy_conn &&
         !(data->easy_conn->handler->flags & PROTOPT_DIRLOCK))
        /* clear the bitmask only if not locked */
        data->easy_conn->cselect_bits = 0;

      if(CURLM_OK >= result)
        /* get the socket(s) and check if the state has been changed since
           last */
        singlesocket(multi, data);

      /* Now we fall-through and do the timer-based stuff, since we don't want
         to force the user to have to deal with timeouts as long as at least
         one connection in fact has traffic. */

      data = NULL; /* set data to NULL again to avoid calling
                      multi_runsingle() in case there's no need to */
      now = Curl_tvnow(); /* get a newer time since the multi_runsingle() loop
                             may have taken some time */
    }
  }
  else {
    /* Asked to run due to time-out. Clear the 'lastcall' variable to force
       update_timer() to trigger a callback to the app again even if the same
       timeout is still the one to run after this call. That handles the case
       when the application asks libcurl to run the timeout prematurely. */
    memset(&multi->timer_lastcall, 0, sizeof(multi->timer_lastcall));
  }

  /*
   * The loop following here will go on as long as there are expire-times left
   * to process in the splay and 'data' will be re-assigned for every expired
   * handle we deal with.
   */
  do {
    /* the first loop lap 'data' can be NULL */
    if(data) {
      SIGPIPE_VARIABLE(pipe_st);

      sigpipe_ignore(data, &pipe_st);
      result = multi_runsingle(multi, now, data);
      sigpipe_restore(&pipe_st);

      if(CURLM_OK >= result)
        /* get the socket(s) and check if the state has been changed since
           last */
        singlesocket(multi, data);
    }

    /* Check if there's one (more) expired timer to deal with! This function
       extracts a matching node if there is one */

    multi->timetree = Curl_splaygetbest(now, multi->timetree, &t);
    if(t) {
      data = t->payload; /* assign this for next loop */
      (void)add_next_timeout(now, multi, t->payload);
    }

  } while(t);

  *running_handles = multi->num_alive;
  return result;
}

#undef curl_multi_setopt
CURLMcode curl_multi_setopt(CURLM *multi_handle,
                            CURLMoption option, ...)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  CURLMcode res = CURLM_OK;
  va_list param;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  va_start(param, option);

  switch(option) {
  case CURLMOPT_SOCKETFUNCTION:
    multi->socket_cb = va_arg(param, curl_socket_callback);
    break;
  case CURLMOPT_SOCKETDATA:
    multi->socket_userp = va_arg(param, void *);
    break;
  case CURLMOPT_PUSHFUNCTION:
    multi->push_cb = va_arg(param, curl_push_callback);
    break;
  case CURLMOPT_PUSHDATA:
    multi->push_userp = va_arg(param, void *);
    break;
  case CURLMOPT_PIPELINING:
    multi->pipelining = va_arg(param, long);
    break;
  case CURLMOPT_TIMERFUNCTION:
    multi->timer_cb = va_arg(param, curl_multi_timer_callback);
    break;
  case CURLMOPT_TIMERDATA:
    multi->timer_userp = va_arg(param, void *);
    break;
  case CURLMOPT_MAXCONNECTS:
    multi->maxconnects = va_arg(param, long);
    break;
  case CURLMOPT_MAX_HOST_CONNECTIONS:
    multi->max_host_connections = va_arg(param, long);
    break;
  case CURLMOPT_MAX_PIPELINE_LENGTH:
    multi->max_pipeline_length = va_arg(param, long);
    break;
  case CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE:
    multi->content_length_penalty_size = va_arg(param, long);
    break;
  case CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE:
    multi->chunk_length_penalty_size = va_arg(param, long);
    break;
  case CURLMOPT_PIPELINING_SITE_BL:
    res = Curl_pipeline_set_site_blacklist(va_arg(param, char **),
                                           &multi->pipelining_site_bl);
    break;
  case CURLMOPT_PIPELINING_SERVER_BL:
    res = Curl_pipeline_set_server_blacklist(va_arg(param, char **),
                                             &multi->pipelining_server_bl);
    break;
  case CURLMOPT_MAX_TOTAL_CONNECTIONS:
    multi->max_total_connections = va_arg(param, long);
    break;
  default:
    res = CURLM_UNKNOWN_OPTION;
    break;
  }
  va_end(param);
  return res;
}

/* we define curl_multi_socket() in the public multi.h header */
#undef curl_multi_socket

CURLMcode curl_multi_socket(CURLM *multi_handle, curl_socket_t s,
                            int *running_handles)
{
  CURLMcode result = multi_socket((struct Curl_multi *)multi_handle, FALSE, s,
                                  0, running_handles);
  if(CURLM_OK >= result)
    update_timer((struct Curl_multi *)multi_handle);
  return result;
}

CURLMcode curl_multi_socket_action(CURLM *multi_handle, curl_socket_t s,
                                   int ev_bitmask, int *running_handles)
{
  CURLMcode result = multi_socket((struct Curl_multi *)multi_handle, FALSE, s,
                                  ev_bitmask, running_handles);
  if(CURLM_OK >= result)
    update_timer((struct Curl_multi *)multi_handle);
  return result;
}

CURLMcode curl_multi_socket_all(CURLM *multi_handle, int *running_handles)

{
  CURLMcode result = multi_socket((struct Curl_multi *)multi_handle,
                                  TRUE, CURL_SOCKET_BAD, 0, running_handles);
  if(CURLM_OK >= result)
    update_timer((struct Curl_multi *)multi_handle);
  return result;
}

static CURLMcode multi_timeout(struct Curl_multi *multi,
                               long *timeout_ms)
{
  static struct timeval tv_zero = {0, 0};

  if(multi->timetree) {
    /* we have a tree of expire times */
    struct timeval now = Curl_tvnow();

    /* splay the lowest to the bottom */
    multi->timetree = Curl_splay(tv_zero, multi->timetree);

    if(Curl_splaycomparekeys(multi->timetree->key, now) > 0) {
      /* some time left before expiration */
      *timeout_ms = curlx_tvdiff(multi->timetree->key, now);
      if(!*timeout_ms)
        /*
         * Since we only provide millisecond resolution on the returned value
         * and the diff might be less than one millisecond here, we don't
         * return zero as that may cause short bursts of busyloops on fast
         * processors while the diff is still present but less than one
         * millisecond! instead we return 1 until the time is ripe.
         */
        *timeout_ms=1;
    }
    else
      /* 0 means immediately */
      *timeout_ms = 0;
  }
  else
    *timeout_ms = -1;

  return CURLM_OK;
}

CURLMcode curl_multi_timeout(CURLM *multi_handle,
                             long *timeout_ms)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  return multi_timeout(multi, timeout_ms);
}

/*
 * Tell the application it should update its timers, if it subscribes to the
 * update timer callback.
 */
static int update_timer(struct Curl_multi *multi)
{
  long timeout_ms;

  if(!multi->timer_cb)
    return 0;
  if(multi_timeout(multi, &timeout_ms)) {
    return -1;
  }
  if(timeout_ms < 0) {
    static const struct timeval none={0, 0};
    if(Curl_splaycomparekeys(none, multi->timer_lastcall)) {
      multi->timer_lastcall = none;
      /* there's no timeout now but there was one previously, tell the app to
         disable it */
      return multi->timer_cb((CURLM*)multi, -1, multi->timer_userp);
    }
    return 0;
  }

  /* When multi_timeout() is done, multi->timetree points to the node with the
   * timeout we got the (relative) time-out time for. We can thus easily check
   * if this is the same (fixed) time as we got in a previous call and then
   * avoid calling the callback again. */
  if(Curl_splaycomparekeys(multi->timetree->key, multi->timer_lastcall) == 0)
    return 0;

  multi->timer_lastcall = multi->timetree->key;

  return multi->timer_cb((CURLM*)multi, timeout_ms, multi->timer_userp);
}

/*
 * multi_freetimeout()
 *
 * Callback used by the llist system when a single timeout list entry is
 * destroyed.
 */
static void multi_freetimeout(void *user, void *entryptr)
{
  (void)user;

  /* the entry was plain malloc()'ed */
  free(entryptr);
}

/*
 * multi_addtimeout()
 *
 * Add a timestamp to the list of timeouts. Keep the list sorted so that head
 * of list is always the timeout nearest in time.
 *
 */
static CURLMcode
multi_addtimeout(struct curl_llist *timeoutlist,
                 struct timeval *stamp)
{
  struct curl_llist_element *e;
  struct timeval *timedup;
  struct curl_llist_element *prev = NULL;

  timedup = malloc(sizeof(*timedup));
  if(!timedup)
    return CURLM_OUT_OF_MEMORY;

  /* copy the timestamp */
  memcpy(timedup, stamp, sizeof(*timedup));

  if(Curl_llist_count(timeoutlist)) {
    /* find the correct spot in the list */
    for(e = timeoutlist->head; e; e = e->next) {
      struct timeval *checktime = e->ptr;
      long diff = curlx_tvdiff(*checktime, *timedup);
      if(diff > 0)
        break;
      prev = e;
    }

  }
  /* else
     this is the first timeout on the list */

  if(!Curl_llist_insert_next(timeoutlist, prev, timedup)) {
    free(timedup);
    return CURLM_OUT_OF_MEMORY;
  }

  return CURLM_OK;
}

/*
 * Curl_expire()
 *
 * given a number of milliseconds from now to use to set the 'act before
 * this'-time for the transfer, to be extracted by curl_multi_timeout()
 *
 * Note that the timeout will be added to a queue of timeouts if it defines a
 * moment in time that is later than the current head of queue.
 *
 * Pass zero to clear all timeout values for this handle.
*/
void Curl_expire(struct SessionHandle *data, long milli)
{
  struct Curl_multi *multi = data->multi;
  struct timeval *nowp = &data->state.expiretime;
  int rc;

  /* this is only interesting while there is still an associated multi struct
     remaining! */
  if(!multi)
    return;

  if(!milli) {
    /* No timeout, clear the time data. */
    if(nowp->tv_sec || nowp->tv_usec) {
      /* Since this is an cleared time, we must remove the previous entry from
         the splay tree */
      struct curl_llist *list = data->state.timeoutlist;

      rc = Curl_splayremovebyaddr(multi->timetree,
                                  &data->state.timenode,
                                  &multi->timetree);
      if(rc)
        infof(data, "Internal error clearing splay node = %d\n", rc);

      /* flush the timeout list too */
      while(list->size > 0)
        Curl_llist_remove(list, list->tail, NULL);

#ifdef DEBUGBUILD
      infof(data, "Expire cleared\n");
#endif
      nowp->tv_sec = 0;
      nowp->tv_usec = 0;
    }
  }
  else {
    struct timeval set;

    set = Curl_tvnow();
    set.tv_sec += milli/1000;
    set.tv_usec += (milli%1000)*1000;

    if(set.tv_usec >= 1000000) {
      set.tv_sec++;
      set.tv_usec -= 1000000;
    }

    if(nowp->tv_sec || nowp->tv_usec) {
      /* This means that the struct is added as a node in the splay tree.
         Compare if the new time is earlier, and only remove-old/add-new if it
         is. */
      long diff = curlx_tvdiff(set, *nowp);
      if(diff > 0) {
        /* the new expire time was later so just add it to the queue
           and get out */
        multi_addtimeout(data->state.timeoutlist, &set);
        return;
      }

      /* the new time is newer than the presently set one, so add the current
         to the queue and update the head */
      multi_addtimeout(data->state.timeoutlist, nowp);

      /* Since this is an updated time, we must remove the previous entry from
         the splay tree first and then re-add the new value */
      rc = Curl_splayremovebyaddr(multi->timetree,
                                  &data->state.timenode,
                                  &multi->timetree);
      if(rc)
        infof(data, "Internal error removing splay node = %d\n", rc);
    }

    *nowp = set;
    data->state.timenode.payload = data;
    multi->timetree = Curl_splayinsert(*nowp,
                                       multi->timetree,
                                       &data->state.timenode);
  }
#if 0
  Curl_splayprint(multi->timetree, 0, TRUE);
#endif
}

/*
 * Curl_expire_latest()
 *
 * This is like Curl_expire() but will only add a timeout node to the list of
 * timers if there is no timeout that will expire before the given time.
 *
 * Use this function if the code logic risks calling this function many times
 * or if there's no particular conditional wait in the code for this specific
 * time-out period to expire.
 *
 */
void Curl_expire_latest(struct SessionHandle *data, long milli)
{
  struct timeval *expire = &data->state.expiretime;

  struct timeval set;

  set = Curl_tvnow();
  set.tv_sec += milli / 1000;
  set.tv_usec += (milli % 1000) * 1000;

  if(set.tv_usec >= 1000000) {
    set.tv_sec++;
    set.tv_usec -= 1000000;
  }

  if(expire->tv_sec || expire->tv_usec) {
    /* This means that the struct is added as a node in the splay tree.
       Compare if the new time is earlier, and only remove-old/add-new if it
         is. */
    long diff = curlx_tvdiff(set, *expire);
    if(diff > 0)
      /* the new expire time was later than the top time, so just skip this */
      return;
  }

  /* Just add the timeout like normal */
  Curl_expire(data, milli);
}

CURLMcode curl_multi_assign(CURLM *multi_handle,
                            curl_socket_t s, void *hashp)
{
  struct Curl_sh_entry *there = NULL;
  struct Curl_multi *multi = (struct Curl_multi *)multi_handle;

  there = sh_getentry(&multi->sockhash, s);

  if(!there)
    return CURLM_BAD_SOCKET;

  there->socketp = hashp;

  return CURLM_OK;
}

size_t Curl_multi_max_host_connections(struct Curl_multi *multi)
{
  return multi ? multi->max_host_connections : 0;
}

size_t Curl_multi_max_total_connections(struct Curl_multi *multi)
{
  return multi ? multi->max_total_connections : 0;
}

curl_off_t Curl_multi_content_length_penalty_size(struct Curl_multi *multi)
{
  return multi ? multi->content_length_penalty_size : 0;
}

curl_off_t Curl_multi_chunk_length_penalty_size(struct Curl_multi *multi)
{
  return multi ? multi->chunk_length_penalty_size : 0;
}

struct curl_llist *Curl_multi_pipelining_site_bl(struct Curl_multi *multi)
{
  return multi->pipelining_site_bl;
}

struct curl_llist *Curl_multi_pipelining_server_bl(struct Curl_multi *multi)
{
  return multi->pipelining_server_bl;
}

void Curl_multi_process_pending_handles(struct Curl_multi *multi)
{
  struct curl_llist_element *e = multi->pending->head;

  while(e) {
    struct SessionHandle *data = e->ptr;
    struct curl_llist_element *next = e->next;

    if(data->mstate == CURLM_STATE_CONNECT_PEND) {
      multistate(data, CURLM_STATE_CONNECT);

      /* Remove this node from the list */
      Curl_llist_remove(multi->pending, e, NULL);

      /* Make sure that the handle will be processed soonish. */
      Curl_expire_latest(data, 1);
    }

    e = next; /* operate on next handle */
  }
}

#ifdef DEBUGBUILD
void Curl_multi_dump(const struct Curl_multi *multi_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct SessionHandle *data;
  int i;
  fprintf(stderr, "* Multi status: %d handles, %d alive\n",
          multi->num_easy, multi->num_alive);
  for(data=multi->easyp; data; data = data->next) {
    if(data->mstate < CURLM_STATE_COMPLETED) {
      /* only display handles that are not completed */
      fprintf(stderr, "handle %p, state %s, %d sockets\n",
              (void *)data,
              statename[data->mstate], data->numsocks);
      for(i=0; i < data->numsocks; i++) {
        curl_socket_t s = data->sockets[i];
        struct Curl_sh_entry *entry = sh_getentry(&multi->sockhash, s);

        fprintf(stderr, "%d ", (int)s);
        if(!entry) {
          fprintf(stderr, "INTERNAL CONFUSION\n");
          continue;
        }
        fprintf(stderr, "[%s %s] ",
                entry->action&CURL_POLL_IN?"RECVING":"",
                entry->action&CURL_POLL_OUT?"SENDING":"");
      }
      if(data->numsocks)
        fprintf(stderr, "\n");
    }
  }
}
#endif
