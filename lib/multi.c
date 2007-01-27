/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <curl/curl.h>

#include "urldata.h"
#include "transfer.h"
#include "url.h"
#include "connect.h"
#include "progress.h"
#include "memory.h"
#include "easyif.h"
#include "multiif.h"
#include "sendf.h"
#include "timeval.h"

/* The last #include file should be: */
#include "memdebug.h"

struct Curl_message {
  /* the 'CURLMsg' is the part that is visible to the external user */
  struct CURLMsg extmsg;
  struct Curl_message *next;
};

typedef enum {
  CURLM_STATE_INIT,        /* start in this state */
  CURLM_STATE_CONNECT,     /* resolve/connect has been sent off */
  CURLM_STATE_WAITRESOLVE, /* awaiting the resolve to finalize */
  CURLM_STATE_WAITCONNECT, /* awaiting the connect to finalize */
  CURLM_STATE_PROTOCONNECT, /* completing the protocol-specific connect
                               phase */
  CURLM_STATE_WAITDO,      /* wait for our turn to send the request */
  CURLM_STATE_DO,          /* start send off the request (part 1) */
  CURLM_STATE_DOING,       /* sending off the request (part 1) */
  CURLM_STATE_DO_MORE,     /* send off the request (part 2) */
  CURLM_STATE_DO_DONE,     /* done sending off request */
  CURLM_STATE_WAITPERFORM, /* wait for our turn to read the response */
  CURLM_STATE_PERFORM,     /* transfer data */
  CURLM_STATE_TOOFAST,     /* wait because limit-rate exceeded */
  CURLM_STATE_DONE,        /* post data transfer operation */
  CURLM_STATE_COMPLETED,   /* operation complete */
  CURLM_STATE_CANCELLED,   /* cancelled */

  CURLM_STATE_LAST /* not a true state, never use this */
} CURLMstate;

/* we support N sockets per easy handle. Set the corresponding bit to what
   action we should wait for */
#define MAX_SOCKSPEREASYHANDLE 5
#define GETSOCK_READABLE (0x00ff)
#define GETSOCK_WRITABLE (0xff00)

struct closure {
  struct closure *next; /* a simple one-way list of structs */
  struct SessionHandle *easy_handle;
};

struct Curl_one_easy {
  /* first, two fields for the linked list of these */
  struct Curl_one_easy *next;
  struct Curl_one_easy *prev;

  struct SessionHandle *easy_handle; /* the easy handle for this unit */
  struct connectdata *easy_conn;     /* the "unit's" connection */

  CURLMstate state;  /* the handle's state */
  CURLcode result;   /* previous result */

  struct Curl_message *msg; /* A pointer to one single posted message.
                               Cleanup should be done on this pointer NOT on
                               the linked list in Curl_multi.  This message
                               will be deleted when this handle is removed
                               from the multi-handle */
  int msg_num; /* number of messages left in 'msg' to return */

  /* Array with the plain socket numbers this handle takes care of, in no
     particular order. Note that all sockets are added to the sockhash, where
     the state etc are also kept. This array is mostly used to detect when a
     socket is to be removed from the hash. See singlesocket(). */
  curl_socket_t sockets[MAX_SOCKSPEREASYHANDLE];
  int numsocks;
};

#define CURL_MULTI_HANDLE 0x000bab1e

#define GOOD_MULTI_HANDLE(x) \
  ((x)&&(((struct Curl_multi *)x)->type == CURL_MULTI_HANDLE))
#define GOOD_EASY_HANDLE(x) \
 (((struct SessionHandle *)x)->magic == CURLEASY_MAGIC_NUMBER)

/* This is the struct known as CURLM on the outside */
struct Curl_multi {
  /* First a simple identifier to easier detect if a user mix up
     this multi handle with an easy handle. Set this to CURL_MULTI_HANDLE. */
  long type;

  /* We have a linked list with easy handles */
  struct Curl_one_easy easy;

  int num_easy; /* amount of entries in the linked list above. */
  int num_msgs; /* amount of messages in the easy handles */
  int num_alive; /* amount of easy handles that are added but have not yet
                    reached COMPLETE state */

  /* callback function and user data pointer for the *socket() API */
  curl_socket_callback socket_cb;
  void *socket_userp;

  /* Hostname cache */
  struct curl_hash *hostcache;

  /* timetree points to the splay-tree of time nodes to figure out expire
     times of all currently set timers */
  struct Curl_tree *timetree;

  /* 'sockhash' is the lookup hash for socket descriptor => easy handles (note
     the pluralis form, there can be more than one easy handle waiting on the
     same actual socket) */
  struct curl_hash *sockhash;

  /* Whether pipelining is enabled for this multi handle */
  bool pipelining_enabled;

  /* shared connection cache */
  struct conncache *connc;

  /* list of easy handles kept around for doing nice connection closures */
  struct closure *closure;

  /* timer callback and user data pointer for the *socket() API */
  curl_multi_timer_callback timer_cb;
  void *timer_userp;
  time_t timer_lastcall; /* the fixed time for the timeout for the previous
                            callback */
};

static bool multi_conn_using(struct Curl_multi *multi,
                             struct SessionHandle *data);
static void singlesocket(struct Curl_multi *multi,
                         struct Curl_one_easy *easy);
static void add_closure(struct Curl_multi *multi,
                        struct SessionHandle *data);
static int update_timer(struct Curl_multi *multi);

#ifdef CURLDEBUG
static const char *statename[]={
  "INIT",
  "CONNECT",
  "WAITRESOLVE",
  "WAITCONNECT",
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
  "CANCELLED"
};

void curl_multi_dump(CURLM *multi_handle);
#endif

/* always use this function to change state, to make debugging easier */
static void multistate(struct Curl_one_easy *easy, CURLMstate state)
{
#ifdef CURLDEBUG
  long index = -1;
#endif
  CURLMstate oldstate = easy->state;

  if(oldstate == state)
    /* don't bother when the new state is the same as the old state */
    return;

  easy->state = state;

#ifdef CURLDEBUG
  if(easy->state > CURLM_STATE_CONNECT &&
     easy->state < CURLM_STATE_COMPLETED)
    index = easy->easy_conn->connectindex;

  infof(easy->easy_handle,
        "STATE: %s => %s handle %p; (connection #%ld) \n",
        statename[oldstate], statename[easy->state],
        (char *)easy, index);
#endif
  if(state == CURLM_STATE_COMPLETED)
    /* changing to COMPLETED means there's one less easy handle 'alive' */
    easy->easy_handle->multi->num_alive--;
}

/*
 * We add one of these structs to the sockhash for a particular socket
 */

struct Curl_sh_entry {
  struct SessionHandle *easy;
  time_t timestamp;
  long inuse;
  int action;  /* what action READ/WRITE this socket waits for */
  curl_socket_t socket; /* mainly to ease debugging */
  void *socketp; /* settable by users with curl_multi_assign() */
};
/* bits for 'action' having no bits means this socket is not expecting any
   action */
#define SH_READ  1
#define SH_WRITE 2

/* make sure this socket is present in the hash for this handle */
static struct Curl_sh_entry *sh_addentry(struct curl_hash *sh,
                                         curl_socket_t s,
                                         struct SessionHandle *data)
{
  struct Curl_sh_entry *there =
    Curl_hash_pick(sh, (char *)&s, sizeof(curl_socket_t));
  struct Curl_sh_entry *check;

  if(there)
    /* it is present, return fine */
    return there;

  /* not present, add it */
  check = calloc(sizeof(struct Curl_sh_entry), 1);
  if(!check)
    return NULL; /* major failure */
  check->easy = data;
  check->socket = s;

  /* make/add new hash entry */
  if(NULL == Curl_hash_add(sh, (char *)&s, sizeof(curl_socket_t), check)) {
    free(check);
    return NULL; /* major failure */
  }

  return check; /* things are good in sockhash land */
}


/* delete the given socket + handle from the hash */
static void sh_delentry(struct curl_hash *sh, curl_socket_t s)
{
  struct Curl_sh_entry *there =
    Curl_hash_pick(sh, (char *)&s, sizeof(curl_socket_t));

  if(there) {
    /* this socket is in the hash */
    /* We remove the hash entry. (This'll end up in a call to
       sh_freeentry().) */
    Curl_hash_delete(sh, (char *)&s, sizeof(curl_socket_t));
  }
}

/*
 * free a sockhash entry
 */
static void sh_freeentry(void *freethis)
{
  struct Curl_sh_entry *p = (struct Curl_sh_entry *) freethis;

  free(p);
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
static struct curl_hash *sh_init(void)
{
  return Curl_hash_alloc(97, sh_freeentry);
}

CURLM *curl_multi_init(void)
{
  struct Curl_multi *multi = (void *)calloc(sizeof(struct Curl_multi), 1);

  if(!multi)
    return NULL;

  multi->type = CURL_MULTI_HANDLE;

  multi->hostcache = Curl_mk_dnscache();
  if(!multi->hostcache) {
    /* failure, free mem and bail out */
    free(multi);
    return NULL;
  }

  multi->sockhash = sh_init();
  if(!multi->sockhash) {
    /* failure, free mem and bail out */
    Curl_hash_destroy(multi->hostcache);
    free(multi);
    return NULL;
  }

  multi->connc = Curl_mk_connc(CONNCACHE_MULTI, -1);
  if(!multi->connc) {
    Curl_hash_destroy(multi->hostcache);
    free(multi);
    return NULL;
  }

  return (CURLM *) multi;
}

CURLMcode curl_multi_add_handle(CURLM *multi_handle,
                                CURL *easy_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;
  struct closure *cl;
  struct closure *prev=NULL;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  /* Verify that we got a somewhat good easy handle too */
  if(!GOOD_EASY_HANDLE(easy_handle))
    return CURLM_BAD_EASY_HANDLE;

  /* Prevent users to add the same handle more than once! */
  if(((struct SessionHandle *)easy_handle)->multi)
    /* possibly we should create a new unique error code for this condition */
    return CURLM_BAD_EASY_HANDLE;

  /* Now, time to add an easy handle to the multi stack */
  easy = (struct Curl_one_easy *)calloc(sizeof(struct Curl_one_easy), 1);
  if(!easy)
    return CURLM_OUT_OF_MEMORY;

  cl = multi->closure;
  while(cl) {
    struct closure *next = cl->next;
    if(cl->easy_handle == (struct SessionHandle *)easy_handle) {
      /* remove this handle from the closure list */
      free(cl);
      if(prev)
        prev->next = next;
      else
        multi->closure = next;
      break; /* no need to continue since this handle can only be present once
                in the list */
    }
    cl = next;
  }

  /* set the easy handle */
  easy->easy_handle = easy_handle;
  multistate(easy, CURLM_STATE_INIT);

  /* for multi interface connections, we share DNS cache automatically if the
     easy handle's one is currently private. */
  if (easy->easy_handle->dns.hostcache &&
      (easy->easy_handle->dns.hostcachetype == HCACHE_PRIVATE)) {
    Curl_hash_destroy(easy->easy_handle->dns.hostcache);
    easy->easy_handle->dns.hostcache = NULL;
    easy->easy_handle->dns.hostcachetype = HCACHE_NONE;
  }

  if (!easy->easy_handle->dns.hostcache ||
      (easy->easy_handle->dns.hostcachetype == HCACHE_NONE)) {
    easy->easy_handle->dns.hostcache = multi->hostcache;
    easy->easy_handle->dns.hostcachetype = HCACHE_MULTI;
  }

  if(easy->easy_handle->state.connc) {
    if(easy->easy_handle->state.connc->type == CONNCACHE_PRIVATE) {
      /* kill old private version */
      Curl_rm_connc(easy->easy_handle->state.connc);
      /* point out our shared one instead */
      easy->easy_handle->state.connc = multi->connc;
    }
    /* else it is already using multi? */
  }
  else
    /* point out our shared one */
    easy->easy_handle->state.connc = multi->connc;

  /* Make sure the type is setup correctly */
  easy->easy_handle->state.connc->type = CONNCACHE_MULTI;

  /* We add this new entry first in the list. We make our 'next' point to the
     previous next and our 'prev' point back to the 'first' struct */
  easy->next = multi->easy.next;
  easy->prev = &multi->easy;

  /* make 'easy' the first node in the chain */
  multi->easy.next = easy;

  /* if there was a next node, make sure its 'prev' pointer links back to
     the new node */
  if(easy->next)
    easy->next->prev = easy;

  Curl_easy_addmulti(easy_handle, multi_handle);

  /* make the SessionHandle struct refer back to this struct */
  easy->easy_handle->set.one_easy = easy;

  /* increase the node-counter */
  multi->num_easy++;

  if((multi->num_easy * 4) > multi->connc->num) {
    /* We want the connection cache to have plenty room. Before we supported
       the shared cache every single easy handle had 5 entries in their cache
       by default. */
    CURLcode res = Curl_ch_connc(easy_handle, multi->connc,
                                 multi->connc->num*4);
    if(res != CURLE_OK)
      /* TODO: we need to do some cleaning up here! */
      return CURLM_OUT_OF_MEMORY;
  }

  /* increase the alive-counter */
  multi->num_alive++;

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
          (void *)sh->easy, sh->easy->magic, sh->socket);
}
#endif

CURLMcode curl_multi_remove_handle(CURLM *multi_handle,
                                   CURL *curl_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  /* Verify that we got a somewhat good easy handle too */
  if(!GOOD_EASY_HANDLE(curl_handle))
    return CURLM_BAD_EASY_HANDLE;

  /* scan through the list and remove the 'curl_handle' */
  easy = multi->easy.next;
  while(easy) {
    if(easy->easy_handle == (struct SessionHandle *)curl_handle)
      break;
    easy=easy->next;
  }

  if(easy) {
    bool premature = (bool)(easy->state != CURLM_STATE_COMPLETED);

    /* If the 'state' is not INIT or COMPLETED, we might need to do something
       nice to put the easy_handle in a good known state when this returns. */
    if(premature)
      /* this handle is "alive" so we need to count down the total number of
         alive connections when this is removed */
      multi->num_alive--;

    if (easy->easy_handle->state.is_in_pipeline &&
        easy->state > CURLM_STATE_DO) {
      /* If the handle is in a pipeline and has finished sending off its
         request, we need to remember the fact that we want to remove this
         handle but do the actual removal at a later time */
      easy->easy_handle->state.cancelled = TRUE;
      return CURLM_OK;
    }

    /* The timer must be shut down before easy->multi is set to NULL,
       else the timenode will remain in the splay tree after
       curl_easy_cleanup is called. */
    Curl_expire(easy->easy_handle, 0);

    if(easy->easy_handle->dns.hostcachetype == HCACHE_MULTI) {
      /* clear out the usage of the shared DNS cache */
      easy->easy_handle->dns.hostcache = NULL;
      easy->easy_handle->dns.hostcachetype = HCACHE_NONE;
    }

    /* if we have a connection we must call Curl_done() here so that we
       don't leave a half-baked one around */
    if(easy->easy_conn) {
      /* Set up the association right */
      easy->easy_conn->data = easy->easy_handle;

      /* Curl_done() clears the conn->data field to lose the association
         between the easy handle and the connection */
      Curl_done(&easy->easy_conn, easy->result, premature);

      if(easy->easy_conn)
        /* the connection is still alive, set back the association to enable
           the check below to trigger TRUE */
        easy->easy_conn->data = easy->easy_handle;
    }

    /* If this easy_handle was the last one in charge for one or more
       connections a the shared connection cache, we might need to keep this
       handle around until either A) the connection is closed and killed
       properly, or B) another easy_handle uses the connection.

       The reason why we need to have a easy_handle associated with a live
       connection is simply that some connections will need a handle to get
       closed down properly. Currently, the only connections that need to keep
       a easy_handle handle around are using FTP(S). Such connections have
       the PROT_CLOSEACTION bit set.

       Thus, we need to check for all connections in the shared cache that
       points to this handle and are using PROT_CLOSEACTION. If there's any,
       we need to add this handle to the list of "easy handles kept around for
       nice connection closures".
     */
    if(multi_conn_using(multi, easy->easy_handle)) {
      /* There's at least one connection using this handle so we must keep
         this handle around. We also keep the connection cache pointer
         pointing to the shared one since that will be used on close as
         well. */
      easy->easy_handle->state.shared_conn = multi;

      /* this handle is still being used by a shared connection cache and
         thus we leave it around for now */
      add_closure(multi, easy->easy_handle);
    }

    if(easy->easy_handle->state.connc->type == CONNCACHE_MULTI) {
      /* if this was using the shared connection cache we clear the pointer
         to that since we're not part of that handle anymore */
      easy->easy_handle->state.connc = NULL;

      /* and modify the connectindex since this handle can't point to the
         connection cache anymore */
      if(easy->easy_conn)
        easy->easy_conn->connectindex = -1;
    }

    /* change state without using multistate(), only to make singlesocket() do
       what we want */
    easy->state = CURLM_STATE_COMPLETED;
    singlesocket(multi, easy); /* to let the application know what sockets
                                  that vanish with this handle */

    Curl_easy_addmulti(easy->easy_handle, NULL); /* clear the association
                                                    to this multi handle */

    /* make the previous node point to our next */
    if(easy->prev)
      easy->prev->next = easy->next;
    /* make our next point to our previous node */
    if(easy->next)
      easy->next->prev = easy->prev;

    easy->easy_handle->set.one_easy = NULL; /* detached */

    /* NOTE NOTE NOTE
       We do not touch the easy handle here! */
    if (easy->msg)
      free(easy->msg);
    free(easy);

    multi->num_easy--; /* one less to care about now */

    update_timer(multi);
    return CURLM_OK;
  }
  else
    return CURLM_BAD_EASY_HANDLE; /* twasn't found */
}

bool Curl_multi_canPipeline(struct Curl_multi* multi)
{
  return multi->pipelining_enabled;
}

static int waitconnect_getsock(struct connectdata *conn,
                               curl_socket_t *sock,
                               int numsocks)
{
  if(!numsocks)
    return GETSOCK_BLANK;

  sock[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_WRITESOCK(0);
}

static int domore_getsock(struct connectdata *conn,
                          curl_socket_t *sock,
                          int numsocks)
{
  if(!numsocks)
    return GETSOCK_BLANK;

  /* When in DO_MORE state, we could be either waiting for us
     to connect to a remote site, or we could wait for that site
     to connect to us. It makes a difference in the way: if we
     connect to the site we wait for the socket to become writable, if
     the site connects to us we wait for it to become readable */
  sock[0] = conn->sock[SECONDARYSOCKET];

  return GETSOCK_WRITESOCK(0);
}

/* returns bitmapped flags for this handle and its sockets */
static int multi_getsock(struct Curl_one_easy *easy,
                         curl_socket_t *socks, /* points to numsocks number
                                                 of sockets */
                         int numsocks)
{
  if (easy->easy_handle->state.pipe_broke) {
    return 0;
  }

  if (easy->state > CURLM_STATE_CONNECT &&
      easy->state < CURLM_STATE_COMPLETED) {
    /* Set up ownership correctly */
    easy->easy_conn->data = easy->easy_handle;
  }

  switch(easy->state) {
  case CURLM_STATE_TOOFAST:  /* returns 0, so will not select. */
  default:
    /* this will get called with CURLM_STATE_COMPLETED when a handle is
       removed */
    return 0;

  case CURLM_STATE_WAITRESOLVE:
    return Curl_resolv_getsock(easy->easy_conn, socks, numsocks);

  case CURLM_STATE_PROTOCONNECT:
    return Curl_protocol_getsock(easy->easy_conn, socks, numsocks);

  case CURLM_STATE_DOING:
    return Curl_doing_getsock(easy->easy_conn, socks, numsocks);

  case CURLM_STATE_WAITCONNECT:
    return waitconnect_getsock(easy->easy_conn, socks, numsocks);

  case CURLM_STATE_DO_MORE:
    return domore_getsock(easy->easy_conn, socks, numsocks);

  case CURLM_STATE_PERFORM:
  case CURLM_STATE_WAITPERFORM:
    return Curl_single_getsock(easy->easy_conn, socks, numsocks);
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
  struct Curl_one_easy *easy;
  int this_max_fd=-1;
  curl_socket_t sockbunch[MAX_SOCKSPEREASYHANDLE];
  int bitmap;
  int i;
  (void)exc_fd_set; /* not used */

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  easy=multi->easy.next;
  while(easy) {
    bitmap = multi_getsock(easy, sockbunch, MAX_SOCKSPEREASYHANDLE);

    for(i=0; i< MAX_SOCKSPEREASYHANDLE; i++) {
      curl_socket_t s = CURL_SOCKET_BAD;

      if(bitmap & GETSOCK_READSOCK(i)) {
        FD_SET(sockbunch[i], read_fd_set);
        s = sockbunch[i];
      }
      if(bitmap & GETSOCK_WRITESOCK(i)) {
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

    easy = easy->next; /* check next handle */
  }

  *max_fd = this_max_fd;

  return CURLM_OK;
}

static CURLMcode multi_runsingle(struct Curl_multi *multi,
                                 struct Curl_one_easy *easy)
{
  struct Curl_message *msg = NULL;
  bool connected;
  bool async;
  bool protocol_connect;
  bool dophase_done;
  bool done;
  CURLMcode result = CURLM_OK;
  struct Curl_transfer_keeper *k;

  do {

    if(!GOOD_EASY_HANDLE(easy->easy_handle))
      return CURLM_BAD_EASY_HANDLE;

    if (easy->easy_handle->state.pipe_broke) {
      infof(easy->easy_handle, "Pipe broke: handle 0x%x, url = %s\n",
            easy, easy->easy_handle->reqdata.path);
      if(easy->easy_handle->state.is_in_pipeline) {
        /* Head back to the CONNECT state */
        multistate(easy, CURLM_STATE_CONNECT);
        result = CURLM_CALL_MULTI_PERFORM;
        easy->result = CURLE_OK;
      } else {
        easy->result = CURLE_COULDNT_CONNECT;
        multistate(easy, CURLM_STATE_COMPLETED);
      }

      easy->easy_handle->state.pipe_broke = FALSE;
      easy->easy_conn = NULL;
      break;
    }

    if (easy->state > CURLM_STATE_CONNECT &&
        easy->state < CURLM_STATE_COMPLETED) {
      /* Make sure we set the connection's current owner */
      easy->easy_conn->data = easy->easy_handle;
    }

    if (CURLM_STATE_WAITCONNECT <= easy->state &&
        easy->state <= CURLM_STATE_DO &&
        easy->easy_handle->change.url_changed) {
      char *gotourl;
      Curl_posttransfer(easy->easy_handle);

      easy->result = Curl_done(&easy->easy_conn, CURLE_OK, FALSE);
      /* We make sure that the pipe broken flag is reset
         because in this case, it isn't an actual break */
      easy->easy_handle->state.pipe_broke = FALSE;
      if(CURLE_OK == easy->result) {
        gotourl = strdup(easy->easy_handle->change.url);
        if(gotourl) {
          easy->easy_handle->change.url_changed = FALSE;
          easy->result = Curl_follow(easy->easy_handle, gotourl, FALSE);
          if(CURLE_OK == easy->result)
            multistate(easy, CURLM_STATE_CONNECT);
          else
            free(gotourl);
        }
        else {
          easy->result = CURLE_OUT_OF_MEMORY;
          multistate(easy, CURLM_STATE_COMPLETED);
          break;
        }
      }
    }

    easy->easy_handle->change.url_changed = FALSE;

    switch(easy->state) {
    case CURLM_STATE_INIT:
      /* init this transfer. */
      easy->result=Curl_pretransfer(easy->easy_handle);

      if(CURLE_OK == easy->result) {
        /* after init, go CONNECT */
        multistate(easy, CURLM_STATE_CONNECT);
        result = CURLM_CALL_MULTI_PERFORM;

        easy->easy_handle->state.used_interface = Curl_if_multi;
      }
      break;

    case CURLM_STATE_CONNECT:
      /* Connect. We get a connection identifier filled in. */
      Curl_pgrsTime(easy->easy_handle, TIMER_STARTSINGLE);
      easy->result = Curl_connect(easy->easy_handle, &easy->easy_conn,
                                  &async, &protocol_connect);

      if(CURLE_OK == easy->result) {
        /* Add this handle to the send pipeline */
        Curl_addHandleToPipeline(easy->easy_handle,
                                 easy->easy_conn->send_pipe);

        if(async)
          /* We're now waiting for an asynchronous name lookup */
          multistate(easy, CURLM_STATE_WAITRESOLVE);
        else {
          /* after the connect has been sent off, go WAITCONNECT unless the
             protocol connect is already done and we can go directly to
             WAITDO! */
          result = CURLM_CALL_MULTI_PERFORM;

          if(protocol_connect) {
            multistate(easy, CURLM_STATE_WAITDO);
          } else {
            multistate(easy, CURLM_STATE_WAITCONNECT);
          }
        }
      }
      break;

    case CURLM_STATE_WAITRESOLVE:
      /* awaiting an asynch name resolve to complete */
    {
      struct Curl_dns_entry *dns = NULL;

      /* check if we have the name resolved by now */
      easy->result = Curl_is_resolved(easy->easy_conn, &dns);

      if(dns) {
        /* Perform the next step in the connection phase, and then move on
           to the WAITCONNECT state */
        easy->result = Curl_async_resolved(easy->easy_conn,
                                           &protocol_connect);

        if(CURLE_OK != easy->result)
          /* if Curl_async_resolved() returns failure, the connection struct
             is already freed and gone */
          easy->easy_conn = NULL;           /* no more connection */
        else {
          /* call again please so that we get the next socket setup */
          result = CURLM_CALL_MULTI_PERFORM;
          if(protocol_connect)
            multistate(easy, CURLM_STATE_DO);
          else
            multistate(easy, CURLM_STATE_WAITCONNECT);
        }
      }

      if(CURLE_OK != easy->result) {
        /* failure detected */
        Curl_disconnect(easy->easy_conn); /* disconnect properly */
        easy->easy_conn = NULL;           /* no more connection */
        break;
      }
    }
    break;

    case CURLM_STATE_WAITCONNECT:
      /* awaiting a completion of an asynch connect */
      easy->result = Curl_is_connected(easy->easy_conn,
                                       FIRSTSOCKET,
                                       &connected);
      if(connected)
        easy->result = Curl_protocol_connect(easy->easy_conn,
                                             &protocol_connect);

      if(CURLE_OK != easy->result) {
        /* failure detected */
        Curl_disconnect(easy->easy_conn); /* close the connection */
        easy->easy_conn = NULL;           /* no more connection */
        break;
      }

      if(connected) {
        if(!protocol_connect) {
          /* We have a TCP connection, but 'protocol_connect' may be false
             and then we continue to 'STATE_PROTOCONNECT'. If protocol
             connect is TRUE, we move on to STATE_DO. */
          multistate(easy, CURLM_STATE_PROTOCONNECT);
        }
        else {
          /* after the connect has completed, go WAITDO */
          multistate(easy, CURLM_STATE_WAITDO);

          result = CURLM_CALL_MULTI_PERFORM;
        }
      }
      break;

    case CURLM_STATE_PROTOCONNECT:
      /* protocol-specific connect phase */
      easy->result = Curl_protocol_connecting(easy->easy_conn,
                                              &protocol_connect);
      if(protocol_connect) {
        /* after the connect has completed, go WAITDO */
        multistate(easy, CURLM_STATE_WAITDO);
        result = CURLM_CALL_MULTI_PERFORM;
      }
      else if(easy->result) {
        /* failure detected */
        Curl_posttransfer(easy->easy_handle);
        Curl_done(&easy->easy_conn, easy->result, FALSE);
        Curl_disconnect(easy->easy_conn); /* close the connection */
        easy->easy_conn = NULL;           /* no more connection */
      }
      break;

    case CURLM_STATE_WAITDO:
      /* Wait for our turn to DO when we're pipelining requests */
#ifdef CURLDEBUG
      infof(easy->easy_handle, "Conn %d send pipe %d inuse %d athead %d\n",
            easy->easy_conn->connectindex,
            easy->easy_conn->send_pipe->size,
            easy->easy_conn->writechannel_inuse,
            Curl_isHandleAtHead(easy->easy_handle,
                                easy->easy_conn->send_pipe));
#endif
      if (!easy->easy_conn->writechannel_inuse &&
          Curl_isHandleAtHead(easy->easy_handle,
                              easy->easy_conn->send_pipe)) {
        /* Grab the channel */
        easy->easy_conn->writechannel_inuse = TRUE;
        multistate(easy, CURLM_STATE_DO);
        result = CURLM_CALL_MULTI_PERFORM;
      }
      break;

    case CURLM_STATE_DO:
      if(easy->easy_handle->set.connect_only) {
        /* keep connection open for application to use the socket */
        easy->easy_conn->bits.close = FALSE;
        multistate(easy, CURLM_STATE_DONE);
        easy->result = CURLE_OK;
        result = CURLM_OK;
      }
      else {
        /* Perform the protocol's DO action */
        easy->result = Curl_do(&easy->easy_conn,
                               &dophase_done);

        if(CURLE_OK == easy->result) {

          if(!dophase_done) {
            /* DO was not completed in one function call, we must continue
               DOING... */
            multistate(easy, CURLM_STATE_DOING);
            result = CURLM_OK;
          }

          /* after DO, go DO_DONE... or DO_MORE */
          else if(easy->easy_conn->bits.do_more) {
            /* we're supposed to do more, but we need to sit down, relax
               and wait a little while first */
            multistate(easy, CURLM_STATE_DO_MORE);
            result = CURLM_OK;
          }
          else {
            /* we're done with the DO, now DO_DONE */
            easy->result = Curl_readwrite_init(easy->easy_conn);
            if(CURLE_OK == easy->result) {
              multistate(easy, CURLM_STATE_DO_DONE);
              result = CURLM_CALL_MULTI_PERFORM;
            }
          }
        }
        else {
          /* failure detected */
          Curl_posttransfer(easy->easy_handle);
          Curl_done(&easy->easy_conn, easy->result, FALSE);
          Curl_disconnect(easy->easy_conn); /* close the connection */
          easy->easy_conn = NULL;           /* no more connection */
        }
      }
      break;

    case CURLM_STATE_DOING:
      /* we continue DOING until the DO phase is complete */
      easy->result = Curl_protocol_doing(easy->easy_conn,
                                         &dophase_done);
      if(CURLE_OK == easy->result) {
        if(dophase_done) {
          /* after DO, go PERFORM... or DO_MORE */
          if(easy->easy_conn->bits.do_more) {
            /* we're supposed to do more, but we need to sit down, relax
               and wait a little while first */
            multistate(easy, CURLM_STATE_DO_MORE);
            result = CURLM_OK;
          }
          else {
            /* we're done with the DO, now DO_DONE */
            easy->result = Curl_readwrite_init(easy->easy_conn);
            if(CURLE_OK == easy->result) {
              multistate(easy, CURLM_STATE_DO_DONE);
              result = CURLM_CALL_MULTI_PERFORM;
            }
          }
        } /* dophase_done */
      }
      else {
        /* failure detected */
        Curl_posttransfer(easy->easy_handle);
        Curl_done(&easy->easy_conn, easy->result, FALSE);
        Curl_disconnect(easy->easy_conn); /* close the connection */
        easy->easy_conn = NULL;           /* no more connection */
      }
      break;

    case CURLM_STATE_DO_MORE:
      /* Ready to do more? */
      easy->result = Curl_is_connected(easy->easy_conn,
                                       SECONDARYSOCKET,
                                       &connected);
      if(connected) {
        /*
         * When we are connected, DO MORE and then go DO_DONE
         */
        easy->result = Curl_do_more(easy->easy_conn);

        if(CURLE_OK == easy->result)
          easy->result = Curl_readwrite_init(easy->easy_conn);
        else
          /* Remove ourselves from the send pipeline */
          Curl_removeHandleFromPipeline(easy->easy_handle,
                                        easy->easy_conn->send_pipe);

        if(CURLE_OK == easy->result) {
          multistate(easy, CURLM_STATE_DO_DONE);
          result = CURLM_CALL_MULTI_PERFORM;
        }
      }
      break;

    case CURLM_STATE_DO_DONE:
      /* Remove ourselves from the send pipeline */
      Curl_removeHandleFromPipeline(easy->easy_handle,
                                    easy->easy_conn->send_pipe);
      /* Add ourselves to the recv pipeline */
      Curl_addHandleToPipeline(easy->easy_handle,
                               easy->easy_conn->recv_pipe);
      multistate(easy, CURLM_STATE_WAITPERFORM);
      result = CURLM_CALL_MULTI_PERFORM;
      break;

    case CURLM_STATE_WAITPERFORM:
#ifdef CURLDEBUG
      infof(easy->easy_handle, "Conn %d recv pipe %d inuse %d athead %d\n",
            easy->easy_conn->connectindex,
            easy->easy_conn->recv_pipe->size,
            easy->easy_conn->readchannel_inuse,
            Curl_isHandleAtHead(easy->easy_handle,
                                easy->easy_conn->recv_pipe));
#endif
      /* Wait for our turn to PERFORM */
      if (!easy->easy_conn->readchannel_inuse &&
          Curl_isHandleAtHead(easy->easy_handle,
                              easy->easy_conn->recv_pipe)) {
        /* Grab the channel */
        easy->easy_conn->readchannel_inuse = TRUE;
        multistate(easy, CURLM_STATE_PERFORM);
        result = CURLM_CALL_MULTI_PERFORM;
      }
      break;

    case CURLM_STATE_TOOFAST: /* limit-rate exceeded in either direction */
      /* if both rates are within spec, resume transfer */
      Curl_pgrsUpdate(easy->easy_conn);
      if ( ( ( easy->easy_handle->set.max_send_speed == 0 ) ||
             ( easy->easy_handle->progress.ulspeed <
               easy->easy_handle->set.max_send_speed ) )  &&
           ( ( easy->easy_handle->set.max_recv_speed == 0 ) ||
             ( easy->easy_handle->progress.dlspeed <
               easy->easy_handle->set.max_recv_speed ) )
        )
      multistate(easy, CURLM_STATE_PERFORM);
      break;

    case CURLM_STATE_PERFORM:
      /* check if over speed */
      if ( (  ( easy->easy_handle->set.max_send_speed > 0 ) &&
              ( easy->easy_handle->progress.ulspeed >
                easy->easy_handle->set.max_send_speed ) )  ||
           (  ( easy->easy_handle->set.max_recv_speed > 0 ) &&
              ( easy->easy_handle->progress.dlspeed >
                easy->easy_handle->set.max_recv_speed ) )
        ) {
        /* Transfer is over the speed limit. Change state.  TODO: Call
         * Curl_expire() with the time left until we're targeted to be below
         * the speed limit again. */
        multistate(easy, CURLM_STATE_TOOFAST );
        break;
      }

      /* read/write data if it is ready to do so */
      easy->result = Curl_readwrite(easy->easy_conn, &done);

      k = &easy->easy_handle->reqdata.keep;

      if (!(k->keepon & KEEP_READ)) {
          /* We're done reading */
          easy->easy_conn->readchannel_inuse = FALSE;
      }

      if (!(k->keepon & KEEP_WRITE)) {
          /* We're done writing */
          easy->easy_conn->writechannel_inuse = FALSE;
      }

      if(easy->result)  {
        /* The transfer phase returned error, we mark the connection to get
         * closed to prevent being re-used. This is becasue we can't
         * possibly know if the connection is in a good shape or not now. */
        easy->easy_conn->bits.close = TRUE;

        if(CURL_SOCKET_BAD != easy->easy_conn->sock[SECONDARYSOCKET]) {
          /* if we failed anywhere, we must clean up the secondary socket if
             it was used */
          sclose(easy->easy_conn->sock[SECONDARYSOCKET]);
          easy->easy_conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD;
        }
        Curl_posttransfer(easy->easy_handle);
        Curl_done(&easy->easy_conn, easy->result, FALSE);
      }
      else if(TRUE == done) {
        char *newurl;
        bool retry = Curl_retry_request(easy->easy_conn, &newurl);

        /* call this even if the readwrite function returned error */
        Curl_posttransfer(easy->easy_handle);

        /* When we follow redirects, must to go back to the CONNECT state */
        if(easy->easy_handle->reqdata.newurl || retry) {
          Curl_removeHandleFromPipeline(easy->easy_handle,
                                        easy->easy_conn->recv_pipe);
          if(!retry) {
            /* if the URL is a follow-location and not just a retried request
               then figure out the URL here */
            newurl = easy->easy_handle->reqdata.newurl;
            easy->easy_handle->reqdata.newurl = NULL;
          }
          easy->result = Curl_done(&easy->easy_conn, CURLE_OK, FALSE);
          if(easy->result == CURLE_OK)
            easy->result = Curl_follow(easy->easy_handle, newurl, retry);
          if(CURLE_OK == easy->result) {
            multistate(easy, CURLM_STATE_CONNECT);
            result = CURLM_CALL_MULTI_PERFORM;
          }
          else
            /* Since we "took it", we are in charge of freeing this on
               failure */
            free(newurl);
        }
        else {
          /* after the transfer is done, go DONE */
          multistate(easy, CURLM_STATE_DONE);
          result = CURLM_CALL_MULTI_PERFORM;
        }
      }

      break;

    case CURLM_STATE_DONE:
      /* Remove ourselves from the receive pipeline */
      Curl_removeHandleFromPipeline(easy->easy_handle,
                                    easy->easy_conn->recv_pipe);
      easy->easy_handle->state.is_in_pipeline = FALSE;

      if (easy->easy_conn->bits.stream_was_rewound) {
          /* This request read past its response boundary so we quickly
             let the other requests consume those bytes since there is no
             guarantee that the socket will become active again */
          result = CURLM_CALL_MULTI_PERFORM;
      }

      if (!easy->easy_handle->state.cancelled) {
        /* post-transfer command */
        easy->result = Curl_done(&easy->easy_conn, CURLE_OK, FALSE);

        /* after we have DONE what we're supposed to do, go COMPLETED, and
           it doesn't matter what the Curl_done() returned! */
        multistate(easy, CURLM_STATE_COMPLETED);
      }

      break;

    case CURLM_STATE_COMPLETED:
      if (easy->easy_handle->state.cancelled)
        /* Go into the CANCELLED state if we were cancelled */
        multistate(easy, CURLM_STATE_CANCELLED);

      /* this is a completed transfer, it is likely to still be connected */

      /* This node should be delinked from the list now and we should post
         an information message that we are complete. */
      break;

    case CURLM_STATE_CANCELLED:
      /* Cancelled transfer, wait to be cleaned up */
      break;

    default:
      return CURLM_INTERNAL_ERROR;
    }

    if(CURLM_STATE_COMPLETED != easy->state) {
      if(CURLE_OK != easy->result) {
        /*
         * If an error was returned, and we aren't in completed state now,
         * then we go to completed and consider this transfer aborted.
         */
        easy->easy_handle->state.is_in_pipeline = FALSE;
        easy->easy_handle->state.pipe_broke = FALSE;

        if(easy->easy_conn) {
          /* if this has a connection, unsubscribe from the pipelines */
          easy->easy_conn->writechannel_inuse = FALSE;
          easy->easy_conn->readchannel_inuse = FALSE;
        }
        multistate(easy, CURLM_STATE_COMPLETED);
      }
    }

  } while (easy->easy_handle->change.url_changed);

  if ((CURLM_STATE_COMPLETED == easy->state) && !easy->msg) {
    if(easy->easy_handle->dns.hostcachetype == HCACHE_MULTI) {
      /* clear out the usage of the shared DNS cache */
      easy->easy_handle->dns.hostcache = NULL;
      easy->easy_handle->dns.hostcachetype = HCACHE_NONE;
    }

    /* now add a node to the Curl_message linked list with this info */
    msg = (struct Curl_message *)malloc(sizeof(struct Curl_message));

    if(!msg)
      return CURLM_OUT_OF_MEMORY;

    msg->extmsg.msg = CURLMSG_DONE;
    msg->extmsg.easy_handle = easy->easy_handle;
    msg->extmsg.data.result = easy->result;
    msg->next = NULL;

    easy->msg = msg;
    easy->msg_num = 1; /* there is one unread message here */

    multi->num_msgs++; /* increase message counter */
  }

  return result;
}


CURLMcode curl_multi_perform(CURLM *multi_handle, int *running_handles)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;
  CURLMcode returncode=CURLM_OK;
  struct Curl_tree *t;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  easy=multi->easy.next;
  while(easy) {
    CURLMcode result;

    if (easy->easy_handle->state.cancelled &&
        easy->state == CURLM_STATE_CANCELLED) {
      /* Remove cancelled handles once it's safe to do so */
      Curl_multi_rmeasy(multi_handle, easy->easy_handle);
      easy->easy_handle = NULL;
      easy = easy->next;
      continue;
    }

    result = multi_runsingle(multi, easy);
    if(result)
      returncode = result;

    easy = easy->next; /* operate on next handle */
  }

  /*
   * Simply remove all expired timers from the splay since handles are dealt
   * with unconditionally by this function and curl_multi_timeout() requires
   * that already passed/handled expire times are removed from the splay.
   */
  do {
    struct timeval now = Curl_tvnow();
    int key = now.tv_sec; /* drop the usec part */

    multi->timetree = Curl_splaygetbest(key, multi->timetree, &t);
    if (t) {
      struct SessionHandle *d = t->payload;
      struct timeval* tv = &d->state.expiretime;

      /* clear the expire times within the handles that we remove from the
         splay tree */
      tv->tv_sec = 0;
      tv->tv_usec = 0;
    }

  } while(t);

  *running_handles = multi->num_alive;

  if ( CURLM_OK == returncode )
    update_timer(multi);
  return returncode;
}

/* This is called when an easy handle is cleanup'ed that is part of a multi
   handle */
void Curl_multi_rmeasy(void *multi_handle, CURL *easy_handle)
{
  curl_multi_remove_handle(multi_handle, easy_handle);
}


CURLMcode curl_multi_cleanup(CURLM *multi_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;
  struct Curl_one_easy *nexteasy;
  int i;
  struct closure *cl;
  struct closure *n;

  if(GOOD_MULTI_HANDLE(multi)) {
    multi->type = 0; /* not good anymore */
    Curl_hash_destroy(multi->hostcache);
    Curl_hash_destroy(multi->sockhash);

    /* go over all connections that have close actions */
    for(i=0; i< multi->connc->num; i++) {
      if(multi->connc->connects[i] &&
         multi->connc->connects[i]->protocol & PROT_CLOSEACTION) {
        Curl_disconnect(multi->connc->connects[i]);
        multi->connc->connects[i] = NULL;
      }
    }
    /* now walk through the list of handles we kept around only to be
       able to close connections "properly" */
    cl = multi->closure;
    while(cl) {
      cl->easy_handle->state.shared_conn = NULL; /* no more shared */
      if(cl->easy_handle->state.closed)
        /* close handle only if curl_easy_cleanup() already has been called
           for this easy handle */
        Curl_close(cl->easy_handle);
      n = cl->next;
      free(cl);
      cl= n;
    }

    Curl_rm_connc(multi->connc);

    /* remove all easy handles */
    easy = multi->easy.next;
    while(easy) {
      nexteasy=easy->next;
      if(easy->easy_handle->dns.hostcachetype == HCACHE_MULTI) {
        /* clear out the usage of the shared DNS cache */
        easy->easy_handle->dns.hostcache = NULL;
        easy->easy_handle->dns.hostcachetype = HCACHE_NONE;
      }

      /* Clear the pointer to the connection cache */
      easy->easy_handle->state.connc = NULL;

      Curl_easy_addmulti(easy->easy_handle, NULL); /* clear the association */

      if (easy->msg)
        free(easy->msg);
      free(easy);
      easy = nexteasy;
    }

    free(multi);

    return CURLM_OK;
  }
  else
    return CURLM_BAD_HANDLE;
}

CURLMsg *curl_multi_info_read(CURLM *multi_handle, int *msgs_in_queue)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;

  *msgs_in_queue = 0; /* default to none */

  if(GOOD_MULTI_HANDLE(multi)) {
    struct Curl_one_easy *easy;

    if(!multi->num_msgs)
      return NULL; /* no messages left to return */

    easy=multi->easy.next;
    while(easy) {
      if(easy->msg_num) {
        easy->msg_num--;
        break;
      }
      easy = easy->next;
    }
    if(!easy)
      return NULL; /* this means internal count confusion really */

    multi->num_msgs--;
    *msgs_in_queue = multi->num_msgs;

    return &easy->msg->extmsg;
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
                         struct Curl_one_easy *easy)
{
  curl_socket_t socks[MAX_SOCKSPEREASYHANDLE];
  int i;
  struct Curl_sh_entry *entry;
  curl_socket_t s;
  int num;
  unsigned int curraction;

  memset(&socks, 0, sizeof(socks));
  for(i=0; i< MAX_SOCKSPEREASYHANDLE; i++)
    socks[i] = CURL_SOCKET_BAD;

  /* Fill in the 'current' struct with the state as it is now: what sockets to
     supervise and for what actions */
  curraction = multi_getsock(easy, socks, MAX_SOCKSPEREASYHANDLE);

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
    entry = Curl_hash_pick(multi->sockhash, (char *)&s, sizeof(s));

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
      entry = sh_addentry(multi->sockhash, s, easy->easy_handle);
      if(!entry)
        /* fatal */
        return;
    }

    multi->socket_cb(easy->easy_handle,
                     s,
                     action,
                     multi->socket_userp,
                     entry ? entry->socketp : NULL);

    entry->action = action; /* store the current action state */
  }

  num = i; /* number of sockets */

  /* when we've walked over all the sockets we should have right now, we must
     make sure to detect sockets that are removed */
  for(i=0; i< easy->numsocks; i++) {
    int j;
    s = easy->sockets[i];
    for(j=0; j<num; j++) {
      if(s == socks[j]) {
        /* this is still supervised */
        s = CURL_SOCKET_BAD;
        break;
      }
    }
    if(s != CURL_SOCKET_BAD) {
      /* this socket has been removed. Remove it */

      entry = Curl_hash_pick(multi->sockhash, (char *)&s, sizeof(s));
      if(entry) {
        /* just a precaution, this socket really SHOULD be in the hash already
           but in case it isn't, we don't have to tell the app to remove it
           either since it never got to know about it */
        multi->socket_cb(easy->easy_handle,
                         s,
                         CURL_POLL_REMOVE,
                         multi->socket_userp,
                         entry ? entry->socketp : NULL);

        sh_delentry(multi->sockhash, s);
      }
    }
  }

  memcpy(easy->sockets, socks, num*sizeof(curl_socket_t));
  easy->numsocks = num;
}

static CURLMcode multi_socket(struct Curl_multi *multi,
                              bool checkall,
                              curl_socket_t s,
                              int *running_handles)
{
  CURLMcode result = CURLM_OK;
  struct SessionHandle *data = NULL;
  struct Curl_tree *t;

  if(checkall) {
    struct Curl_one_easy *easyp;
    /* *perform() deals with running_handles on its own */
    result = curl_multi_perform(multi, running_handles);

    /* walk through each easy handle and do the socket state change magic
       and callbacks */
    easyp=multi->easy.next;
    while(easyp) {
      singlesocket(multi, easyp);
      easyp = easyp->next;
    }

    /* or should we fall-through and do the timer-based stuff? */
    return result;
  }
  else if (s != CURL_SOCKET_TIMEOUT) {

    struct Curl_sh_entry *entry =
      Curl_hash_pick(multi->sockhash, (char *)&s, sizeof(s));

    if(!entry)
      /* unmatched socket, major problemo! */
      return CURLM_BAD_SOCKET; /* better return code? */

    data = entry->easy;

    if(data->magic != CURLEASY_MAGIC_NUMBER)
      /* bad bad bad bad bad bad bad */
      return CURLM_INTERNAL_ERROR;

    result = multi_runsingle(multi, data->set.one_easy);

    if(result == CURLM_OK)
      /* get the socket(s) and check if the state has been changed since
         last */
      singlesocket(multi, data->set.one_easy);

    /* Now we fall-through and do the timer-based stuff, since we don't want
       to force the user to have to deal with timeouts as long as at least one
       connection in fact has traffic. */

    data = NULL; /* set data to NULL again to avoid calling multi_runsingle()
                    in case there's no need to */
  }

  /*
   * The loop following here will go on as long as there are expire-times left
   * to process in the splay and 'data' will be re-assigned for every expired
   * handle we deal with.
   */
  do {
    int key;
    struct timeval now;

    /* the first loop lap 'data' can be NULL */
    if(data) {
      result = multi_runsingle(multi, data->set.one_easy);

      if(result == CURLM_OK)
        /* get the socket(s) and check if the state has been changed since
           last */
        singlesocket(multi, data->set.one_easy);
    }

    /* Check if there's one (more) expired timer to deal with! This function
       extracts a matching node if there is one */

    now = Curl_tvnow();
    key = now.tv_sec; /* drop the usec part */

    multi->timetree = Curl_splaygetbest(key, multi->timetree, &t);
    if(t) {
      /* assign 'data' to be the easy handle we just removed from the splay
         tree */
      data = t->payload;
      /* clear the expire time within the handle we removed from the
         splay tree */
      data->state.expiretime.tv_sec = 0;
      data->state.expiretime.tv_usec = 0;
    }

  } while(t);

  *running_handles = multi->num_alive;
  return result;
}

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
  case CURLMOPT_PIPELINING:
    multi->pipelining_enabled = (bool)(0 != va_arg(param, long));
    break;
  case CURLMOPT_TIMERFUNCTION:
    multi->timer_cb = va_arg(param, curl_multi_timer_callback);
    break;
  case CURLMOPT_TIMERDATA:
    multi->timer_userp = va_arg(param, void *);
    break;
  default:
    res = CURLM_UNKNOWN_OPTION;
    break;
  }
  va_end(param);
  return res;
}


CURLMcode curl_multi_socket(CURLM *multi_handle, curl_socket_t s,
                            int *running_handles)
{
  CURLMcode result = multi_socket((struct Curl_multi *)multi_handle, FALSE, s,
                                  running_handles);
  if (CURLM_OK == result)
    update_timer((struct Curl_multi *)multi_handle);
  return result;
}

CURLMcode curl_multi_socket_all(CURLM *multi_handle, int *running_handles)

{
  CURLMcode result = multi_socket((struct Curl_multi *)multi_handle,
                                  TRUE, CURL_SOCKET_BAD, running_handles);
  if (CURLM_OK == result)
    update_timer((struct Curl_multi *)multi_handle);
  return result;
}

static CURLMcode multi_timeout(struct Curl_multi *multi,
                               long *timeout_ms)
{
  if(multi->timetree) {
    /* we have a tree of expire times */
    struct timeval now = Curl_tvnow();

    /* splay the lowest to the bottom */
    multi->timetree = Curl_splay(0, multi->timetree);

    /* At least currently, the splay key is a time_t for the expire time */
    *timeout_ms = (multi->timetree->key - now.tv_sec) * 1000 -
      now.tv_usec/1000;
    if(*timeout_ms < 0)
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
  if (!multi->timer_cb)
    return 0;
  if ( multi_timeout(multi, &timeout_ms) != CURLM_OK )
    return -1;
  if ( timeout_ms < 0 )
    return 0;

  /* When multi_timeout() is done, multi->timetree points to the node with the
   * timeout we got the (relative) time-out time for. We can thus easily check
   * if this is the same (fixed) time as we got in a previous call and then
   * avoid calling the callback again. */
  if(multi->timetree->key == multi->timer_lastcall)
    return 0;

  multi->timer_lastcall = multi->timetree->key;

  return multi->timer_cb((CURLM*)multi, timeout_ms, multi->timer_userp);
}

/* given a number of milliseconds from now to use to set the 'act before
   this'-time for the transfer, to be extracted by curl_multi_timeout() */
void Curl_expire(struct SessionHandle *data, long milli)
{
  struct Curl_multi *multi = data->multi;
  struct timeval *nowp = &data->state.expiretime;
  int rc;

  /* this is only interesting for multi-interface using libcurl, and only
     while there is still a multi interface struct remaining! */
  if(!multi)
    return;

  if(!milli) {
    /* No timeout, clear the time data. */
    if(nowp->tv_sec) {
      /* Since this is an cleared time, we must remove the previous entry from
         the splay tree */
      rc = Curl_splayremovebyaddr(multi->timetree,
                                  &data->state.timenode,
                                  &multi->timetree);
      if(rc)
        infof(data, "Internal error clearing splay node = %d\n", rc);
      infof(data, "Expire cleared\n");
      nowp->tv_sec = 0;
      nowp->tv_usec = 0;
    }
  }
  else {
    struct timeval set;
    int rest;

    set = Curl_tvnow();
    set.tv_sec += milli/1000;
    set.tv_usec += (milli%1000)*1000;

    rest = (int)(set.tv_usec - 1000000);
    if(rest > 0) {
      /* bigger than a full microsec */
      set.tv_sec++;
      set.tv_usec -= 1000000;
    }

    if(nowp->tv_sec) {
      /* This means that the struct is added as a node in the splay tree.
         Compare if the new time is earlier, and only remove-old/add-new if it
         is. */
      long diff = curlx_tvdiff(set, *nowp);
      if(diff > 0)
        /* the new expire time was later so we don't change this */
        return;

      /* Since this is an updated time, we must remove the previous entry from
         the splay tree first and then re-add the new value */
      rc = Curl_splayremovebyaddr(multi->timetree,
                                  &data->state.timenode,
                                  &multi->timetree);
      if(rc)
        infof(data, "Internal error removing splay node = %d\n", rc);
    }

    *nowp = set;
#if 0
    infof(data, "Expire at %ld / %ld (%ldms)\n",
          (long)nowp->tv_sec, (long)nowp->tv_usec, milli);
#endif
    data->state.timenode.payload = data;
    multi->timetree = Curl_splayinsert((int)nowp->tv_sec,
                                       multi->timetree,
                                       &data->state.timenode);
  }
#if 0
  Curl_splayprint(multi->timetree, 0, TRUE);
#endif
}

CURLMcode curl_multi_assign(CURLM *multi_handle,
                            curl_socket_t s, void *hashp)
{
  struct Curl_sh_entry *there = NULL;
  struct Curl_multi *multi = (struct Curl_multi *)multi_handle;

  if(s != CURL_SOCKET_BAD)
    there = Curl_hash_pick(multi->sockhash, (char *)&s, sizeof(curl_socket_t));

  if(!there)
    return CURLM_BAD_SOCKET;

  there->socketp = hashp;

  return CURLM_OK;
}

static bool multi_conn_using(struct Curl_multi *multi,
                             struct SessionHandle *data)
{
  /* any live CLOSEACTION-connections pointing to the give 'data' ? */
  int i;

  for(i=0; i< multi->connc->num; i++) {
    if(multi->connc->connects[i] &&
       (multi->connc->connects[i]->data == data) &&
       multi->connc->connects[i]->protocol & PROT_CLOSEACTION)
      return TRUE;
  }

  return FALSE;
}

/* Add the given data pointer to the list of 'closure handles' that are kept
   around only to be able to close some connections nicely - just make sure
   that this handle isn't already added, like for the cases when an easy
   handle is removed, added and removed again... */
static void add_closure(struct Curl_multi *multi,
                        struct SessionHandle *data)
{
  int i;
  struct closure *cl = (struct closure *)calloc(sizeof(struct closure), 1);
  struct closure *p=NULL;
  struct closure *n;
  if(cl) {
    cl->easy_handle = data;
    cl->next = multi->closure;
    multi->closure = cl;
  }

  p = multi->closure;
  cl = p->next; /* start immediately on the second since the first is the one
                   we just added and it is _very_ likely to actually exist
                   used in the cache since that's the whole purpose of adding
                   it to this list! */

  /* When adding, scan through all the other currently kept handles and see if
     there are any connections still referring to them and kill them if not. */
  while(cl) {
    bool inuse = FALSE;
    for(i=0; i< multi->connc->num; i++) {
      if(multi->connc->connects[i] &&
         (multi->connc->connects[i]->data == cl->easy_handle)) {
        inuse = TRUE;
        break;
      }
    }

    n = cl->next;

    if(!inuse) {
      /* cl->easy_handle is now killable */
      infof(data, "Delayed kill of easy handle %p\n", cl->easy_handle);
      /* unmark it as not having a connection around that uses it anymore */
      cl->easy_handle->state.shared_conn= NULL;
      Curl_close(cl->easy_handle);
      if(p)
        p->next = n;
      else
        multi->closure = n;
      free(cl);
    }
    else
      p = cl;

    cl = n;
  }

}

#ifdef CURLDEBUG
void curl_multi_dump(CURLM *multi_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;
  int i;
  fprintf(stderr, "* Multi status: %d handles, %d alive\n",
          multi->num_easy, multi->num_alive);
  for(easy=multi->easy.next; easy; easy = easy->next) {
    if(easy->state != CURLM_STATE_COMPLETED) {
      /* only display handles that are not completed */
      fprintf(stderr, "handle %p, state %s, %d sockets\n",
              (void *)easy->easy_handle,
              statename[easy->state], easy->numsocks);
      for(i=0; i < easy->numsocks; i++) {
        curl_socket_t s = easy->sockets[i];
        struct Curl_sh_entry *entry =
          Curl_hash_pick(multi->sockhash, (char *)&s, sizeof(s));

        fprintf(stderr, "%d ", (int)s);
        if(!entry) {
          fprintf(stderr, "INTERNAL CONFUSION\n");
          continue;
        }
        fprintf(stderr, "[%s %s] ",
                entry->action&CURL_POLL_IN?"RECVING":"",
                entry->action&CURL_POLL_OUT?"SENDING":"");
      }
      if(easy->numsocks)
        fprintf(stderr, "\n");
    }
  }
}
#endif
