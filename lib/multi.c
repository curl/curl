/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
  CURLM_STATE_DO,          /* start send off the request (part 1) */
  CURLM_STATE_DOING,       /* sending off the request (part 1) */
  CURLM_STATE_DO_MORE,     /* send off the request (part 2) */
  CURLM_STATE_PERFORM,     /* transfer data */
  CURLM_STATE_TOOFAST,     /* wait because limit-rate exceeded */
  CURLM_STATE_DONE,        /* post data transfer operation */
  CURLM_STATE_COMPLETED,   /* operation complete */

  CURLM_STATE_LAST /* not a true state, never use this */
} CURLMstate;

/* we support 16 sockets per easy handle. Set the corresponding bit to what
   action we should wait for */
#define MAX_SOCKSPEREASYHANDLE 16
#define GETSOCK_READABLE (0x00ff)
#define GETSOCK_WRITABLE (0xff00)

struct socketstate {
  curl_socket_t socks[MAX_SOCKSPEREASYHANDLE];
  unsigned int action; /* socket action bitmap */
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

  struct socketstate sockstate; /* for the socket API magic */
};

#define CURL_MULTI_HANDLE 0x000bab1e

#define GOOD_MULTI_HANDLE(x) \
  ((x)&&(((struct Curl_multi *)x)->type == CURL_MULTI_HANDLE))
#define GOOD_EASY_HANDLE(x) (x)

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
};

/* always use this function to change state, to make debugging easier */
static void multistate(struct Curl_one_easy *easy, CURLMstate state)
{
#ifdef CURLDEBUG
  const char *statename[]={
    "INIT",
    "CONNECT",
    "WAITRESOLVE",
    "WAITCONNECT",
    "PROTOCONNECT",
    "DO",
    "DOING",
    "DO_MORE",
    "PERFORM",
    "TOOFAST",
    "DONE",
    "COMPLETED",
  };
  CURLMstate oldstate = easy->state;
#endif

  easy->state = state;

#ifdef CURLDEBUG
  infof(easy->easy_handle,
        "STATE: %s => %s handle %p: \n",
        statename[oldstate], statename[easy->state], (char *)easy);
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
  void *socketp; /* settable by users with curl_multi_assign() */
};
/* bits for 'action' having no bits means this socket is not expecting any
   action */
#define SH_READ  1
#define SH_WRITE 2

/* make sure this socket is present in the hash for this handle */
static int sh_addentry(struct curl_hash *sh,
                       curl_socket_t s,
                       struct SessionHandle *data)
{
  struct Curl_sh_entry *there =
    Curl_hash_pick(sh, (char *)&s, sizeof(curl_socket_t));
  struct Curl_sh_entry *check;

  if(there)
    /* it is present, return fine */
    return 0;

  /* not present, add it */
  check = calloc(sizeof(struct Curl_sh_entry), 1);
  if(!check)
    return 1; /* major failure */
  check->easy = data;

  /* make/add new hash entry */
  if(NULL == Curl_hash_add(sh, (char *)&s, sizeof(curl_socket_t), check))
    return 1; /* major failure */

  return 0; /* things are good in sockhash land */
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

  return (CURLM *) multi;
}

CURLMcode curl_multi_add_handle(CURLM *multi_handle,
                                CURL *easy_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;
  int i;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  /* Verify that we got a somewhat good easy handle too */
  if(!GOOD_EASY_HANDLE(easy_handle))
    return CURLM_BAD_EASY_HANDLE;

  /* Now, time to add an easy handle to the multi stack */
  easy = (struct Curl_one_easy *)calloc(sizeof(struct Curl_one_easy), 1);
  if(!easy)
    return CURLM_OUT_OF_MEMORY;

  for(i=0; i< MAX_SOCKSPEREASYHANDLE; i++)
    easy->sockstate.socks[i] = CURL_SOCKET_BAD;

  /* set the easy handle */
  easy->easy_handle = easy_handle;
  multistate(easy, CURLM_STATE_INIT);

  /* for multi interface connections, we share DNS cache automaticly if the
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
  /* increase the alive-counter */
  multi->num_alive++;

  return CURLM_OK;
}

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
    /* If the 'state' is not INIT or COMPLETED, we might need to do something
       nice to put the easy_handle in a good known state when this returns. */
    if(easy->state != CURLM_STATE_COMPLETED)
      /* this handle is "alive" so we need to count down the total number of
         alive connections when this is removed */
      multi->num_alive--;

    /* The timer must be shut down before easy->multi is set to NULL,
       else the timenode will remain in the splay tree after
       curl_easy_cleanup is called. */
    Curl_expire(easy->easy_handle, 0);

    if(easy->easy_handle->dns.hostcachetype == HCACHE_MULTI) {
      /* clear out the usage of the shared DNS cache */
      easy->easy_handle->dns.hostcache = NULL;
      easy->easy_handle->dns.hostcachetype = HCACHE_NONE;
    }

    Curl_easy_addmulti(easy->easy_handle, NULL); /* clear the association
                                                    to this multi handle */

    /* if we have a connection we must call Curl_done() here so that we
       don't leave a half-baked one around */
    if(easy->easy_conn)
      Curl_done(&easy->easy_conn, easy->result);

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

    return CURLM_OK;
  }
  else
    return CURLM_BAD_EASY_HANDLE; /* twasn't found */
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
  switch(easy->state) {
  case CURLM_STATE_TOOFAST:  /* returns 0, so will not select. */
  default:
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

  do {
    if (CURLM_STATE_WAITCONNECT <= easy->state &&
        easy->state <= CURLM_STATE_DO &&
        easy->easy_handle->change.url_changed) {
      char *gotourl;
      Curl_posttransfer(easy->easy_handle);

      easy->result = Curl_done(&easy->easy_conn, CURLE_OK);
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
        if(async)
          /* We're now waiting for an asynchronous name lookup */
          multistate(easy, CURLM_STATE_WAITRESOLVE);
        else {
          /* after the connect has been sent off, go WAITCONNECT unless the
             protocol connect is already done and we can go directly to
             DO! */
          result = CURLM_CALL_MULTI_PERFORM;

          if(protocol_connect)
            multistate(easy, CURLM_STATE_DO);
          else
            multistate(easy, CURLM_STATE_WAITCONNECT);
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
      easy->result = Curl_is_connected(easy->easy_conn, FIRSTSOCKET,
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
          /* after the connect has completed, go DO */
          multistate(easy, CURLM_STATE_DO);
          result = CURLM_CALL_MULTI_PERFORM;
        }
      }
      break;

    case CURLM_STATE_PROTOCONNECT:
      /* protocol-specific connect phase */
      easy->result = Curl_protocol_connecting(easy->easy_conn,
                                              &protocol_connect);
      if(protocol_connect) {
        /* after the connect has completed, go DO */
        multistate(easy, CURLM_STATE_DO);
        result = CURLM_CALL_MULTI_PERFORM;
      }
      else if(easy->result) {
        /* failure detected */
        Curl_posttransfer(easy->easy_handle);
        Curl_done(&easy->easy_conn, easy->result);
        Curl_disconnect(easy->easy_conn); /* close the connection */
        easy->easy_conn = NULL;           /* no more connection */
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
        easy->result = Curl_do(&easy->easy_conn, &dophase_done);

        if(CURLE_OK == easy->result) {

          if(!dophase_done) {
            /* DO was not completed in one function call, we must continue
               DOING... */
            multistate(easy, CURLM_STATE_DOING);
            result = CURLM_OK;
          }

          /* after DO, go PERFORM... or DO_MORE */
          else if(easy->easy_conn->bits.do_more) {
            /* we're supposed to do more, but we need to sit down, relax
               and wait a little while first */
            multistate(easy, CURLM_STATE_DO_MORE);
            result = CURLM_OK;
          }
          else {
            /* we're done with the DO, now PERFORM */
            easy->result = Curl_readwrite_init(easy->easy_conn);
            if(CURLE_OK == easy->result) {
              multistate(easy, CURLM_STATE_PERFORM);
              result = CURLM_CALL_MULTI_PERFORM;
            }
          }
        }
        else {
          /* failure detected */
          Curl_posttransfer(easy->easy_handle);
          Curl_done(&easy->easy_conn, easy->result);
          Curl_disconnect(easy->easy_conn); /* close the connection */
          easy->easy_conn = NULL;           /* no more connection */
        }
      }
      break;

    case CURLM_STATE_DOING:
      /* we continue DOING until the DO phase is complete */
      easy->result = Curl_protocol_doing(easy->easy_conn, &dophase_done);
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
            /* we're done with the DO, now PERFORM */
            easy->result = Curl_readwrite_init(easy->easy_conn);
            if(CURLE_OK == easy->result) {
              multistate(easy, CURLM_STATE_PERFORM);
              result = CURLM_CALL_MULTI_PERFORM;
            }
          }
        } /* dophase_done */
      }
      else {
        /* failure detected */
        Curl_posttransfer(easy->easy_handle);
        Curl_done(&easy->easy_conn, easy->result);
        Curl_disconnect(easy->easy_conn); /* close the connection */
        easy->easy_conn = NULL;           /* no more connection */
      }
      break;

    case CURLM_STATE_DO_MORE:
      /* Ready to do more? */
      easy->result = Curl_is_connected(easy->easy_conn, SECONDARYSOCKET,
                                       &connected);
      if(connected) {
        /*
         * When we are connected, DO MORE and then go PERFORM
         */
        easy->result = Curl_do_more(easy->easy_conn);

        if(CURLE_OK == easy->result)
          easy->result = Curl_readwrite_init(easy->easy_conn);

        if(CURLE_OK == easy->result) {
          multistate(easy, CURLM_STATE_PERFORM);
          result = CURLM_CALL_MULTI_PERFORM;
        }
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
        Curl_done(&easy->easy_conn, easy->result);
      }

      else if(TRUE == done) {
        char *newurl;
        bool retry = Curl_retry_request(easy->easy_conn, &newurl);

        /* call this even if the readwrite function returned error */
        Curl_posttransfer(easy->easy_handle);

        /* When we follow redirects, must to go back to the CONNECT state */
        if(easy->easy_conn->newurl || retry) {
          if(!retry) {
            /* if the URL is a follow-location and not just a retried request
               then figure out the URL here */
            newurl = easy->easy_conn->newurl;
            easy->easy_conn->newurl = NULL;
          }
          easy->result = Curl_done(&easy->easy_conn, CURLE_OK);
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
      /* post-transfer command */
      easy->result = Curl_done(&easy->easy_conn, CURLE_OK);

      /* after we have DONE what we're supposed to do, go COMPLETED, and
         it doesn't matter what the Curl_done() returned! */
      multistate(easy, CURLM_STATE_COMPLETED);
      break;

    case CURLM_STATE_COMPLETED:
      /* this is a completed transfer, it is likely to still be connected */

      /* This node should be delinked from the list now and we should post
         an information message that we are complete. */
      break;
    default:
      return CURLM_INTERNAL_ERROR;
    }

    if(CURLM_STATE_COMPLETED != easy->state) {
      if(CURLE_OK != easy->result) {
        /*
         * If an error was returned, and we aren't in completed state now,
         * then we go to completed and consider this transfer aborted.  */
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
    msg->next=NULL;

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
    CURLMcode result = multi_runsingle(multi, easy);
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

  if(GOOD_MULTI_HANDLE(multi)) {
    multi->type = 0; /* not good anymore */
    Curl_hash_destroy(multi->hostcache);
    Curl_hash_destroy(multi->sockhash);

    /* remove all easy handles */
    easy = multi->easy.next;
    while(easy) {
      nexteasy=easy->next;
      if(easy->easy_handle->dns.hostcachetype == HCACHE_MULTI) {
        /* clear out the usage of the shared DNS cache */
        easy->easy_handle->dns.hostcache = NULL;
        easy->easy_handle->dns.hostcachetype = HCACHE_NONE;
      }
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
  struct socketstate current;
  int i;

  memset(&current, 0, sizeof(current));
  for(i=0; i< MAX_SOCKSPEREASYHANDLE; i++)
    current.socks[i] = CURL_SOCKET_BAD;

  /* first fill in the 'current' struct with the state as it is now */
  current.action = multi_getsock(easy, current.socks, MAX_SOCKSPEREASYHANDLE);

  /* when filled in, we compare with the previous round's state in a first
     quick memory compare check */
  if(memcmp(&current, &easy->sockstate, sizeof(struct socketstate))) {

    /* there is difference, call the callback once for every socket change ! */
    for(i=0; i< MAX_SOCKSPEREASYHANDLE; i++) {
      int action;
      curl_socket_t s = current.socks[i];

      /* Ok, this approach is probably too naive and simple-minded but
         it might work for a start */

      if((easy->sockstate.socks[i] == CURL_SOCKET_BAD) &&
         (s == CURL_SOCKET_BAD)) {
        /* no socket now and there was no socket before */
        break;
      }

      if(s == CURL_SOCKET_BAD) {
        /* socket is removed */
        action = CURL_POLL_REMOVE;
        s = easy->sockstate.socks[i]; /* this is the removed socket */
      }
      else {
        if(easy->sockstate.socks[i] == s) {
          /* still the same socket, but are we waiting for the same actions? */
          unsigned int curr;
          unsigned int prev;

          /* the current read/write bits for this particular socket */
          curr = current.action & (GETSOCK_READSOCK(i) | GETSOCK_WRITESOCK(i));

          /* the previous read/write bits for this particular socket */
          prev = easy->sockstate.action &
            (GETSOCK_READSOCK(i) | GETSOCK_WRITESOCK(i));

          if(curr == prev)
            continue;
        }

        action = CURL_POLL_NONE;
        if(current.action & GETSOCK_READSOCK(i))
          action |= CURL_POLL_IN;
        if(current.action & GETSOCK_WRITESOCK(i))
          action |= CURL_POLL_OUT;
      }

      /* Update the sockhash accordingly BEFORE the callback if not a removal,
         in case the callback wants to use curl_multi_assign(), but do the
         removal AFTER the callback for the very same reason (but then to be
         able to pass the correct entry->socketp) */

      if(action != CURL_POLL_REMOVE)
        /* make sure this socket is present in the hash for this handle */
        sh_addentry(multi->sockhash, s, easy->easy_handle);

      /* call the callback with this new info */
      if(multi->socket_cb) {
        struct Curl_sh_entry *entry =
          Curl_hash_pick(multi->sockhash, (char *)&s, sizeof(s));

        multi->socket_cb(easy->easy_handle,
                         s,
                         action,
                         multi->socket_userp,
                         entry ? entry->socketp : NULL);
      }

      if(action == CURL_POLL_REMOVE)
        /* remove from hash for this easy handle */
        sh_delentry(multi->sockhash, s);

    }
    /* copy the current state to the storage area */
    memcpy(&easy->sockstate, &current, sizeof(struct socketstate));
  }
  else {
    /* identical, nothing new happened so we don't do any callbacks */
  }

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
  default:
    res = CURLM_UNKNOWN_OPTION;
  }
  va_end(param);
  return res;
}


CURLMcode curl_multi_socket(CURLM *multi_handle, curl_socket_t s,
                            int *running_handles)
{
  return multi_socket((struct Curl_multi *)multi_handle, FALSE, s,
                      running_handles);
}

CURLMcode curl_multi_socket_all(CURLM *multi_handle, int *running_handles)

{
  return multi_socket((struct Curl_multi *)multi_handle,
                      TRUE, CURL_SOCKET_BAD, running_handles);
}

CURLMcode curl_multi_timeout(CURLM *multi_handle,
                             long *timeout_ms)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

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
    infof(data, "Expire at %ld / %ld (%ldms)\n",
          (long)nowp->tv_sec, (long)nowp->tv_usec, milli);

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
