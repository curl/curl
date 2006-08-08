/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * Connect N connections. Z are idle, and X are active. Transfer as fast as
 * possible.
 *
 * Output detailed timing information.
 *
 * Uses libevent.
 *
 */

/* The maximum number of simultanoues connections/transfers we support */
#define NCONNECTIONS 50000

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/poll.h>

#include <curl/curl.h>

#include <event.h> /* for libevent */

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define MICROSEC 1000000 /* number of microseconds in one second */

/* The maximum time (in microseconds) we run the test */
#define RUN_FOR_THIS_LONG (5*MICROSEC)

/* Number of loops (seconds) we allow the total download amount and alive
   connections to remain the same until we bail out. Set this slightly higher
   when using asynch supported libcurl. */
#define IDLE_TIME 10

struct globalinfo {
  size_t dlcounter;
};

struct connection {
  CURL *e;
  int id; /* just a counter for easy browsing */
  char *url;
  size_t dlcounter;
  struct globalinfo *global;
  char error[CURL_ERROR_SIZE];
};

/* this is the struct associated with each file descriptor libcurl tells us
   it is dealing with */
struct fdinfo {
  /* create a link list of fdinfo structs */
  struct fdinfo *next;
  struct fdinfo *prev;
  curl_socket_t sockfd;
  CURL *easy;
  int action; /* as set by libcurl */
  long timeout; /* as set by libcurl */
  struct event ev; /* */
  int evset; /* true if the 'ev' struct has been used in a event_set() call */
  CURLM *multi; /* pointer to the multi handle */
  int *running_handles; /* pointer to the running_handles counter */
};

static struct fdinfo *allsocks;

static int running_handles;

/* we have the timerevent global so that when the final socket-based event is
   done, we can remove the timerevent as well */
static struct event timerevent;

static void update_timeout(CURLM *multi_handle);

/* called from libevent on action on a particular socket ("event") */
static void eventcallback(int fd, short type, void *userp)
{
  struct fdinfo *fdp = (struct fdinfo *)userp;
  CURLMcode rc;

  fprintf(stderr, "EVENT callback type %d\n", type);

  /* tell libcurl to deal with the transfer associated with this socket */
  do {
    rc = curl_multi_socket(fdp->multi, fd, fdp->running_handles);
  } while (rc == CURLM_CALL_MULTI_PERFORM);

  if(rc) {
    fprintf(stderr, "curl_multi_socket() returned %d\n", (int)rc);
  }

  fprintf(stderr, "running_handles: %d\n", *fdp->running_handles);
  if(!*fdp->running_handles) {
    /* last transfer is complete, kill pending timeout */
    fprintf(stderr, "last transfer done, kill timeout\n");
    if(evtimer_pending(&timerevent, NULL))
      evtimer_del(&timerevent);
  }
  else
    update_timeout(fdp->multi);
}

/* called from libevent when our timer event expires */
static void timercallback(int fd, short type, void *userp)
{
  (void)fd; /* not used for this */
  (void)type; /* ignored in here */
  CURLM *multi_handle = (CURLM *)userp;
  int running_handles;
  CURLMcode rc;

  fprintf(stderr, "EVENT timeout\n");

  /* tell libcurl to deal with the transfer associated with this socket */
  do {
    rc = curl_multi_socket(multi_handle, CURL_SOCKET_TIMEOUT,
                           &running_handles);
  } while (rc == CURLM_CALL_MULTI_PERFORM);

  if(running_handles)
    /* Get the current timeout value from libcurl and set a new timeout */
    update_timeout(multi_handle);
}

static void remsock(struct fdinfo *f)
{
  if(!f)
    /* did not find socket to remove! */
    return;

  if(f->evset)
    event_del(&f->ev);

  if(f->prev)
    f->prev->next = f->next;
  if(f->next)
    f->next->prev = f->prev;
  else
    /* this was the last entry */
    allsocks = NULL;
}

static void setsock(struct fdinfo *fdp, curl_socket_t s, CURL *easy,
                    int action)
{
  fdp->sockfd = s;
  fdp->action = action;
  fdp->easy = easy;

  if(fdp->evset)
    /* first remove the existing event if the old setup was used */
    event_del(&fdp->ev);

  /* now use and add the current socket setup to libevent. The EV_PERSIST is
     the key here as otherwise libevent will automatically remove the event
     when it occurs the first time */
  event_set(&fdp->ev, fdp->sockfd,
            (action&CURL_POLL_IN?EV_READ:0)|
            (action&CURL_POLL_OUT?EV_WRITE:0)| EV_PERSIST,
            eventcallback, fdp);

  fdp->evset=1;

  fprintf(stderr, "event_add() for fd %d\n", s);

  /* We don't use any socket-specific timeout but intead we use a single
     global one. This is (mostly) because libcurl doesn't expose any
     particular socket- based timeout value. */
  event_add(&fdp->ev, NULL);
}

static void addsock(curl_socket_t s, CURL *easy, int action, CURLM *multi)
{
  struct fdinfo *fdp = calloc(sizeof(struct fdinfo), 1);

  fdp->multi = multi;
  fdp->running_handles = &running_handles;
  setsock(fdp, s, easy, action);

  if(allsocks) {
    fdp->next = allsocks;
    allsocks->prev = fdp;

    /* now set allsocks to point to the new struct */
    allsocks = fdp;
  }
  else
    allsocks = fdp;

  /* Set this association in libcurl */
  curl_multi_assign(multi, s, fdp);
}

/* on port 8999 we run a fork enabled sws that supports 'idle' and 'stream' */
#define PORT "8999"

#define HOST "127.0.0.1"

#define URL_IDLE   "http://" HOST ":" PORT "/1000"
#if 1
#define URL_ACTIVE "http://" HOST ":" PORT "/1001"
#else
#define URL_ACTIVE "http://localhost/"
#endif

static int socket_callback(CURL *easy,      /* easy handle */
                           curl_socket_t s, /* socket */
                           int what,        /* see above */
                           void *cbp,       /* callback pointer */
                           void *socketp)   /* socket pointer */
{
  struct fdinfo *fdp = (struct fdinfo *)socketp;
  char *whatstr[]={
    "none",
    "IN",
    "OUT",
    "INOUT",
    "REMOVE"};

  fprintf(stderr, "socket %d easy %p what %s\n", s, easy,
          whatstr[what]);

  if(what == CURL_POLL_REMOVE)
    remsock(fdp);
  else {
    if(!fdp) {
      /* not previously known, add it and set association */
      printf("Add info for socket %d %s%s\n", s,
             what&CURL_POLL_IN?"READ":"",
             what&CURL_POLL_OUT?"WRITE":"" );
      addsock(s, easy, what, cbp);
    }
    else {
      /* we already know about it, just change action/timeout */
      printf("Changing info for socket %d from %d to %d\n",
             s, fdp->action, what);
      setsock(fdp, s, easy, what);
    }
  }
  return 0; /* return code meaning? */
}


static size_t
writecallback(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  struct connection *c = (struct connection *)data;
  (void)ptr;

  c->dlcounter += realsize;
  c->global->dlcounter += realsize;

  printf("%02d: %d, total %d\n",
         c->id, c->dlcounter, c->global->dlcounter);

  return realsize;
}

struct globalinfo info;
struct connection *conns;

int num_total;
int num_idle;
int num_active;

static void update_timeout(CURLM *multi_handle)
{
  long timeout_ms;
  struct timeval timeout;

  /* Since we need a global timeout to occur after a given time of inactivity,
     we use a single timeout-event. Get the timeout value from libcurl, and
     update it after every call to libcurl. */
  curl_multi_timeout(multi_handle, &timeout_ms);

  /* convert ms to timeval */
  timeout.tv_sec = timeout_ms/1000;
  timeout.tv_usec = (timeout_ms%1000)*1000;
  evtimer_add(&timerevent, &timeout);
}

int main(int argc, char **argv)
{
  CURLM *multi_handle;
  CURLMsg *msg;
  CURLcode code = CURLE_OK;
  int i;

  memset(&info, 0, sizeof(struct globalinfo));

  if(argc < 3) {
    printf("Usage: hiper-event [num idle] [num active]\n");
    return 1;
  }

  num_idle = atoi(argv[1]);
  num_active = atoi(argv[2]);

  num_total = num_idle + num_active;

  conns = calloc(num_total, sizeof(struct connection));
  if(!conns) {
    printf("Out of memory\n");
    return 3;
  }

  if(num_total >= NCONNECTIONS) {
    printf("Too many connections requested, increase NCONNECTIONS!\n");
    return 2;
  }

  event_init(); /* Initalize the event library */

  printf("About to do %d connections\n", num_total);

  /* initialize the timeout event */
  evtimer_set(&timerevent, timercallback, multi_handle);

  /* init the multi stack */
  multi_handle = curl_multi_init();

  for(i=0; i< num_total; i++) {
    CURL *e;

    memset(&conns[i], 0, sizeof(struct connection));

    if(i < num_idle)
      conns[i].url = URL_IDLE;
    else
      conns[i].url = URL_ACTIVE;

    e  = curl_easy_init();

    if(!e) {
      printf("curl_easy_init() for handle %d failed, exiting!\n", i);
      return 2;
    }

    conns[i].e = e;
    conns[i].id = i;
    conns[i].global = &info;

    curl_easy_setopt(e, CURLOPT_URL, conns[i].url);
    curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, writecallback);
    curl_easy_setopt(e, CURLOPT_WRITEDATA, &conns[i]);
    curl_easy_setopt(e, CURLOPT_VERBOSE, 0);
    curl_easy_setopt(e, CURLOPT_ERRORBUFFER, conns[i].error);
    curl_easy_setopt(e, CURLOPT_PRIVATE, &conns[i]);

    /* add the easy to the multi */
    if(CURLM_OK != curl_multi_add_handle(multi_handle, e)) {
      printf("curl_multi_add_handle() returned error for %d\n", i);
      return 3;
    }
  }

  curl_multi_setopt(multi_handle, CURLMOPT_SOCKETFUNCTION, socket_callback);
  curl_multi_setopt(multi_handle, CURLMOPT_SOCKETDATA, multi_handle);

  /* we start the action by calling *socket_all() */
  while(CURLM_CALL_MULTI_PERFORM == curl_multi_socket_all(multi_handle,
                                                          &running_handles));

  /* update timeout */
  update_timeout(multi_handle);

  /* event_dispatch() runs the event main loop. It ends when no events are
     left to wait for. */

  event_dispatch();

  {
    /* something made connections fail, extract the reason and tell */
    int msgs_left;
    struct connection *cptr;
    while ((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
      if (msg->msg == CURLMSG_DONE) {
        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &cptr);

        printf("%d => (%d) %s\n",
               cptr->id, msg->data.result, cptr->error);
      }
    }
  }

  curl_multi_cleanup(multi_handle);

  /* cleanup all the easy handles */
  for(i=0; i< num_total; i++)
    curl_easy_cleanup(conns[i].e);

  return code;
}
