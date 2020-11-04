/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
/* <DESC>
 * multi socket API usage with libevent 2
 * </DESC>
 */
/* Example application source code using the multi socket interface to
   download many files at once.

Written by Jeff Pohlmeyer

Requires libevent version 2 and a (POSIX?) system that has mkfifo().

This is an adaptation of libcurl's "hipev.c" and libevent's "event-test.c"
sample programs.

When running, the program creates the named pipe "hiper.fifo"

Whenever there is input into the fifo, the program reads the input as a list
of URL's and creates some new easy handles to fetch each URL via the
curl_multi "hiper" API.


Thus, you can try a single URL:
  % echo http://www.yahoo.com > hiper.fifo

Or a whole bunch of them:
  % cat my-url-list > hiper.fifo

The fifo buffer is handled almost instantly, so you can even add more URL's
while the previous requests are still being downloaded.

Note:
  For the sake of simplicity, URL length is limited to 1023 char's !

This is purely a demo app, all retrieved data is simply discarded by the write
callback.

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/poll.h>
#include <curl/curl.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/cdefs.h>

#define MSG_OUT stdout /* Send info to stdout, change to stderr if you want */


/* Global information, common to all connections */
typedef struct _GlobalInfo
{
  struct event_base *evbase;
  struct event fifo_event;
  struct event timer_event;
  CURLM *multi;
  int still_running;
  FILE *input;
  int stopped;
} GlobalInfo;


/* Information associated with a specific easy handle */
typedef struct _ConnInfo
{
  CURL *easy;
  char *url;
  GlobalInfo *global;
  char error[CURL_ERROR_SIZE];
} ConnInfo;


/* Information associated with a specific socket */
typedef struct _SockInfo
{
  curl_socket_t sockfd;
  CURL *easy;
  int action;
  long timeout;
  struct event ev;
  GlobalInfo *global;
} SockInfo;

#define mycase(code) \
  case code: s = __STRING(code)

/* Die if we get a bad CURLMcode somewhere */
static void mcode_or_die(const char *where, CURLMcode code)
{
  if(CURLM_OK != code) {
    const char *s;
    switch(code) {
      mycase(CURLM_BAD_HANDLE); break;
      mycase(CURLM_BAD_EASY_HANDLE); break;
      mycase(CURLM_OUT_OF_MEMORY); break;
      mycase(CURLM_INTERNAL_ERROR); break;
      mycase(CURLM_UNKNOWN_OPTION); break;
      mycase(CURLM_LAST); break;
      default: s = "CURLM_unknown"; break;
      mycase(CURLM_BAD_SOCKET);
      fprintf(MSG_OUT, "ERROR: %s returns %s\n", where, s);
      /* ignore this error */
      return;
    }
    fprintf(MSG_OUT, "ERROR: %s returns %s\n", where, s);
    exit(code);
  }
}


/* Update the event timer after curl_multi library calls */
static int multi_timer_cb(CURLM *multi, long timeout_ms, GlobalInfo *g)
{
  struct timeval timeout;
  (void)multi;

  timeout.tv_sec = timeout_ms/1000;
  timeout.tv_usec = (timeout_ms%1000)*1000;
  fprintf(MSG_OUT, "multi_timer_cb: Setting timeout to %ld ms\n", timeout_ms);

  /*
   * if timeout_ms is -1, just delete the timer
   *
   * For all other values of timeout_ms, this should set or *update* the timer
   * to the new value
   */
  if(timeout_ms == -1)
    evtimer_del(&g->timer_event);
  else /* includes timeout zero */
    evtimer_add(&g->timer_event, &timeout);
  return 0;
}


/* Check for completed transfers, and remove their easy handles */
static void check_multi_info(GlobalInfo *g)
{
  char *eff_url;
  CURLMsg *msg;
  int msgs_left;
  ConnInfo *conn;
  CURL *easy;
  CURLcode res;

  fprintf(MSG_OUT, "REMAINING: %d\n", g->still_running);
  while((msg = curl_multi_info_read(g->multi, &msgs_left))) {
    if(msg->msg == CURLMSG_DONE) {
      easy = msg->easy_handle;
      res = msg->data.result;
      curl_easy_getinfo(easy, CURLINFO_PRIVATE, &conn);
      curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &eff_url);
      fprintf(MSG_OUT, "DONE: %s => (%d) %s\n", eff_url, res, conn->error);
      curl_multi_remove_handle(g->multi, easy);
      free(conn->url);
      curl_easy_cleanup(easy);
      free(conn);
    }
  }
  if(g->still_running == 0 && g->stopped)
    event_base_loopbreak(g->evbase);
}



/* Called by libevent when we get action on a multi socket */
static void event_cb(int fd, short kind, void *userp)
{
  GlobalInfo *g = (GlobalInfo*) userp;
  CURLMcode rc;

  int action =
    ((kind & EV_READ) ? CURL_CSELECT_IN : 0) |
    ((kind & EV_WRITE) ? CURL_CSELECT_OUT : 0);

  rc = curl_multi_socket_action(g->multi, fd, action, &g->still_running);
  mcode_or_die("event_cb: curl_multi_socket_action", rc);

  check_multi_info(g);
  if(g->still_running <= 0) {
    fprintf(MSG_OUT, "last transfer done, kill timeout\n");
    if(evtimer_pending(&g->timer_event, NULL)) {
      evtimer_del(&g->timer_event);
    }
  }
}



/* Called by libevent when our timeout expires */
static void timer_cb(int fd, short kind, void *userp)
{
  GlobalInfo *g = (GlobalInfo *)userp;
  CURLMcode rc;
  (void)fd;
  (void)kind;

  rc = curl_multi_socket_action(g->multi,
                                  CURL_SOCKET_TIMEOUT, 0, &g->still_running);
  mcode_or_die("timer_cb: curl_multi_socket_action", rc);
  check_multi_info(g);
}



/* Clean up the SockInfo structure */
static void remsock(SockInfo *f)
{
  if(f) {
    event_del(&f->ev);
    free(f);
  }
}



/* Assign information to a SockInfo structure */
static void setsock(SockInfo *f, curl_socket_t s, CURL *e, int act,
                    GlobalInfo *g)
{
  int kind =
     ((act & CURL_POLL_IN) ? EV_READ : 0) |
     ((act & CURL_POLL_OUT) ? EV_WRITE : 0) | EV_PERSIST;

  f->sockfd = s;
  f->action = act;
  f->easy = e;
  event_del(&f->ev);
  event_assign(&f->ev, g->evbase, f->sockfd, kind, event_cb, g);
  event_add(&f->ev, NULL);
}



/* Initialize a new SockInfo structure */
static void addsock(curl_socket_t s, CURL *easy, int action, GlobalInfo *g)
{
  SockInfo *fdp = calloc(sizeof(SockInfo), 1);

  fdp->global = g;
  setsock(fdp, s, easy, action, g);
  curl_multi_assign(g->multi, s, fdp);
}

/* CURLMOPT_SOCKETFUNCTION */
static int sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp)
{
  GlobalInfo *g = (GlobalInfo*) cbp;
  SockInfo *fdp = (SockInfo*) sockp;
  const char *whatstr[]={ "none", "IN", "OUT", "INOUT", "REMOVE" };

  fprintf(MSG_OUT,
          "socket callback: s=%d e=%p what=%s ", s, e, whatstr[what]);
  if(what == CURL_POLL_REMOVE) {
    fprintf(MSG_OUT, "\n");
    remsock(fdp);
  }
  else {
    if(!fdp) {
      fprintf(MSG_OUT, "Adding data: %s\n", whatstr[what]);
      addsock(s, e, what, g);
    }
    else {
      fprintf(MSG_OUT,
              "Changing action from %s to %s\n",
              whatstr[fdp->action], whatstr[what]);
      setsock(fdp, s, e, what, g);
    }
  }
  return 0;
}



/* CURLOPT_WRITEFUNCTION */
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
  (void)ptr;
  (void)data;
  return size * nmemb;
}


/* CURLOPT_PROGRESSFUNCTION */
static int prog_cb(void *p, double dltotal, double dlnow, double ult,
                   double uln)
{
  ConnInfo *conn = (ConnInfo *)p;
  (void)ult;
  (void)uln;

  fprintf(MSG_OUT, "Progress: %s (%g/%g)\n", conn->url, dlnow, dltotal);
  return 0;
}


/* Create a new easy handle, and add it to the global curl_multi */
static void new_conn(char *url, GlobalInfo *g)
{
  ConnInfo *conn;
  CURLMcode rc;

  conn = calloc(1, sizeof(ConnInfo));
  conn->error[0]='\0';

  conn->easy = curl_easy_init();
  if(!conn->easy) {
    fprintf(MSG_OUT, "curl_easy_init() failed, exiting!\n");
    exit(2);
  }
  conn->global = g;
  conn->url = strdup(url);
  curl_easy_setopt(conn->easy, CURLOPT_URL, conn->url);
  curl_easy_setopt(conn->easy, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(conn->easy, CURLOPT_WRITEDATA, conn);
  curl_easy_setopt(conn->easy, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(conn->easy, CURLOPT_ERRORBUFFER, conn->error);
  curl_easy_setopt(conn->easy, CURLOPT_PRIVATE, conn);
  curl_easy_setopt(conn->easy, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(conn->easy, CURLOPT_PROGRESSFUNCTION, prog_cb);
  curl_easy_setopt(conn->easy, CURLOPT_PROGRESSDATA, conn);
  curl_easy_setopt(conn->easy, CURLOPT_FOLLOWLOCATION, 1L);
  fprintf(MSG_OUT,
          "Adding easy %p to multi %p (%s)\n", conn->easy, g->multi, url);
  rc = curl_multi_add_handle(g->multi, conn->easy);
  mcode_or_die("new_conn: curl_multi_add_handle", rc);

  /* note that the add_handle() will set a time-out to trigger very soon so
     that the necessary socket_action() call will be called by this app */
}

/* This gets called whenever data is received from the fifo */
static void fifo_cb(int fd, short event, void *arg)
{
  char s[1024];
  long int rv = 0;
  int n = 0;
  GlobalInfo *g = (GlobalInfo *)arg;
  (void)fd;
  (void)event;

  do {
    s[0]='\0';
    rv = fscanf(g->input, "%1023s%n", s, &n);
    s[n]='\0';
    if(n && s[0]) {
      if(!strcmp(s, "stop")) {
        g->stopped = 1;
        if(g->still_running == 0)
          event_base_loopbreak(g->evbase);
      }
      else
        new_conn(s, arg);  /* if we read a URL, go get it! */
    }
    else
      break;
  } while(rv != EOF);
}

/* Create a named pipe and tell libevent to monitor it */
static const char *fifo = "hiper.fifo";
static int init_fifo(GlobalInfo *g)
{
  struct stat st;
  curl_socket_t sockfd;

  fprintf(MSG_OUT, "Creating named pipe \"%s\"\n", fifo);
  if(lstat (fifo, &st) == 0) {
    if((st.st_mode & S_IFMT) == S_IFREG) {
      errno = EEXIST;
      perror("lstat");
      exit(1);
    }
  }
  unlink(fifo);
  if(mkfifo (fifo, 0600) == -1) {
    perror("mkfifo");
    exit(1);
  }
  sockfd = open(fifo, O_RDWR | O_NONBLOCK, 0);
  if(sockfd == -1) {
    perror("open");
    exit(1);
  }
  g->input = fdopen(sockfd, "r");

  fprintf(MSG_OUT, "Now, pipe some URL's into > %s\n", fifo);
  event_assign(&g->fifo_event, g->evbase, sockfd, EV_READ|EV_PERSIST,
               fifo_cb, g);
  event_add(&g->fifo_event, NULL);
  return (0);
}

static void clean_fifo(GlobalInfo *g)
{
    event_del(&g->fifo_event);
    fclose(g->input);
    unlink(fifo);
}

int main(int argc, char **argv)
{
  GlobalInfo g;
  (void)argc;
  (void)argv;

  memset(&g, 0, sizeof(GlobalInfo));
  g.evbase = event_base_new();
  init_fifo(&g);
  g.multi = curl_multi_init();
  evtimer_assign(&g.timer_event, g.evbase, timer_cb, &g);

  /* setup the generic multi interface options we want */
  curl_multi_setopt(g.multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
  curl_multi_setopt(g.multi, CURLMOPT_SOCKETDATA, &g);
  curl_multi_setopt(g.multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
  curl_multi_setopt(g.multi, CURLMOPT_TIMERDATA, &g);

  /* we don't call any curl_multi_socket*() function yet as we have no handles
     added! */

  event_base_dispatch(g.evbase);

  /* this, of course, won't get called since only way to stop this program is
     via ctrl-C, but it is here to show how cleanup /would/ be done. */
  clean_fifo(&g);
  event_del(&g.timer_event);
  event_base_free(g.evbase);
  curl_multi_cleanup(g.multi);
  return 0;
}
