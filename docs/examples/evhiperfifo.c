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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * multi socket interface together with libev
 * </DESC>
 */
/* Example application source code using the multi socket interface to
 * download many files at once.
 *
 * This example features the same basic functionality as hiperfifo.c does,
 * but this uses libev instead of libevent.
 *
 * Written by Jeff Pohlmeyer, converted to use libev by Markus Koetter

Requires libev and a (POSIX?) system that has mkfifo().

This is an adaptation of libfetch's "hipev.c" and libevent's "event-test.c"
sample programs.

When running, the program creates the named pipe "hiper.fifo"

Whenever there is input into the fifo, the program reads the input as a list
of URL's and creates some new easy handles to fetch each URL via the
fetch_multi "hiper" API.


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
#include <fetch/fetch.h>
#include <ev.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define MSG_OUT stdout /* Send info to stdout, change to stderr if you want */


/* Global information, common to all connections */
typedef struct _GlobalInfo
{
  struct ev_loop *loop;
  struct ev_io fifo_event;
  struct ev_timer timer_event;
  FETCHM *multi;
  int still_running;
  FILE *input;
} GlobalInfo;


/* Information associated with a specific easy handle */
typedef struct _ConnInfo
{
  FETCH *easy;
  char *url;
  GlobalInfo *global;
  char error[FETCH_ERROR_SIZE];
} ConnInfo;


/* Information associated with a specific socket */
typedef struct _SockInfo
{
  fetch_socket_t sockfd;
  FETCH *easy;
  int action;
  long timeout;
  struct ev_io ev;
  int evset;
  GlobalInfo *global;
} SockInfo;

static void timer_cb(EV_P_ struct ev_timer *w, int revents);

/* Update the event timer after fetch_multi library calls */
static int multi_timer_cb(FETCHM *multi, long timeout_ms, GlobalInfo *g)
{
  (void)multi;
  printf("%s %li\n", __PRETTY_FUNCTION__, timeout_ms);
  ev_timer_stop(g->loop, &g->timer_event);
  if(timeout_ms >= 0) {
    /* -1 means delete, other values are timeout times in milliseconds */
    double  t = timeout_ms / 1000;
    ev_timer_init(&g->timer_event, timer_cb, t, 0.);
    ev_timer_start(g->loop, &g->timer_event);
  }
  return 0;
}

/* Die if we get a bad FETCHMcode somewhere */
static void mcode_or_die(const char *where, FETCHMcode code)
{
  if(FETCHM_OK != code) {
    const char *s;
    switch(code) {
    case FETCHM_BAD_HANDLE:
      s = "FETCHM_BAD_HANDLE";
      break;
    case FETCHM_BAD_EASY_HANDLE:
      s = "FETCHM_BAD_EASY_HANDLE";
      break;
    case FETCHM_OUT_OF_MEMORY:
      s = "FETCHM_OUT_OF_MEMORY";
      break;
    case FETCHM_INTERNAL_ERROR:
      s = "FETCHM_INTERNAL_ERROR";
      break;
    case FETCHM_UNKNOWN_OPTION:
      s = "FETCHM_UNKNOWN_OPTION";
      break;
    case FETCHM_LAST:
      s = "FETCHM_LAST";
      break;
    default:
      s = "FETCHM_unknown";
      break;
    case FETCHM_BAD_SOCKET:
      s = "FETCHM_BAD_SOCKET";
      fprintf(MSG_OUT, "ERROR: %s returns %s\n", where, s);
      /* ignore this error */
      return;
    }
    fprintf(MSG_OUT, "ERROR: %s returns %s\n", where, s);
    exit(code);
  }
}



/* Check for completed transfers, and remove their easy handles */
static void check_multi_info(GlobalInfo *g)
{
  char *eff_url;
  FETCHMsg *msg;
  int msgs_left;
  ConnInfo *conn;
  FETCH *easy;
  FETCHcode res;

  fprintf(MSG_OUT, "REMAINING: %d\n", g->still_running);
  while((msg = fetch_multi_info_read(g->multi, &msgs_left))) {
    if(msg->msg == FETCHMSG_DONE) {
      easy = msg->easy_handle;
      res = msg->data.result;
      fetch_easy_getinfo(easy, FETCHINFO_PRIVATE, &conn);
      fetch_easy_getinfo(easy, FETCHINFO_EFFECTIVE_URL, &eff_url);
      fprintf(MSG_OUT, "DONE: %s => (%d) %s\n", eff_url, res, conn->error);
      fetch_multi_remove_handle(g->multi, easy);
      free(conn->url);
      fetch_easy_cleanup(easy);
      free(conn);
    }
  }
}



/* Called by libevent when we get action on a multi socket */
static void event_cb(EV_P_ struct ev_io *w, int revents)
{
  GlobalInfo *g;
  FETCHMcode rc;
  int action;

  printf("%s  w %p revents %i\n", __PRETTY_FUNCTION__, (void *)w, revents);
  g = (GlobalInfo*) w->data;

  action = ((revents & EV_READ) ? FETCH_POLL_IN : 0) |
           ((revents & EV_WRITE) ? FETCH_POLL_OUT : 0);
  rc = fetch_multi_socket_action(g->multi, w->fd, action, &g->still_running);
  mcode_or_die("event_cb: fetch_multi_socket_action", rc);
  check_multi_info(g);
  if(g->still_running <= 0) {
    fprintf(MSG_OUT, "last transfer done, kill timeout\n");
    ev_timer_stop(g->loop, &g->timer_event);
  }
}

/* Called by libevent when our timeout expires */
static void timer_cb(EV_P_ struct ev_timer *w, int revents)
{
  GlobalInfo *g;
  FETCHMcode rc;

  printf("%s  w %p revents %i\n", __PRETTY_FUNCTION__, (void *)w, revents);

  g = (GlobalInfo *)w->data;

  rc = fetch_multi_socket_action(g->multi, FETCH_SOCKET_TIMEOUT, 0,
                                &g->still_running);
  mcode_or_die("timer_cb: fetch_multi_socket_action", rc);
  check_multi_info(g);
}

/* Clean up the SockInfo structure */
static void remsock(SockInfo *f, GlobalInfo *g)
{
  printf("%s  \n", __PRETTY_FUNCTION__);
  if(f) {
    if(f->evset)
      ev_io_stop(g->loop, &f->ev);
    free(f);
  }
}



/* Assign information to a SockInfo structure */
static void setsock(SockInfo *f, fetch_socket_t s, FETCH *e, int act,
                    GlobalInfo *g)
{
  int kind = ((act & FETCH_POLL_IN) ? EV_READ : 0) |
             ((act & FETCH_POLL_OUT) ? EV_WRITE : 0);

  printf("%s  \n", __PRETTY_FUNCTION__);

  f->sockfd = s;
  f->action = act;
  f->easy = e;
  if(f->evset)
    ev_io_stop(g->loop, &f->ev);
  ev_io_init(&f->ev, event_cb, f->sockfd, kind);
  f->ev.data = g;
  f->evset = 1;
  ev_io_start(g->loop, &f->ev);
}



/* Initialize a new SockInfo structure */
static void addsock(fetch_socket_t s, FETCH *easy, int action, GlobalInfo *g)
{
  SockInfo *fdp = calloc(1, sizeof(SockInfo));

  fdp->global = g;
  setsock(fdp, s, easy, action, g);
  fetch_multi_assign(g->multi, s, fdp);
}

/* FETCHMOPT_SOCKETFUNCTION */
static int sock_cb(FETCH *e, fetch_socket_t s, int what, void *cbp, void *sockp)
{
  GlobalInfo *g = (GlobalInfo*) cbp;
  SockInfo *fdp = (SockInfo*) sockp;
  const char *whatstr[]={ "none", "IN", "OUT", "INOUT", "REMOVE"};

  printf("%s e %p s %i what %i cbp %p sockp %p\n",
         __PRETTY_FUNCTION__, e, s, what, cbp, sockp);

  fprintf(MSG_OUT,
          "socket callback: s=%d e=%p what=%s ", s, e, whatstr[what]);
  if(what == FETCH_POLL_REMOVE) {
    fprintf(MSG_OUT, "\n");
    remsock(fdp, g);
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


/* FETCHOPT_WRITEFUNCTION */
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  ConnInfo *conn = (ConnInfo*) data;
  (void)ptr;
  (void)conn;
  return realsize;
}

/* FETCHOPT_XFERINFOFUNCTION */
static int xferinfo_cb(void *p, fetch_off_t dltotal, fetch_off_t dlnow,
                       fetch_off_t ult, fetch_off_t uln)
{
  ConnInfo *conn = (ConnInfo *)p;
  (void)ult;
  (void)uln;

  fprintf(MSG_OUT, "Progress: %s (%" FETCH_FORMAT_FETCH_OFF_T
          "/%" FETCH_FORMAT_FETCH_OFF_T ")\n", conn->url, dlnow, dltotal);
  return 0;
}


/* Create a new easy handle, and add it to the global fetch_multi */
static void new_conn(const char *url, GlobalInfo *g)
{
  ConnInfo *conn;
  FETCHMcode rc;

  conn = calloc(1, sizeof(ConnInfo));
  conn->error[0]='\0';

  conn->easy = fetch_easy_init();
  if(!conn->easy) {
    fprintf(MSG_OUT, "fetch_easy_init() failed, exiting!\n");
    exit(2);
  }
  conn->global = g;
  conn->url = strdup(url);
  fetch_easy_setopt(conn->easy, FETCHOPT_URL, conn->url);
  fetch_easy_setopt(conn->easy, FETCHOPT_WRITEFUNCTION, write_cb);
  fetch_easy_setopt(conn->easy, FETCHOPT_WRITEDATA, conn);
  fetch_easy_setopt(conn->easy, FETCHOPT_VERBOSE, 1L);
  fetch_easy_setopt(conn->easy, FETCHOPT_ERRORBUFFER, conn->error);
  fetch_easy_setopt(conn->easy, FETCHOPT_PRIVATE, conn);
  fetch_easy_setopt(conn->easy, FETCHOPT_NOPROGRESS, 0L);
  fetch_easy_setopt(conn->easy, FETCHOPT_XFERINFOFUNCTION, xferinfo_cb);
  fetch_easy_setopt(conn->easy, FETCHOPT_PROGRESSDATA, conn);
  fetch_easy_setopt(conn->easy, FETCHOPT_LOW_SPEED_TIME, 3L);
  fetch_easy_setopt(conn->easy, FETCHOPT_LOW_SPEED_LIMIT, 10L);

  fprintf(MSG_OUT,
          "Adding easy %p to multi %p (%s)\n", conn->easy, g->multi, url);
  rc = fetch_multi_add_handle(g->multi, conn->easy);
  mcode_or_die("new_conn: fetch_multi_add_handle", rc);

  /* note that add_handle() sets a timeout to trigger soon so that the
     necessary socket_action() gets called */
}

/* This gets called whenever data is received from the fifo */
static void fifo_cb(EV_P_ struct ev_io *w, int revents)
{
  char s[1024];
  long int rv = 0;
  int n = 0;
  GlobalInfo *g = (GlobalInfo *)w->data;

  (void)revents;

  do {
    s[0]='\0';
    rv = fscanf(g->input, "%1023s%n", s, &n);
    s[n]='\0';
    if(n && s[0]) {
      new_conn(s, g);  /* if we read a URL, go get it! */
    }
    else
      break;
  } while(rv != EOF);
}

/* Create a named pipe and tell libevent to monitor it */
static int init_fifo(GlobalInfo *g)
{
  struct stat st;
  static const char *fifo = "hiper.fifo";
  fetch_socket_t sockfd;

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
  ev_io_init(&g->fifo_event, fifo_cb, sockfd, EV_READ);
  ev_io_start(g->loop, &g->fifo_event);
  return 0;
}

int main(int argc, char **argv)
{
  GlobalInfo g;
  (void)argc;
  (void)argv;

  memset(&g, 0, sizeof(GlobalInfo));
  g.loop = ev_default_loop(0);

  init_fifo(&g);
  g.multi = fetch_multi_init();

  ev_timer_init(&g.timer_event, timer_cb, 0., 0.);
  g.timer_event.data = &g;
  g.fifo_event.data = &g;
  fetch_multi_setopt(g.multi, FETCHMOPT_SOCKETFUNCTION, sock_cb);
  fetch_multi_setopt(g.multi, FETCHMOPT_SOCKETDATA, &g);
  fetch_multi_setopt(g.multi, FETCHMOPT_TIMERFUNCTION, multi_timer_cb);
  fetch_multi_setopt(g.multi, FETCHMOPT_TIMERDATA, &g);

  /* we do not call any fetch_multi_socket*() function yet as we have no handles
     added! */

  ev_loop(g.loop, 0);
  fetch_multi_cleanup(g.multi);
  return 0;
}
