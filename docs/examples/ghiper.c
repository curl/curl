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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * multi socket API usage together with glib2
 * </DESC>
 */
/* Example application source code using the multi socket interface to
 * download many files at once.
 *
 * Written by Jeff Pohlmeyer

 Requires glib-2.x and a (POSIX?) system that has mkfifo().

 This is an adaptation of libfetch's "hipev.c" and libevent's "event-test.c"
 sample programs, adapted to use glib's g_io_channel in place of libevent.

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

 This is purely a demo app, all retrieved data is simply discarded by the write
 callback.

*/

#include <glib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fetch/fetch.h>

#define MSG_OUT g_print /* Change to "g_error" to write to stderr */
#define SHOW_VERBOSE 0  /* Set to non-zero for libfetch messages */
#define SHOW_PROGRESS 0 /* Set to non-zero to enable progress callback */

/* Global information, common to all connections */
typedef struct _GlobalInfo
{
  FETCHM *multi;
  guint timer_event;
  int still_running;
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
  GIOChannel *ch;
  guint ev;
  GlobalInfo *global;
} SockInfo;

/* Die if we get a bad FETCHMcode somewhere */
static void mcode_or_die(const char *where, FETCHMcode code)
{
  if (FETCHM_OK != code)
  {
    const char *s;
    switch (code)
    {
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
    case FETCHM_BAD_SOCKET:
      s = "FETCHM_BAD_SOCKET";
      break;
    case FETCHM_UNKNOWN_OPTION:
      s = "FETCHM_UNKNOWN_OPTION";
      break;
    case FETCHM_LAST:
      s = "FETCHM_LAST";
      break;
    default:
      s = "FETCHM_unknown";
    }
    MSG_OUT("ERROR: %s returns %s\n", where, s);
    exit(code);
  }
}

/* Check for completed transfers, and remove their easy handles */
static void check_multi_info(GlobalInfo *g)
{
  FETCHMsg *msg;
  int msgs_left;

  MSG_OUT("REMAINING: %d\n", g->still_running);
  while ((msg = fetch_multi_info_read(g->multi, &msgs_left)))
  {
    if (msg->msg == FETCHMSG_DONE)
    {
      FETCH *easy = msg->easy_handle;
      FETCHcode res = msg->data.result;
      char *eff_url;
      ConnInfo *conn;
      fetch_easy_getinfo(easy, FETCHINFO_PRIVATE, &conn);
      fetch_easy_getinfo(easy, FETCHINFO_EFFECTIVE_URL, &eff_url);
      MSG_OUT("DONE: %s => (%d) %s\n", eff_url, res, conn->error);
      fetch_multi_remove_handle(g->multi, easy);
      free(conn->url);
      fetch_easy_cleanup(easy);
      free(conn);
    }
  }
}

/* Called by glib when our timeout expires */
static gboolean timer_cb(gpointer data)
{
  GlobalInfo *g = (GlobalInfo *)data;
  FETCHMcode rc;

  rc = fetch_multi_socket_action(g->multi,
                                 FETCH_SOCKET_TIMEOUT, 0, &g->still_running);
  mcode_or_die("timer_cb: fetch_multi_socket_action", rc);
  check_multi_info(g);
  return FALSE;
}

/* Update the event timer after fetch_multi library calls */
static int update_timeout_cb(FETCHM *multi, long timeout_ms, void *userp)
{
  struct timeval timeout;
  GlobalInfo *g = (GlobalInfo *)userp;
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  MSG_OUT("*** update_timeout_cb %ld => %ld:%ld ***\n",
          timeout_ms, timeout.tv_sec, timeout.tv_usec);

  /*
   * if timeout_ms is -1, just delete the timer
   *
   * For other values of timeout_ms, this should set or *update* the timer to
   * the new value
   */
  if (timeout_ms >= 0)
    g->timer_event = g_timeout_add(timeout_ms, timer_cb, g);
  return 0;
}

/* Called by glib when we get action on a multi socket */
static gboolean event_cb(GIOChannel *ch, GIOCondition condition, gpointer data)
{
  GlobalInfo *g = (GlobalInfo *)data;
  FETCHMcode rc;
  int fd = g_io_channel_unix_get_fd(ch);

  int action =
      ((condition & G_IO_IN) ? FETCH_CSELECT_IN : 0) |
      ((condition & G_IO_OUT) ? FETCH_CSELECT_OUT : 0);

  rc = fetch_multi_socket_action(g->multi, fd, action, &g->still_running);
  mcode_or_die("event_cb: fetch_multi_socket_action", rc);

  check_multi_info(g);
  if (g->still_running)
  {
    return TRUE;
  }
  else
  {
    MSG_OUT("last transfer done, kill timeout\n");
    if (g->timer_event)
    {
      g_source_remove(g->timer_event);
    }
    return FALSE;
  }
}

/* Clean up the SockInfo structure */
static void remsock(SockInfo *f)
{
  if (!f)
  {
    return;
  }
  if (f->ev)
  {
    g_source_remove(f->ev);
  }
  g_free(f);
}

/* Assign information to a SockInfo structure */
static void setsock(SockInfo *f, fetch_socket_t s, FETCH *e, int act,
                    GlobalInfo *g)
{
  GIOCondition kind =
      ((act & FETCH_POLL_IN) ? G_IO_IN : 0) |
      ((act & FETCH_POLL_OUT) ? G_IO_OUT : 0);

  f->sockfd = s;
  f->action = act;
  f->easy = e;
  if (f->ev)
  {
    g_source_remove(f->ev);
  }
  f->ev = g_io_add_watch(f->ch, kind, event_cb, g);
}

/* Initialize a new SockInfo structure */
static void addsock(fetch_socket_t s, FETCH *easy, int action, GlobalInfo *g)
{
  SockInfo *fdp = g_malloc0(sizeof(SockInfo));

  fdp->global = g;
  fdp->ch = g_io_channel_unix_new(s);
  setsock(fdp, s, easy, action, g);
  fetch_multi_assign(g->multi, s, fdp);
}

/* FETCHMOPT_SOCKETFUNCTION */
static int sock_cb(FETCH *e, fetch_socket_t s, int what, void *cbp, void *sockp)
{
  GlobalInfo *g = (GlobalInfo *)cbp;
  SockInfo *fdp = (SockInfo *)sockp;
  static const char *whatstr[] = {"none", "IN", "OUT", "INOUT", "REMOVE"};

  MSG_OUT("socket callback: s=%d e=%p what=%s ", s, e, whatstr[what]);
  if (what == FETCH_POLL_REMOVE)
  {
    MSG_OUT("\n");
    remsock(fdp);
  }
  else
  {
    if (!fdp)
    {
      MSG_OUT("Adding data: %s%s\n",
              (what & FETCH_POLL_IN) ? "READ" : "",
              (what & FETCH_POLL_OUT) ? "WRITE" : "");
      addsock(s, e, what, g);
    }
    else
    {
      MSG_OUT(
          "Changing action from %d to %d\n", fdp->action, what);
      setsock(fdp, s, e, what, g);
    }
  }
  return 0;
}

/* FETCHOPT_WRITEFUNCTION */
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  ConnInfo *conn = (ConnInfo *)data;
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

  fprintf(MSG_OUT, "Progress: %s (%" FETCH_FORMAT_FETCH_OFF_T "/%" FETCH_FORMAT_FETCH_OFF_T ")\n", conn->url, dlnow, dltotal);
  return 0;
}

/* Create a new easy handle, and add it to the global fetch_multi */
static void new_conn(const char *url, GlobalInfo *g)
{
  ConnInfo *conn;
  FETCHMcode rc;

  conn = g_malloc0(sizeof(ConnInfo));
  conn->error[0] = '\0';
  conn->easy = fetch_easy_init();
  if (!conn->easy)
  {
    MSG_OUT("fetch_easy_init() failed, exiting!\n");
    exit(2);
  }
  conn->global = g;
  conn->url = g_strdup(url);
  fetch_easy_setopt(conn->easy, FETCHOPT_URL, conn->url);
  fetch_easy_setopt(conn->easy, FETCHOPT_WRITEFUNCTION, write_cb);
  fetch_easy_setopt(conn->easy, FETCHOPT_WRITEDATA, &conn);
  fetch_easy_setopt(conn->easy, FETCHOPT_VERBOSE, (long)SHOW_VERBOSE);
  fetch_easy_setopt(conn->easy, FETCHOPT_ERRORBUFFER, conn->error);
  fetch_easy_setopt(conn->easy, FETCHOPT_PRIVATE, conn);
  fetch_easy_setopt(conn->easy, FETCHOPT_NOPROGRESS, SHOW_PROGRESS ? 0L : 1L);
  fetch_easy_setopt(conn->easy, FETCHOPT_XFERINFOFUNCTION, xferinfo_cb);
  fetch_easy_setopt(conn->easy, FETCHOPT_PROGRESSDATA, conn);
  fetch_easy_setopt(conn->easy, FETCHOPT_FOLLOWLOCATION, 1L);
  fetch_easy_setopt(conn->easy, FETCHOPT_CONNECTTIMEOUT, 30L);
  fetch_easy_setopt(conn->easy, FETCHOPT_LOW_SPEED_LIMIT, 1L);
  fetch_easy_setopt(conn->easy, FETCHOPT_LOW_SPEED_TIME, 30L);

  MSG_OUT("Adding easy %p to multi %p (%s)\n", conn->easy, g->multi, url);
  rc = fetch_multi_add_handle(g->multi, conn->easy);
  mcode_or_die("new_conn: fetch_multi_add_handle", rc);

  /* note that add_handle() sets a timeout to trigger soon so that the
     necessary socket_action() gets called */
}

/* This gets called by glib whenever data is received from the fifo */
static gboolean fifo_cb(GIOChannel *ch, GIOCondition condition, gpointer data)
{
#define BUF_SIZE 1024
  gsize len, tp;
  gchar *buf, *tmp, *all = NULL;
  GIOStatus rv;

  do
  {
    GError *err = NULL;
    rv = g_io_channel_read_line(ch, &buf, &len, &tp, &err);
    if (buf)
    {
      if (tp)
      {
        buf[tp] = '\0';
      }
      new_conn(buf, (GlobalInfo *)data);
      g_free(buf);
    }
    else
    {
      buf = g_malloc(BUF_SIZE + 1);
      while (TRUE)
      {
        buf[BUF_SIZE] = '\0';
        g_io_channel_read_chars(ch, buf, BUF_SIZE, &len, &err);
        if (len)
        {
          buf[len] = '\0';
          if (all)
          {
            tmp = all;
            all = g_strdup_printf("%s%s", tmp, buf);
            g_free(tmp);
          }
          else
          {
            all = g_strdup(buf);
          }
        }
        else
        {
          break;
        }
      }
      if (all)
      {
        new_conn(all, (GlobalInfo *)data);
        g_free(all);
      }
      g_free(buf);
    }
    if (err)
    {
      g_error("fifo_cb: %s", err->message);
      g_free(err);
      break;
    }
  } while ((len) && (rv == G_IO_STATUS_NORMAL));
  return TRUE;
}

int init_fifo(void)
{
  struct stat st;
  const char *fifo = "hiper.fifo";
  int socket;

  if (lstat(fifo, &st) == 0)
  {
    if ((st.st_mode & S_IFMT) == S_IFREG)
    {
      errno = EEXIST;
      perror("lstat");
      exit(1);
    }
  }

  unlink(fifo);
  if (mkfifo(fifo, 0600) == -1)
  {
    perror("mkfifo");
    exit(1);
  }

  socket = open(fifo, O_RDWR | O_NONBLOCK, 0);

  if (socket == -1)
  {
    perror("open");
    exit(1);
  }
  MSG_OUT("Now, pipe some URL's into > %s\n", fifo);

  return socket;
}

int main(void)
{
  GlobalInfo *g = g_malloc0(sizeof(GlobalInfo));
  GMainLoop *gmain;
  int fd;
  GIOChannel *ch;

  fd = init_fifo();
  ch = g_io_channel_unix_new(fd);
  g_io_add_watch(ch, G_IO_IN, fifo_cb, g);
  gmain = g_main_loop_new(NULL, FALSE);
  g->multi = fetch_multi_init();
  fetch_multi_setopt(g->multi, FETCHMOPT_SOCKETFUNCTION, sock_cb);
  fetch_multi_setopt(g->multi, FETCHMOPT_SOCKETDATA, g);
  fetch_multi_setopt(g->multi, FETCHMOPT_TIMERFUNCTION, update_timeout_cb);
  fetch_multi_setopt(g->multi, FETCHMOPT_TIMERDATA, g);

  /* we do not call any fetch_multi_socket*() function yet as we have no handles
     added! */

  g_main_loop_run(gmain);
  fetch_multi_cleanup(g->multi);
  return 0;
}
