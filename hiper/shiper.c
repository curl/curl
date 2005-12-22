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
 * Run for a specific amount of time (10 secs for now). Output detailed timing
 * information.
 *
 * The same is hiper.c but instead using the new *socket() API instead of the
 * "old" *perform() call.
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

struct ourfdset {
  /* __fds_bits is what the Linux glibc headers use when they declare the
     fd_set struct so by using this we can actually avoid the typecase for the
     FD_SET() macro usage but it would hardly be portable */
  char __fds_bits[NCONNECTIONS/8];
};
#define FD2_ZERO(x) memset(x, 0, sizeof(struct ourfdset))

typedef struct ourfdset fd2_set;

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

struct fdinfo {
  /* create a link list of fdinfo structs */
  struct fdinfo *next;
  struct fdinfo *prev;
  curl_socket_t sockfd;
  CURL *easy;
  int action; /* as set by libcurl */
  long timeout; /* as set by libcurl */
  struct event ev;
};

static struct fdinfo *allsocks;

static struct fdinfo *findsock(curl_socket_t s)
{
  /* return the struct for the given socket */
  struct fdinfo *fdp = allsocks;

  while(fdp) {
    if(fdp->sockfd == s)
      break;
    fdp = fdp->next;
  }
  return fdp; /* a struct pointer or NULL */
}

static void remsock(curl_socket_t s)
{
  struct fdinfo *fdp;
  while(fdp) {
    if(fdp->sockfd == s)
      break;
    fdp = fdp->next;
  }
  if(!fdp)
    /* did not find socket to remove! */
    return;

  if(fdp->prev)
    fdp->prev->next = fdp->next;
  if(fdp->next)
    fdp->next->prev = fdp->prev;
  else
    /* this was the last entry */
    allsocks = NULL;
}

static void setsock(struct fdinfo *fdp, curl_socket_t s, CURL *easy,
                    int action, long timeout)
{
  fdp->sockfd = s;
  fdp->action = action;
  fdp->timeout = timeout;
  fdp->easy = easy;
}

static void addsock(curl_socket_t s, CURL *easy, int action, long timeout)
{
  struct fdinfo *fdp = calloc(sizeof(struct fdinfo), 1);

  setsock(fdp, s, easy, action, timeout);

  if(allsocks) {
    fdp->next = allsocks;
    allsocks->prev = fdp;

    /* now set allsocks to point to the new struct */
    allsocks = fdp;
  }
  else
    allsocks = fdp;
}

static void fdinfo2fdset(fd2_set *fdread, fd2_set *fdwrite, int *maxfd)
{
  struct fdinfo *fdp = allsocks;
  int writable=0;

  FD2_ZERO(fdread);
  FD2_ZERO(fdwrite);

  *maxfd = 0;

#if 0
  printf("Wait for: ");
#endif

  while(fdp) {
    if(fdp->action & CURL_POLL_IN) {
      FD_SET(fdp->sockfd, (fd_set *)fdread);
    }
    if(fdp->action & CURL_POLL_OUT) {
      FD_SET(fdp->sockfd, (fd_set *)fdwrite);
      writable++;
    }

#if 0
    printf("%d (%s%s) ",
           fdp->sockfd,
           (fdp->action & CURL_POLL_IN)?"r":"",
           (fdp->action & CURL_POLL_OUT)?"w":"");
#endif

    if(fdp->sockfd > *maxfd)
      *maxfd = fdp->sockfd;

    fdp = fdp->next;
  }
#if 0
  if(writable)
    printf("Check for %d writable sockets\n", writable);
#endif
}

/* on port 8999 we run a modified (fork-) sws that supports pure idle and full
   stream mode */
#define PORT "8999"

#define HOST "192.168.1.13"

#define URL_IDLE   "http://" HOST ":" PORT "/1000"
#define URL_ACTIVE "http://" HOST ":" PORT "/1001"


static int socket_callback(CURL *easy,      /* easy handle */
                           curl_socket_t s, /* socket */
                           int what,        /* see above */
                           long ms,         /* timeout for wait */
                           void *userp)     /* "private" pointer */
{
  struct fdinfo *fdp;
  printf("socket %d easy %p what %d timeout %ld\n", s, easy, what, ms);

  if(what == CURL_POLL_REMOVE)
    remsock(s);
  else {
    fdp = findsock(s);

    if(!fdp) {
      addsock(s, easy, what, ms);
    }
    else {
      /* we already know about it, just change action/timeout */
      printf("Changing info for socket %d from %d to %d\n",
             s, fdp->action, what);
      setsock(fdp, s, easy, what, ms);
    }
  }
  return 0; /* return code meaning? */
}


static size_t
writecallback(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  struct connection *c = (struct connection *)data;

  c->dlcounter += realsize;
  c->global->dlcounter += realsize;

#if 0
  printf("%02d: %d, total %d\n",
         c->id, c->dlcounter, c->global->dlcounter);
#endif
  return realsize;
}

/* return the diff between two timevals, in us */
static long tvdiff(struct timeval *newer, struct timeval *older)
{
  return (newer->tv_sec-older->tv_sec)*1000000+
    (newer->tv_usec-older->tv_usec);
}


/* store the start time of the program in this variable */
static struct timeval timer;

static void timer_start(void)
{
  /* capture the time of the start moment */
  gettimeofday(&timer, NULL);
}

static struct timeval cont; /* at this moment we continued */

int still_running; /* keep number of running handles */

struct conncount {
  long time_us;
  long laps;
  long maxtime;
};

static struct timeval timerpause;
static void timer_pause(void)
{
  /* capture the time of the pause moment */
  gettimeofday(&timerpause, NULL);

  /* If we have a previous continue (all times except the first), we can now
     store the time for a whole "lap" */
  if(cont.tv_sec) {
    long lap;

    lap = tvdiff(&timerpause, &cont);
  }
}

static long paused; /* amount of us we have been pausing */

static void timer_continue(void)
{
  /* Capture the time of the restored operation moment, now calculate how long
     time we were paused and added that to the 'paused' variable.
   */
  gettimeofday(&cont, NULL);

  paused += tvdiff(&cont, &timerpause);
}

static long total; /* amount of us from start to stop */
static void timer_total(void)
{
  struct timeval stop;
  /* Capture the time of the operation stopped moment, now calculate how long
     time we were running and how much of that pausing.
   */
  gettimeofday(&stop, NULL);

  total = tvdiff(&stop, &timer);
}

struct globalinfo info;
struct connection *conns;

long selects;
long timeouts;

long multi_socket;
long performalive;
long performselect;
long topselect;

int num_total;
int num_idle;
int num_active;

static void report(void)
{
  int i;
  long active = total - paused;
  long numdl = 0;

  for(i=0; i < num_total; i++) {
    if(conns[i].dlcounter)
      numdl++;
  }

  printf("Summary from %d simultanoues transfers (%d active)\n",
         num_total, num_active);
  printf("%d out of %d connections provided data\n", numdl, num_total);

  printf("Total time: %ldus paused: %ldus curl_multi_socket(): %ldus\n",
         total, paused, active);

  printf("%d calls to select() "
         "Average time: %dus\n",
         selects, paused/selects);
  printf(" Average number of readable connections per select() return: %d\n",
         performselect/selects);

  printf(" Max number of readable connections for a single select() "
         "return: %d\n",
         topselect);

  printf("%ld calls to multi_socket(), "
         "Average time: %ldus\n",
         multi_socket, active/multi_socket);

  printf("%ld select() timeouts\n", timeouts);

  printf("Downloaded %ld bytes in %ld bytes/sec, %ld usec/byte\n",
         info.dlcounter,
         info.dlcounter/(total/1000000),
         total/info.dlcounter);

}

int main(int argc, char **argv)
{
  CURLM *multi_handle;
  CURLMsg *msg;
  CURLcode code = CURLE_OK;
  CURLMcode mcode = CURLM_OK;
  int rc;
  int i;
  fd2_set fdsizecheck;
  int selectmaxamount;
  struct fdinfo *fdp;
  char act;

  memset(&info, 0, sizeof(struct globalinfo));

  selectmaxamount = sizeof(fdsizecheck) * 8;
  printf("select() supports max %d connections\n", selectmaxamount);

  if(argc < 3) {
    printf("Usage: hiper [num idle] [num active]\n");
    return 1;
  }

  num_idle = atoi(argv[1]);
  num_active = atoi(argv[2]);

  num_total = num_idle + num_active;

  if(num_total > selectmaxamount) {
    printf("Requested more connections than supported!\n");
    return 4;
  }

  conns = calloc(num_total, sizeof(struct connection));
  if(!conns) {
    printf("Out of memory\n");
    return 3;
  }

  if(num_total >= NCONNECTIONS) {
    printf("Too many connections requested, increase NCONNECTIONS!\n");
    return 2;
  }

  printf("About to do %d connections\n", num_total);

  /* init the multi stack */
  multi_handle = curl_multi_init();

  for(i=0; i< num_total; i++) {
    CURL *e;
    char *nl;

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
#if 0
    curl_easy_setopt(e, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(e, CURLOPT_ERRORBUFFER, conns[i].error);
    curl_easy_setopt(e, CURLOPT_PRIVATE, &conns[i]);

    /* add the easy to the multi */
    if(CURLM_OK != curl_multi_add_handle(multi_handle, e)) {
      printf("curl_multi_add_handle() returned error for %d\n", i);
      return 3;
    }
  }

  /* we start the action by calling *socket() right away */
  while(CURLM_CALL_MULTI_PERFORM ==
        curl_multi_socket_all(multi_handle, socket_callback, NULL));

  printf("Starting timer, expects to run for %ldus\n", RUN_FOR_THIS_LONG);
  timer_start();
  timer_pause();

  while(1) {
    struct timeval timeout;
    int rc; /* select() return code */

    fd2_set fdread;
    fd2_set fdwrite;
    int maxfd;

    /* set a suitable timeout to play around with */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    /* convert file descriptors from the transfers to fd_sets */
    fdinfo2fdset(&fdread, &fdwrite, &maxfd);

    selects++;
    rc = select(maxfd+1,
                (fd_set *)&fdread,
                (fd_set *)&fdwrite,
                NULL, &timeout);
    switch(rc) {
    case -1:
      /* select error */
      break;
    case 0:
      timeouts++;
    default:
      /* timeout or readable/writable sockets */

      for(i=0, fdp = allsocks; fdp; fdp = fdp->next) {
        act = 0;
        if((fdp->action & CURL_POLL_IN) &&
           FD_ISSET(fdp->sockfd, &fdread)) {
          act |= CURL_POLL_IN;
          i++;
        }
        if((fdp->action & CURL_POLL_OUT) &&
           FD_ISSET(fdp->sockfd, &fdwrite)) {
          act |= CURL_POLL_OUT;
          i++;
        }

        if(act) {
          multi_socket++;
#if 0
          printf("multi_socket for %p socket %d (%d)\n",
                 fdp, fdp->sockfd, act);
#endif
          timer_continue();
          if(act & CURL_POLL_OUT)
            act--;
          curl_multi_socket(multi_handle,
                            CURL_SOCKET_BAD,
                            fdp->easy,
                            socket_callback, NULL);
          timer_pause();
        }
      }

#if 0
      curl_multi_socket_all(multi_handle, socket_callback, NULL);
#endif

      performselect += rc;
      if(rc > topselect)
        topselect = rc;
      break;
    }

    timer_total(); /* calculate the total time spent so far */

    if(total > RUN_FOR_THIS_LONG) {
      printf("Stopped after %ldus\n", total);
      break;
    }
  }

  if(still_running != num_total) {
    /* something made connections fail, extract the reason and tell */
    int msgs_left;
    struct connection *cptr;
    while ((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
      if (msg->msg == CURLMSG_DONE) {
        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &cptr);

        printf("%d => (%d) %s", cptr->id, msg->data.result, cptr->error);
      }
    }

  }

  curl_multi_cleanup(multi_handle);

  /* cleanup all the easy handles */
  for(i=0; i< num_total; i++)
    curl_easy_cleanup(conns[i].e);

  report();

  return code;
}
