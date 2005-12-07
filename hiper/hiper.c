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
 */

/* The maximum number of simultanoues connections/transfers we support */
#define NCONNECTIONS 50000

#define __FD_SETSIZE NCONNECTIONS
#define FD_SETSIZE NCONNECTIONS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/poll.h>

#include <curl/curl.h>

#define MICROSEC 1000000 /* number of microseconds in one second */

/* The maximum time (in microseconds) we run the test */
#define RUN_FOR_THIS_LONG (10*MICROSEC)

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

/* on port 8999 we run a modified (fork-) sws that supports pure idle and full
   stream mode */
#define PORT "8999"

#define HOST "192.168.1.13"

#define URL_IDLE   "http://" HOST ":" PORT "/1000"
#define URL_ACTIVE "http://" HOST ":" PORT "/1001"

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
long selectsalive;
long timeouts;

long perform;
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

  printf("Total time: %ldus select(): %ldus curl_multi_perform(): %ldus\n",
         total, paused, active);

  printf("%d calls to curl_multi_perform() average %d alive "
         "Average time: %dus\n",
         perform, performalive/perform, active/perform);

  printf("%d calls to select(), average %d alive "
         "Average time: %dus\n",
         selects, selectsalive/selects,
         paused/selects);
  printf(" Average number of readable connections per select() return: %d\n",
         performselect/selects);
  printf(" Max number of readable connections for a single select() "
         "return: %d\n",
         topselect);

  printf("%ld select() timeouts\n", timeouts);

#if 0
  for(i=1; i< num_total; i++) {
    if(timecount[i].laps) {
      printf("Time %d connections, average %ld max %ld (%ld laps) "
             "average/conn: %ld\n",
             i,
             timecount[i].time_us/timecount[i].laps,
             timecount[i].maxtime,
             timecount[i].laps,
             (timecount[i].time_us/timecount[i].laps)/i );
    }
  }
#endif
}

int main(int argc, char **argv)
{
  CURLM *multi_handle;
  CURLMsg *msg;
  CURLcode code = CURLE_OK;
  CURLMcode mcode = CURLM_OK;
  int rc;
  int i;

  int prevalive=-1;
  int prevsamecounter=0;
  int prevtotal = -1;

  memset(&info, 0, sizeof(struct globalinfo));

  if(argc < 3) {
    printf("Usage: hiper [num idle] [num active]\n");
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
    printf("Increase NCONNECTIONS!\n");
    return 2;
  }

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

#if 0
    printf("%d: Add URL %s\n", i, conns[i].url);
#endif
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
    curl_multi_add_handle(multi_handle, e);
  }

    /* we start some action by calling perform right away */
  while(CURLM_CALL_MULTI_PERFORM ==
        curl_multi_perform(multi_handle, &still_running));

  printf("Starting timer, expects to run for %ldus\n", RUN_FOR_THIS_LONG);
  timer_start();

  while(still_running == num_total) {
    struct timeval timeout;
    int rc; /* select() return code */

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* set a suitable timeout to play around with */
    timeout.tv_sec = 0;
    timeout.tv_usec = 50000;

    /* get file descriptors from the transfers */
    curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
    printf("maxfd: %d\n", maxfd);

    timer_pause();
    selects++;
    selectsalive += still_running;
    rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

#if 0
    /* Output this here to make it outside the timer */
    printf("Running: %d (%d bytes)\n", still_running, info.dlcounter);
#endif
    timer_continue();

    switch(rc) {
    case -1:
      /* select error */
      break;
    case 0:
      timeouts++;
    default:
      /* timeout or readable/writable sockets */
      do {
        perform++;
        performalive += still_running;
      }
      while(CURLM_CALL_MULTI_PERFORM ==
            curl_multi_perform(multi_handle, &still_running));

      performselect += rc;
      if(rc > topselect)
        topselect = rc;
      break;
    }

    if(total > RUN_FOR_THIS_LONG) {
      printf("Stopped after %ldus\n", total);
      break;
    }

    if(prevalive != still_running) {
      printf("%d connections alive\n", still_running);
    }
    prevalive = still_running;

    timer_total(); /* calculate the total time spent so far */
  }

  if(still_running != num_total) {
    /* something made connections fail, extract the reason and tell */
    int msgs_left;
    struct connection *cptr;
    while ((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
      if (msg->msg == CURLMSG_DONE) {
        printf("Handle %p returned %d\n", msg->easy_handle, msg->data.result);

        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &cptr);

        printf("   Error message: %s\n", cptr->error);
      }
    }

  }

  curl_multi_cleanup(multi_handle);

  /* cleanup all the easy handles */
  for(i=0; i< NCONNECTIONS; i++)
    curl_easy_cleanup(conns[i].e);

  report();

  return code;
}
