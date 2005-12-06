/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * Connect to N sites simultanouesly and download data.
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/poll.h>

#include <curl/curl.h>

/* The number of simultanoues connections/transfers we do */
#define NCONNECTIONS 2000

/* The least number of connections we are interested in, so when we go below
   this amount we can just as well stop */
#define NMARGIN 50

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
  char url[80];
  size_t dlcounter;
  struct globalinfo *global;
};

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

struct conncount timecount[NCONNECTIONS+1];

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

    timecount[still_running].time_us += lap;
    timecount[still_running].laps++; /* number of times added */

    if(lap > timecount[still_running].maxtime) {
      timecount[still_running].maxtime = lap;
    }
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
static void timer_stop(void)
{
  struct timeval stop;
  /* Capture the time of the operation stopped moment, now calculate how long
     time we were running and how much of that pausing.
   */
  gettimeofday(&stop, NULL);

  total = tvdiff(&stop, &timer);
}

struct globalinfo info;
struct connection conns[NCONNECTIONS];

long selects;
long selectsalive;
long timeouts;

long perform;
long performalive;
long performselect;
long topselect;

static void report(void)
{
  int i;
  long active = total - paused;
  long numdl = 0;

  for(i=0; i < NCONNECTIONS; i++) {
    if(conns[i].dlcounter)
      numdl++;
  }

  printf("Summary from %d simultanoues transfers:\n",
         NCONNECTIONS);

  printf("Total time %ldus - Paused %ldus = Active %ldus =\n Active/total"
         " %ldus\n",
         total, paused, active, active/NCONNECTIONS);

  printf(" Active/(connections that delivered data) = %ldus\n",
         active/numdl);

  printf("%d out of %d connections provided data\n", numdl, NCONNECTIONS);

  printf("%d calls to curl_multi_perform(), average %d alive. "
         "Average time: %dus\n",
         perform, performalive/perform, active/perform);

  printf("%d calls to select(), average %d alive\n",
         selects, selectsalive/selects);
  printf(" Average number of readable connections per select() return: %d\n",
         performselect/selects);
  printf(" Max number of readable connections for a single select() "
         "return: %d\n",
         topselect);

  printf("%ld select() timeouts\n", timeouts);

  for(i=1; i< NCONNECTIONS; i++) {
    if(timecount[i].laps) {
      printf("Time %d connections, average %ld max %ld (%ld laps) average/conn: %ld\n",
             i,
             timecount[i].time_us/timecount[i].laps,
             timecount[i].maxtime,
             timecount[i].laps,
             (timecount[i].time_us/timecount[i].laps)/i );
    }
  }
}

int main(int argc, char **argv)
{
  CURLM *multi_handle;
  CURLMsg *msg;
  CURLcode code = CURLE_OK;
  CURLMcode mcode = CURLM_OK;
  int rc;
  int i;
  FILE *urls;
  int startindex=0;
  char buffer[256];

  int prevalive=-1;
  int prevsamecounter=0;
  int prevtotal = -1;

  memset(&info, 0, sizeof(struct globalinfo));

  if(argc < 2) {
    printf("Usage: hiper [file] [start index]\n");
    return 1;
  }

  urls = fopen(argv[1], "r");
  if(!urls)
    /* failed to open list of urls */
    return 1;

  if(argc > 2)
    startindex = atoi(argv[2]);

  if(startindex) {
    /* Pass this many lines before we start using URLs from the file. On
       repeated invokes, try using different indexes to avoid torturing the
       same servers. */
    while(startindex--) {
      if(!fgets(buffer, sizeof(buffer), urls))
        break;
    }
  }

  /* init the multi stack */
  multi_handle = curl_multi_init();

  for(i=0; i< NCONNECTIONS; i++) {
    CURL *e;
    char *nl;

    memset(&conns[i], 0, sizeof(struct connection));

    /* read a line from the file of URLs */
    if(!fgets(conns[i].url, sizeof(conns[i].url), urls))
      /* failed to read a line */
      break;

    /* strip off trailing newlines */
    nl = strchr(conns[i].url, '\n');
    if(nl)
      *nl=0; /* cut */

    printf("%d: Add URL %s\n", i, conns[i].url);

    e  = curl_easy_init();
    conns[i].e = e;
    conns[i].id = i;
    conns[i].global = &info;

    curl_easy_setopt(e, CURLOPT_URL, conns[i].url);
    curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, writecallback);
    curl_easy_setopt(e, CURLOPT_WRITEDATA, &conns[i]);
#if 0
    curl_easy_setopt(e, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(e, CURLOPT_ERRORBUFFER, errorbuffer);
#endif

    /* add the easy to the multi */
    curl_multi_add_handle(multi_handle, e);
  }

    /* we start some action by calling perform right away */
  while(CURLM_CALL_MULTI_PERFORM ==
        curl_multi_perform(multi_handle, &still_running));

  printf("Starting timer!\n");
  timer_start();

  while(still_running) {
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

    timer_pause();
    selects++;
    selectsalive += still_running;
    rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

    /* Output this here to make it outside the timer */
    printf("Running: %d (%d bytes)\n", still_running, info.dlcounter);

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
    if(still_running < NMARGIN) {
      printf("Only %d connections left alive, existing\n",
             still_running);
      break;
    }

    if((prevalive == still_running) && (prevtotal == info.dlcounter) &&
       info.dlcounter) {
      /* The same amount of still alive transfers as last lap, increase
         counter. Only do this if _anything_ has been downloaded since it
         tends to come here during the initial name lookup phase when using
         asynch DNS libcurl otherwise.
       */
      prevsamecounter++;

      if(prevsamecounter >= IDLE_TIME) {
        /* for the sake of being efficient, we stop the operation when
           IDLE_TIME has passed without any bytes transfered */
        printf("Idle time (%d secs) reached (with %d still claimed alive),"
               " exiting\n",
               IDLE_TIME, still_running);
        break;
      }
    }
    else {
      prevsamecounter=0;
    }
    prevalive = still_running;
    prevtotal = info.dlcounter;
  }

  timer_stop();

  curl_multi_cleanup(multi_handle);

  /* cleanup all the easy handles */
  for(i=0; i< NCONNECTIONS; i++)
    curl_easy_cleanup(conns[i].e);

  report();

  return code;
}
