/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2013 - 2017, Linus Nielsen Feltzing, <linus@haxx.se>
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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000
#define MAX_URLS 200
#define MAX_BLACKLIST 20
#define BUNDLE_SIZE 2
#define NUM_HANDLE_REUSES 3

#define CONTENT_LENGTH    "Content-Length: 8"
#define DATAFMT           "%08.8u"
#define DATALEN           8
/*
#define PADDINGLEN        256
*/
#define        MAX(a,b) (((a)>(b))?(a):(b))
#define        MIN(a,b) (((a)<(b))?(a):(b))

static int urltime[MAX_URLS];
static char *urlstring[MAX_URLS];
static CURL *handles[MAX_URLS];
static char *site_blacklist[MAX_BLACKLIST];
static char *server_blacklist[MAX_BLACKLIST];
static int num_handles;
static int blacklist_num_servers;
static int blacklist_num_sites;
static char *test_base_url;
static struct curl_slist *curl_headers = NULL;
static int write_req_sequence = 0;
static int read_req_sequence = 0;

static size_t
write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  size_t datasize = MIN(DATALEN, realsize);
/*
  (void)contents;
  (void)userp;
*/
  char buf[DATALEN + 1];

  snprintf(buf, sizeof(buf), DATAFMT, (unsigned int) userp);
  printf("Received data '%*.*s' - expected '" DATAFMT "' - %s sequence %s\n",
    datasize, datasize, contents, (unsigned int) userp,
    strncmp(buf, contents, datasize) ? "MISMATCH" : "OK",
    write_req_sequence % num_handles == (int) (userp) ? "OK" : "OUT-OF-ORDER");

/*
  assert(write_req_sequence % num_handles == (int) (userp));
*/
  write_req_sequence++;

  return realsize;
}


static size_t
read_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
  static size_t sent = 0;

  if(sent) {
    /* Alternate between sending 8 bytes (data) and 0 bytes (EOF) */
    sent = 0;
  }
  else {
    sent = snprintf(contents, nmemb * size, DATAFMT, (unsigned int) userp);
/*
//    memmove((char  *)contents + sent, padding,
//      MIN(PADDINGLEN, size*nmemb-sent));
//    sent += MIN(PADDINGLEN, size*nmemb-sent);
*/
    printf("read_callback for seq %u (sending %zu/%zu bytes) sequence %s\n",
      (unsigned int) userp, sent, size*nmemb,
      read_req_sequence % num_handles == (int) (userp) ?
        "OK" : "OUT-OF-ORDER");
  }

/*
  assert(read_req_sequence % num_handles == (int) (userp));
*/
  if(sent == 0) {
    read_req_sequence++;
  }

  return sent;
}

struct Sockets
{
  curl_socket_t *sockets;
  int count;      /* number of sockets actually stored in array */
  int max_count;  /* max number of sockets that fit in allocated array */
};

struct ReadWriteSockets
{
  struct Sockets read, write;
};

/**
 * Remove a file descriptor from a sockets array.
 */
static void removeFd(struct Sockets* sockets, curl_socket_t fd, int mention)
{
  int i;

  if(mention)
    fprintf(stderr, "Remove socket fd %d\n", (int) fd);

  for(i = 0; i < sockets->count; ++i) {
    if(sockets->sockets[i] == fd) {
      if(i < sockets->count - 1)
        memmove(&sockets->sockets[i], &sockets->sockets[i + 1],
              sizeof(curl_socket_t) * (sockets->count - (i + 1)));
      --sockets->count;
    }
  }
}

/**
 * Add a file descriptor to a sockets array.
 */
static void addFd(struct Sockets* sockets, curl_socket_t fd, const char *what)
{
  /**
   * To ensure we only have each file descriptor once, we remove it then add
   * it again.
   */
  fprintf(stderr, "Add socket fd %d for %s\n", (int) fd, what);
  removeFd(sockets, fd, 0);
  /*
   * Allocate array storage when required.
   */
  if(!sockets->sockets) {
    sockets->sockets = malloc(sizeof(curl_socket_t) * 20U);
    if(!sockets->sockets)
      return;
    sockets->max_count = 20;
  }
  else if(sockets->count + 1 > sockets->max_count) {
    curl_socket_t *oldptr = sockets->sockets;
    sockets->sockets = realloc(oldptr, sizeof(curl_socket_t) *
                               (sockets->max_count + 20));
    if(!sockets->sockets) {
      /* cleanup in test_cleanup */
      sockets->sockets = oldptr;
      return;
    }
    sockets->max_count += 20;
  }
  /*
   * Add file descriptor to array.
   */
  sockets->sockets[sockets->count] = fd;
  ++sockets->count;
}

/**
 * Callback invoked by curl to poll reading / writing of a socket.
 */
static int curlSocketCallback(CURL *easy, curl_socket_t s, int action,
                              void *userp, void *socketp)
{
  struct ReadWriteSockets* sockets = userp;

  (void)easy; /* unused */
  (void)socketp; /* unused */

  if(action == CURL_POLL_IN || action == CURL_POLL_INOUT)
    addFd(&sockets->read, s, "read");

  if(action == CURL_POLL_OUT || action == CURL_POLL_INOUT)
    addFd(&sockets->write, s, "write");

  if(action == CURL_POLL_REMOVE) {
    removeFd(&sockets->read, s, 1);
    removeFd(&sockets->write, s, 0);
  }

  return 0;
}

/**
 * Callback invoked by curl to set a timeout.
 */
static int curlTimerCallback(CURLM *multi, long timeout_ms, void *userp)
{
  struct timeval* timeout = userp;

  (void)multi; /* unused */
  if(timeout_ms != -1) {
    *timeout = tutil_tvnow();
    timeout->tv_usec += timeout_ms * 1000;
  }
  else {
    timeout->tv_sec = -1;
  }
  return 0;
}

/**
 * Check for curl completion.
 */
static int checkForCompletion(CURLM *curl, int *success)
{
  int numMessages;
  CURLMsg *message;
  int result = 0;
  *success = 0;
  while((message = curl_multi_info_read(curl, &numMessages)) != NULL) {
    if(message->msg == CURLMSG_DONE) {
      result = 1;
      if(message->data.result == CURLE_OK)
        *success = 1;
      else
        *success = 0;
    }
    else {
      fprintf(stderr, "Got an unexpected message from curl: %i\n",
              (int)message->msg);
      result = 1;
      *success = 0;
    }
  }
  return result;
}

static int getMicroSecondTimeout(struct timeval* timeout)
{
  struct timeval now;
  ssize_t result;
  now = tutil_tvnow();
  result = (ssize_t)((timeout->tv_sec - now.tv_sec) * 1000000 +
    timeout->tv_usec - now.tv_usec);
  if(result < 0)
    result = 0;

  return curlx_sztosi(result);
}

/**
 * Update a fd_set with all of the sockets in use.
 */
static void updateFdSet(struct Sockets* sockets, fd_set* fdset,
                        curl_socket_t *maxFd)
{
  int i;
  for(i = 0; i < sockets->count; ++i) {
    FD_SET(sockets->sockets[i], fdset);
    if(*maxFd < sockets->sockets[i] + 1) {
      *maxFd = sockets->sockets[i] + 1;
    }
  }
}

static void check_multi_info(CURLM *m)
{
  char *done_url;
  CURLMsg *message;
  int pending;
  CURL *easy_handle;

  while((message = curl_multi_info_read(m, &pending))) {
    switch(message->msg) {
    case CURLMSG_DONE:
      /* Do not use message data after calling curl_multi_remove_handle() and
         curl_easy_cleanup(). As per curl_multi_info_read() docs:
         "WARNING: The data the returned pointer points to will not survive
         calling curl_multi_cleanup, curl_multi_remove_handle or
         curl_easy_cleanup." */
      easy_handle = message->easy_handle;

      curl_easy_getinfo(easy_handle, CURLINFO_EFFECTIVE_URL, &done_url);
      printf("%s DONE\n", done_url);

      curl_multi_remove_handle(m, easy_handle);
      break;

    default:
      fprintf(stderr, "CURLMSG default\n");
      break;
    }
  }
}

static void notifyCurl(CURLM *curl, curl_socket_t s, int evBitmask,
                       const char *info)
{
  int numhandles = 0;
  CURLMcode result = curl_multi_socket_action(curl, s, evBitmask, &numhandles);
  if(result != CURLM_OK) {
    fprintf(stderr, "Curl error on %s: %i (%s)\n",
            info, result, curl_multi_strerror(result));
  }

  check_multi_info(curl);
}

/**
 * Invoke curl when a file descriptor is set.
 */
static void checkFdSet(CURLM *curl, struct Sockets *sockets, fd_set *fdset,
                       int evBitmask, const char *name)
{
  int i;
  for(i = 0; i < sockets->count; ++i) {
    if(FD_ISSET(sockets->sockets[i], fdset)) {
      notifyCurl(curl, sockets->sockets[i], evBitmask, name);
    }
  }
}

static int parse_url_file(const char *filename)
{
  FILE *f;
  int filetime;
  char buf[200];

  num_handles = 0;
  blacklist_num_sites = 0;
  blacklist_num_servers = 0;

  f = fopen(filename, "rb");
  if(!f)
    return 0;

  while(!feof(f)) {
    if(fscanf(f, "%d %s\n", &filetime, buf)) {
      urltime[num_handles] = filetime;
      urlstring[num_handles] = strdup(buf);
      num_handles++;
      continue;
    }

    if(fscanf(f, "blacklist_site %s\n", buf)) {
      site_blacklist[blacklist_num_sites] = strdup(buf);
      blacklist_num_sites++;
      continue;
    }

    break;
  }
  fclose(f);

  site_blacklist[blacklist_num_sites] = NULL;
  server_blacklist[blacklist_num_servers] = NULL;
  return num_handles;
}

static void free_urls(void)
{
  int i;
  for(i = 0; i < num_handles; i++) {
    Curl_safefree(urlstring[i]);
  }
  for(i = 0; i < blacklist_num_servers; i++) {
    Curl_safefree(server_blacklist[i]);
  }
  for(i = 0; i < blacklist_num_sites; i++) {
    Curl_safefree(site_blacklist[i]);
  }
}

static int create_handles(void)
{
  int i;

  for(i = 0; i < num_handles; i++) {
    handles[i] = curl_easy_init();
  }
  return 0;
}

static void setup_handle(char *base_url, CURLM *m, int handlenum, int seq)
{
  char urlbuf[256];

  curl_easy_reset(handles[handlenum]);

  snprintf(urlbuf, sizeof(urlbuf), "%s%s", base_url, urlstring[handlenum]);
  curl_easy_setopt(handles[handlenum], CURLOPT_URL, urlbuf);
  curl_easy_setopt(handles[handlenum], CURLOPT_POST, 1);
  curl_easy_setopt(handles[handlenum], CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(handles[handlenum], CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(handles[handlenum], CURLOPT_HTTPHEADER, curl_headers);
  curl_easy_setopt(handles[handlenum], CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(handles[handlenum], CURLOPT_WRITEDATA, (void *) seq);
  curl_easy_setopt(handles[handlenum], CURLOPT_READFUNCTION, read_callback);
  curl_easy_setopt(handles[handlenum], CURLOPT_READDATA, (void *) seq);

  curl_multi_add_handle(m, handles[handlenum]);
}

static void remove_handles(void)
{
  int i;

  for(i = 0; i < num_handles; i++) {
    if(handles[i])
      curl_easy_cleanup(handles[i]);
  }
}

static void add_handles(CURLM *m, int start)
{
  static int i = 0;
  int j;

  /* Add BUNDLE_SIZE easy handles at a time.
     Call this repeatedly from various places until all the
     available easy handles have been added. It's ok to call it more.
  */
  if(start) i = 0;
  for(j = 0 ; i<num_handles && j<BUNDLE_SIZE ; i++, j++) {
    fprintf(stdout, "Adding handle %d, sequence %d\n", i, i);

    setup_handle(test_base_url, m, i, i);
  }
}

int test(char *URL)
{
  int res = 0;
  CURLM *m = NULL;
  int success = 0;
  struct ReadWriteSockets sockets = {{NULL, 0, 0}, {NULL, 0, 0}};
  struct timeval timeout = {-1, 0};
  struct timeval last_handle_add;
  test_base_url = URL;

  if(parse_url_file(libtest_arg2) <= 0)
    goto test_cleanup;

  start_test_timing();

  curl_global_init(CURL_GLOBAL_ALL);

  multi_init(m);

  create_handles();

  multi_setopt(m, CURLMOPT_PIPELINING, 1L);
  multi_setopt(m, CURLMOPT_MAX_HOST_CONNECTIONS, 1L);
  multi_setopt(m, CURLMOPT_MAX_PIPELINE_LENGTH, 2L);

  multi_setopt(m, CURLMOPT_PIPELINING_SITE_BL, site_blacklist);
  multi_setopt(m, CURLMOPT_PIPELINING_SERVER_BL, server_blacklist);

  multi_setopt(m, CURLMOPT_SOCKETFUNCTION, curlSocketCallback);
  multi_setopt(m, CURLMOPT_SOCKETDATA, &sockets);


  multi_setopt(m, CURLMOPT_TIMERFUNCTION, curlTimerCallback);
  multi_setopt(m, CURLMOPT_TIMERDATA, &timeout);

  last_handle_add = tutil_tvnow();

  curl_headers = curl_slist_append(curl_headers, "Expect:");
  curl_headers = curl_slist_append(curl_headers, CONTENT_LENGTH);

  add_handles(m, 1);
  while(!checkForCompletion(m, &success) &&
    read_req_sequence != num_handles) {
    fd_set readSet, writeSet;
    curl_socket_t maxFd = 0;
    struct timeval tv = {10, 0};

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    updateFdSet(&sockets.read, &readSet, &maxFd);
    updateFdSet(&sockets.write, &writeSet, &maxFd);

    if(timeout.tv_sec != -1) {
      int usTimeout = getMicroSecondTimeout(&timeout);
      tv.tv_sec = usTimeout / 1000000;
      tv.tv_usec = usTimeout % 1000000;
    }
    else if(maxFd <= 0) {
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
    }

    select_test((int)maxFd, &readSet, &writeSet, NULL, &tv);

    /* Check the sockets for reading / writing */
    checkFdSet(m, &sockets.read, &readSet, CURL_CSELECT_IN, "read");
    checkFdSet(m, &sockets.write, &writeSet, CURL_CSELECT_OUT, "write");

    if(timeout.tv_sec != -1 && getMicroSecondTimeout(&timeout) == 0) {
      /* Curl's timer has elapsed. */
      notifyCurl(m, CURL_SOCKET_TIMEOUT, 0, "timeout");
      add_handles(m, 0);
    }

    abort_on_test_timeout();
  }

test_cleanup:

  curl_slist_free_all(curl_headers);

  remove_handles();

  /* undocumented cleanup sequence - type UB */

  curl_multi_cleanup(m);
  curl_global_cleanup();

  /* free local memory */
  free(sockets.read.sockets);
  free(sockets.write.sockets);

  free_urls();
  return res;
}
