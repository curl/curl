/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * This is the 'proxyauth.c' test app posted by Shmulik Regev on the libcurl
 * mailing list on 10 Jul 2007, converted to a test case.
 *
 * argv1 = URL
 * argv2 = proxy
 * argv3 = proxyuser:password
 * argv4 = host name to use for the custom Host: header
 */

#include "test.h"

#define PROXY arg2
#define PROXYUSERPWD arg3
#define HOST test_argv[4]

static void init(CURLM *cm, const char* url, const char* userpwd,
                struct curl_slist *headers)
{
  CURL *eh = curl_easy_init();

  curl_easy_setopt(eh, CURLOPT_URL, url);
  curl_easy_setopt(eh, CURLOPT_PROXY, PROXY);
  curl_easy_setopt(eh, CURLOPT_PROXYUSERPWD, userpwd);
  curl_easy_setopt(eh, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  curl_easy_setopt(eh, CURLOPT_VERBOSE, 1);
  curl_easy_setopt(eh, CURLOPT_HEADER, 1);
  curl_easy_setopt(eh, CURLOPT_HTTPHEADER, headers); /* custom Host: */

  curl_multi_add_handle(cm, eh);
}

static int loop(CURLM *cm, const char* url, const char* userpwd,
                struct curl_slist *headers)
{
  CURLMsg *msg;
  long L;
  int M, Q, U = -1;
  fd_set R, W, E;
  struct timeval T;

  init(cm, url, userpwd, headers);

  while (U) {
    while (CURLM_CALL_MULTI_PERFORM == curl_multi_perform(cm, &U));

    if (U) {
      FD_ZERO(&R);
      FD_ZERO(&W);
      FD_ZERO(&E);

      if (curl_multi_fdset(cm, &R, &W, &E, &M)) {
        fprintf(stderr, "E: curl_multi_fdset\n");
        return EXIT_FAILURE;
      }

      /* In a real-world program you OF COURSE check the return that maxfd is
         bigger than -1 so that the call to select() below makes sense! */

      if (curl_multi_timeout(cm, &L)) {
        fprintf(stderr, "E: curl_multi_timeout\n");
        return EXIT_FAILURE;
      }

      if(L != -1) {
        T.tv_sec = L/1000;
        T.tv_usec = (L%1000)*1000;
      }
      else {
        T.tv_sec = 5;
        T.tv_usec = 0;
      }

      if (0 > select(M+1, &R, &W, &E, &T)) {
        fprintf(stderr, "E: select\n");
        return EXIT_FAILURE;
      }
    }

    while ((msg = curl_multi_info_read(cm, &Q))) {
      if (msg->msg == CURLMSG_DONE) {
        char *url;
        CURL *e = msg->easy_handle;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &url);
        fprintf(stderr, "R: %d - %s <%s>\n",
                msg->data.result, curl_easy_strerror(msg->data.result), url);
        curl_multi_remove_handle(cm, e);
        curl_easy_cleanup(e);
      }
      else {
        fprintf(stderr, "E: CURLMsg (%d)\n", msg->msg);
      }
    }
  }

  return 1;
}

int test(char *URL)
{
  CURLM *cm;
  struct curl_slist *headers = NULL;
  char buffer[246]; /* naively fixed-size */

  if(test_argc < 4)
    return 99;

  sprintf(buffer, "Host: %s", HOST);

  /* now add a custom Host: header */
  headers = curl_slist_append(headers, buffer);

  curl_global_init(CURL_GLOBAL_ALL);

  cm = curl_multi_init();
  loop(cm, URL, PROXYUSERPWD, headers);

  fprintf(stderr, "lib540: now we do the request again\n");
  loop(cm, URL, PROXYUSERPWD, headers);

  curl_multi_cleanup(cm);

  curl_global_cleanup();

  curl_slist_free_all(headers);

  return EXIT_SUCCESS;
}
