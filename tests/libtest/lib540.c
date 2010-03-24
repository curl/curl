/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
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

#include "memdebug.h"

#define PROXY libtest_arg2
#define PROXYUSERPWD libtest_arg3
#define HOST test_argv[4]

static int init(CURLM *cm, const char* url, const char* userpwd,
                struct curl_slist *headers)
{
  CURL *eh;
  int res;

  if ((eh = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    return 1; /* failure */
  }

  res = curl_easy_setopt(eh, CURLOPT_URL, url);
  if(res) return 1;
  res = curl_easy_setopt(eh, CURLOPT_PROXY, PROXY);
  if(res) return 1;
  res = curl_easy_setopt(eh, CURLOPT_PROXYUSERPWD, userpwd);
  if(res) return 1;
  res = curl_easy_setopt(eh, CURLOPT_PROXYAUTH, (long)CURLAUTH_ANY);
  if(res) return 1;
  res = curl_easy_setopt(eh, CURLOPT_VERBOSE, 1L);
  if(res) return 1;
  res = curl_easy_setopt(eh, CURLOPT_HEADER, 1L);
  if(res) return 1;
  res = curl_easy_setopt(eh, CURLOPT_HTTPHEADER, headers); /* custom Host: */
  if(res) return 1;

  if ((res = (int)curl_multi_add_handle(cm, eh)) != CURLM_OK) {
    fprintf(stderr, "curl_multi_add_handle() failed, "
            "with code %d\n", res);
    return 1; /* failure */
  }

  return 0; /* success */
}

static int loop(CURLM *cm, const char* url, const char* userpwd,
                struct curl_slist *headers)
{
  CURLMsg *msg;
  CURLMcode code;
  long L;
  int M, Q, U = -1;
  fd_set R, W, E;
  struct timeval T;

  if(init(cm, url, userpwd, headers))
    return 1; /* failure */

  while (U) {

    do {
      code = curl_multi_perform(cm, &U);
    } while (code == CURLM_CALL_MULTI_PERFORM);

    if (U) {
      FD_ZERO(&R);
      FD_ZERO(&W);
      FD_ZERO(&E);

      if (curl_multi_fdset(cm, &R, &W, &E, &M)) {
        fprintf(stderr, "E: curl_multi_fdset\n");
        return 1; /* failure */
      }

      /* In a real-world program you OF COURSE check the return that maxfd is
         bigger than -1 so that the call to select() below makes sense! */

      if (curl_multi_timeout(cm, &L)) {
        fprintf(stderr, "E: curl_multi_timeout\n");
        return 1; /* failure */
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
        return 1; /* failure */
      }
    }

    while ((msg = curl_multi_info_read(cm, &Q))) {
      if (msg->msg == CURLMSG_DONE) {
        CURL *e = msg->easy_handle;
        fprintf(stderr, "R: %d - %s\n", (int)msg->data.result,
                curl_easy_strerror(msg->data.result));
        curl_multi_remove_handle(cm, e);
        curl_easy_cleanup(e);
      }
      else {
        fprintf(stderr, "E: CURLMsg (%d)\n", (int)msg->msg);
      }
    }
  }

  return 0; /* success */
}

int test(char *URL)
{
  CURLM *cm = NULL;
  struct curl_slist *headers = NULL;
  char buffer[246]; /* naively fixed-size */
  int res;

  if(test_argc < 4)
    return 99;

  sprintf(buffer, "Host: %s", HOST);

  /* now add a custom Host: header */
  headers = curl_slist_append(headers, buffer);
  if(!headers) {
    fprintf(stderr, "curl_slist_append() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    curl_slist_free_all(headers);
    return TEST_ERR_MAJOR_BAD;
  }

  if ((cm = curl_multi_init()) == NULL) {
    fprintf(stderr, "curl_multi_init() failed\n");
    curl_slist_free_all(headers);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  res = loop(cm, URL, PROXYUSERPWD, headers);
  if(res)
    goto test_cleanup;

  fprintf(stderr, "lib540: now we do the request again\n");
  res = loop(cm, URL, PROXYUSERPWD, headers);

test_cleanup:

  curl_multi_cleanup(cm);

  curl_global_cleanup();

  curl_slist_free_all(headers);

  return res;
}
