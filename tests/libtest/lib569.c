/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include "test.h"

#include <curl/mprintf.h>

#include "memdebug.h"

/* build request url */
static char *suburl(const char *base, int i)
{
  return curl_maprintf("%s%.4d", base, i);
}

/*
 * Test Session ID capture
 */
int test(char *URL)
{
  int res;
  CURL *curl;
  char *stream_uri = NULL;
  char *rtsp_session_id;
  int request=1;
  int i;
  FILE *idfile = NULL;

  idfile = fopen(libtest_arg2, "wb");
  if(idfile == NULL) {
    fprintf(stderr, "couldn't open the Session ID File\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    fclose(idfile);
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    fclose(idfile);
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_HEADERDATA, stdout);
  test_setopt(curl, CURLOPT_WRITEDATA, stdout);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  test_setopt(curl, CURLOPT_URL, URL);

  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
  res = curl_easy_perform(curl);
  if(res != (int)CURLE_BAD_FUNCTION_ARGUMENT) {
    fprintf(stderr, "This should have failed. "
            "Cannot setup without a Transport: header");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* Go through the various Session IDs */
  for(i = 0; i < 3; i++) {
    if((stream_uri = suburl(URL, request++)) == NULL) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
    free(stream_uri);
    stream_uri = NULL;

    test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
    test_setopt(curl, CURLOPT_RTSP_TRANSPORT, "Fake/NotReal/JustATest;foo=baz");
    res = curl_easy_perform(curl);
    if(res)
      goto test_cleanup;

    curl_easy_getinfo(curl, CURLINFO_RTSP_SESSION_ID, &rtsp_session_id);
    fprintf(idfile, "Got Session ID: [%s]\n", rtsp_session_id);
    rtsp_session_id = NULL;

    if((stream_uri = suburl(URL, request++)) == NULL) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
    free(stream_uri);
    stream_uri = NULL;

    test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_TEARDOWN);
    res = curl_easy_perform(curl);

    /* Clear for the next go-round */
    test_setopt(curl, CURLOPT_RTSP_SESSION_ID, NULL);
  }

test_cleanup:

  if(idfile)
    fclose(idfile);

  if(stream_uri)
    free(stream_uri);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}

