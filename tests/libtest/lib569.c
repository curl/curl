/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
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
  CURLcode res;
  CURL *curl;
  char *stream_uri;
  char *rtsp_session_id;
  int request=1;
  int i;
  FILE *idfile;

  idfile = fopen(libtest_arg2, "w");
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

  curl_easy_setopt(curl, CURLOPT_HEADERDATA, stdout);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdout);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  curl_easy_setopt(curl, CURLOPT_URL, URL);

  curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
  res = curl_easy_perform(curl);
  if(res != CURLE_BAD_FUNCTION_ARGUMENT) {
    fprintf(stderr, "This should have failed. "
            "Cannot setup without a Transport: header");
    fclose(idfile);
    return TEST_ERR_MAJOR_BAD;
  }

  /* Go through the various Session IDs */
  for(i = 0; i < 3; i++) {
    stream_uri = suburl(URL, request++);
    curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
    free(stream_uri);

    curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
    curl_easy_setopt(curl, CURLOPT_RTSP_TRANSPORT,
                           "Fake/NotReal/JustATest;foo=baz");
    res = curl_easy_perform(curl);
    if(res) {
      fclose(idfile);
      return res;
    }

    curl_easy_getinfo(curl, CURLINFO_RTSP_SESSION_ID, &rtsp_session_id);
    fprintf(idfile, "Got Session ID: [%s]\n", rtsp_session_id);
    rtsp_session_id = NULL;

    stream_uri = suburl(URL, request++);
    curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
    free(stream_uri);

    curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_TEARDOWN);
    curl_easy_perform(curl);

    /* Clear for the next go-round */
    curl_easy_setopt(curl, CURLOPT_RTSP_SESSION_ID, NULL);
  }

  fclose(idfile);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}

