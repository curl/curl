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

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <curl/mprintf.h>

#include "memdebug.h"

/* build request url */
static char *suburl(const char *base, int i)
{
  return curl_maprintf("%s%.4d", base, i);
}

/*
 * Test the Client->Server ANNOUNCE functionality (PUT style)
 */
int test(char *URL)
{
  CURLcode res;
  CURL *curl;
  int sdp;
  FILE *sdpf;
  struct_stat file_info;
  char *stream_uri;
  int request=1;
  struct curl_slist *custom_headers=NULL;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  curl_easy_setopt(curl, CURLOPT_HEADERDATA, stdout);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdout);

  curl_easy_setopt(curl, CURLOPT_URL, URL);

  stream_uri = suburl(URL, request++);
  curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
  free(stream_uri);

  sdp = open("log/file568.txt", O_RDONLY);
  fstat(sdp, &file_info);
  close(sdp);

  sdpf = fopen("log/file568.txt", "rb");
  if(sdpf == NULL) {
    fprintf(stderr, "can't open log/file568.txt\n");
    return TEST_ERR_MAJOR_BAD;
  }
  curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_ANNOUNCE);

  curl_easy_setopt(curl, CURLOPT_READDATA, sdpf);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) file_info.st_size);

  /* Do the ANNOUNCE */
  res = curl_easy_perform(curl);
  if(res) {
    fclose(sdpf);
    return res;
  }

  curl_easy_setopt(curl, CURLOPT_UPLOAD, 0L);
  fclose(sdpf);

  /* Make sure we can do a normal request now */
  stream_uri = suburl(URL, request++);
  curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
  free(stream_uri);

  curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_DESCRIBE);
  res = curl_easy_perform(curl);
  if(res)
    return res;

  /* Now do a POST style one */

  stream_uri = suburl(URL, request++);
  curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
  free(stream_uri);

  custom_headers = curl_slist_append(custom_headers,
                                     "Content-Type: posty goodness");

  curl_easy_setopt(curl, CURLOPT_RTSPHEADER, custom_headers);
  curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_ANNOUNCE);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
                         "postyfield=postystuff&project=curl\n");

  res = curl_easy_perform(curl);
  if(res)
    return res;

  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, NULL);
  curl_easy_setopt(curl, CURLOPT_RTSPHEADER, NULL);
  curl_slist_free_all(custom_headers);

  /* Make sure we can do a normal request now */
  stream_uri = suburl(URL, request++);
  curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
  free(stream_uri);

  curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_OPTIONS);
  res = curl_easy_perform(curl);
  if(res)
    return res;

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}

