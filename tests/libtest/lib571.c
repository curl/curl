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

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <curl/mprintf.h>

#include "memdebug.h"

#define RTP_DATA_SIZE 12
static const char *RTP_DATA = "$_1234\n\0asdf";

static int rtp_packet_count = 0;

static size_t rtp_write(void *ptr, size_t size, size_t nmemb, void *stream) {
  char *data = (char *)ptr;
  int channel = (int)data[0];
  int message_size = (int)(size * nmemb - 3);
  int i;
  (void)stream;

  printf("RTP: message size %d, channel %d\n", message_size, channel);

  data += 3;
  for(i = 0; i < message_size; i+= RTP_DATA_SIZE) {
    if(message_size - i > RTP_DATA_SIZE) {
      if(memcmp(RTP_DATA, data + i, RTP_DATA_SIZE) != 0) {
        printf("RTP PAYLOAD CORRUPTED [%s]\n", data + i);
      }
    } else {
      if (memcmp(RTP_DATA, data + i, message_size - i) != 0) {
        printf("RTP PAYLOAD END CORRUPTED (%d), [%s]\n",
               message_size - i, data + i);
      }
    }
  }

  rtp_packet_count++;
  fprintf(stderr, "packet count is %d\n", rtp_packet_count);

  return size * nmemb;
}

/* build request url */
static char *suburl(const char *base, int i)
{
  return curl_maprintf("%s%.4d", base, i);
}

int test(char *URL)
{
  CURLcode res;
  CURL *curl;
  char *stream_uri;
  int request=1;
  FILE *protofile;

  protofile = fopen(libtest_arg2, "w");
  if(protofile == NULL) {
    fprintf(stderr, "Couldn't open the protocol dump file\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    fclose(protofile);
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    fclose(protofile);
    return TEST_ERR_MAJOR_BAD;
  }
  curl_easy_setopt(curl, CURLOPT_URL, URL);

  stream_uri = suburl(URL, request++);
  curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
  free(stream_uri);

  curl_easy_setopt(curl, CURLOPT_INTERLEAVEFUNCTION, rtp_write);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, protofile);

  curl_easy_setopt(curl, CURLOPT_RTSP_TRANSPORT, "RTP/AVP/TCP;interleaved=0-1");
  curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
  res = curl_easy_perform(curl);

  /* This PLAY starts the interleave */
  stream_uri = suburl(URL, request++);
  curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
  free(stream_uri);
  curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_PLAY);
  res = curl_easy_perform(curl);

  /* The DESCRIBE request will try to consume data after the Content */
  stream_uri = suburl(URL, request++);
  curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
  free(stream_uri);
  curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_DESCRIBE);

  res = curl_easy_perform(curl);

  stream_uri = suburl(URL, request++);
  curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,stream_uri);
  free(stream_uri);
  curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_PLAY);
  res = curl_easy_perform(curl);

  fprintf(stderr, "PLAY COMPLETE\n");

  /* Use Receive to get the rest of the data */
  while(!res && rtp_packet_count < 13) {
    fprintf(stderr, "LOOPY LOOP!\n");
    curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_RECEIVE);
    res = curl_easy_perform(curl);
  }

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  fclose(protofile);

  return (int)res;
}

