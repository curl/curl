/*
 * Copyright (c) 2011 - 2021, Jim Hollinger
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Jim Hollinger nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/* <DESC>
 * A basic RTSP transfer
 * </DESC>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined (WIN32)
#  include <conio.h>  /* _getch() */
#else
#  include <termios.h>
#  include <unistd.h>

static int _getch(void)
{
  struct termios oldt, newt;
  int ch;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~( ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  ch = getchar();
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  return ch;
}
#endif

#include <curl/curl.h>

#define VERSION_STR  "V1.0"

/* error handling macros */
#define my_curl_easy_setopt(A, B, C)                               \
  do {                                                             \
    res = curl_easy_setopt((A), (B), (C));                         \
    if(res != CURLE_OK)                                            \
      fprintf(stderr, "curl_easy_setopt(%s, %s, %s) failed: %d\n", \
              #A, #B, #C, res);                                    \
  } while(0)

#define my_curl_easy_perform(A)                                         \
  do {                                                                  \
    res = curl_easy_perform(A);                                         \
    if(res != CURLE_OK)                                                 \
      fprintf(stderr, "curl_easy_perform(%s) failed: %d\n", #A, res);   \
  } while(0)

/* send RTSP OPTIONS request */
static void rtsp_options(CURL *curl, const char *uri)
{
  CURLcode res = CURLE_OK;
  printf("\nRTSP: OPTIONS %s\n", uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_OPTIONS);
  my_curl_easy_perform(curl);
}


/* send RTSP DESCRIBE request and write sdp response to a file */
static void rtsp_describe(CURL *curl, const char *uri,
                          const char *sdp_filename)
{
  CURLcode res = CURLE_OK;
  FILE *sdp_fp = fopen(sdp_filename, "wb");
  printf("\nRTSP: DESCRIBE %s\n", uri);
  if(!sdp_fp) {
    fprintf(stderr, "Could not open '%s' for writing\n", sdp_filename);
    sdp_fp = stdout;
  }
  else {
    printf("Writing SDP to '%s'\n", sdp_filename);
  }
  my_curl_easy_setopt(curl, CURLOPT_WRITEDATA, sdp_fp);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_DESCRIBE);
  my_curl_easy_perform(curl);
  my_curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdout);
  if(sdp_fp != stdout) {
    fclose(sdp_fp);
  }
}

/* send RTSP SETUP request */
static void rtsp_setup(CURL *curl, const char *uri, const char *transport)
{
  CURLcode res = CURLE_OK;
  printf("\nRTSP: SETUP %s\n", uri);
  printf("      TRANSPORT %s\n", transport);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_TRANSPORT, transport);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_SETUP);
  my_curl_easy_perform(curl);
}


/* send RTSP PLAY request */
static void rtsp_play(CURL *curl, const char *uri, const char *range)
{
  CURLcode res = CURLE_OK;
  printf("\nRTSP: PLAY %s\n", uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, uri);
  my_curl_easy_setopt(curl, CURLOPT_RANGE, range);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_PLAY);
  my_curl_easy_perform(curl);

  /* switch off using range again */
  my_curl_easy_setopt(curl, CURLOPT_RANGE, NULL);
}


/* send RTSP TEARDOWN request */
static void rtsp_teardown(CURL *curl, const char *uri)
{
  CURLcode res = CURLE_OK;
  printf("\nRTSP: TEARDOWN %s\n", uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_TEARDOWN);
  my_curl_easy_perform(curl);
}


/* convert url into an sdp filename */
static void get_sdp_filename(const char *url, char *sdp_filename,
                             size_t namelen)
{
  const char *s = strrchr(url, '/');
  strcpy(sdp_filename, "video.sdp");
  if(s != NULL) {
    s++;
    if(s[0] != '\0') {
      snprintf(sdp_filename, namelen, "%s.sdp", s);
    }
  }
}


/* scan sdp file for media control attribute */
static void get_media_control_attribute(const char *sdp_filename,
                                        char *control)
{
  int max_len = 256;
  char *s = malloc(max_len);
  FILE *sdp_fp = fopen(sdp_filename, "rb");
  control[0] = '\0';
  if(sdp_fp != NULL) {
    while(fgets(s, max_len - 2, sdp_fp) != NULL) {
      sscanf(s, " a = control: %s", control);
    }
    fclose(sdp_fp);
  }
  free(s);
}


/* main app */
int main(int argc, char * const argv[])
{
#if 1
  const char *transport = "RTP/AVP;unicast;client_port=1234-1235";  /* UDP */
#else
  /* TCP */
  const char *transport = "RTP/AVP/TCP;unicast;client_port=1234-1235";
#endif
  const char *range = "0.000-";
  int rc = EXIT_SUCCESS;
  char *base_name = NULL;

  printf("\nRTSP request %s\n", VERSION_STR);
  printf("    Project website: "
    "https://github.com/BackupGGCode/rtsprequest\n");
  printf("    Requires curl V7.20 or greater\n\n");

  /* check command line */
  if((argc != 2) && (argc != 3)) {
    base_name = strrchr(argv[0], '/');
    if(!base_name) {
      base_name = strrchr(argv[0], '\\');
    }
    if(!base_name) {
      base_name = argv[0];
    }
    else {
      base_name++;
    }
    printf("Usage:   %s url [transport]\n", base_name);
    printf("         url of video server\n");
    printf("         transport (optional) specifier for media stream"
           " protocol\n");
    printf("         default transport: %s\n", transport);
    printf("Example: %s rtsp://192.168.0.2/media/video1\n\n", base_name);
    rc = EXIT_FAILURE;
  }
  else {
    const char *url = argv[1];
    char *uri = malloc(strlen(url) + 32);
    char *sdp_filename = malloc(strlen(url) + 32);
    char *control = malloc(strlen(url) + 32);
    CURLcode res;
    get_sdp_filename(url, sdp_filename, strlen(url) + 32);
    if(argc == 3) {
      transport = argv[2];
    }

    /* initialize curl */
    res = curl_global_init(CURL_GLOBAL_ALL);
    if(res == CURLE_OK) {
      curl_version_info_data *data = curl_version_info(CURLVERSION_NOW);
      CURL *curl;
      fprintf(stderr, "    curl V%s loaded\n", data->version);

      /* initialize this curl session */
      curl = curl_easy_init();
      if(curl != NULL) {
        my_curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
        my_curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        my_curl_easy_setopt(curl, CURLOPT_HEADERDATA, stdout);
        my_curl_easy_setopt(curl, CURLOPT_URL, url);

        /* request server options */
        snprintf(uri, strlen(url) + 32, "%s", url);
        rtsp_options(curl, uri);

        /* request session description and write response to sdp file */
        rtsp_describe(curl, uri, sdp_filename);

        /* get media control attribute from sdp file */
        get_media_control_attribute(sdp_filename, control);

        /* setup media stream */
        snprintf(uri, strlen(url) + 32, "%s/%s", url, control);
        rtsp_setup(curl, uri, transport);

        /* start playing media stream */
        snprintf(uri, strlen(url) + 32, "%s/", url);
        rtsp_play(curl, uri, range);
        printf("Playing video, press any key to stop ...");
        _getch();
        printf("\n");

        /* teardown session */
        rtsp_teardown(curl, uri);

        /* cleanup */
        curl_easy_cleanup(curl);
        curl = NULL;
      }
      else {
        fprintf(stderr, "curl_easy_init() failed\n");
      }
      curl_global_cleanup();
    }
    else {
      fprintf(stderr, "curl_global_init(%s) failed: %d\n",
              "CURL_GLOBAL_ALL", res);
    }
    free(control);
    free(sdp_filename);
    free(uri);
  }

  return rc;
}
