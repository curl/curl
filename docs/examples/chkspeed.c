/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/* <DESC>
 * Show transfer timing info after download completes.
 * </DESC>
 */
/* Example source code to show how the callback function can be used to
 * download data into a chunk of memory instead of storing it in a file.
 * After successful download we use curl_easy_getinfo() calls to get the
 * amount of downloaded bytes, the time used for the whole download, and
 * the average download speed.
 * On Linux you can create the download test files with:
 * dd if=/dev/urandom of=file_1M.bin bs=1M count=1
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>

#define URL_BASE "http://speedtest.your.domain/"
#define URL_1M   URL_BASE "file_1M.bin"
#define URL_2M   URL_BASE "file_2M.bin"
#define URL_5M   URL_BASE "file_5M.bin"
#define URL_10M  URL_BASE "file_10M.bin"
#define URL_20M  URL_BASE "file_20M.bin"
#define URL_50M  URL_BASE "file_50M.bin"
#define URL_100M URL_BASE "file_100M.bin"

#define CHKSPEED_VERSION "1.0"

static size_t WriteCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
  /* we are not interested in the downloaded bytes itself,
     so we only return the size we would have saved ... */
  (void)ptr;  /* unused */
  (void)data; /* unused */
  return (size_t)(size * nmemb);
}

int main(int argc, char *argv[])
{
  CURL *curl_handle;
  CURLcode res;
  int prtall = 0, prtsep = 0, prttime = 0;
  const char *url = URL_1M;
  char *appname = argv[0];

  if(argc > 1) {
    /* parse input parameters */
    for(argc--, argv++; *argv; argc--, argv++) {
      if(strncasecmp(*argv, "-", 1) == 0) {
        if(strncasecmp(*argv, "-H", 2) == 0) {
          fprintf(stderr,
                  "\rUsage: %s [-m=1|2|5|10|20|50|100] [-t] [-x] [url]\n",
                  appname);
          exit(1);
        }
        else if(strncasecmp(*argv, "-V", 2) == 0) {
          fprintf(stderr, "\r%s %s - %s\n",
                  appname, CHKSPEED_VERSION, curl_version());
          exit(1);
        }
        else if(strncasecmp(*argv, "-A", 2) == 0) {
          prtall = 1;
        }
        else if(strncasecmp(*argv, "-X", 2) == 0) {
          prtsep = 1;
        }
        else if(strncasecmp(*argv, "-T", 2) == 0) {
          prttime = 1;
        }
        else if(strncasecmp(*argv, "-M=", 3) == 0) {
          long m = strtol((*argv) + 3, NULL, 10);
          switch(m) {
          case 1:
            url = URL_1M;
            break;
          case 2:
            url = URL_2M;
            break;
          case 5:
            url = URL_5M;
            break;
          case 10:
            url = URL_10M;
            break;
          case 20:
            url = URL_20M;
            break;
          case 50:
            url = URL_50M;
            break;
          case 100:
            url = URL_100M;
            break;
          default:
            fprintf(stderr, "\r%s: invalid parameter %s\n",
                    appname, *argv + 3);
            exit(1);
          }
        }
        else {
          fprintf(stderr, "\r%s: invalid or unknown option %s\n",
                  appname, *argv);
          exit(1);
        }
      }
      else {
        url = *argv;
      }
    }
  }

  /* print separator line */
  if(prtsep) {
    printf("-------------------------------------------------\n");
  }
  /* print localtime */
  if(prttime) {
    time_t t = time(NULL);
    printf("Localtime: %s", ctime(&t));
  }

  /* init libcurl */
  curl_global_init(CURL_GLOBAL_ALL);

  /* init the curl session */
  curl_handle = curl_easy_init();

  /* specify URL to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);

  /* send all data to this function  */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteCallback);

  /* some servers don't like requests that are made without a user-agent
     field, so we provide one */
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT,
                   "libcurl-speedchecker/" CHKSPEED_VERSION);

  /* get it! */
  res = curl_easy_perform(curl_handle);

  if(CURLE_OK == res) {
    curl_off_t val;

    /* check for bytes downloaded */
    res = curl_easy_getinfo(curl_handle, CURLINFO_SIZE_DOWNLOAD_T, &val);
    if((CURLE_OK == res) && (val>0))
      printf("Data downloaded: %" CURL_FORMAT_CURL_OFF_T " bytes.\n", val);

    /* check for total download time */
    res = curl_easy_getinfo(curl_handle, CURLINFO_TOTAL_TIME_T, &val);
    if((CURLE_OK == res) && (val>0))
      printf("Total download time: %" CURL_FORMAT_CURL_OFF_T ".%06ld sec.\n",
             (val / 1000000), (long)(val % 1000000));

    /* check for average download speed */
    res = curl_easy_getinfo(curl_handle, CURLINFO_SPEED_DOWNLOAD_T, &val);
    if((CURLE_OK == res) && (val>0))
      printf("Average download speed: %" CURL_FORMAT_CURL_OFF_T
             " kbyte/sec.\n", val / 1024);

    if(prtall) {
      /* check for name resolution time */
      res = curl_easy_getinfo(curl_handle, CURLINFO_NAMELOOKUP_TIME_T, &val);
      if((CURLE_OK == res) && (val>0))
        printf("Name lookup time: %" CURL_FORMAT_CURL_OFF_T ".%06ld sec.\n",
               (val / 1000000), (long)(val % 1000000));

      /* check for connect time */
      res = curl_easy_getinfo(curl_handle, CURLINFO_CONNECT_TIME_T, &val);
      if((CURLE_OK == res) && (val>0))
        printf("Connect time: %" CURL_FORMAT_CURL_OFF_T ".%06ld sec.\n",
               (val / 1000000), (long)(val % 1000000));
    }
  }
  else {
    fprintf(stderr, "Error while fetching '%s' : %s\n",
            url, curl_easy_strerror(res));
  }

  /* cleanup curl stuff */
  curl_easy_cleanup(curl_handle);

  /* we're done with libcurl, so clean it up */
  curl_global_cleanup();

  return 0;
}
