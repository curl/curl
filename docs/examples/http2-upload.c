/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/* <DESC>
 * Multiplexed HTTP/2 uploads over a single connection
 * </DESC>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

/* somewhat Unix-specific */
#ifndef _MSC_VER
#include <sys/time.h>
#include <unistd.h>
#endif

/* curl stuff */
#include <curl/curl.h>
#include <curl/mprintf.h>

#ifndef CURLPIPE_MULTIPLEX
/* This little trick makes sure that we do not enable pipelining for libcurls
   old enough to not have this symbol. It is _not_ defined to zero in a recent
   libcurl header. */
#define CURLPIPE_MULTIPLEX 0
#endif

#define NUM_HANDLES 1000

#ifdef _MSC_VER
#define gettimeofday(a, b) my_gettimeofday((a), (b))
static
int my_gettimeofday(struct timeval *tp, void *tzp)
{
  (void)tzp;
  if(tp) {
    /* Offset between 1601-01-01 and 1970-01-01 in 100 nanosec units */
    #define _WIN32_FT_OFFSET (116444736000000000)
    union {
      CURL_TYPEOF_CURL_OFF_T ns100; /* time since 1 Jan 1601 in 100ns units */
      FILETIME ft;
    } _now;
    GetSystemTimeAsFileTime(&_now.ft);
    tp->tv_usec = (long)((_now.ns100 / 10) % 1000000);
    tp->tv_sec = (long)((_now.ns100 - _WIN32_FT_OFFSET) / 10000000);
  }
  return 0;
}
#endif

struct input {
  FILE *in;
  size_t bytes_read; /* count up */
  CURL *hnd;
  int num;
};

static
void dump(const char *text, int num, unsigned char *ptr, size_t size,
          char nohex)
{
  size_t i;
  size_t c;
  unsigned int width = 0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stderr, "%d %s, %lu bytes (0x%lx)\n",
          num, text, (unsigned long)size, (unsigned long)size);

  for(i = 0; i < size; i += width) {

    fprintf(stderr, "%4.4lx: ", (unsigned long)i);

    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i + c < size)
          fprintf(stderr, "%02x ", ptr[i + c]);
        else
          fputs("   ", stderr);
    }

    for(c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      fprintf(stderr, "%c",
              (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stderr); /* newline */
  }
}

static
int my_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
  char timebuf[60];
  const char *text;
  struct input *i = (struct input *)userp;
  int num = i->num;
  static time_t epoch_offset;
  static int    known_offset;
  struct timeval tv;
  time_t secs;
  struct tm *now;
  (void)handle; /* prevent compiler warning */

  gettimeofday(&tv, NULL);
  if(!known_offset) {
    epoch_offset = time(NULL) - tv.tv_sec;
    known_offset = 1;
  }
  secs = epoch_offset + tv.tv_sec;
  now = localtime(&secs);  /* not thread safe but we do not care */
  curl_msnprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
                 now->tm_hour, now->tm_min, now->tm_sec, (long)tv.tv_usec);

  switch(type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "%s [%d] Info: %s", timebuf, num, data);
    return 0;
  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  default: /* in case a new one is introduced to shock us */
    return 0;
  }

  dump(text, num, (unsigned char *)data, size, 1);
  return 0;
}

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct input *i = userp;
  size_t retcode = fread(ptr, size, nmemb, i->in);
  i->bytes_read += retcode;
  return retcode;
}

static void setup(struct input *i, int num, const char *upload)
{
  FILE *out;
  char url[256];
  char filename[128];
  struct stat file_info;
  curl_off_t uploadsize;
  CURL *hnd;

  hnd = i->hnd = curl_easy_init();
  i->num = num;
  curl_msnprintf(filename, 128, "dl-%d", num);
  out = fopen(filename, "wb");
  if(!out) {
    fprintf(stderr, "error: could not open file %s for writing: %s\n", upload,
            strerror(errno));
    exit(1);
  }

  curl_msnprintf(url, 256, "https://localhost:8443/upload-%d", num);

  /* get the file size of the local file */
  if(stat(upload, &file_info)) {
    fprintf(stderr, "error: could not stat file %s: %s\n", upload,
            strerror(errno));
    exit(1);
  }

  uploadsize = file_info.st_size;

  i->in = fopen(upload, "rb");
  if(!i->in) {
    fprintf(stderr, "error: could not open file %s for reading: %s\n", upload,
            strerror(errno));
    exit(1);
  }

  /* write to this file */
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, out);

  /* we want to use our own read function */
  curl_easy_setopt(hnd, CURLOPT_READFUNCTION, read_callback);
  /* read from this file */
  curl_easy_setopt(hnd, CURLOPT_READDATA, i);
  /* provide the size of the upload */
  curl_easy_setopt(hnd, CURLOPT_INFILESIZE_LARGE, uploadsize);

  /* send in the URL to store the upload as */
  curl_easy_setopt(hnd, CURLOPT_URL, url);

  /* upload please */
  curl_easy_setopt(hnd, CURLOPT_UPLOAD, 1L);

  /* please be verbose */
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, my_trace);
  curl_easy_setopt(hnd, CURLOPT_DEBUGDATA, i);

  /* HTTP/2 please */
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

  /* we use a self-signed test server, skip verification during debugging */
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);

#if (CURLPIPE_MULTIPLEX > 0)
  /* wait for pipe connection to confirm */
  curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);
#endif
}

/*
 * Upload all files over HTTP/2, using the same physical connection!
 */
int main(int argc, char **argv)
{
  struct input trans[NUM_HANDLES];
  CURLM *multi_handle;
  int i;
  int still_running = 0; /* keep number of running handles */
  const char *filename = "index.html";
  int num_transfers;

  if(argc > 1) {
    /* if given a number, do that many transfers */
    num_transfers = atoi(argv[1]);

    if(!num_transfers || (num_transfers > NUM_HANDLES))
      num_transfers = 3; /* a suitable low default */

    if(argc > 2)
      /* if given a file name, upload this! */
      filename = argv[2];
  }
  else
    num_transfers = 3;

  /* init a multi stack */
  multi_handle = curl_multi_init();

  for(i = 0; i < num_transfers; i++) {
    setup(&trans[i], i, filename);

    /* add the individual transfer */
    curl_multi_add_handle(multi_handle, trans[i].hnd);
  }

  curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  /* We do HTTP/2 so let's stick to one connection per host */
  curl_multi_setopt(multi_handle, CURLMOPT_MAX_HOST_CONNECTIONS, 1L);

  do {
    CURLMcode mc = curl_multi_perform(multi_handle, &still_running);

    if(still_running)
      /* wait for activity, timeout or "nothing" */
      mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);

    if(mc)
      break;

  } while(still_running);

  curl_multi_cleanup(multi_handle);

  for(i = 0; i < num_transfers; i++) {
    curl_multi_remove_handle(multi_handle, trans[i].hnd);
    curl_easy_cleanup(trans[i].hnd);
  }

  return 0;
}
