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
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS  /* for _snprintf(), fopen(), localtime(),
                                    strerror() */
#endif
#endif

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

#include <curl/curl.h>

#ifndef CURLPIPE_MULTIPLEX
/* This little trick makes sure that we do not enable pipelining for libcurls
   old enough to not have this symbol. It is _not_ defined to zero in a recent
   libcurl header. */
#define CURLPIPE_MULTIPLEX 0L
#endif

#ifdef _WIN32
#undef stat
#define stat _stati64
#undef fstat
#define fstat _fstati64
#define fileno _fileno
#endif

#if defined(_MSC_VER) && (_MSC_VER < 1900)
#define snprintf _snprintf
#endif

#ifdef _MSC_VER
#define gettimeofday(a, b) my_gettimeofday(a, b)
static int my_gettimeofday(struct timeval *tp, void *tzp)
{
  (void)tzp;
  if(tp) {
/* Offset between 1601-01-01 and 1970-01-01 in 100 nanosec units */
#define WIN32_FT_OFFSET (116444736000000000)
    union {
      CURL_TYPEOF_CURL_OFF_T ns100; /* time since 1 Jan 1601 in 100ns units */
      FILETIME ft;
    } _now;
    GetSystemTimeAsFileTime(&_now.ft);
    tp->tv_usec = (long)((_now.ns100 / 10) % 1000000);
    tp->tv_sec = (long)((_now.ns100 - WIN32_FT_OFFSET) / 10000000);
  }
  return 0;
}
#endif

struct input {
  FILE *in;
  FILE *out;
  size_t bytes_read; /* count up */
  CURL *curl;
  int num;
};

static void dump(const char *text, int num, const unsigned char *ptr,
                 size_t size, char nohex)
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
      /* check again for 0D0A, to avoid an extra \n if it is at width */
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stderr); /* newline */
  }
}

static int my_trace(CURL *curl, curl_infotype type,
                    char *data, size_t size, void *userp)
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
  (void)curl;

  gettimeofday(&tv, NULL);
  if(!known_offset) {
    epoch_offset = time(NULL) - tv.tv_sec;
    known_offset = 1;
  }
  secs = epoch_offset + tv.tv_sec;
  now = localtime(&secs);  /* not thread-safe but we do not care */
  snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
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

static size_t read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct input *i = userp;
  size_t retcode = fread(ptr, size, nmemb, i->in);
  i->bytes_read += retcode;
  return retcode;
}

static int setup(struct input *t, int num, const char *upload)
{
  char url[256];
  char filename[128];
  struct stat file_info;
  curl_off_t uploadsize;
  CURL *curl;

  curl = t->curl = NULL;

  t->num = num;
  snprintf(filename, sizeof(filename), "dl-%d", num);
  t->out = fopen(filename, "wb");
  if(!t->out) {
    fprintf(stderr, "error: could not open file %s for writing: %s\n",
            upload, strerror(errno));
    return 1;
  }

  snprintf(url, sizeof(url), "https://localhost:8443/upload-%d", num);

  t->in = fopen(upload, "rb");
  if(!t->in) {
    fprintf(stderr, "error: could not open file %s for reading: %s\n",
            upload, strerror(errno));
    fclose(t->out);
    t->out = NULL;
    return 1;
  }

  if(fstat(fileno(t->in), &file_info) != 0) {
    fprintf(stderr, "error: could not stat file %s: %s\n", upload,
            strerror(errno));
    fclose(t->out);
    t->out = NULL;
    return 1;
  }

  uploadsize = file_info.st_size;

  curl = t->curl = curl_easy_init();
  if(curl) {

    /* write to this file */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, t->out);

    /* we want to use our own read function */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_cb);
    /* read from this file */
    curl_easy_setopt(curl, CURLOPT_READDATA, t);
    /* provide the size of the upload */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, uploadsize);

    /* send in the URL to store the upload as */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* upload please */
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    /* please be verbose */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, t);

    /* HTTP/2 please */
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

    /* we use a self-signed test server, skip verification during debugging */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

#if (CURLPIPE_MULTIPLEX > 0)
    /* wait for pipe connection to confirm */
    curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
  }
  return 0;
}

/*
 * Upload all files over HTTP/2, using the same physical connection!
 */
int main(int argc, char **argv)
{
  CURLcode result;
  struct input *trans;
  CURLM *multi = NULL;
  int i;
  const char *filename = "index.html";
  int still_running = 0; /* keep number of running handles */
  int num_transfers;

  if(argc > 1) {
    /* if given a number, do that many transfers */
    num_transfers = atoi(argv[1]);
    if((num_transfers < 1) || (num_transfers > 1000))
      num_transfers = 3;  /* a suitable low default */

    if(argc > 2)
      /* if given a filename, upload this! */
      filename = argv[2];
  }
  else
    num_transfers = 3;  /* a suitable low default */

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return (int)result;

  trans = calloc(num_transfers, sizeof(*trans));
  if(!trans) {
    fprintf(stderr, "error allocating transfer structs\n");
    goto error;
  }

  /* init a multi stack */
  multi = curl_multi_init();
  if(!multi)
    goto error;

  for(i = 0; i < num_transfers; i++) {
    if(setup(&trans[i], i, filename)) {
      goto error;
    }

    /* add the individual transfer */
    curl_multi_add_handle(multi, trans[i].curl);
  }

  curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  /* We do HTTP/2 so let's stick to one connection per host */
  curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, 1L);

  do {
    CURLMcode mresult = curl_multi_perform(multi, &still_running);

    if(still_running)
      /* wait for activity, timeout or "nothing" */
      mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);

    if(mresult)
      break;

  } while(still_running);

error:

  if(multi) {
    for(i = 0; i < num_transfers; i++) {
      curl_multi_remove_handle(multi, trans[i].curl);
      curl_easy_cleanup(trans[i].curl);

      if(trans[i].in)
        fclose(trans[i].in);
      if(trans[i].out)
        fclose(trans[i].out);
    }
    curl_multi_cleanup(multi);
  }

  free(trans);

  curl_global_cleanup();

  return 0;
}
