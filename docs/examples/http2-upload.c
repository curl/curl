/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * Multiplexed HTTP/2 uploads over a single connection
 * </DESC>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

/* somewhat unix-specific */
#include <sys/time.h>
#include <unistd.h>

/* curl stuff */
#include <curl/curl.h>

#ifndef CURLPIPE_MULTIPLEX
/* This little trick will just make sure that we don't enable pipelining for
   libcurls old enough to not have this symbol. It is _not_ defined to zero in
   a recent libcurl header. */
#define CURLPIPE_MULTIPLEX 0
#endif

#define NUM_HANDLES 1000

static void *curl_hnd[NUM_HANDLES];
static int num_transfers;

/* a handle to number lookup, highly ineffective when we do many
   transfers... */
static int hnd2num(CURL *hnd)
{
  int i;
  for(i = 0; i< num_transfers; i++) {
    if(curl_hnd[i] == hnd)
      return i;
  }
  return 0; /* weird, but just a fail-safe */
}

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

  fprintf(stderr, "%d %s, %ld bytes (0x%lx)\n",
          num, text, (long)size, (long)size);

  for(i = 0; i<size; i += width) {

    fprintf(stderr, "%4.4lx: ", (long)i);

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
              (ptr[i + c] >= 0x20) && (ptr[i + c]<0x80)?ptr[i + c]:'.');
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
  int num = hnd2num(handle);
  static time_t epoch_offset;
  static int    known_offset;
  struct timeval tv;
  time_t secs;
  struct tm *now;

  (void)handle; /* prevent compiler warning */
  (void)userp;

  gettimeofday(&tv, NULL);
  if(!known_offset) {
    epoch_offset = time(NULL) - tv.tv_sec;
    known_offset = 1;
  }
  secs = epoch_offset + tv.tv_sec;
  now = localtime(&secs);  /* not thread safe but we don't care */
  snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
           now->tm_hour, now->tm_min, now->tm_sec, (long)tv.tv_usec);

  switch(type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "%s [%d] Info: %s", timebuf, num, data);
    /* FALLTHROUGH */
  default: /* in case a new one is introduced to shock us */
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
  }

  dump(text, num, (unsigned char *)data, size, 1);
  return 0;
}

struct input {
  FILE *in;
  size_t bytes_read; /* count up */
  CURL *hnd;
};

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct input *i = userp;
  size_t retcode = fread(ptr, size, nmemb, i->in);
  i->bytes_read += retcode;
  return retcode;
}

static struct input indata[NUM_HANDLES];

static void setup(CURL *hnd, int num, const char *upload)
{
  FILE *out;
  char url[256];
  char filename[128];
  struct stat file_info;
  curl_off_t uploadsize;

  snprintf(filename, 128, "dl-%d", num);
  out = fopen(filename, "wb");

  snprintf(url, 256, "https://localhost:8443/upload-%d", num);

  /* get the file size of the local file */
  stat(upload, &file_info);
  uploadsize = file_info.st_size;

  indata[num].in = fopen(upload, "rb");
  indata[num].hnd = hnd;

  /* write to this file */
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, out);

  /* we want to use our own read function */
  curl_easy_setopt(hnd, CURLOPT_READFUNCTION, read_callback);
  /* read from this file */
  curl_easy_setopt(hnd, CURLOPT_READDATA, &indata[num]);
  /* provide the size of the upload */
  curl_easy_setopt(hnd, CURLOPT_INFILESIZE_LARGE, uploadsize);

  /* send in the URL to store the upload as */
  curl_easy_setopt(hnd, CURLOPT_URL, url);

  /* upload please */
  curl_easy_setopt(hnd, CURLOPT_UPLOAD, 1L);

  /* please be verbose */
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, my_trace);

  /* HTTP/2 please */
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

  /* we use a self-signed test server, skip verification during debugging */
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);

#if (CURLPIPE_MULTIPLEX > 0)
  /* wait for pipe connection to confirm */
  curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);
#endif

  curl_hnd[num] = hnd;
}

/*
 * Upload all files over HTTP/2, using the same physical connection!
 */
int main(int argc, char **argv)
{
  CURL *easy[NUM_HANDLES];
  CURLM *multi_handle;
  int i;
  int still_running; /* keep number of running handles */
  const char *filename = "index.html";

  if(argc > 1)
    /* if given a number, do that many transfers */
    num_transfers = atoi(argv[1]);

  if(argc > 2)
    /* if given a file name, upload this! */
    filename = argv[2];

  if(!num_transfers || (num_transfers > NUM_HANDLES))
    num_transfers = 3; /* a suitable low default */

  /* init a multi stack */
  multi_handle = curl_multi_init();

  for(i = 0; i<num_transfers; i++) {
    easy[i] = curl_easy_init();
    /* set options */
    setup(easy[i], i, filename);

    /* add the individual transfer */
    curl_multi_add_handle(multi_handle, easy[i]);
  }

  curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  /* We do HTTP/2 so let's stick to one connection per host */
  curl_multi_setopt(multi_handle, CURLMOPT_MAX_HOST_CONNECTIONS, 1L);

  /* we start some action by calling perform right away */
  curl_multi_perform(multi_handle, &still_running);

  do {
    struct timeval timeout;
    int rc; /* select() return code */
    CURLMcode mc; /* curl_multi_fdset() return code */

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;

    long curl_timeo = -1;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* set a suitable timeout to play around with */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    curl_multi_timeout(multi_handle, &curl_timeo);
    if(curl_timeo >= 0) {
      timeout.tv_sec = curl_timeo / 1000;
      if(timeout.tv_sec > 1)
        timeout.tv_sec = 1;
      else
        timeout.tv_usec = (curl_timeo % 1000) * 1000;
    }

    /* get file descriptors from the transfers */
    mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_fdset() failed, code %d.\n", mc);
      break;
    }

    /* On success the value of maxfd is guaranteed to be >= -1. We call
       select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
       no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
       to sleep 100ms, which is the minimum suggested value in the
       curl_multi_fdset() doc. */

    if(maxfd == -1) {
#ifdef _WIN32
      Sleep(100);
      rc = 0;
#else
      /* Portable sleep for platforms other than Windows. */
      struct timeval wait = { 0, 100 * 1000 }; /* 100ms */
      rc = select(0, NULL, NULL, NULL, &wait);
#endif
    }
    else {
      /* Note that on some platforms 'timeout' may be modified by select().
         If you need access to the original value save a copy beforehand. */
      rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);
    }

    switch(rc) {
    case -1:
      /* select error */
      break;
    case 0:
    default:
      /* timeout or readable/writable sockets */
      curl_multi_perform(multi_handle, &still_running);
      break;
    }
  } while(still_running);

  curl_multi_cleanup(multi_handle);

  for(i = 0; i<num_transfers; i++)
    curl_easy_cleanup(easy[i]);

  return 0;
}
