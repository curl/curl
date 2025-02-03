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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * Multiplexed HTTP/2 downloads over a single connection
 * </DESC>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* fetch stuff */
#include <fetch/fetch.h>
#include <fetch/mprintf.h>

#ifndef FETCHPIPE_MULTIPLEX
/* This little trick makes sure that we do not enable pipelining for libfetchs
   old enough to not have this symbol. It is _not_ defined to zero in a recent
   libfetch header. */
#define FETCHPIPE_MULTIPLEX 0
#endif

struct transfer {
  FETCH *easy;
  unsigned int num;
  FILE *out;
};

#define NUM_HANDLES 1000

static
void dump(const char *text, unsigned int num, unsigned char *ptr, size_t size,
          char nohex)
{
  size_t i;
  size_t c;

  unsigned int width = 0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stderr, "%u %s, %lu bytes (0x%lx)\n",
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
int my_trace(FETCH *handle, fetch_infotype type,
             char *data, size_t size,
             void *userp)
{
  const char *text;
  struct transfer *t = (struct transfer *)userp;
  unsigned int num = t->num;
  (void)handle; /* prevent compiler warning */

  switch(type) {
  case FETCHINFO_TEXT:
    fprintf(stderr, "== %u Info: %s", num, data);
    return 0;
  case FETCHINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case FETCHINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case FETCHINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case FETCHINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case FETCHINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case FETCHINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  default: /* in case a new one is introduced to shock us */
    return 0;
  }

  dump(text, num, (unsigned char *)data, size, 1);
  return 0;
}

static void setup(struct transfer *t, int num)
{
  char filename[128];
  FETCH *hnd;

  hnd = t->easy = fetch_easy_init();

  fetch_msnprintf(filename, 128, "dl-%d", num);

  t->out = fopen(filename, "wb");
  if(!t->out) {
    fprintf(stderr, "error: could not open file %s for writing: %s\n",
            filename, strerror(errno));
    exit(1);
  }

  /* write to this file */
  fetch_easy_setopt(hnd, FETCHOPT_WRITEDATA, t->out);

  /* set the same URL */
  fetch_easy_setopt(hnd, FETCHOPT_URL, "https://localhost:8443/index.html");

  /* please be verbose */
  fetch_easy_setopt(hnd, FETCHOPT_VERBOSE, 1L);
  fetch_easy_setopt(hnd, FETCHOPT_DEBUGFUNCTION, my_trace);
  fetch_easy_setopt(hnd, FETCHOPT_DEBUGDATA, t);

  /* enlarge the receive buffer for potentially higher transfer speeds */
  fetch_easy_setopt(hnd, FETCHOPT_BUFFERSIZE, 100000L);

  /* HTTP/2 please */
  fetch_easy_setopt(hnd, FETCHOPT_HTTP_VERSION, FETCH_HTTP_VERSION_2_0);

#if (FETCHPIPE_MULTIPLEX > 0)
  /* wait for pipe connection to confirm */
  fetch_easy_setopt(hnd, FETCHOPT_PIPEWAIT, 1L);
#endif
}

/*
 * Download many transfers over HTTP/2, using the same connection!
 */
int main(int argc, char **argv)
{
  struct transfer trans[NUM_HANDLES];
  FETCHM *multi_handle;
  int i;
  int still_running = 0; /* keep number of running handles */
  int num_transfers;
  if(argc > 1) {
    /* if given a number, do that many transfers */
    num_transfers = atoi(argv[1]);
    if((num_transfers < 1) || (num_transfers > NUM_HANDLES))
      num_transfers = 3; /* a suitable low default */
  }
  else
    num_transfers = 3; /* suitable default */

  /* init a multi stack */
  multi_handle = fetch_multi_init();

  for(i = 0; i < num_transfers; i++) {
    setup(&trans[i], i);

    /* add the individual transfer */
    fetch_multi_add_handle(multi_handle, trans[i].easy);
  }

  fetch_multi_setopt(multi_handle, FETCHMOPT_PIPELINING, FETCHPIPE_MULTIPLEX);

  do {
    FETCHMcode mc = fetch_multi_perform(multi_handle, &still_running);

    if(still_running)
      /* wait for activity, timeout or "nothing" */
      mc = fetch_multi_poll(multi_handle, NULL, 0, 1000, NULL);

    if(mc)
      break;
  } while(still_running);

  for(i = 0; i < num_transfers; i++) {
    fetch_multi_remove_handle(multi_handle, trans[i].easy);
    fetch_easy_cleanup(trans[i].easy);
  }

  fetch_multi_cleanup(multi_handle);

  return 0;
}
