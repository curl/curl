---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_INTERLEAVEDATA
Section: 3
Source: libfetch
Protocol:
  - RTSP
See-also:
  - FETCHOPT_INTERLEAVEFUNCTION (3)
  - FETCHOPT_RTSP_REQUEST (3)
Added-in: 7.20.0
---

# NAME

FETCHOPT_INTERLEAVEDATA - pointer passed to RTSP interleave callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_INTERLEAVEDATA, void *pointer);
~~~

# DESCRIPTION

This is the userdata *pointer* that is passed to
FETCHOPT_INTERLEAVEFUNCTION(3) when interleaved RTP data is received. If
the interleave function callback is not set, this pointer is not used
anywhere.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct local {
  void *custom;
};
static size_t rtp_write(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct local *l = userp;
  printf("my pointer: %p\n", l->custom);
  /* take care of the packet in 'ptr', then return... */
  return size * nmemb;
}

int main(void)
{
  struct local rtp_data;
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_INTERLEAVEFUNCTION, rtp_write);
    fetch_easy_setopt(fetch, FETCHOPT_INTERLEAVEDATA, &rtp_data);

    fetch_easy_perform(fetch);
 }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
