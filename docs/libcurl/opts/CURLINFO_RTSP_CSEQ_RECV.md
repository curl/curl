---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_RTSP_CSEQ_RECV
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_RTSP_SERVER_CSEQ (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

FETCHINFO_RTSP_CSEQ_RECV - get the recently received CSeq

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_RTSP_CSEQ_RECV, long *cseq);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the most recently received CSeq from the
server. If your application encounters a *FETCHE_RTSP_CSEQ_ERROR* then you
may wish to troubleshoot and/or fix the CSeq mismatch by peeking at this
value.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "rtsp://rtsp.example.com");
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      long cseq;
      fetch_easy_getinfo(fetch, FETCHINFO_RTSP_CSEQ_RECV, &cseq);
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
