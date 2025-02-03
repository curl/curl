---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_RTSP_SESSION_ID
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_RTSP_CSEQ_RECV (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

FETCHINFO_RTSP_SESSION_ID - get RTSP session ID

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_RTSP_SESSION_ID, char **id);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive a pointer to a string holding the
most recent RTSP Session ID.

Applications wishing to resume an RTSP session on another connection should
retrieve this info before closing the active connection.

The **id** pointer is NULL or points to private memory. You MUST NOT free - it
gets freed when you call fetch_easy_cleanup(3) on the corresponding fetch
handle.

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
      char *id;
      fetch_easy_getinfo(fetch, FETCHINFO_RTSP_SESSION_ID, &id);
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
