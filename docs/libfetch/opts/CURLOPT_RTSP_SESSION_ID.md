---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RTSP_SESSION_ID
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_RTSP_REQUEST (3)
  - FETCHOPT_RTSP_STREAM_URI (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

FETCHOPT_RTSP_SESSION_ID - RTSP session ID

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_RTSP_SESSION_ID, char *id);
~~~

# DESCRIPTION

Pass a char pointer as a parameter to set the value of the current RTSP
Session ID for the handle. Useful for resuming an in-progress session. Once
this value is set to any non-NULL value, libfetch returns
*FETCHE_RTSP_SESSION_ERROR* if ID received from the server does not match. If
unset (or set to NULL), libfetch automatically sets the ID the first time the
server sets it in a response.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    char *prev_id; /* saved from before somehow */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "rtsp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_RTSP_SESSION_ID, prev_id);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
